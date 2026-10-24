//! ama-core — the AMA (Agentic Microkernel Architecture) kernel.
//!
//! Deliberately minimal, like QNX's procnto: a process table, an IPC
//! router over Unix Domain Sockets, an append-only ledger, capability
//! checks on every message, and a watchdog/supervisor that respawns
//! crashed agents from their last ledger checkpoint. Agents NEVER touch
//! global state — they checkpoint their own state into the ledger.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod sandbox;
pub mod seccomp;

// ---------------------------------------------------------------------------
// Envelope: the typed message contract. The kernel validates EVERY incoming
// envelope against this schema and refuses unknown kinds (QNX: "the kernel
// attaches no special meaning to the content of a message" — but well-defined
// message types exist).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Envelope {
    Register { name: String, caps: Vec<String> },
    Heartbeat { uin: u64, step: String, phase: String },
    Send { uin: u64, to: String, body: Value },
    Checkpoint { uin: u64, state: Value },
    Recovered { uin: u64 },
    Done { uin: u64 },
    Note { uin: u64, text: String },
}

impl Envelope {
    /// Strict per-kind schema validation. Returns Err naming the missing or
    /// unexpected field — the kernel never "best-effort" parses.
    pub fn parse(line: &str) -> Result<Envelope, String> {
        let v: Value = serde_json::from_str(line).map_err(|e| format!("invalid json: {e}"))?;
        let kind = v
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("missing 'kind'")?
            .to_string();
        let take_u64 = |k: &str| v.get(k).and_then(Value::as_u64).ok_or(format!("missing '{k}'"));
        match kind.as_str() {
            "register" => {
                let name = v
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or("register: missing 'name'")?
                    .to_string();
                let caps = v
                    .get("caps")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(String::from)
                            .collect::<Vec<_>>()
                    })
                    .ok_or("register: missing 'caps' array")?;
                if let Some(extra) = v.get("uin") {
                    return Err(format!("register: unexpected field 'uin' = {extra}"));
                }
                Ok(Envelope::Register { name, caps })
            }
            "heartbeat" => Ok(Envelope::Heartbeat {
                uin: take_u64("uin")?,
                step: v
                    .get("step")
                    .and_then(Value::as_str)
                    .ok_or("heartbeat: missing 'step'")?
                    .to_string(),
                phase: v
                    .get("phase")
                    .and_then(Value::as_str)
                    .ok_or("heartbeat: missing 'phase' (executing|blocked)")?
                    .to_string(),
            }),
            "send" => Ok(Envelope::Send {
                uin: take_u64("uin")?,
                to: v
                    .get("to")
                    .and_then(Value::as_str)
                    .ok_or("send: missing 'to'")?
                    .to_string(),
                body: v.get("body").cloned().ok_or("send: missing 'body'")?,
            }),
            "checkpoint" => Ok(Envelope::Checkpoint {
                uin: take_u64("uin")?,
                state: v.get("state").cloned().ok_or("checkpoint: missing 'state'")?,
            }),
            "recovered" => Ok(Envelope::Recovered { uin: take_u64("uin")? }),
            "done" => Ok(Envelope::Done { uin: take_u64("uin")? }),
            "note" => Ok(Envelope::Note {
                uin: take_u64("uin")?,
                text: v
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or("note: missing 'text'")?
                    .to_string(),
            }),
            other => Err(format!("unknown envelope kind '{other}'")),
        }
    }

    pub fn to_line(&self) -> String {
        let v = match self {
            Envelope::Register { name, caps } => json!({"kind": "register", "name": name, "caps": caps}),
            Envelope::Heartbeat { uin, step, phase } => {
                json!({"kind": "heartbeat", "uin": uin, "step": step, "phase": phase})
            }
            Envelope::Send { uin, to, body } => json!({"kind": "send", "uin": uin, "to": to, "body": body}),
            Envelope::Checkpoint { uin, state } => json!({"kind": "checkpoint", "uin": uin, "state": state}),
            Envelope::Recovered { uin } => json!({"kind": "recovered", "uin": uin}),
            Envelope::Done { uin } => json!({"kind": "done", "uin": uin}),
            Envelope::Note { uin, text } => json!({"kind": "note", "uin": uin, "text": text}),
        };
        format!("{v}\n")
    }
}

// ---------------------------------------------------------------------------
// Ledger: append-only, the ONLY global state in the system.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub ev: String,
    pub detail: Value,
}

pub struct Ledger {
    path: std::path::PathBuf,
    seq: AtomicU64,
}

impl Ledger {
    pub fn open(path: &std::path::Path) -> std::io::Result<Ledger> {
        let seq = {
            let f = std::fs::File::open(path).ok();
            let mut n = 0u64;
            if let Some(f) = f {
                for line in BufReader::new(f).lines().map_while(Result::ok) {
                    if serde_json::from_str::<Value>(&line).is_ok() {
                        n += 1;
                    }
                }
            }
            AtomicU64::new(n)
        };
        Ok(Ledger { path: path.to_path_buf(), seq })
    }

    pub fn append(&self, ev: &str, detail: Value) -> std::io::Result<LedgerEvent> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let e = LedgerEvent { seq, ts_ms, ev: ev.into(), detail };
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&e).unwrap())?;
        f.flush()?;
        Ok(e)
    }

    pub fn read_all(&self) -> Vec<LedgerEvent> {
        std::fs::File::open(&self.path)
            .ok()
            .map(|f| {
                BufReader::new(f)
                    .lines()
                    .map_while(Result::ok)
                    .filter_map(|l| serde_json::from_str::<LedgerEvent>(&l).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Last checkpoint recorded for a UIN — the respawn source of truth.
    pub fn last_checkpoint(&self, uin: u64) -> Option<Value> {
        self.read_all()
            .into_iter()
            .rev()
            .find(|e| e.ev == "checkpoint" && e.detail.get("uin").and_then(Value::as_u64) == Some(uin))
            .map(|e| e.detail.get("state").cloned().unwrap_or(Value::Null))
    }
}

// ---------------------------------------------------------------------------
// Process table + capabilities.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ProcState {
    Registered,
    Running,
    Completed,
    Killed(String),
    Dead,
}

#[derive(Debug)]
pub struct ProcEntry {
    pub uin: u64,
    pub name: String,
    pub pid: u32,
    pub caps: Vec<String>,
    pub state: ProcState,
    pub last_hb: Instant,
    pub last_step: String,
    pub last_phase: String,
    pub stuck_sweeps: u32,
    pub respawns: u32,
    pub last_checkpoint: Option<Value>,
    pub task_path: String,
    pub out: Option<UnixStream>,
}

pub struct Kernel {
    pub socket_path: std::path::PathBuf,
    pub ledger: Arc<Ledger>,
    pub agents: Arc<Mutex<HashMap<u64, Arc<Mutex<ProcEntry>>>>>,
    by_name: Arc<Mutex<HashMap<String, u64>>>,
    next_uin: AtomicU64,
    pub hb_timeout_ms: u64,
    pub hb_interval_ms: u64,
    pub max_respawns: u32,
    pub agentd_path: String,
    pub apply_cgroups: bool,
}

impl Kernel {
    pub fn new(
        socket_path: &std::path::Path,
        ledger_path: &std::path::Path,
        agentd_path: &str,
        hb_interval_ms: u64,
        hb_timeout_ms: u64,
        max_respawns: u32,
    ) -> std::io::Result<Kernel> {
        Ok(Kernel {
            socket_path: socket_path.to_path_buf(),
            ledger: Arc::new(Ledger::open(ledger_path)?),
            agents: Arc::new(Mutex::new(HashMap::new())),
            by_name: Arc::new(Mutex::new(HashMap::new())),
            next_uin: AtomicU64::new(0),
            hb_timeout_ms,
            hb_interval_ms,
            max_respawns,
            agentd_path: agentd_path.to_string(),
            apply_cgroups: false,
        })
    }

    /// Spawn an agent process from a manifest entry. The process is the
    /// isolation unit: its own PID, its own ephemeral memory.
    pub fn spawn_agent(&self, name: &str, task_path: &str) -> std::io::Result<()> {
        let uin = self.next_uin.fetch_add(1, Ordering::SeqCst);
        let mut cmd = Command::new(&self.agentd_path);
        cmd.args(["--socket", self.socket_path.to_str().unwrap_or("/tmp/ama.sock"), "--task", task_path])
            .env("AMA_UIN", uin.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd.spawn()?;
        let pid = child.id();
        let entry = Arc::new(Mutex::new(ProcEntry {
            uin,
            name: name.into(),
            pid,
            caps: Vec::new(),
            state: ProcState::Registered,
            last_hb: Instant::now(),
            last_step: String::new(),
            last_phase: "executing".into(),
            stuck_sweeps: 0,
            respawns: 0,
            last_checkpoint: None,
            task_path: task_path.into(),
            out: None,
        }));
        if self.apply_cgroups {
            let _ = sandbox::apply_cgroup(pid, name);
        }
        self.agents.lock().unwrap().insert(uin, entry);
        self.by_name.lock().unwrap().insert(name.into(), uin);
        self.ledger.append("spawned", json!({"uin": uin, "name": name, "pid": pid, "task": task_path}))?;
        Ok(())
    }

    /// Capability check: the ONLY path a message takes. Denials are
    /// journaled — a refused send is a security event, not a silent drop.
    pub fn check_cap(&self, uin: u64, verb: &str, target: &str) -> Result<(), String> {
        let need = format!("{verb}:{target}");
        let agents = self.agents.lock().unwrap();
        let entry = agents.get(&uin).ok_or("unknown uin")?;
        if entry.lock().unwrap().caps.iter().any(|c| c == &need) {
            Ok(())
        } else {
            drop(agents);
            self.ledger
                .append("cap_denied", json!({"uin": uin, "needed": need}))
                .map_err(|e| e.to_string())?;
            Err(format!("capability '{need}' not granted"))
        }
    }

    pub fn route_send(&self, from: u64, to: &str, body: &Value) -> Result<(), String> {
        let uin = self
            .by_name
            .lock()
            .unwrap()
            .get(to)
            .copied()
            .ok_or_else(|| format!("unknown agent '{to}'"))?;
        let conn = {
            let agents = self.agents.lock().unwrap();
            let entry = agents.get(&uin).ok_or("no process table entry")?;
            let mut e = entry.lock().unwrap();
            match e.state {
                ProcState::Dead | ProcState::Completed => {
                    return Err(if e.state == ProcState::Dead {
                        format!("agent '{to}' is dead (respawn budget exhausted)")
                    } else {
                        format!("agent '{to}' has completed its task")
                    })
                }
                ProcState::Registered | ProcState::Running | ProcState::Killed(_) => e
                    .out
                    .as_mut()
                    .map(|s| s.try_clone().map_err(|e| e.to_string()))
                    .transpose()?,
            }
        };
        let mut w = conn.ok_or_else(|| format!("agent '{to}' has no connection"))?;
        let msg = format!("{}\n", json!({"kind": "msg", "from": from, "body": body}));
        w.write_all(msg.as_bytes()).map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())?;
        self.ledger
            .append("delivered", json!({"from": from, "to": uin, "body": body}))
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Kill + journal. The process disappears; its ephemeral memory
    /// disappears with it.
    pub fn kill(&self, uin: u64, reason: &str) {
        let child_pid = {
            let agents = self.agents.lock().unwrap();
            match agents.get(&uin) {
                Some(e) => {
                    let mut e = e.lock().unwrap();
                    if matches!(e.state, ProcState::Killed(_) | ProcState::Dead | ProcState::Completed) {
                        return; // already judged — fail-fast is idempotent
                    }
                    e.state = ProcState::Killed(reason.into());
                    e.pid
                }
                None => return,
            }
        };
        let _ = Command::new("kill")
            .args(["-9", &child_pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        self.ledger
            .append("killed", json!({"uin": uin, "pid": child_pid, "reason": reason}))
            .ok();
    }

    /// Atomic respawn: fresh process from the last ledger checkpoint.
    pub fn respawn(&self, uin: u64) {
        let (name, task, respawns, checkpoint) = {
            let agents = self.agents.lock().unwrap();
            let e = match agents.get(&uin) {
                Some(e) => e.lock().unwrap(),
                None => return,
            };
            let n = e.name.clone();
            let t = e.task_path.clone();
            let r = e.respawns;
            let c = e.last_checkpoint.clone();
            (n, t, r, c)
        };
        if respawns >= self.max_respawns {
            let agents = self.agents.lock().unwrap();
            if let Some(e) = agents.get(&uin) {
                e.lock().unwrap().state = ProcState::Dead;
            }
            drop(agents);
            self.ledger.append("dead", json!({"uin": uin, "name": name, "reason": "respawn budget exhausted"})).ok();
            return;
        }
        let mut cmd = Command::new(&self.agentd_path);
        cmd.args(["--socket", self.socket_path.to_str().unwrap_or("/tmp/ama.sock"), "--task", &task])
            .env("AMA_UIN", uin.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                self.ledger.append("respawn_failed", json!({"uin": uin, "err": e.to_string()})).ok();
                return;
            }
        };
        let pid = child.id();
        let agents = self.agents.lock().unwrap();
        if let Some(e) = agents.get(&uin) {
            let mut e = e.lock().unwrap();
            e.pid = pid;
            e.respawns += 1;
            e.state = ProcState::Registered;
            e.last_hb = Instant::now();
            e.last_step = String::new();
            e.stuck_sweeps = 0;
            // the fresh instance inherits the ledger checkpoint on register
            e.last_checkpoint = checkpoint.or(e.last_checkpoint.clone());
        }
        drop(agents);
        self.ledger
            .append("respawned", json!({"uin": uin, "name": name, "pid": pid}))
            .ok();
    }

    /// Watchdog sweep: heartbeat timeout AND progress-loop detection.
    pub fn sweep(&self) {
        let suspects: Vec<(u64, String)> = {
            let agents = self.agents.lock().unwrap();
            agents
                .values()
                .filter_map(|e| {
                    let mut e = e.lock().unwrap();
                    if e.out.is_none() {
                        return None; // never connected — registration grace
                    }
                    if matches!(e.state, ProcState::Dead | ProcState::Completed | ProcState::Killed(_)) {
                        return None; // already judged — never re-kill, never re-journal
                    }
                    let hb_age = e.last_hb.elapsed().as_millis() as u64;
                    if hb_age > self.hb_timeout_ms {
                        return Some((e.uin, format!("heartbeat timeout ({} ms)", hb_age)));
                    }
                    // progress watchdog: the SAME step for K sweeps WHILE
                    // EXECUTING = an infinite reasoning loop candidate. A
                    // BLOCKED agent (wait/sleep/kernel IO) is legitimate —
                    // the distinction is carried on the heartbeat.
                    if e.last_phase == "executing" && !e.last_step.is_empty() && e.state == ProcState::Running {
                        e.stuck_sweeps += 1;
                        if e.stuck_sweeps >= 5 {
                            return Some((e.uin, format!("no progress on step '{}' for {} sweeps", e.last_step, e.stuck_sweeps)));
                        }
                    }
                    None
                })
                .collect()
        };
        for (uin, reason) in suspects {
            self.kill(uin, &reason);
            self.respawn(uin);
        }
    }
}

// ---------------------------------------------------------------------------
// Router: UDS listener + thread-per-connection. Full duplex: the kernel
// writes deliveries to the same socket it reads envelopes from.
// ---------------------------------------------------------------------------

pub struct Router {
    pub kernel: Arc<Kernel>,
}

impl Router {
    /// BIND FIRST, spawn agents after — the listener must exist before any
    /// agent process starts connecting (experiment 001 regression, now the
    /// router's own contract).
    pub fn serve(kernel: Kernel, agents: &[(String, String)]) -> std::io::Result<std::thread::JoinHandle<()>> {
        let kernel = Arc::new(kernel);
        let _ = std::fs::remove_file(&kernel.socket_path);
        let listener = std::os::unix::net::UnixListener::bind(&kernel.socket_path)?;
        let k = kernel.clone();
        let watchdog = std::thread::spawn(move || loop {
            k.sweep();
            std::thread::sleep(Duration::from_millis(200));
        });
        std::mem::forget(watchdog);
        // bind is live now — spawn the manifest's agents
        for (name, task) in agents {
            if let Err(e) = kernel.spawn_agent(name, task) {
                eprintln!("[ama] spawn {name}: {e}");
            }
        }
        let handle = std::thread::spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => {
                        let k = kernel.clone();
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(None);
                        std::thread::spawn(move || Router::connection(k, stream));
                    }
                    Err(_) => continue,
                }
            }
        });
        Ok(handle)
    }

    fn connection(kernel: Arc<Kernel>, stream: UnixStream) {
        let mut writer = match stream.try_clone() {
            Ok(w) => w,
            Err(_) => return,
        };
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut my_uin: Option<u64> = None;
        let mut writer = stream;
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF: the process died or exited
                Ok(_) => {}
                Err(_) => break,
            }
            // control channel verbs (grant/revoke) — operators may
            // renegotiate capabilities AT RUNTIME; agents can never reach
            // this: their first envelope registers them
            if let Ok(v) = serde_json::from_str::<Value>(line.trim_end()) {
                match v.get("kind").and_then(Value::as_str) {
                    Some("ctl_grant") if my_uin.is_none() => {
                        let name = v.get("name").and_then(Value::as_str).unwrap_or("");
                        let caps: Vec<String> = v
                            .get("caps")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                            .unwrap_or_default();
                        let uin = kernel.by_name.lock().unwrap().get(name).copied();
                        if let Some(uin) = uin {
                            {
                                let agents = kernel.agents.lock().unwrap();
                                if let Some(entry) = agents.get(&uin) {
                                    let mut e = entry.lock().unwrap();
                                    for c in &caps {
                                        if !e.caps.contains(c) {
                                            e.caps.push(c.clone());
                                        }
                                    }
                                }
                            }
                            kernel.ledger.append("cap_granted", json!({"uin": uin, "name": name, "caps": caps})).ok();
                            let _ = write!(writer, "{}\n", json!({"kind": "granted", "name": name}));
                            let _ = writer.flush();
                            continue;
                        }
                    }
                    Some("ctl_revoke") if my_uin.is_none() => {
                        let name = v.get("name").and_then(Value::as_str).unwrap_or("");
                        let caps: Vec<String> = v
                            .get("caps")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                            .unwrap_or_default();
                        let uin = kernel.by_name.lock().unwrap().get(name).copied();
                        if let Some(uin) = uin {
                            {
                                let agents = kernel.agents.lock().unwrap();
                                if let Some(entry) = agents.get(&uin) {
                                    let mut e = entry.lock().unwrap();
                                    e.caps.retain(|c| !caps.contains(c));
                                }
                            }
                            kernel.ledger.append("cap_revoked", json!({"uin": uin, "name": name, "caps": caps})).ok();
                            let _ = write!(writer, "{}\n", json!({"kind": "revoked", "name": name}));
                            let _ = writer.flush();
                            continue;
                        }
                    }
                    _ => {}
                }
            }
            // control channel: an UNREGISTERED connection may dump the
            // process table (the operator's `ama ps`). Agents can never
            // reach this: their first envelope registers them.
            if line.trim_end() == "{\"kind\": \"ctl_ps\"}" && my_uin.is_none() {
                let dump: Vec<Value> = {
                    let agents = kernel.agents.lock().unwrap();
                    agents
                        .values()
                        .map(|e| {
                            let e = e.lock().unwrap();
                            json!({
                                "uin": e.uin, "name": e.name, "pid": e.pid,
                                "state": match &e.state {
                                    ProcState::Registered => "registered",
                                    ProcState::Running => "running",
                                    ProcState::Completed => "completed",
                                    ProcState::Killed(r) => "killed",
                                    ProcState::Dead => "dead",
                                },
                                "killed_reason": if let ProcState::Killed(r) = &e.state { json!(r) } else { Value::Null },
                                "respawns": e.respawns,
                                "last_step": e.last_step,
                                "caps": e.caps,
                            })
                        })
                        .collect()
                };
                let _ = write!(writer, "{}\n", json!({"kind": "ps", "agents": dump}));
                let _ = writer.flush();
                continue;
            }
            let env = match Envelope::parse(line.trim_end()) {
                Ok(e) => e,
                Err(reason) => {
                    kernel.ledger.append("malformed", json!({"reason": reason, "line": line.trim_end()})).ok();
                    let _ = write!(
                        writer,
                        "{}\n",
                        json!({"kind": "error", "reason": format!("rejected: {reason}")})
                    );
                    let _ = writer.flush();
                    continue;
                }
            };
            match Router::handle(&kernel, &mut writer, env, &mut my_uin) {
                Ok(()) => {}
                Err(e) => {
                    let _ = write!(writer, "{}\n", json!({"kind": "error", "reason": e}));
                    let _ = writer.flush();
                }
            }
        }
        // EOF: if this connection belonged to a live agent, the process is
        // gone — fail fast, respawn from the ledger.
        if let Some(uin) = my_uin {
            let live = {
                let agents = kernel.agents.lock().unwrap();
                match agents.get(&uin) {
                    Some(e) => {
                        let mut e = e.lock().unwrap();
                        let was_live = !matches!(
                            e.state,
                            ProcState::Killed(_) | ProcState::Dead | ProcState::Completed
                        );
                        if was_live {
                            e.state = ProcState::Killed("process exited".into());
                        }
                        was_live
                    }
                    None => false,
                }
            };
            if live {
                kernel.ledger.append("crashed", json!({"uin": uin})).ok();
                kernel.respawn(uin);
            }
        }
    }

    fn handle(kernel: &Kernel, writer: &mut UnixStream, env: Envelope, my_uin: &mut Option<u64>) -> Result<(), String> {
        match env {
            Envelope::Register { name, caps } => {
                let uin = kernel
                    .by_name
                    .lock()
                    .unwrap()
                    .get(&name)
                    .copied()
                    .ok_or_else(|| format!("unknown agent '{name}' — not in the manifest"))?;
                {
                    let agents = kernel.agents.lock().unwrap();
                    let entry = agents.get(&uin).ok_or("no entry")?;
                    let mut e = entry.lock().unwrap();
                    e.caps = caps;
                    e.state = ProcState::Running;
                    e.out = Some(writer.try_clone().map_err(|e| e.to_string())?);
                    e.last_hb = Instant::now();
                    e.stuck_sweeps = 0;
                    e.last_step = String::new();
                }
                *my_uin = Some(uin);
                kernel.ledger.append("registered", json!({"uin": uin, "name": name})).map_err(|e| e.to_string())?;
                let recover = kernel.ledger.last_checkpoint(uin);
                writer.write_all(
                    format!(
                        "{}\n",
                        json!({"kind": "welcome", "uin": uin, "recover": recover})
                    )
                    .as_bytes(),
                )
                .map_err(|e| e.to_string())?;
                writer.flush().map_err(|e| e.to_string())?;
                Ok(())
            }
            Envelope::Heartbeat { uin, step, phase } => {
                let agents = kernel.agents.lock().unwrap();
                let entry = agents.get(&uin).ok_or("unknown uin")?;
                let mut e = entry.lock().unwrap();
                if e.last_step != step && phase == "executing" {
                    e.stuck_sweeps = 0; // progress detected
                }
                e.last_step = step;
                e.last_phase = phase;
                e.last_hb = Instant::now();
                if e.state == ProcState::Registered {
                    e.state = ProcState::Running;
                }
                Ok(())
            }
            Envelope::Send { uin, to, body } => {
                kernel.check_cap(uin, "send", &to)?;
                kernel.route_send(uin, &to, &body)?;
                writer
                    .write_all(format!("{}\n", json!({"kind": "sent", "to": to})).as_bytes())
                    .map_err(|e| e.to_string())?;
                writer.flush().map_err(|e| e.to_string())?;
                Ok(())
            }
            Envelope::Checkpoint { uin, state } => {
                let e = kernel
                    .ledger
                    .append("checkpoint", json!({"uin": uin, "state": state}))
                    .map_err(|e| e.to_string())?;
                let agents = kernel.agents.lock().unwrap();
                if let Some(entry) = agents.get(&uin) {
                    entry.lock().unwrap().last_checkpoint = Some(state.clone());
                }
                drop(agents);
                writer
                    .write_all(format!("{}\n", json!({"kind": "acked", "seq": e.seq})).as_bytes())
                    .map_err(|e| e.to_string())?;
                writer.flush().map_err(|e| e.to_string())?;
                Ok(())
            }
            Envelope::Done { uin } => {
                let agents = kernel.agents.lock().unwrap();
                if let Some(entry) = agents.get(&uin) {
                    let mut e = entry.lock().unwrap();
                    e.state = ProcState::Completed;
                }
                drop(agents);
                kernel
                    .ledger
                    .append("completed", json!({"uin": uin}))
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Envelope::Note { uin, text } => {
                kernel.ledger.append("agent_note", json!({"uin": uin, "text": text})).map_err(|e| e.to_string())?;
                Ok(())
            }
            Envelope::Recovered { uin: _ } => {
                kernel.ledger.append("recovered", json!({"uin": my_uin.unwrap_or(0)})).map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }
}

#[derive(Deserialize)]
pub struct Manifest {
    pub kernel: KernelConfig,
    pub agents: Vec<AgentSpec>,
}

#[derive(Deserialize, Clone)]
pub struct KernelConfig {
    pub socket: String,
    pub ledger: String,
    #[serde(default = "default_hb")]
    pub hb_interval_ms: u64,
    #[serde(default = "default_timeout")]
    pub hb_timeout_ms: u64,
    #[serde(default)]
    pub max_respawns: u32,
}

fn default_hb() -> u64 {
    150
}
fn default_timeout() -> u64 {
    1200
}

#[derive(Deserialize)]
pub struct AgentSpec {
    pub name: String,
    pub task: String,
}
