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
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod proto;
pub mod qos;
pub mod sandbox;
pub mod seccomp;

use std::io::{self, Write as IoWrite};

/// §3: the wire format is per-connection. JSON (newline-delimited) was the
/// v0.1 contract; msgpack (§6.2 wire encoding, length-prefixed with the
/// 0xFF magic) is the binary alternative — the kernel speaks BOTH and
/// answers each connection in ITS format.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Wire {
    Json,
    Msgpack,
    /// protobuf (hand-rolled encoder, §6.2 "protobuf remains an option")
    Proto,
}

/// Serialize + frame an envelope in the connection's wire format.
pub fn write_envelope(w: &mut dyn IoWrite, wire: Wire, v: &Value) -> io::Result<()> {
    match wire {
        Wire::Json => {
            // ONE write() syscall: `writeln!(w, "{v}")` fragments the
            // Display output byte-by-byte, and two threads sharing one
            // stream can interleave fragments MID-LINE (seen in the
            // experiment 003 ledger: heartbeats corrupting checkpoints)
            w.write_all(format!("{v}\n").as_bytes())?;
            w.flush()
        }
        Wire::Msgpack => {
            let bytes = rmp_serde::to_vec_named(v)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            w.write_all(&[0xFF])?;
            w.write_all(&(bytes.len() as u32).to_le_bytes())?;
            w.write_all(&bytes)?;
            w.flush()
        }
        Wire::Proto => {
            let bytes = proto::encode_value(v)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            w.write_all(&[0x0A])?;
            w.write_all(&(bytes.len() as u32).to_le_bytes())?;
            w.write_all(&bytes)?;
            w.flush()
        }
    }
}

/// Read one PROTOBUF frame (0x0A magic + u32 LE length + proto message).
pub fn read_proto_frame<R: std::io::Read>(r: &mut R) -> io::Result<Value> {
    let mut magic = [0u8; 1];
    r.read_exact(&mut magic)?;
    if magic[0] != 0x0A {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing 0x0A magic",
        ));
    }
    let mut lenb = [0u8; 4];
    r.read_exact(&mut lenb)?;
    let len = u32::from_le_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    // raw decode — NO Envelope schema check here: this frame may be a
    // kernel→agent REPLY (welcome/sent/acked/msg/error), which is outside
    // the agent→kernel Envelope vocabulary. The kernel's handle_value
    // re-validates agent envelopes; the agent's reader accepts replies
    // verbatim, exactly like the JSON/msgpack readers.
    proto::decode_raw(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Read one msgpack frame (0xFF magic + u32 LE length + payload).
pub fn read_msgpack_frame<R: std::io::Read>(r: &mut R) -> io::Result<Value> {
    let mut magic = [0u8; 1];
    r.read_exact(&mut magic)?;
    if magic[0] != 0xFF {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing 0xFF magic",
        ));
    }
    let mut lenb = [0u8; 4];
    r.read_exact(&mut lenb)?;
    let len = u32::from_le_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    rmp_serde::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------
// Envelope: the typed message contract. The kernel validates EVERY incoming
// envelope against this schema and refuses unknown kinds (QNX: "the kernel
// attaches no special meaning to the content of a message" — but well-defined
// message types exist).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Envelope {
    Register {
        name: String,
        caps: Vec<String>,
    },
    Heartbeat {
        uin: u64,
        step: String,
        phase: String,
    },
    /// Kernel → agent: registration accepted. `recover` carries the last
    /// ledger checkpoint (None when the agent is fresh). The proto reader
    /// enforces this schema — a missing Welcome variant made the agentd
    /// drop the connection on the very first frame (experiment 004:
    /// proto agents died of heartbeat timeout because welcome never
    /// reached the inbox).
    Welcome {
        uin: u64,
        recover: Option<Value>,
    },
    Send {
        uin: u64,
        to: String,
        body: Value,
    },
    Checkpoint {
        uin: u64,
        state: Value,
    },
    Recovered {
        uin: u64,
    },
    Done {
        uin: u64,
    },
    Note {
        uin: u64,
        text: String,
    },
}

impl Envelope {
    /// Strict per-kind schema validation. Returns Err naming the missing or
    /// unexpected field — the kernel never "best-effort" parses.
    pub fn parse(line: &str) -> Result<Envelope, String> {
        let v: Value = serde_json::from_str(line).map_err(|e| format!("invalid json: {e}"))?;
        Envelope::from_value(&v)
    }

    /// The typed contract over ANY wire format (JSON lines or msgpack —
    /// the SAME validation, the kernel never best-effort parses).
    pub fn from_value(v: &Value) -> Result<Envelope, String> {
        let kind = v
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("missing 'kind'")?
            .to_string();
        let take_u64 = |k: &str| {
            v.get(k)
                .and_then(Value::as_u64)
                .ok_or(format!("missing '{k}'"))
        };
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
            "welcome" => Ok(Envelope::Welcome {
                uin: take_u64("uin")?,
                recover: v.get("recover").and_then(|r| {
                    if r.is_null() {
                        None
                    } else {
                        Some(r.clone())
                    }
                }),
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
                state: v
                    .get("state")
                    .cloned()
                    .ok_or("checkpoint: missing 'state'")?,
            }),
            "recovered" => Ok(Envelope::Recovered {
                uin: take_u64("uin")?,
            }),
            "done" => Ok(Envelope::Done {
                uin: take_u64("uin")?,
            }),
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
            Envelope::Register { name, caps } => {
                json!({"kind": "register", "name": name, "caps": caps})
            }
            Envelope::Heartbeat { uin, step, phase } => {
                json!({"kind": "heartbeat", "uin": uin, "step": step, "phase": phase})
            }
            Envelope::Welcome { uin, recover } => {
                json!({"kind": "welcome", "uin": uin, "recover": recover})
            }
            Envelope::Send { uin, to, body } => {
                json!({"kind": "send", "uin": uin, "to": to, "body": body})
            }
            Envelope::Checkpoint { uin, state } => {
                json!({"kind": "checkpoint", "uin": uin, "state": state})
            }
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
    /// append is called from multiple connection threads — a torn line
    /// poisons the whole ledger (experiment 003 caught this)
    write_lock: Mutex<()>,
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
        Ok(Ledger {
            path: path.to_path_buf(),
            seq,
            write_lock: Mutex::new(()),
        })
    }

    pub fn append(&self, ev: &str, detail: Value) -> std::io::Result<LedgerEvent> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let e = LedgerEvent {
            seq,
            ts_ms,
            ev: ev.into(),
            detail,
        };
        let _guard = self.write_lock.lock().unwrap();
        // the ledger must survive its parent dir being removed mid-flight
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&e).unwrap())?;
        f.flush()?;
        drop(_guard);
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
            .find(|e| {
                e.ev == "checkpoint" && e.detail.get("uin").and_then(Value::as_u64) == Some(uin)
            })
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
    /// the agent's connection in ANY transport (UDS or TCP — §3);
    /// Mutex-serialized: route_send (sender's thread) and this agent's
    /// own ack replies write the SAME fd concurrently — unsynchronized
    /// writes interleave msgpack frames mid-payload
    pub out: Option<Arc<Mutex<Peer>>>,
    pub wire: Wire,
    /// "microvm" = the watched PID is a Firecracker VM, not an OS
    /// process; respawn must re-boot the VM, not the agentd binary
    pub isolation: Option<String>,
    /// delivery priority (0 = highest); default 5
    pub priority: u8,
    /// delay-tolerant destination: sends to it while disconnected are
    /// held by the kernel (custody) instead of failing
    pub dtn: bool,
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
    /// network-remote IPC (§3): agents may connect over TCP from other
    /// hosts; the envelope contract and capability checks are identical
    pub tcp_addr: Option<String>,
    /// per-agent Firecracker boot script (vm/boot_agent.sh) for the
    /// microVM isolation tier
    pub vm_boot: Option<String>,
    /// QoS (per-sender token buckets) + DTN (store-and-forward custody
    /// store) — see qos.rs
    pub delivery: Mutex<qos::DeliverySystem>,
    /// DTN routing table: destination name -> relay name (next hop)
    pub routes: std::collections::HashMap<String, String>,
    /// hop budget for a routed bundle
    pub max_hops: u8,
    /// bodies above this size are fragmented (None = never)
    pub max_bundle_bytes: Option<usize>,
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
            tcp_addr: None,
            vm_boot: None,
            delivery: Mutex::new(qos::DeliverySystem::new(1024, Duration::from_secs(300))),
            routes: std::collections::HashMap::new(),
            max_hops: default_max_hops_u8(),
            max_bundle_bytes: None,
        })
    }

    /// Configure the delivery link from the manifest's kernel section:
    /// admission limits and the WFQ capacity.
    pub fn configure_delivery(
        &self,
        max_bytes_per_sec: Option<u32>,
        max_queue_bytes: Option<u64>,
        wfq_capacity: Option<f64>,
        link_bytes_per_tick: Option<u64>,
    ) {
        let mut d = self.delivery.lock().unwrap();
        d.admission.max_bytes_per_sec = max_bytes_per_sec;
        if let Some(q) = max_queue_bytes {
            d.admission.max_queue_bytes = q;
        }
        if let Some(c) = wfq_capacity {
            d.wfq = qos::WfqScheduler::new(c);
        }
        d.link_bytes_per_tick = link_bytes_per_tick;
    }

    /// Install the DTN routing table and the hop/fragment policy.
    pub fn configure_routing(
        &mut self,
        routes: &[RouteSpec],
        max_hops: u8,
        max_bundle_bytes: Option<usize>,
    ) {
        for r in routes {
            self.routes.insert(r.dest.clone(), r.via.clone());
        }
        self.max_hops = max_hops;
        self.max_bundle_bytes = max_bundle_bytes;
    }

    /// Is this agent connected right now?
    fn agent_ready(&self, uin: u64) -> bool {
        let agents = self.agents.lock().unwrap();
        match agents.get(&uin) {
            Some(e) => {
                let e = e.lock().unwrap();
                matches!(e.state, ProcState::Running | ProcState::Registered) && e.out.is_some()
            }
            None => false,
        }
    }

    /// Write a kernel->agent frame to a connected agent.
    fn write_to(&self, uin: u64, msg: &Value) -> Result<(), String> {
        let (wire, mut w) = {
            let agents = self.agents.lock().unwrap();
            let entry = agents.get(&uin).ok_or("no process table entry")?;
            let e = entry.lock().unwrap();
            let p = e.out.as_ref().ok_or("no connection")?;
            let guard = p.lock().unwrap();
            (e.wire, guard.try_clone().map_err(|e| e.to_string())?)
        };
        let w_ref: &mut dyn IoWrite = &mut w;
        write_envelope(w_ref, wire, msg).map_err(|e| e.to_string())
    }

    /// Reverse lookup: the destination's NAME — what a relay echoes back
    /// when it forwards the bundle (a relay never sees the kernel's UINs).
    fn name_of(&self, uin: u64) -> Option<String> {
        let by_name = self.by_name.lock().unwrap();
        by_name
            .iter()
            .find(|(_, u)| **u == uin)
            .map(|(n, _)| n.clone())
    }

    /// Hand custody of `b` to its next hop (a relay agent) as a `bundle`
    /// frame. The kernel KEEPS its copy until the relay acknowledges.
    fn forward_to_relay(&self, b: &qos::DtnBundle, relay: u64) -> Result<(), String> {
        let to_name = self.name_of(b.to).ok_or("no name for the destination")?;
        let frag = b
            .frag
            .map(|m| json!({"id": m.id, "index": m.index, "total": m.total}));
        let msg = json!({
            "kind": "bundle",
            "bundle_id": b.bundle_id,
            "from": b.from,
            "to": to_name,
            "to_uin": b.to,
            "hops": b.hops,
            "frag": frag,
            "body": b.body,
        });
        self.write_to(relay, &msg)
    }

    /// Declare an agent's QoS at registration time (priority is stored
    /// on the entry; a rate limit installs its token bucket).
    pub fn set_qos(&self, uin: u64, priority: u8, rate: Option<u32>) {
        {
            let agents = self.agents.lock().unwrap();
            if let Some(e) = agents.get(&uin) {
                e.lock().unwrap().priority = priority;
            }
        }
        self.delivery.lock().unwrap().set_rate(uin, rate);
    }

    /// Spawn an agent process from a manifest entry. The process is the
    /// isolation unit: its own PID, its own ephemeral memory.
    pub fn spawn_agent(&self, name: &str, task_path: &str) -> std::io::Result<()> {
        self.spawn_agent_opts(name, task_path, None, Some(Wire::Json), None, None, false)
    }

    /// `tcp`: connect over the network-remote transport; `wire`: speak
    /// JSON, msgpack, or protobuf (per-agent options); `isolation`:
    /// "microvm" boots the agent inside its own Firecracker microVM
    /// (see vm/boot_agent.sh) instead of an OS process
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_agent_opts(
        &self,
        name: &str,
        task_path: &str,
        tcp: Option<&str>,
        wire_opt: Option<Wire>,
        isolation: Option<&str>,
        qos: Option<QosSpec>,
        dtn: bool,
    ) -> std::io::Result<()> {
        // 8 params by design: name/task/tcp/wire/isolation are the
        // pre-existing spawn surface, qos+dtn are the delivery contract
        let uin = self.next_uin.fetch_add(1, Ordering::SeqCst);
        let microvm = isolation == Some("microvm");
        let mut cmd = if microvm {
            // the VM tier: the "agent process" IS a Firecracker microVM.
            // The boot script assembles the per-agent initramfs (static
            // agentd + task baked in), wires a private tap and execs
            // firecracker — the PID we watch is the whole VM. The guest
            // agentd connects back over TCP; the envelope contract and
            // capability checks are byte-identical to the host tiers.
            let script = self.vm_boot.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "isolation 'microvm' requires kernel.vm_boot (vm/boot_agent.sh)",
                )
            })?;
            let port = self
                .tcp_addr
                .as_ref()
                .and_then(|a| a.rsplit(':').next()?.parse::<u64>().ok())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "isolation 'microvm' requires kernel.tcp_port",
                    )
                })?;
            let mut c = Command::new(script);
            c.args([uin.to_string(), task_path.into(), port.to_string()]);
            c
        } else {
            let mut c = Command::new(&self.agentd_path);
            c.args([
                "--socket",
                self.socket_path.to_str().unwrap_or("/tmp/ama.sock"),
                "--task",
                task_path,
            ]);
            c
        };
        if !microvm {
            let tcp_addr = tcp.map(String::from).or_else(|| self.tcp_addr.clone());
            if let Some(addr) = tcp_addr {
                cmd.arg("--tcp").arg(addr);
            }
        }
        if !microvm {
            if let Some(w) = wire_opt {
                let s = match w {
                    Wire::Json => "json",
                    Wire::Msgpack => "msgpack",
                    Wire::Proto => "proto",
                };
                cmd.arg("--wire").arg(s);
            }
        }
        cmd.env("AMA_UIN", uin.to_string());
        // microVM: the guest's SERIAL CONSOLE is firecracker's STDOUT —
        // nulling it discards the only window into the VM (and the
        // guest agentd's panics); capture it with the stderr file
        if microvm && std::env::var("AMA_DEBUG").is_ok() {
            // stdout follows the debug path chosen below (set after)
        } else {
            cmd.stdout(Stdio::null());
        }
        // debug mode: keep agent stderr in a per-agent file (watchdog
        // forensics) instead of dropping it
        if std::env::var("AMA_DEBUG").is_ok() {
            let p = std::path::PathBuf::from(format!(
                "/tmp/ama_dbg_agent_{}.stderr",
                self.next_uin.load(Ordering::SeqCst)
            ));
            let f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&p);
            if let Ok(f) = f {
                if microvm {
                    // the VM's serial console (firecracker stdout) shares
                    // the forensics file
                    let _ = cmd.stdout(Stdio::from(f.try_clone().expect("stdout clone")));
                }
                cmd.stderr(Stdio::from(f));
            } else {
                cmd.stderr(Stdio::null());
            }
        } else {
            cmd.stderr(Stdio::null());
        }
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
            wire: Wire::Json,
            isolation: isolation.map(String::from),
            priority: qos.and_then(|q| q.priority).unwrap_or(5).min(9),
            dtn,
        }));
        if self.apply_cgroups {
            let _ = sandbox::apply_cgroup(pid, name);
        }
        self.agents.lock().unwrap().insert(uin, entry);
        self.by_name.lock().unwrap().insert(name.into(), uin);
        // QoS registration: the sender's token bucket is installed at
        // spawn time so a rate limit applies from the FIRST envelope
        if let Some(q) = qos {
            self.set_qos(
                uin,
                q.priority.unwrap_or(5).min(9),
                q.max_msgs_per_sec.filter(|r| *r > 0),
            );
            let mut d = self.delivery.lock().unwrap();
            // WFQ weight and the sender's own admission budget
            d.set_weight(uin, q.weight.unwrap_or(1.0));
            d.set_byte_rate(uin, q.max_bytes_per_sec);
        }
        self.ledger.append(
            "spawned",
            json!({"uin": uin, "name": name, "pid": pid, "task": task_path, "dtn": dtn}),
        )?;
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

    /// QoS-aware, DTN-capable delivery path.
    ///
    /// QoS: the SENDER's token bucket gates the send (a bursty agent
    /// cannot starve the others); the DESTINATION's priority orders the
    /// DTN queue when delivery must be deferred.
    ///
    /// DTN: when the destination is disconnected (dead, killed, or
    /// pre-registration) and it declared `dtn: true`, the kernel takes
    /// CUSTODY of the message instead of failing the send — store-and-
    /// forward with a TTL, delivered on the next registration. Without
    /// `dtn: true` the historical behaviour stands: the send fails.
    pub fn route_send(&self, from: u64, to: &str, body: &Value) -> Result<(), String> {
        let uin = self
            .by_name
            .lock()
            .unwrap()
            .get(to)
            .copied()
            .ok_or_else(|| format!("unknown agent '{to}'"))?;

        let bytes = serde_json::to_vec(body).map(|b| b.len()).unwrap_or(0);

        // ADMISSION CONTROL first: byte rate + queue bound. A refused
        // message never enters the kernel (journaled, never silent).
        // NOTE: the guard must be scoped — a MutexGuard held by an
        // `if let` scrutinee lives to the end of the whole `if let`
        // statement, and re-locking inside the block self-deadlocks
        // (std Mutex is not reentrant; this hung the kernel once).
        let admission = {
            let mut d = self.delivery.lock().unwrap();
            d.admit_bytes(from, bytes)
        };
        if let Err(reason) = admission {
            self.delivery.lock().unwrap().record_denied();
            self.ledger
                .append(
                    "admission_denied",
                    json!({"from": from, "to": uin, "bytes": bytes, "reason": reason}),
                )
                .map_err(|e| e.to_string())?;
            return Err(format!("admission: {reason}"));
        }

        // QoS gate: a rate-limited sender is throttled even when
        // the destination is up — backpressure before entry, not after.
        let allowed = { self.delivery.lock().unwrap().allow(from) };
        if !allowed {
            self.delivery.lock().unwrap().record_throttled();
            self.ledger
                .append(
                    "qos_throttled",
                    json!({"from": from, "to": uin, "body": body}),
                )
                .map_err(|e| e.to_string())?;
            return Err(format!("qos: sender {from} over its rate limit"));
        }

        let (wire, w, dest_priority, dest_dtn, deliverable): (Wire, Option<Peer>, u8, bool, bool) = {
            let agents = self.agents.lock().unwrap();
            let entry = agents.get(&uin).ok_or("no process table entry")?;
            let e = entry.lock().unwrap();
            let deliverable =
                matches!(e.state, ProcState::Running | ProcState::Registered) && e.out.is_some();
            let w = if deliverable {
                match e.out.as_ref() {
                    Some(p) => {
                        let guard = p.lock().unwrap();
                        guard.try_clone().ok()
                    }
                    None => None,
                }
            } else {
                None
            };
            (e.wire, w, e.priority, e.dtn, deliverable)
        };

        if !deliverable {
            // DTN custody: hold the message for the target's next
            // registration — or route it to a relay when the manifest
            // says which one reaches the destination
            if dest_dtn {
                let bundle_id = self.delivery.lock().unwrap().new_bundle_id();
                return self.dtn_route(from, to, uin, body.clone(), dest_priority, 0, bundle_id);
            }
            // not DTN-tolerant: the historical explicit failure
            let agents = self.agents.lock().unwrap();
            let entry = agents.get(&uin).ok_or("no process table entry")?;
            let e = entry.lock().unwrap();
            return Err(match e.state {
                ProcState::Dead => format!("agent '{to}' is dead (respawn budget exhausted)"),
                ProcState::Completed => format!("agent '{to}' has completed its task"),
                _ => format!("agent '{to}' has no connection"),
            });
        }

        // SCHEDULING: while the link is idle a connected destination is
        // served straight through (work-conserving, zero added latency).
        // Under contention the message joins the WFQ queue and the
        // watchdog's tick serves it by virtual finish tag — weight, not
        // arrival order, decides who gets the link.
        let go_fast = {
            let mut d = self.delivery.lock().unwrap();
            !d.link_busy() && d.link_ready(bytes)
        };
        if !go_fast {
            let mut d = self.delivery.lock().unwrap();
            d.schedule(from, uin, body.clone(), bytes)
                .map_err(|e| e.to_string())?;
            drop(d);
            self.ledger
                .append(
                    "qos_scheduled",
                    json!({"from": from, "to": uin, "bytes": bytes}),
                )
                .map_err(|e| e.to_string())?;
            return Ok(());
        }

        let mut w = w.ok_or_else(|| format!("agent '{to}' has no connection"))?;
        let msg = json!({"kind": "msg", "from": from, "body": body});
        let w_ref: &mut dyn IoWrite = &mut w;
        write_envelope(w_ref, wire, &msg).map_err(|e| e.to_string())?;
        self.delivery
            .lock()
            .unwrap()
            .record_fast_path(from, uin, bytes);
        self.ledger
            .append(
                "delivered",
                json!({"from": from, "to": uin, "bytes": bytes, "body": body}),
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Drain the WFQ delivery queue in virtual-finish-tag order. Called
    /// from the watchdog tick (and once more at the end of `sweep`), so a
    /// scheduled message waits at most one tick (200 ms) — the price of
    /// fair scheduling on a kernel with no dedicated link thread.
    pub fn drain_delivery_queue(&self) {
        let mut served = 0usize;
        loop {
            let next = {
                let mut d = self.delivery.lock().unwrap();
                // peek before popping: a message the link cannot carry
                // yet stays queued (WFQ order is preserved across ticks)
                let head = d.pending.peek().map(|m| m.0.bytes);
                match head {
                    Some(b) if d.link_ready(b) => match d.pop_next() {
                        Some(m) => m,
                        None => break,
                    },
                    _ => break,
                }
            };
            // resolve the destination's writer
            let target: Option<(Wire, Peer)> = {
                let agents = self.agents.lock().unwrap();
                match agents.get(&next.to) {
                    Some(entry) => {
                        let e = entry.lock().unwrap();
                        let deliverable =
                            matches!(e.state, ProcState::Running | ProcState::Registered)
                                && e.out.is_some();
                        if deliverable {
                            e.out.as_ref().and_then(|p| {
                                let guard = p.lock().unwrap();
                                guard.try_clone().ok().map(|w| (e.wire, w))
                            })
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            };
            match target {
                Some((wire, mut w)) => {
                    let msg = json!({"kind": "msg", "from": next.from, "body": next.body});
                    let w_ref: &mut dyn IoWrite = &mut w;
                    match write_envelope(w_ref, wire, &msg) {
                        Ok(()) => {
                            served += 1;
                            self.delivery.lock().unwrap().record_delivery(&next);
                            self.ledger
                                .append(
                                    "qos_delivered",
                                    json!({
                                        "from": next.from,
                                        "to": next.to,
                                        "bytes": next.bytes,
                                        "tag": next.tag,
                                    }),
                                )
                                .ok();
                        }
                        Err(e) => {
                            let mut d = self.delivery.lock().unwrap();
                            d.record_queued_drop(next.bytes);
                            drop(d);
                            self.ledger
                                .append(
                                    "qos_dropped",
                                    json!({"to": next.to, "bytes": next.bytes, "err": e.to_string()}),
                                )
                                .ok();
                        }
                    }
                }
                None => {
                    // destination vanished while queued: it loses the
                    // message, and the drop is journaled (never silent)
                    let mut d = self.delivery.lock().unwrap();
                    d.record_queued_drop(next.bytes);
                    drop(d);
                    self.ledger
                        .append(
                            "qos_dropped",
                            json!({"to": next.to, "bytes": next.bytes, "reason": "destination disconnected"}),
                        )
                        .ok();
                }
            }
        }
        if served > 0 {
            let snap = self.delivery.lock().unwrap().stats();
            self.ledger
                .append(
                    "qos_accounting",
                    json!({"served_now": served, "stats": snap}),
                )
                .ok();
        }
    }

    /// Route one logical bundle: fragment it when it is too large,
    /// hand it to a configured relay (journaled custody transfer), or
    /// store it for the destination's next registration.
    #[allow(clippy::too_many_arguments)]
    pub fn dtn_route(
        &self,
        from: u64,
        to_name: &str,
        to_uin: u64,
        body: Value,
        priority: u8,
        hops: u8,
        bundle_id: u64,
    ) -> Result<(), String> {
        self.dtn_route_ext(from, to_name, to_uin, body, priority, hops, bundle_id, true)
    }

    /// `allow_routing = false` means "this bundle is already in transit":
    /// it must not be re-routed by the static table (that is what would
    /// make relay2 hand the bundle straight back to relay1 and loop).
    #[allow(clippy::too_many_arguments)]
    pub fn dtn_route_ext(
        &self,
        from: u64,
        to_name: &str,
        to_uin: u64,
        body: Value,
        priority: u8,
        hops: u8,
        bundle_id: u64,
        allow_routing: bool,
    ) -> Result<(), String> {
        self.dtn_route_frag(
            from,
            to_name,
            to_uin,
            body,
            priority,
            hops,
            bundle_id,
            allow_routing,
            None,
        )
    }

    /// The routing core with the fragment slot: a body that IS already a
    /// fragment (in transit through a relay) must never be fragmented
    /// again — that would multiply the message on every hop.
    #[allow(clippy::too_many_arguments)]
    pub fn dtn_route_frag(
        &self,
        from: u64,
        to_name: &str,
        to_uin: u64,
        body: Value,
        priority: u8,
        hops: u8,
        bundle_id: u64,
        allow_routing: bool,
        frag: Option<qos::FragMeta>,
    ) -> Result<(), String> {
        // FRAGMENTATION: a body above the threshold travels as numbered
        // fragments, each routed independently
        if frag.is_none() {
            if let Some(max) = self.max_bundle_bytes {
                let size = serde_json::to_vec(&body).map(|v| v.len()).unwrap_or(0);
                // the threshold applies to the ENCODED fragment payload (hex,
                // so 2 chars per byte): compare like with like
                if size * 2 > max {
                    let frags = qos::fragment_body(&body, max, bundle_id)?;
                    let n = frags.len();
                    for (meta, piece) in frags {
                        self.dtn_route_piece_ext(
                            from,
                            to_name,
                            to_uin,
                            piece,
                            priority,
                            hops,
                            bundle_id,
                            Some(meta),
                            allow_routing,
                        )?;
                    }
                    self.ledger
                        .append(
                            "dtn_fragmented",
                            json!({"from": from, "to": to_uin, "bundle_id": bundle_id,
                               "bytes": size, "fragments": n}),
                        )
                        .map_err(|e| e.to_string())?;
                    return Ok(());
                }
            }
        }
        self.dtn_route_piece_ext(
            from,
            to_name,
            to_uin,
            body,
            priority,
            hops,
            bundle_id,
            frag,
            allow_routing,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn dtn_route_piece_ext(
        &self,
        from: u64,
        to_name: &str,
        to_uin: u64,
        body: Value,
        priority: u8,
        hops: u8,
        bundle_id: u64,
        frag: Option<qos::FragMeta>,
        allow_routing: bool,
    ) -> Result<(), String> {
        // the next hop, when the manifest declares a route AND the bundle
        // is not already in transit through a relay's chosen path
        let next = if allow_routing {
            self.routes
                .get(to_name)
                .and_then(|via| self.by_name.lock().unwrap().get(via).copied())
        } else {
            None
        };

        if let Some(relay) = next {
            if hops >= self.max_hops {
                self.ledger
                    .append(
                        "dtn_hop_limit",
                        json!({"from": from, "to": to_uin, "bundle_id": bundle_id, "hops": hops}),
                    )
                    .map_err(|e| e.to_string())?;
                return Err(format!("dtn: hop limit ({}) reached", self.max_hops));
            }
            let relay_ready = self.agent_ready(relay);
            {
                let mut d = self.delivery.lock().unwrap();
                d.store_routed(
                    from,
                    to_uin,
                    body.clone(),
                    priority,
                    None,
                    Some(relay),
                    hops,
                    bundle_id,
                    frag,
                )?;
            }
            if relay_ready {
                let mut b = qos::DtnBundle::new(
                    from,
                    to_uin,
                    body.clone(),
                    priority,
                    Duration::from_secs(300),
                );
                b.bundle_id = bundle_id;
                b.hops = hops;
                b.frag = frag;
                self.forward_to_relay(&b, relay)?;
                self.ledger
                    .append(
                        "dtn_relayed",
                        json!({"from": from, "to": to_uin, "relay": relay,
                               "bundle_id": bundle_id, "hops": hops + 1}),
                    )
                    .map_err(|e| e.to_string())?;
            } else {
                self.ledger
                    .append(
                        "dtn_stored",
                        json!({"from": from, "to": to_uin, "next_hop": relay,
                               "bundle_id": bundle_id, "hops": hops, "body": body}),
                    )
                    .map_err(|e| e.to_string())?;
            }
            return Ok(());
        }

        // no route: plain custody for the destination itself
        {
            let mut d = self.delivery.lock().unwrap();
            d.store_routed(
                from,
                to_uin,
                body.clone(),
                priority,
                None,
                None,
                hops,
                bundle_id,
                frag,
            )?;
        }
        self.ledger
            .append(
                "dtn_stored",
                json!({"from": from, "to": to_uin, "priority": priority,
                       "bundle_id": bundle_id, "hops": hops, "body": body}),
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// DTN flush: called on registration — deliver the destination's held
    /// bundles in PRIORITY order (0 first), journal every delivery and
    /// every expiry. Runs BEFORE the welcome is written so the fresh
    /// agent sees its backlog as its first messages.
    pub fn dtn_flush(&self, uin: u64) -> Result<(), String> {
        let (wire, writer, name) = {
            let agents = self.agents.lock().unwrap();
            let entry = agents.get(&uin).ok_or("no process table entry")?;
            let e = entry.lock().unwrap();
            let w = match e.out.as_ref() {
                Some(p) => {
                    let guard = p.lock().unwrap();
                    guard.try_clone().map_err(|e| e.to_string())?
                }
                None => return Ok(()), // still no connection — nothing to flush into
            };
            (e.wire, w, e.name.clone())
        };
        let (bundles, expired) = {
            let mut d = self.delivery.lock().unwrap();
            let out = d.drain_for(uin);
            let exp = d.take_expired_report();
            (out, exp)
        };
        for b in &expired {
            self.ledger
                .append(
                    "dtn_expired",
                    json!({"from": b.from, "to": uin, "body": b.body}),
                )
                .ok();
        }
        let count = bundles.len();
        for b in bundles {
            let msg = json!({"kind": "msg", "from": b.from, "body": b.body});
            let mut w = writer.try_clone().map_err(|e| e.to_string())?;
            let w_ref: &mut dyn IoWrite = &mut w;
            write_envelope(w_ref, wire, &msg).map_err(|e| e.to_string())?;
            self.ledger
                .append(
                    "dtn_delivered",
                    json!({"from": b.from, "to": uin, "priority": b.priority, "body": b.body}),
                )
                .map_err(|e| e.to_string())?;
        }
        if count > 0 {
            self.ledger
                .append(
                    "dtn_flushed",
                    json!({"to": uin, "name": name, "count": count}),
                )
                .ok();
        }

        // ROUTING: bundles whose next hop is this agent — the relay is
        // back, hand it the custody it was waiting for
        let via = self.delivery.lock().unwrap().drain_via(uin);
        for b in &via {
            self.forward_to_relay(b, uin)?;
            self.ledger
                .append(
                    "dtn_relayed",
                    json!({"from": b.from, "to": b.to, "relay": uin,
                           "bundle_id": b.bundle_id, "hops": b.hops + 1}),
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// The process-table dump for the operator's `ama ps`.
    pub fn ps_dump(&self) -> Vec<Value> {
        let agents = self.agents.lock().unwrap();
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
                        ProcState::Killed(_) => "killed",
                        ProcState::Dead => "dead",
                    },
                    "killed_reason": if let ProcState::Killed(r) = &e.state { json!(r) } else { Value::Null },
                    "respawns": e.respawns,
                    "isolation": e.isolation.clone().unwrap_or_else(|| "process".into()),
                    "last_step": e.last_step,
                    "caps": e.caps,
                    "wire": match e.wire {
                        Wire::Json => "json",
                        Wire::Msgpack => "msgpack",
                        Wire::Proto => "proto",
                    },
                })
            })
            .collect()
    }

    /// Kill + journal. The process disappears; its ephemeral memory
    /// disappears with it.
    pub fn kill(&self, uin: u64, reason: &str) {
        let child_pid = {
            let agents = self.agents.lock().unwrap();
            match agents.get(&uin) {
                Some(e) => {
                    let mut e = e.lock().unwrap();
                    if matches!(
                        e.state,
                        ProcState::Killed(_) | ProcState::Dead | ProcState::Completed
                    ) {
                        return; // already judged — fail-fast is idempotent
                    }
                    e.state = ProcState::Killed(reason.into());
                    e.out = None;
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
            .append(
                "killed",
                json!({"uin": uin, "pid": child_pid, "reason": reason}),
            )
            .ok();
    }

    /// Atomic respawn: fresh process from the last ledger checkpoint.
    /// The respawn MUST carry the agent's wire: the fresh agentd otherwise
    /// defaults to json and re-registers under a different wire than the
    /// manifest asked for (experiment 004: proto agent reborn as json).
    pub fn respawn(&self, uin: u64) {
        let (name, task, respawns, checkpoint, wire, isolation, priority, dtn) = {
            let agents = self.agents.lock().unwrap();
            let e = match agents.get(&uin) {
                Some(e) => e.lock().unwrap(),
                None => return,
            };
            let n = e.name.clone();
            let t = e.task_path.clone();
            let r = e.respawns;
            let c = e.last_checkpoint.clone();
            let w = e.wire;
            let iso = e.isolation.clone();
            let pr = e.priority;
            let dn = e.dtn;
            (n, t, r, c, w, iso, pr, dn)
        };
        if respawns >= self.max_respawns {
            let agents = self.agents.lock().unwrap();
            if let Some(e) = agents.get(&uin) {
                e.lock().unwrap().state = ProcState::Dead;
            }
            drop(agents);
            self.ledger
                .append(
                    "dead",
                    json!({"uin": uin, "name": name, "reason": "respawn budget exhausted"}),
                )
                .ok();
            return;
        }
        let microvm = isolation.as_deref() == Some("microvm");
        let mut cmd = if microvm {
            // the respawn of a VM agent re-boots the WHOLE microVM: a
            // fresh initramfs is assembled (the ledger checkpoint rides
            // inside the task file) and firecracker runs it again
            let script = self.vm_boot.as_deref().unwrap_or("vm/boot_agent.sh");
            let port = self
                .tcp_addr
                .as_ref()
                .and_then(|a| a.rsplit(':').next()?.parse::<u64>().ok())
                .unwrap_or(0);
            let mut c = Command::new(script);
            c.args([uin.to_string(), task.clone(), port.to_string()]);
            c
        } else {
            let mut c = Command::new(&self.agentd_path);
            c.args([
                "--socket",
                self.socket_path.to_str().unwrap_or("/tmp/ama.sock"),
                "--task",
                &task,
            ])
            .env("AMA_UIN", uin.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
            {
                let s = match wire {
                    Wire::Json => "json",
                    Wire::Msgpack => "msgpack",
                    Wire::Proto => "proto",
                };
                c.arg("--wire").arg(s);
            }
            c
        };
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                self.ledger
                    .append("respawn_failed", json!({"uin": uin, "err": e.to_string()}))
                    .ok();
                return;
            }
        };
        let pid = child.id();
        let agents = self.agents.lock().unwrap();
        if let Some(e) = agents.get(&uin) {
            let mut e = e.lock().unwrap();
            e.pid = pid;
            e.respawns += 1;
            // KEEP the state (Killed) until the fresh instance registers —
            // resetting to Registered here let the OLD process's EOF race
            // in and trigger a SECOND respawn (seen in the 003 ledger)
            e.last_hb = Instant::now();
            e.last_step = String::new();
            e.stuck_sweeps = 0;
            // the fresh instance inherits the ledger checkpoint on register
            e.last_checkpoint = checkpoint.or(e.last_checkpoint.clone());
            // delivery contract survives the respawn: a reborn agent keeps
            // its priority and its DTN custody role
            e.priority = priority;
            e.dtn = dtn;
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
                    // never connected — registration grace
                    e.out.as_ref()?;
                    if matches!(
                        e.state,
                        ProcState::Dead | ProcState::Completed | ProcState::Killed(_)
                    ) {
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
                    if e.last_phase == "executing"
                        && !e.last_step.is_empty()
                        && e.state == ProcState::Running
                    {
                        e.stuck_sweeps += 1;
                        if e.stuck_sweeps >= 5 {
                            return Some((
                                e.uin,
                                format!(
                                    "no progress on step '{}' for {} sweeps",
                                    e.last_step, e.stuck_sweeps
                                ),
                            ));
                        }
                    }
                    None
                })
                .collect()
        };
        // QoS: refill the link's per-tick budget, then serve the WFQ
        // queue while the budget lasts (the rest waits for the next tick)
        self.delivery.lock().unwrap().refill_link();
        self.drain_delivery_queue();

        // DTN sweep: bundles whose TTL ran out while the destination
        // never registered — journaled then dropped (never silent)
        {
            let expired = self.delivery.lock().unwrap().sweep_expired();
            for b in expired {
                self.ledger
                    .append(
                        "dtn_expired",
                        json!({"from": b.from, "to": b.to, "body": b.body}),
                    )
                    .ok();
            }
        }
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

/// One manifest agent, expanded: (name, task, tcp target, wire, isolation)
pub type AgentSpecTuple = (
    String,
    String,
    Option<String>,
    Option<Wire>,
    Option<String>,
    Option<QosSpec>,
    bool,
);

pub struct Router {
    pub kernel: Arc<Kernel>,
}

impl Router {
    /// BIND FIRST, spawn agents after — the listener must exist before any
    /// agent process starts connecting (experiment 001 regression, now the
    /// router's own contract).
    pub fn serve(
        kernel: Kernel,
        agents: &[(String, String)],
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        let a: Vec<AgentSpecTuple> = agents
            .iter()
            .map(|(n, t)| {
                (
                    n.clone(),
                    t.clone(),
                    None,
                    Some(Wire::Json),
                    None,
                    None,
                    false,
                )
            })
            .collect();
        Router::serve_full(kernel, &a)
    }

    pub fn serve_full(
        kernel: Kernel,
        agents: &[AgentSpecTuple],
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        let kernel = Arc::new(kernel);
        let _ = std::fs::remove_file(&kernel.socket_path);
        let listener = std::os::unix::net::UnixListener::bind(&kernel.socket_path)?;
        let k = kernel.clone();
        let watchdog = std::thread::spawn(move || loop {
            k.sweep();
            std::thread::sleep(Duration::from_millis(200));
        });
        std::mem::forget(watchdog);
        // network-remote listener: SAME envelope contract over TCP (§3)
        if let Some(addr) = kernel.tcp_addr.clone() {
            let k = kernel.clone();
            std::thread::spawn(move || match std::net::TcpListener::bind(&addr) {
                Ok(tcp) => {
                    eprintln!("[ama] tcp listener up on {addr}");
                    for conn in tcp.incoming().flatten() {
                        let stream = conn;
                        let k = k.clone();
                        let _ = stream.set_nodelay(true);
                        let _ = stream.set_read_timeout(None);
                        std::thread::spawn(move || Router::connection(k, Peer::Tcp(stream)));
                    }
                }
                Err(e) => eprintln!("[ama] tcp listener {addr}: {e}"),
            });
        }
        // bind is live now — spawn the manifest's agents
        for (name, task, tcp, wire, iso, qos, dtn) in agents {
            if let Err(e) = kernel.spawn_agent_opts(
                name,
                task,
                tcp.as_deref(),
                *wire,
                iso.as_deref(),
                *qos,
                *dtn,
            ) {
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
                        std::thread::spawn(move || Router::connection(k, Peer::Unix(stream)));
                    }
                    Err(_) => continue,
                }
            }
        });
        Ok(handle)
    }

    /// One connection, any transport, both wire formats. The FIRST byte
    /// decides the format: `{` = JSON lines (v0.1 contract), 0xFF = the
    /// length-prefixed msgpack frames (§6.2 wire encoding).
    fn connection(kernel: Arc<Kernel>, mut peer: Peer) {
        let mut first = [0u8; 1];
        if peer.read(&mut first).unwrap_or(0) == 0 {
            return;
        }
        let my_uin = match first[0] {
            b'{' => Router::json_loop(kernel.clone(), &mut JsonPeer::new(peer, first[0])),
            0xFF => Router::msgpack_loop(kernel.clone(), peer, true),
            0x0A => Router::proto_loop(kernel.clone(), peer),
            _ => {
                // a payload that does not even carry the schema magic is a
                // violation — journal it (never silently drop a rejected
                // connection)
                kernel
                    .ledger
                    .append("malformed", json!({"reason": "invalid json: first byte is not '{' or 0xFF (schema violation)", "seen": first[0]}))
                    .ok();
                None
            }
        };
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

    fn proto_loop(kernel: Arc<Kernel>, mut peer: Peer) -> Option<u64> {
        let mut my_uin: Option<u64> = None;
        // first frame: the 0x0A magic byte was already consumed
        let mut v = {
            let mut lenb = [0u8; 4];
            if peer.read_exact(&mut lenb).is_err() {
                return None;
            }
            let len = u32::from_le_bytes(lenb) as usize;
            let mut buf = vec![0u8; len];
            if peer.read_exact(&mut buf).is_err() {
                return None;
            }
            match proto::decode_raw(&buf) {
                Ok(val) => val,
                Err(e) => {
                    kernel
                        .ledger
                        .append(
                            "malformed",
                            json!({"reason": format!("proto: first frame decode failed: {e}")}),
                        )
                        .ok();
                    return None;
                }
            }
        };
        if std::env::var("AMA_DEBUG").is_ok() {
            eprintln!("[proto_loop] first frame: {v}");
        }
        loop {
            match Router::handle_value(&kernel, &mut peer, &v, &mut my_uin, Wire::Proto) {
                Ok(()) => {}
                Err(e) => {
                    let _ = write_envelope(
                        &mut peer,
                        Wire::Proto,
                        &json!({"kind": "error", "reason": e}),
                    );
                }
            }
            match read_proto_frame(&mut peer) {
                Ok(v2) => {
                    if std::env::var("AMA_DEBUG").is_ok() {
                        eprintln!("[proto_loop] next frame: {v2}");
                    }
                    v = v2;
                }
                Err(_) => break,
            }
        }
        my_uin
    }

    fn msgpack_loop(kernel: Arc<Kernel>, mut peer: Peer, _first_magic_seen: bool) -> Option<u64> {
        let mut my_uin: Option<u64> = None;
        if std::env::var("AMA_DEBUG").is_ok() {
            eprintln!("[msgpack_loop] entered");
        }
        // first frame: the magic byte was already consumed
        let mut v = {
            let mut lenb = [0u8; 4];
            if peer.read_exact(&mut lenb).is_err() {
                return None;
            }
            let len = u32::from_le_bytes(lenb) as usize;
            let mut buf = vec![0u8; len];
            if peer.read_exact(&mut buf).is_err() {
                return None;
            }
            match rmp_serde::from_slice::<Value>(&buf) {
                Ok(v) => v,
                Err(e) => {
                    kernel
                        .ledger
                        .append("malformed", json!({"reason": format!("msgpack: {e}")}))
                        .ok();
                    return None;
                }
            }
        };
        let last_wire = Wire::Msgpack;
        loop {
            match Router::handle_value(&kernel, &mut peer, &v, &mut my_uin, last_wire) {
                Ok(()) => {}
                Err(e) => {
                    let _ = write_envelope(
                        &mut peer,
                        Wire::Msgpack,
                        &json!({"kind": "error", "reason": e}),
                    );
                }
            }
            match read_msgpack_frame(&mut peer) {
                Ok(v2) => {
                    if std::env::var("AMA_DEBUG").is_ok() {
                        eprintln!("[msgpack_loop] next frame: {v2}");
                    }
                    v = v2;
                }
                Err(_) => break,
            }
        }
        let _ = last_wire;
        my_uin
    }

    fn json_loop(kernel: Arc<Kernel>, reader: &mut JsonPeer) -> Option<u64> {
        let mut my_uin: Option<u64> = None;
        let mut line = String::new();
        // the first '{' was already consumed by the mode detector
        match reader.read_line_after(&mut line) {
            Ok(true) => {}
            _ => return None,
        }
        // the first '{' is ALREADY in `line` (pushed by the JsonPeer) —
        // prepending a second brace produced `{{kind` → "key must be a
        // string" (caught by experiment 003)
        let first = line.trim_end().to_string();
        if std::env::var("AMA_DEBUG_JSON").is_ok() {
            eprintln!("[json_loop] first line = {first:?}");
        }
        let mut v = match serde_json::from_str::<Value>(&first) {
            Ok(v) => {
                if std::env::var("AMA_DEBUG").is_ok() {
                    eprintln!("[json_loop] first frame: {v}");
                }
                v
            }
            Err(e) => {
                kernel
                    .ledger
                    .append(
                        "malformed",
                        json!({"reason": format!("invalid json: {e}"), "line": first}),
                    )
                    .ok();
                return None;
            }
        };
        loop {
            match Router::handle_value(&kernel, reader.peer_mut(), &v, &mut my_uin, Wire::Json) {
                Ok(()) => {}
                Err(e) => {
                    let _ = write_envelope(
                        reader.peer_mut(),
                        Wire::Json,
                        &json!({"kind": "error", "reason": format!("rejected: {e}")}),
                    );
                }
            }
            line.clear();
            match reader.read_line_after(&mut line) {
                Ok(true) => {}
                _ => break, // EOF: process gone
            }
            if std::env::var("AMA_DEBUG_JSON").is_ok() {
                eprintln!("[json_loop] line = {:?}", line.trim_end());
            }
            match serde_json::from_str::<Value>(line.trim_end()) {
                Ok(v2) => {
                    if std::env::var("AMA_DEBUG").is_ok() {
                        eprintln!("[json_loop] frame: {v2}");
                    }
                    v = v2;
                }
                Err(e) => {
                    kernel.ledger.append("malformed", json!({"reason": format!("invalid json: {e}"), "line": line.trim_end()})).ok();
                    let _ = write_envelope(
                        reader.peer_mut(),
                        Wire::Json,
                        &json!({"kind": "error", "reason": format!("rejected: invalid json: {e}")}),
                    );
                    continue;
                }
            }
        }
        my_uin
    }

    /// Handle ONE decoded envelope (transport- and format-agnostic).
    fn handle_value(
        kernel: &Kernel,
        writer: &mut Peer,
        v: &Value,
        my_uin: &mut Option<u64>,
        wire: Wire,
    ) -> Result<(), String> {
        // control channel verbs — operators may dump the table and
        // renegotiate capabilities AT RUNTIME; agents can never reach
        // this: their first envelope registers them
        if my_uin.is_none() {
            if let Some(kind) = v.get("kind").and_then(Value::as_str) {
                match kind {
                    "ctl_qos" => {
                        // bandwidth accounting + queue state, operator-only
                        let stats = kernel.delivery.lock().unwrap().stats();
                        let reply = json!({"kind": "qos", "stats": stats});
                        write_envelope(writer, wire, &reply).map_err(|e| e.to_string())?;
                        return Ok(());
                    }
                    "ctl_ps" => {
                        let dump = kernel.ps_dump();
                        let reply = json!({"kind": "ps", "agents": dump});
                        if std::env::var("AMA_DEBUG_JSON").is_ok() {
                            eprintln!("[ctl_ps] reply = {reply}");
                        }
                        write_envelope(writer, wire, &reply).map_err(|e| e.to_string())?;
                        return Ok(());
                    }
                    "ctl_grant" | "ctl_revoke" => {
                        let name = v.get("name").and_then(Value::as_str).unwrap_or("");
                        let caps: Vec<String> = v
                            .get("caps")
                            .and_then(Value::as_array)
                            .map(|a| {
                                a.iter()
                                    .filter_map(Value::as_str)
                                    .map(String::from)
                                    .collect()
                            })
                            .unwrap_or_default();
                        let uin = kernel.by_name.lock().unwrap().get(name).copied();
                        if let Some(uin) = uin {
                            {
                                let agents = kernel.agents.lock().unwrap();
                                if let Some(entry) = agents.get(&uin) {
                                    let mut e = entry.lock().unwrap();
                                    if kind == "ctl_grant" {
                                        for c in &caps {
                                            if !e.caps.contains(c) {
                                                e.caps.push(c.clone());
                                            }
                                        }
                                    } else {
                                        e.caps.retain(|c| !caps.contains(c));
                                    }
                                }
                            }
                            let ev = if kind == "ctl_grant" {
                                "cap_granted"
                            } else {
                                "cap_revoked"
                            };
                            kernel
                                .ledger
                                .append(ev, json!({"uin": uin, "name": name, "caps": caps}))
                                .ok();
                            let ack = if kind == "ctl_grant" {
                                "granted"
                            } else {
                                "revoked"
                            };
                            write_envelope(writer, wire, &json!({"kind": ack, "name": name}))
                                .map_err(|e| e.to_string())?;
                            return Ok(());
                        }
                    }
                    _ => {}
                }
            }
        }
        // agent envelopes
        // DTN routing verbs, handled at the Value level (a relay agent
        // forwards custody and acknowledges custody transfers). They are
        // not part of the core Envelope vocabulary because they carry
        // routing coordinates the kernel never trusts from a wire schema.
        if let Some(me) = *my_uin {
            if let Some(kind) = v.get("kind").and_then(Value::as_str) {
                match kind {
                    "relay" => {
                        let bundle_id = v.get("bundle_id").and_then(Value::as_u64).unwrap_or(0);
                        let to_name = v.get("to").and_then(Value::as_str).unwrap_or("");
                        let hops = v.get("hops").and_then(Value::as_u64).unwrap_or(0) as u8;
                        let orig = v.get("from").and_then(Value::as_u64).unwrap_or(me);
                        let body = v.get("body").cloned().unwrap_or(Value::Null);
                        let frag_meta = v.get("frag").filter(|f| !f.is_null()).and_then(|f| {
                            Some(qos::FragMeta {
                                id: f.get("id")?.as_u64()?,
                                index: f.get("index")?.as_u64()? as u32,
                                total: f.get("total")?.as_u64()? as u32,
                            })
                        });
                        if hops > kernel.max_hops {
                            kernel
                                .ledger
                                .append(
                                    "dtn_hop_limit",
                                    json!({"bundle_id": bundle_id, "to": to_name, "hops": hops}),
                                )
                                .map_err(|e| e.to_string())?;
                            return Err(format!("dtn: hop limit ({}) reached", kernel.max_hops));
                        }
                        let Some(target) = kernel.by_name.lock().unwrap().get(to_name).copied()
                        else {
                            return Err(format!("relay: unknown agent '{to_name}'"));
                        };
                        // multi-hop: the relay may name the NEXT relay
                        // itself (the kernel validates and counts hops)
                        if let Some(next_name) = v.get("next").and_then(Value::as_str) {
                            if hops >= kernel.max_hops {
                                kernel
                                    .ledger
                                    .append(
                                        "dtn_hop_limit",
                                        json!({"bundle_id": bundle_id, "hops": hops}),
                                    )
                                    .map_err(|e| e.to_string())?;
                                return Err("dtn: hop limit reached".to_string());
                            }
                            let Some(next_uin) =
                                kernel.by_name.lock().unwrap().get(next_name).copied()
                            else {
                                return Err(format!("relay: unknown next hop '{next_name}'"));
                            };
                            let ready = kernel.agent_ready(next_uin);
                            {
                                let mut d = kernel.delivery.lock().unwrap();
                                d.store_routed(
                                    orig,
                                    target,
                                    body.clone(),
                                    5,
                                    None,
                                    Some(next_uin),
                                    hops,
                                    bundle_id,
                                    frag_meta,
                                )?;
                            }
                            if ready {
                                let mut b = qos::DtnBundle::new(
                                    orig,
                                    target,
                                    body.clone(),
                                    5,
                                    Duration::from_secs(300),
                                );
                                b.bundle_id = bundle_id;
                                b.hops = hops;
                                b.frag = frag_meta;
                                kernel.forward_to_relay(&b, next_uin)?;
                                kernel
                                    .ledger
                                    .append(
                                        "dtn_relayed",
                                        json!({"from": orig, "to": target, "relay": next_uin,
                                               "bundle_id": bundle_id, "hops": hops + 1}),
                                    )
                                    .map_err(|e| e.to_string())?;
                            }
                            // the relay's own ack contract: confirm the
                            // hand-off, otherwise drain_acks blocks forever
                            write_envelope(
                                writer,
                                wire,
                                &json!({"kind": "acked", "bundle_id": bundle_id}),
                            )
                            .map_err(|e| e.to_string())?;
                            return Ok(());
                        }
                        if kernel.agent_ready(target) {
                            kernel
                                .write_to(
                                    target,
                                    &json!({"kind": "msg", "from": orig, "body": body}),
                                )
                                .map_err(|e| e.to_string())?;
                            kernel
                                .ledger
                                .append(
                                    "dtn_delivered",
                                    json!({"from": orig, "to": target, "via": me,
                                           "bundle_id": bundle_id, "hops": hops}),
                                )
                                .map_err(|e| e.to_string())?;
                        } else {
                            // in transit: store custody for the destination,
                            // do NOT re-apply the static routing table
                            kernel.dtn_route_frag(
                                orig, to_name, target, body, 5, hops, bundle_id, false, frag_meta,
                            )?;
                        }
                        write_envelope(
                            writer,
                            wire,
                            &json!({"kind": "acked", "bundle_id": bundle_id}),
                        )
                        .map_err(|e| e.to_string())?;
                        return Ok(());
                    }
                    "custody_ack" => {
                        let bundle_id = v.get("bundle_id").and_then(Value::as_u64).unwrap_or(0);
                        // CUSTODY TRANSFER: the relay owns the bundle now,
                        // so the kernel deletes its own copy (exactly once)
                        let frag_index = v
                            .get("frag_index")
                            .and_then(Value::as_u64)
                            .map(|i| i as u32);
                        let released = kernel
                            .delivery
                            .lock()
                            .unwrap()
                            .ack_custody(bundle_id, frag_index);
                        kernel
                            .ledger
                            .append(
                                "dtn_custody_ack",
                                json!({"bundle_id": bundle_id, "frag_index": frag_index,
                                       "by": me, "released": released}),
                            )
                            .map_err(|e| e.to_string())?;
                        write_envelope(
                            writer,
                            wire,
                            &json!({"kind": "acked", "bundle_id": bundle_id, "custody": true}),
                        )
                        .map_err(|e| e.to_string())?;
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        let env = match Envelope::from_value(v) {
            Ok(e) => e,
            Err(reason) => {
                kernel
                    .ledger
                    .append("malformed", json!({"reason": reason, "line": v}))
                    .ok();
                return Err(reason);
            }
        };
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
                    let e = entry.lock().unwrap();
                    // one live instance per UIN: a second register (stale
                    // process that didn't get the kill, or a duplicate)
                    // is refused — the respawning pid is the authority
                    if let ProcState::Running = e.state {
                        return Err(format!(
                            "agent '{name}' already registered (stale instance refused)"
                        ));
                    }
                    drop(e);
                    drop(agents);
                }
                {
                    let agents = kernel.agents.lock().unwrap();
                    let entry = agents.get(&uin).ok_or("no entry")?;
                    let mut e = entry.lock().unwrap();
                    e.caps = caps;
                    e.state = ProcState::Running;
                    e.out = Some(Arc::new(Mutex::new(
                        writer.try_clone().map_err(|e| e.to_string())?,
                    )));
                    e.wire = wire;
                    e.last_hb = Instant::now();
                    e.stuck_sweeps = 0;
                    e.last_step = String::new();
                }
                *my_uin = Some(uin);
                // DTN custody flush: the fresh agent gets its held bundles
                // (priority order) BEFORE its welcome — its backlog arrives
                // as its first messages
                kernel.dtn_flush(uin)?;
                kernel
                    .ledger
                    .append(
                        "registered",
                        json!({"uin": uin, "name": name, "wire": format!("{wire:?}")}),
                    )
                    .map_err(|e| e.to_string())?;
                let recover = kernel.ledger.last_checkpoint(uin);
                write_envelope(
                    writer,
                    wire,
                    &json!({"kind": "welcome", "uin": uin, "recover": recover}),
                )
                .map_err(|e| e.to_string())?;
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
                write_envelope(writer, wire, &json!({"kind": "sent", "to": to}))
                    .map_err(|e| e.to_string())?;
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
                write_envelope(writer, wire, &json!({"kind": "acked", "seq": e.seq}))
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Envelope::Done { uin } => {
                let agents = kernel.agents.lock().unwrap();
                if let Some(entry) = agents.get(&uin) {
                    entry.lock().unwrap().state = ProcState::Completed;
                }
                drop(agents);
                kernel
                    .ledger
                    .append("completed", json!({"uin": uin}))
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Envelope::Note { uin, text } => {
                kernel
                    .ledger
                    .append("agent_note", json!({"uin": uin, "text": text}))
                    .map_err(|e| e.to_string())?;
                // ACK: the agent's drain_acks blocks until one arrives — an
                // unacked note looked like a stalled process to the watchdog
                write_envelope(writer, wire, &json!({"kind": "acked", "note": true}))
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Envelope::Welcome { uin: _, recover: _ } => {
                // the kernel SENDS welcome; receiving one back is a
                // schema-legal envelope from a confused agent — journal
                // and ignore (never crash the reader thread)
                kernel.ledger.append("malformed", json!({"reason": "unexpected welcome from agent", "uin": my_uin.unwrap_or(0)})).ok();
                Ok(())
            }
            Envelope::Recovered { uin: _ } => {
                kernel
                    .ledger
                    .append("recovered", json!({"uin": my_uin.unwrap_or(0)}))
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }
}

/// Peer: one agent connection over ANY transport (UDS or TCP — the
/// envelope contract and capability checks are identical).
pub enum Peer {
    Unix(UnixStream),
    Tcp(std::net::TcpStream),
}

impl std::io::Read for Peer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Peer::Unix(s) => s.read(buf),
            Peer::Tcp(s) => s.read(buf),
        }
    }
}

impl std::io::Write for Peer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Peer::Unix(s) => s.write(buf),
            Peer::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Peer::Unix(s) => s.flush(),
            Peer::Tcp(s) => s.flush(),
        }
    }
}

impl Peer {
    pub fn try_clone(&self) -> std::io::Result<Peer> {
        match self {
            Peer::Unix(s) => Ok(Peer::Unix(s.try_clone()?)),
            Peer::Tcp(s) => Ok(Peer::Tcp(s.try_clone()?)),
        }
    }
}

/// A JSON peer whose first byte was consumed by the mode detector.
struct JsonPeer {
    peer: Peer,
    first: Option<u8>,
    done: bool,
}

impl JsonPeer {
    fn new(peer: Peer, first: u8) -> JsonPeer {
        JsonPeer {
            peer,
            first: Some(first),
            done: false,
        }
    }
    /// read one JSON line; the stored first byte is prepended on the
    /// first call; returns Ok(false) on EOF
    fn read_line_after(&mut self, line: &mut String) -> std::io::Result<bool> {
        if self.done {
            return Ok(false);
        }
        if let Some(b) = self.first.take() {
            line.push(b as char);
        }
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        loop {
            match self.peer.read(&mut b) {
                Ok(0) => {
                    self.done = true;
                    line.push_str(&String::from_utf8_lossy(&buf));
                    return Ok(!line.is_empty());
                }
                Ok(_) => {
                    if b[0] == b'\n' {
                        line.push_str(&String::from_utf8_lossy(&buf));
                        return Ok(true);
                    }
                    buf.push(b[0]);
                }
                Err(e) => return Err(e),
            }
        }
    }
    fn peer_mut(&mut self) -> &mut Peer {
        &mut self.peer
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
    /// network-remote listener (kernel accepts agents over TCP too)
    #[serde(default)]
    pub tcp_port: Option<u16>,
    /// bind address for the TCP listener — "0.0.0.0" when microVM agents
    /// arrive through tap devices (the default 127.0.0.1 only serves
    /// host-local agents)
    #[serde(default)]
    pub tcp_bind: Option<String>,
    /// per-agent Firecracker boot script (relative to the kernel's cwd);
    /// required when any agent declares isolation "microvm"
    #[serde(default)]
    pub vm_boot: Option<String>,
    /// admission control: kernel-wide byte rate per sender (None =
    /// unlimited; an agent's own `qos.max_bytes_per_sec` overrides it)
    #[serde(default)]
    pub admission_max_bytes_per_sec: Option<u32>,
    /// admission control: hard bound on the bytes the kernel may hold in
    /// its delivery queue (default 16 MiB)
    #[serde(default)]
    pub admission_max_queue_bytes: Option<u64>,
    /// WFQ link capacity in bytes per virtual tick (default 16384)
    #[serde(default)]
    pub wfq_capacity: Option<f64>,
    /// delivery link capacity in BYTES PER WATCHDOG TICK (None = the
    /// link is infinitely fast). A finite value is what makes the
    /// backlog — and therefore WFQ — real.
    #[serde(default)]
    pub link_bytes_per_tick: Option<u64>,
    /// DTN routing: static routes "to reach `dest`, hand custody to
    /// `via`" — the kernel forwards, the relay re-emits, hop by hop
    #[serde(default)]
    pub routes: Vec<RouteSpec>,
    /// maximum hops a bundle may travel before it is dropped
    #[serde(default = "default_max_hops")]
    pub max_hops: u8,
    /// split bodies larger than this (bytes of encoded fragment payload)
    #[serde(default)]
    pub max_bundle_bytes: Option<usize>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RouteSpec {
    pub dest: String,
    pub via: String,
}

fn default_max_hops() -> u8 {
    4
}

fn default_max_hops_u8() -> u8 {
    4
}

fn default_hb() -> u64 {
    150
}
fn default_timeout() -> u64 {
    1200
}

/// Per-agent delivery QoS: `priority` 0..=9 (0 = highest, delivered
/// first), `max_msgs_per_sec` = token-bucket rate limit for this SENDER
/// (None/0 = unlimited).
#[derive(Deserialize, Clone, Copy, Debug, Default)]
pub struct QosSpec {
    #[serde(default)]
    pub priority: Option<u8>,
    /// message-rate token bucket (per sender)
    #[serde(default)]
    pub max_msgs_per_sec: Option<u32>,
    /// byte-rate admission budget (per sender); overrides the kernel-wide
    /// `admission_max_bytes_per_sec` for this agent
    #[serde(default)]
    pub max_bytes_per_sec: Option<u32>,
    /// WFQ weight: the share of a contended delivery link (default 1.0;
    /// weight 3 gets three times the link of weight 1)
    #[serde(default)]
    pub weight: Option<f64>,
}

#[derive(Deserialize)]
pub struct AgentSpec {
    pub name: String,
    pub task: String,
    /// "tcp" = connect over the network-remote transport (default: UDS)
    #[serde(default)]
    pub transport: Option<String>,
    /// "msgpack" = binary wire format (default: JSON lines)
    #[serde(default)]
    pub wire: Option<String>,
    /// "microvm" = run this agent inside its own Firecracker microVM
    /// (the deepest isolation tier: a real VM per agent for hostile
    /// tool code — see vm/boot_agent.sh)
    #[serde(default)]
    pub isolation: Option<String>,
    /// delivery QoS: priority + per-sender rate limit
    #[serde(default)]
    pub qos: Option<QosSpec>,
    /// delay-tolerant: when true, sends TO this agent are held by the
    /// kernel (custody transfer) while it is disconnected, with a TTL,
    /// and delivered when it registers again
    #[serde(default)]
    pub dtn: bool,
}

#[cfg(test)]
mod json_peer_tests {
    use super::*;

    #[test]
    fn json_peer_reads_two_lines() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut writer = b;
        let mut peer = JsonPeer::new(Peer::Unix(a), b'{');
        writer.write_all(b"\"x\": 1}\n{\"y\": 2}\n").unwrap();
        let mut line = String::new();
        assert!(peer.read_line_after(&mut line).unwrap());
        assert_eq!(line, "{\"x\": 1}");
        line.clear();
        assert!(peer.read_line_after(&mut line).unwrap());
        assert_eq!(line, "{\"y\": 2}");
    }
}
