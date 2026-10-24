//! ama-agentd — the agent-side process. Ephemeral by construction: all
//! working state lives in this process's memory; durable state only via
//! `checkpoint` into the kernel's ledger. If the process dies, its context
//! (KV cache, scratchpad) disappears with it.
//!
//! v0.2: the agent jails ITSELF with seccomp-bpf at startup, and speaks
//! EITHER transport (UDS default, `--tcp host:port` for network-remote)
//! in EITHER wire format (JSON lines default, `--wire msgpack` binary).

use ama_core::{read_msgpack_frame, write_envelope, Peer, Wire};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Step {
    /// checkpoint the current step index + state into the ledger
    Checkpoint { state: Value },
    /// send to another agent (capability-gated by the kernel)
    Send { to: String, body: Value },
    /// block until a message arrives
    Wait,
    /// simulate an uncaught crash (fail-fast demo)
    Crash,
    /// simulate an infinite reasoning loop (watchdog demo)
    Loop { ms: u64 },
    Sleep { ms: u64 },
    /// journal an observation into the ledger (kernel `agent_note` event)
    Note { msg: String },
}

#[derive(Debug, Deserialize)]
struct Task {
    name: String,
    caps: Vec<String>,
    steps: Vec<Step>,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut socket = String::new();
    let mut task_path = String::new();
    let mut tcp: Option<String> = None;
    let mut wire = Wire::Json;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next().unwrap_or_default(),
            "--task" => task_path = args.next().unwrap_or_default(),
            "--tcp" => tcp = Some(args.next().unwrap_or_default()),
            "--wire" => {
                wire = match args.next().unwrap_or_default().as_str() {
                    "msgpack" => Wire::Msgpack,
                    _ => Wire::Json,
                }
            }
            _ => {}
        }
    }
    let task: Task = serde_json::from_slice(
        &std::fs::read(&task_path).unwrap_or_else(|e| panic!("task {task_path}: {e}")),
    )
    .expect("task schema");

    // §2: the agent jails ITSELF before doing any work — no_new_privs +
    // seccomp denylist (mount/ptrace/module-load/bpf/… return EPERM)
    if let Err(e) = ama_core::seccomp::apply_seccomp_self() {
        eprintln!("[agentd {}] seccomp jail unavailable: {e}", task.name);
    }

    // §3: connect over the transport this agent was configured for —
    // UDS (local) or TCP (network-remote). Same contract either way.
    let peer = match &tcp {
        Some(addr) => {
            Peer::Tcp(std::net::TcpStream::connect(addr).expect("connect to kernel over TCP"))
        }
        None => Peer::Unix(UnixStream::connect(&socket).expect("connect to kernel")),
    };
    let mut w = peer.try_clone().expect("clone");

    // reader thread: kernel pushes (welcome/msg/error) into a queue —
    // parsed per wire format
    let inbox: Arc<Mutex<VecDeque<Value>>> = Arc::new(Mutex::new(VecDeque::new()));
    let last_step: Arc<AtomicU64> = Arc::new(AtomicU64::new(0)); // current step index for heartbeats
    // 0 = executing (watchdog counts stuck sweeps), 1 = blocked on IO/wait
    let phase: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let alive: Arc<AtomicBool> = Arc::new(AtomicBool::new(true));
    {
        let inbox = inbox.clone();
        let alive = alive.clone();
        let mut r = peer.try_clone().expect("reader clone");
        std::thread::spawn(move || match wire {
            Wire::Json => {
                let mut r = BufReader::new(r);
                let mut line = String::new();
                while alive.load(Ordering::SeqCst) {
                    line.clear();
                    match r.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                    if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
                        inbox.lock().unwrap().push_back(v);
                    }
                }
                alive.store(false, Ordering::SeqCst);
            }
            Wire::Msgpack => loop {
                if !alive.load(Ordering::SeqCst) {
                    break;
                }
                match read_msgpack_frame(&mut r) {
                    Ok(v) => inbox.lock().unwrap().push_back(v),
                    Err(_) => break,
                }
            },
        });
    }

    // heartbeat thread: the watchdog's only view of this process. Gated on
    // the registered UIN (0 until welcome arrives).
    // u64::MAX = not registered yet — 0 is a LEGITIMATE first UIN and
    // must never be treated as the sentinel (this killed every first agent)
    let uin_holder: Arc<AtomicU64> = Arc::new(AtomicU64::new(u64::MAX));
    {
        let last_step = last_step.clone();
        let alive = alive.clone();
        let uin_holder = uin_holder.clone();
        let phase_task = phase.clone();
        let mut w = w.try_clone().expect("hb clone");
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(150));
            if !alive.load(Ordering::SeqCst) {
                break;
            }
            let u = uin_holder.load(Ordering::SeqCst);
            if u == u64::MAX {
                continue; // not registered yet
            }
            let step = last_step.load(Ordering::SeqCst);
            let ph = if phase_task.load(Ordering::SeqCst) == 1 {
                "blocked"
            } else {
                "executing"
            };
            let _ = write_envelope(
                &mut w,
                wire,
                &json!({"kind": "heartbeat", "uin": u, "step": step.to_string(), "phase": ph}),
            );
        });
    }

    let send = |w: &mut Peer, v: &Value| write_envelope(w, wire, v).expect("send");

    // register
    send(&mut w, &json!({"kind": "register", "name": task.name, "caps": task.caps}));

    // process welcome (and any recover state) first
    let mut uin: u64 = 0;
    let mut recovered_from: Option<Value> = None;
    let welcome = loop {
        match inbox.lock().unwrap().pop_front() {
            Some(v) => break Some(v),
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    };
    if let Some(wl) = welcome {
        eprintln!("[agentd {}] welcome at {:?}", task.name, std::time::SystemTime::now());
        uin = wl.get("uin").and_then(Value::as_u64).unwrap_or(0);
        uin_holder.store(uin, Ordering::SeqCst);
        recovered_from = match wl.get("recover") {
            Some(v) if v.is_object() => Some(v.clone()),
            _ => None,
        };
    }

    // resume from checkpoint: skip already-completed steps (at-least-once)
    let mut idx: usize = 0;
    if let Some(rec) = &recovered_from {
        if let Some(done) = rec.get("step_index").and_then(Value::as_u64) {
            idx = done as usize;
        }
        eprintln!("[agentd {}] recovered at step {} from ledger checkpoint", task.name, idx);
    }

    let drain_acks = |inbox: &Arc<Mutex<VecDeque<Value>>>| {
        loop {
            let mut q = inbox.lock().unwrap();
            let mut acked = false;
            q.retain(|v| {
                let kind = v.get("kind").and_then(Value::as_str).unwrap_or("");
                if matches!(kind, "sent" | "acked" | "error") {
                    acked = true;
                    return false; // consumed
                }
                true
            });
            drop(q);
            if acked {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };

    while idx < task.steps.len() {
        if std::env::var("AMA_DEBUG_STEP").is_ok() {
            eprintln!("[agentd {}] step {} at {:?}", task.name, idx, std::time::SystemTime::now());
        }
        last_step.store(idx as u64, Ordering::SeqCst);
        let step = &task.steps[idx];
        match step {
            Step::Checkpoint { state } => {
                send(
                    &mut w,
                    &json!({"kind": "checkpoint", "uin": uin, "state": {"step_index": idx + 1, "state": state}}),
                );
                drain_acks(&inbox);
            }
            Step::Send { to, body } => {
                send(&mut w, &json!({"kind": "send", "uin": uin, "to": to, "body": body}));
                drain_acks(&inbox);
            }
            Step::Note { msg } => {
                send(&mut w, &json!({"kind": "note", "uin": uin, "text": msg}));
                drain_acks(&inbox);
            }
            Step::Wait => {
                phase.store(1, Ordering::SeqCst);
                loop {
                    if let Some(v) = inbox.lock().unwrap().pop_front() {
                        if v.get("kind").and_then(Value::as_str) == Some("msg") {
                            break;
                        }
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                phase.store(0, Ordering::SeqCst);
            }
            Step::Crash => {
                eprintln!("[agentd {}] CRASH injected at step {}", task.name, idx);
                std::process::exit(1);
            }
            Step::Loop { ms } => {
                // an infinite reasoning loop: heartbeat keeps flowing but the
                // step NEVER advances — the kernel's progress watchdog fires
                let deadline = std::time::Instant::now() + Duration::from_millis(*ms);
                while std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            Step::Sleep { ms } => {
                phase.store(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(*ms));
                phase.store(0, Ordering::SeqCst);
            }
        }
        idx += 1;
    }
    eprintln!("[agentd {}] task complete", task.name);
    send(&mut w, &json!({"kind": "done", "uin": uin}));
    std::thread::sleep(Duration::from_millis(200)); // let the ack/EOF settle
    std::process::exit(0);
}
