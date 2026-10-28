//! ama-agentd — the agent-side process. Ephemeral by construction: all
//! working state lives in this process's memory; durable state only via
//! `checkpoint` into the kernel's ledger. If the process dies, its context
//! (KV cache, scratchpad) disappears with it.
//!
//! v0.2: the agent jails ITSELF with seccomp-bpf at startup, and speaks
//! EITHER transport (UDS default, `--tcp host:port` for network-remote)
//! in EITHER wire format (JSON lines default, `--wire msgpack` binary).

use ama_core::{read_msgpack_frame, read_proto_frame, write_envelope, Peer, Wire};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Step {
    /// checkpoint the current step index + state into the ledger
    Checkpoint {
        state: Value,
    },
    /// send to another agent (capability-gated by the kernel)
    Send {
        to: String,
        body: Value,
    },
    /// block until a message arrives
    Wait,
    /// simulate an uncaught crash (fail-fast demo)
    Crash,
    /// simulate an infinite reasoning loop (watchdog demo)
    Loop {
        ms: u64,
    },
    Sleep {
        ms: u64,
    },
    /// journal an observation into the ledger (kernel `agent_note` event)
    Note {
        msg: String,
    },
    /// DTN relay: take custody of a `bundle` frame from the inbox,
    /// ACKNOWLEDGE the custody transfer, then hand the bundle onward with
    /// the `relay` envelope (hops + 1). Blocks up to `timeout_ms` waiting
    /// for a bundle; no bundle = nothing to forward.
    Relay {
        #[serde(default = "default_relay_timeout")]
        timeout_ms: u64,
        /// the NEXT relay this agent chooses for the bundle (multi-hop);
        /// absent = hand it to the final destination
        #[serde(default)]
        next: Option<String>,
    },
}

fn default_relay_timeout() -> u64 {
    8000
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
                    "proto" => Wire::Proto,
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
    eprintln!(
        "[agentd {}] task loaded ({} steps)",
        task.name,
        task.steps.len()
    );

    // §2: the agent jails ITSELF before doing any work — no_new_privs +
    // seccomp denylist (mount/ptrace/module-load/bpf/… return EPERM).
    // SKIPPED for microVM agents (AMA_VM=1): the guest runs inside a real
    // Firecracker VM — the VM is the jail, and a seccomp filter that
    // denies socket(AF_INET) kills PID 1 BEFORE it can connect (exit code
    // 0x6500 = panic "Attempted to kill init", experiment 005)
    if std::env::var("AMA_VM").is_err() {
        // F09: isolation fails CLOSED — an agent does NOT run unprotected
        // because a filter failed to install. AMA_ALLOW_NO_SECCOMP=1 is
        // the explicit downgrade, announced loudly.
        if let Err(e) = ama_core::seccomp::apply_seccomp_self() {
            if std::env::var("AMA_ALLOW_NO_SECCOMP").is_ok() {
                eprintln!(
                    "[agentd {}] WARNING: running WITHOUT the seccomp jail (AMA_ALLOW_NO_SECCOMP=1): {e}",
                    task.name
                );
            } else {
                eprintln!(
                    "[agentd {}] FATAL: seccomp jail unavailable: {e} — refusing to run unprotected (set AMA_ALLOW_NO_SECCOMP=1 to downgrade explicitly)",
                    task.name
                );
                std::process::exit(2);
            }
        }
    }

    eprintln!("[agentd {}] seccomp applied", task.name);

    // §3: connect over the transport this agent was configured for —
    // UDS (local) or TCP (network-remote). Same contract either way.
    let peer = match &tcp {
        Some(addr) => Peer::Tcp({
            eprintln!(
                "[agentd {}] connecting to kernel over TCP: {addr}",
                task.name
            );
            std::net::TcpStream::connect(addr).expect("connect to kernel over TCP")
        }),
        None => {
            eprintln!("[agentd {}] connecting over UDS: {socket}", task.name);
            let st = UnixStream::connect(&socket).expect("connect to kernel");
            eprintln!("[agentd {}] connected", task.name);
            Peer::Unix(st)
        }
    };
    // §3: ONE shared writer, Mutex-serialized — the heartbeat thread and
    // the task loop write to the SAME fd; unsynchronized writes interleave
    // msgpack frames mid-payload and the kernel's read_exact then stalls
    // on a garbage length (caught by experiment 004: b's ping vanished)
    let writer: Arc<Mutex<Peer>> = Arc::new(Mutex::new(peer));

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
        let mut r = writer.lock().unwrap().try_clone().expect("reader clone");
        std::thread::spawn(move || {
            match wire {
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
                Wire::Proto => loop {
                    if !alive.load(Ordering::SeqCst) {
                        break;
                    }
                    match read_proto_frame(&mut r) {
                        Ok(v) => inbox.lock().unwrap().push_back(v),
                        Err(_) => break,
                    }
                },
            }
            // F08: DISCONNECT is a signal — poison the inbox so every wait
            // loop terminates instead of hanging forever (all three wire
            // arms converge here)
            alive.store(false, Ordering::SeqCst);
            inbox
                .lock()
                .unwrap()
                .push_back(json!({"kind": "__disconnected"}));
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
        let writer = writer.clone();
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
            let mut w = writer.lock().unwrap();
            let _ = write_envelope(
                &mut *w,
                wire,
                &json!({"kind": "heartbeat", "uin": u, "step": step.to_string(), "phase": ph}),
            );
        });
    }

    let send = |writer: &Arc<Mutex<Peer>>, v: &Value| {
        let mut w = writer.lock().unwrap();
        write_envelope(&mut *w, wire, v).expect("send")
    };

    // register
    send(
        &writer,
        &json!({"kind": "register", "name": task.name, "caps": task.caps,
                "pid": std::process::id(),
                "token": std::env::var("AMA_REGISTER_TOKEN").ok()}),
    );

    eprintln!("[agentd {}] register sent", task.name);

    // process welcome (and any recover state) first
    let mut uin: u64 = 0;
    let mut recovered_from: Option<Value> = None;
    // DTN flush delivers the backlog BEFORE the welcome is read: the
    // welcome loop must skip anything that is not a welcome WITHOUT
    // losing it (a backlog message consumed as the welcome would give
    // the agent a garbage UIN — experiment 006). Non-welcome frames are
    // collected and pushed back IN ORDER once the welcome is found —
    // pushing back as we go would cycle the backlog forever and the
    // welcome at the tail would never be reached.
    let welcome = {
        let mut deferred: Vec<Value> = Vec::new();
        let mut polls: u64 = 0;
        let w = loop {
            // pop into a local: the guard drops at the end of THIS
            // statement, never during the sleep below (holding it across
            // the sleep starved the reader thread — see header comment)
            let got = inbox.lock().unwrap().pop_front();
            match got {
                Some(v) => {
                    if v.get("kind").and_then(Value::as_str) == Some("welcome") {
                        break v;
                    }
                    deferred.push(v);
                }
                None => {
                    polls += 1;
                    if polls.is_multiple_of(1000) {
                        eprintln!(
                            "[agentd {}] still waiting for welcome ({} polls)",
                            task.name, polls
                        );
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        };
        if !deferred.is_empty() {
            let mut q = inbox.lock().unwrap();
            for v in deferred {
                q.push_back(v);
            }
        }
        Some(w)
    };
    if let Some(wl) = welcome {
        eprintln!(
            "[agentd {}] welcome at {:?}",
            task.name,
            std::time::SystemTime::now()
        );
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
        eprintln!(
            "[agentd {}] recovered at step {} from ledger checkpoint",
            task.name, idx
        );
    }

    // F08: the reply is TYPED — `sent`/`acked` are success, an `error`
    // reply is surfaced to the caller (the old drain_acks treated them
    // ALL as completion, so a rejected operation silently ADVANCED the
    // task). A timeout bounds every wait; a poisoned inbox (disconnect)
    // ends the process — the kernel's watchdog owns what happens next.
    const REPLY_TIMEOUT_MS: u64 = 10_000;
    let await_reply = |inbox: &Arc<Mutex<VecDeque<Value>>>| -> Result<Value, String> {
        let deadline = std::time::Instant::now() + Duration::from_millis(REPLY_TIMEOUT_MS);
        loop {
            if std::time::Instant::now() > deadline {
                return Err("reply timeout".to_string());
            }
            let mut q = inbox.lock().unwrap();
            let mut reply: Option<Value> = None;
            q.retain(|v| {
                let kind = v.get("kind").and_then(Value::as_str).unwrap_or("");
                if reply.is_none() && matches!(kind, "sent" | "acked" | "error") {
                    reply = Some(v.clone());
                    return false; // consumed
                }
                true
            });
            drop(q);
            if let Some(r) = reply {
                if r.get("kind").and_then(Value::as_str) == Some("error") {
                    return Err(r
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("error")
                        .to_string());
                }
                return Ok(r);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    // explicit outcome policy: a failed operation is LOGGED LOUDLY (the
    // step still advances — the historical scripted-task contract — but
    // the failure is visible on stderr and the journal instead of being
    // conflated with success)
    let drain_acks = |inbox: &Arc<Mutex<VecDeque<Value>>>| match await_reply(inbox) {
        Ok(_) => {}
        Err(reason) => {
            eprintln!("[agentd {}] OPERATION FAILED: {reason}", task.name);
        }
    };

    while idx < task.steps.len() {
        if std::env::var("AMA_DEBUG_STEP").is_ok() {
            eprintln!(
                "[agentd {}] step {} at {:?}",
                task.name,
                idx,
                std::time::SystemTime::now()
            );
        }
        last_step.store(idx as u64, Ordering::SeqCst);
        let step = &task.steps[idx];
        match step {
            Step::Checkpoint { state } => {
                send(
                    &writer,
                    &json!({"kind": "checkpoint", "uin": uin, "state": {"step_index": idx + 1, "state": state}}),
                );
                drain_acks(&inbox);
            }
            Step::Send { to, body } => {
                send(
                    &writer,
                    &json!({"kind": "send", "uin": uin, "to": to, "body": body}),
                );
                drain_acks(&inbox);
            }
            Step::Relay { timeout_ms, next } => {
                // this step is an I/O wait: declare it BLOCKED so the
                // progress watchdog does not read it as a reasoning loop
                phase.store(1, Ordering::SeqCst);
                // wait for a bundle frame (the kernel hands custody here)
                let deadline = std::time::Instant::now() + Duration::from_millis(*timeout_ms);
                let mut bundle: Option<Value> = None;
                while std::time::Instant::now() < deadline {
                    let got = inbox.lock().unwrap().pop_front();
                    if let Some(v) = got {
                        if v.get("kind").and_then(Value::as_str) == Some("bundle") {
                            bundle = Some(v);
                            break;
                        }
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                if let Some(b) = bundle {
                    let bundle_id = b.get("bundle_id").and_then(Value::as_u64).unwrap_or(0);
                    let hops = b.get("hops").and_then(Value::as_u64).unwrap_or(0);
                    // a fragment is its own custody unit: the ack names
                    // the index so the kernel releases exactly it
                    let frag_index = b
                        .get("frag")
                        .and_then(|f| f.get("index"))
                        .and_then(Value::as_u64);
                    // custody transfer: the relay owns it now, the kernel
                    // drops its copy when it sees this ack
                    send(
                        &writer,
                        &json!({"kind": "custody_ack", "uin": uin,
                                "bundle_id": bundle_id, "frag_index": frag_index}),
                    );
                    drain_acks(&inbox);
                    send(
                        &writer,
                        &json!({
                            "kind": "relay",
                            "uin": uin,
                            "bundle_id": bundle_id,
                            "from": b.get("from").cloned().unwrap_or(json!(0)),
                            "to": b.get("to").cloned().unwrap_or(Value::Null),
                            "hops": hops + 1,
                            "next": next.clone(),
                            "frag": b.get("frag").cloned().unwrap_or(Value::Null),
                            "body": b.get("body").cloned().unwrap_or(Value::Null),
                        }),
                    );
                    drain_acks(&inbox);
                }
                phase.store(0, Ordering::SeqCst);
            }
            Step::Note { msg } => {
                send(&writer, &json!({"kind": "note", "uin": uin, "text": msg}));
                drain_acks(&inbox);
            }
            Step::Wait => {
                phase.store(1, Ordering::SeqCst);
                loop {
                    let got = inbox.lock().unwrap().pop_front();
                    if let Some(v) = got {
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
    send(&writer, &json!({"kind": "done", "uin": uin}));
    std::thread::sleep(Duration::from_millis(200)); // let the ack/EOF settle
    std::process::exit(0);
}
