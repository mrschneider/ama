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
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod custody;
pub mod proto;
pub mod qos;
pub mod resources;
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

/// Debug flags resolved ONCE per process. `std::env::var` on EVERY frame
/// (the router read loops did this) takes the environ lock and scans the
/// environment per message — a hot-path syscall-free win for free.
pub fn debug_enabled() -> bool {
    use std::sync::OnceLock;
    static AMA_DEBUG: OnceLock<bool> = OnceLock::new();
    *AMA_DEBUG.get_or_init(|| std::env::var("AMA_DEBUG").is_ok())
}

pub fn debug_json_enabled() -> bool {
    use std::sync::OnceLock;
    static AMA_DEBUG_JSON: OnceLock<bool> = OnceLock::new();
    *AMA_DEBUG_JSON.get_or_init(|| std::env::var("AMA_DEBUG_JSON").is_ok())
}

/// F10: make THIS process unreadable to its own same-UID children.
/// With dumpable=0 the kernel's `/proc/<pid>/{environ,mem,fd}` tree is
/// EACCES to every other process running as the same uid — which is what
/// keeps `AMA_OPERATOR_TOKEN` out of an agent's reach while agents still
/// share the kernel's OS identity. Socket file modes alone cannot do it:
/// 0600 on the control socket admits every same-uid process, agents
/// included.
pub fn set_non_dumpable() {
    use std::sync::OnceLock;
    static LOCKED: OnceLock<()> = OnceLock::new();
    LOCKED.get_or_init(|| unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0);
    });
}

/// 128 bits of /dev/urandom as hex — instance tokens and, when nothing
/// was pre-shared, the operator credential.
pub fn random_token() -> String {
    let mut f =
        std::fs::File::open("/dev/urandom").expect("open /dev/urandom for the registration token");
    use std::io::Read;
    let mut bytes = [0u8; 16];
    f.read_exact(&mut bytes)
        .expect("read /dev/urandom for the registration token");
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// F10: the operator credential — pre-shared through AMA_OPERATOR_TOKEN
/// (the kernel and the operator CLI both read it), generated fresh when
/// unset. It is never written to disk and never handed to a child
/// (`build_agent_command` strips it from the child env), so the only
/// places it exists are the two non-dumpable processes that need it.
pub fn operator_token_from_env() -> String {
    match std::env::var("AMA_OPERATOR_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => random_token(),
    }
}

/// F10 migration hatch: manifests that OMIT `caps` used to silently fall
/// back to whatever the TASK asked for — a task could grant itself. The
/// default is now NO grants; export AMA_LEGACY_TRUST_TASK_CAPS=1 to keep
/// the old behaviour while a manifest is migrated.
pub fn legacy_trust_task_caps() -> bool {
    use std::sync::OnceLock;
    static LEGACY: OnceLock<bool> = OnceLock::new();
    *LEGACY.get_or_init(|| std::env::var("AMA_LEGACY_TRUST_TASK_CAPS").is_ok_and(|v| v == "1"))
}

/// Credential compare that does not short-circuit on the first differing
/// byte (the length is not secret; the content is).
pub fn credential_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Serialize + frame an envelope in the connection's wire format.
/// F03: encode to bytes FIRST. The dedicated per-connection writer owns
/// every byte that reaches a socket, so a frame is built completely
/// off-socket and handed over as one buffer — nothing can interleave
/// mid-payload on any wire.
pub fn encode_envelope(wire: Wire, v: &Value) -> io::Result<Vec<u8>> {
    match wire {
        Wire::Json => {
            // ONE serialization: to_writer straight into the frame buffer
            // replaces format!("{v}\n"), which paid a full Display pass
            // plus a String allocation per message.
            let mut buf = Vec::with_capacity(256);
            serde_json::to_writer(&mut buf, v)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            buf.push(b'\n');
            Ok(buf)
        }
        Wire::Msgpack => {
            let bytes = rmp_serde::to_vec_named(v)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let mut buf = Vec::with_capacity(bytes.len() + 5);
            buf.push(0xFF);
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&bytes);
            Ok(buf)
        }
        Wire::Proto => {
            let bytes = proto::encode_value(v)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let mut buf = Vec::with_capacity(bytes.len() + 5);
            buf.push(0x0A);
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&bytes);
            Ok(buf)
        }
    }
}

/// Direct single-writer helper — used by the agentd (its socket has one
/// writer thread too). The kernel never writes a socket directly
/// anymore; it ENQUEUES (see `Outbound`).
pub fn write_envelope(w: &mut dyn IoWrite, wire: Wire, v: &Value) -> io::Result<()> {
    let buf = encode_envelope(wire, v)?;
    w.write_all(&buf)?;
    w.flush()
}

// ------------------------------------------------------------- F03: Outbound
/// Per-connection outbound queue cap. The kernel holds AT MOST this many
/// bytes per connection no matter what the peer does — memory stays
/// bounded under sustained contention.
pub const OUTBOUND_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// How long ONE write may block on a peer that stopped reading before
/// the connection is judged (the deadline lives on the writer's socket).
pub const OUTBOUND_WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_millis(500);

struct BudgetedFrame {
    bytes: Vec<u8>,
    _global: resources::ByteReservation,
    _agent: resources::ByteReservation,
}

struct OutboundState {
    frames: std::collections::VecDeque<BudgetedFrame>,
    bytes: usize,
}

/// F03 (review item 3): ONE writer per connection, fed by a BOUNDED
/// queue. Properties this buys, in the order the review asks for:
///   * framing — the writer thread is the ONLY code that touches the
///     socket, so concurrent deliveries, welcome messages, acks and
///     errors can never interleave (json/msgpack/proto alike);
///   * isolation — `push` NEVER blocks and never allocates past the
///     byte cap, so a peer that stops reading cannot stall an unrelated
///     agent, `ama ps`, or the watchdog's sweep;
///   * bounded memory — queue-full is a DEFINED behavior: the frame is
///     refused, the connection is closed, the event is journaled, and
///     the normal EOF path judges the agent;
///   * deadline — the writer's socket carries a write timeout, so a
///     half-dead peer releases the writer thread instead of parking it.
pub struct Outbound {
    wire: Wire,
    cap: usize,
    state: Mutex<OutboundState>,
    idle: std::sync::Condvar,
    closed: std::sync::atomic::AtomicBool,
    ledger: Arc<Ledger>,
    budget: Mutex<Arc<resources::ByteBudget>>,
}

impl Outbound {
    pub fn wire(&self) -> Wire {
        self.wire
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Stop feeding the writer and drop whatever is still queued (the
    /// connection is gone — pending frames go with it).
    pub fn close(&self) {
        self.closed.swap(true, std::sync::atomic::Ordering::SeqCst);
        {
            let mut st = self.state.lock().unwrap();
            st.frames.clear();
            st.bytes = 0;
        }
        self.idle.notify_all();
    }

    /// Enqueue one ALREADY-ENCODED frame. Never blocks; the only
    /// failure modes are "closed" and "queue full" — both of which
    /// close the connection rather than growing memory.
    pub fn push(&self, frame: Vec<u8>) -> Result<(), String> {
        if self.is_closed() {
            return Err("connection closed".to_string());
        }
        let global = self
            .ledger
            .outbound_budget
            .reserve(frame.len())
            .ok_or_else(|| {
                self.ledger
                    .append("outbound_budget_full", json!({"scope": "global"}))
                    .ok();
                "global outbound byte budget exhausted".to_string()
            })?;
        let budget = self.budget.lock().unwrap().clone();
        let agent = budget.reserve(frame.len()).ok_or_else(|| {
            self.ledger
                .append(
                    "outbound_queue_full",
                    json!({"scope": "agent", "cap": self.cap}),
                )
                .ok();
            self.close();
            "agent outbound byte budget exhausted — connection closed".to_string()
        })?;
        {
            let mut st = self.state.lock().unwrap();
            if self.is_closed() {
                return Err("connection closed".into());
            }
            if st.bytes + frame.len() > self.cap {
                drop(st);
                self.ledger
                    .append(
                        "outbound_queue_full",
                        json!({"wire": format!("{:?}", self.wire), "cap": self.cap}),
                    )
                    .ok();
                self.close();
                return Err(
                    "outbound queue full (peer stopped reading) — connection closed".to_string(),
                );
            }
            st.bytes += frame.len();
            st.frames.push_back(BudgetedFrame {
                bytes: frame,
                _global: global,
                _agent: agent,
            });
        }
        self.idle.notify_one();
        Ok(())
    }

    /// Encode with THIS connection's wire and enqueue.
    pub fn send(&self, v: &Value) -> Result<(), String> {
        let frame = encode_envelope(self.wire, v).map_err(|e| e.to_string())?;
        self.push(frame)
    }

    fn pop(&self) -> Option<BudgetedFrame> {
        let mut st = self.state.lock().unwrap();
        loop {
            if let Some(f) = st.frames.pop_front() {
                st.bytes -= f.bytes.len();
                return Some(f);
            }
            if self.is_closed() {
                return None;
            }
            st = self.idle.wait(st).unwrap();
        }
    }
}

/// Spawn the ONE thread allowed to write to `writer`, and return the
/// handle every kernel path enqueues through. Public: it is how any
/// connection (kernel, integration test, benchmark) obtains its
/// `Outbound`.
pub fn spawn_writer(ledger: Arc<Ledger>, writer: Peer, wire: Wire) -> Arc<Outbound> {
    spawn_writer_reserved(ledger, writer, wire, None)
}

fn spawn_writer_reserved(
    ledger: Arc<Ledger>,
    writer: Peer,
    wire: Wire,
    lease: Option<Arc<resources::ConnectionReservation>>,
) -> Arc<Outbound> {
    let out = Arc::new(Outbound {
        wire,
        cap: ledger.outbound_agent_limit.load(Ordering::Relaxed) as usize,
        state: Mutex::new(OutboundState {
            frames: std::collections::VecDeque::new(),
            bytes: 0,
        }),
        idle: std::sync::Condvar::new(),
        closed: std::sync::atomic::AtomicBool::new(false),
        budget: Mutex::new(Arc::new(resources::ByteBudget::new(
            ledger.outbound_agent_limit.load(Ordering::Relaxed) as usize,
        ))),
        ledger,
    });
    let o = Arc::clone(&out);
    std::thread::spawn(move || {
        let _lease = lease;
        let mut w = writer;
        let _ = w.set_write_timeout(Some(OUTBOUND_WRITE_DEADLINE));
        while let Some(frame) = o.pop() {
            if w.write_all(&frame.bytes).is_err() || w.flush().is_err() {
                o.ledger
                    .append(
                        "outbound_write_failed",
                        json!({"wire": format!("{:?}", o.wire)}),
                    )
                    .ok();
                o.close();
                return;
            }
        }
    });
    out
}

// F07: peer-supplied lengths are UNTRUSTED — no allocation before the
// bound is checked (a 4 GB declared length used to become a 4 GB
// allocation attempt: OOM as a service)
pub const MAX_FRAME: usize = 16 * 1024 * 1024; // 16 MiB

/// F05/F07: how long a spawned agent may take to register before the
/// watchdog kills and respawns it.
pub const REGISTRATION_DEADLINE_FACTOR: u64 = 3;

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
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "binary frame exceeds size limit",
        ));
    }
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
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "binary frame exceeds size limit",
        ));
    }
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
        /// the registering process's own pid (telemetry; NOT auth — pids
        /// are world-readable)
        pid: u32,
        /// F01/F10: the registration token the kernel handed the spawned
        /// process via AMA_REGISTER_TOKEN — required in EVERY state. A
        /// dead identity comes back only through the operator's
        /// ctl_restart, never by an unauthenticated claim
        token: Option<String>,
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
                let pid = v
                    .get("pid")
                    .and_then(Value::as_u64)
                    .ok_or("register: missing 'pid' (the kernel binds registration to the spawned instance)")?
                    as u32;
                let token = v.get("token").and_then(Value::as_str).map(String::from);
                Ok(Envelope::Register {
                    name,
                    caps,
                    pid,
                    token,
                })
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
            Envelope::Register {
                name,
                caps,
                pid,
                token,
            } => {
                let mut v = json!({"kind": "register", "name": name, "caps": caps, "pid": pid});
                if let Some(t) = token {
                    v["token"] = json!(t);
                }
                v
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
    /// poisons the whole ledger (experiment 003 caught this). The writer
    /// handle is persistent: opening the file on EVERY append cost ~8-18 us
    /// per event and was roughly HALF the route_send hot-path cost
    /// (perf_bench measured it). Reopened on demand when the file or its
    /// parent dir vanish mid-flight.
    writer: Mutex<Option<std::fs::File>>,
    /// Complete recovery index, populated from the active snapshot + WAL tail.
    cp_index: Mutex<HashMap<u64, Value>>,
    /// Poisoned on I/O failure; recovery must repair any partial append.
    failed: std::sync::atomic::AtomicBool,
    segment_bytes: AtomicU64,
    snapshot_bytes: AtomicU64,
    pub outbound_budget: Arc<resources::ByteBudget>,
    outbound_agent_limit: AtomicU64,
    agent_outbound_budgets: Mutex<HashMap<u64, std::sync::Weak<resources::ByteBudget>>>,
}

impl Ledger {
    fn agent_budget(&self, uin: u64) -> Arc<resources::ByteBudget> {
        let mut budgets = self.agent_outbound_budgets.lock().unwrap();
        budgets.retain(|_, budget| budget.strong_count() > 0);
        if let Some(budget) = budgets.get(&uin).and_then(std::sync::Weak::upgrade) {
            return budget;
        }
        let budget = Arc::new(resources::ByteBudget::new(
            self.outbound_agent_limit.load(Ordering::Relaxed) as usize,
        ));
        budgets.insert(uin, Arc::downgrade(&budget));
        budget
    }

    /// F10(item 4): repair a crash-torn tail at EXACT byte boundaries.
    ///
    /// Records are newline-terminated by `append` (one write for the
    /// line, then one for the newline), so the legal endings are:
    ///   * `<complete record>\n`                       — validate it and stop;
    ///   * `<complete record>` with the newline missing  — crash between
    ///     the two writes: RECOVER it by appending the newline;
    ///   * anything else after the last `\n`             — a partial
    ///     write: cut EXACTLY at that boundary.
    ///
    /// The old repair computed `line.len() + 1` from the parsed line —
    /// for the common no-trailing-newline case that overshot by one
    /// byte and deleted the PREVIOUS record's newline, letting the next
    /// append concatenate two records onto one line. It also ignored
    /// set_len's result and printed "torn tail repaired" unconditionally.
    ///
    /// Memory stays bounded: the file is scanned backwards in 8 KiB
    /// chunks (a 1 GiB ledger must not become a 1 GiB allocation); only
    /// the single last record is read whole, bounded by the largest
    /// record ever written.
    fn repair_tail(path: &std::path::Path) -> std::io::Result<()> {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let len = f.metadata()?.len();
        if len == 0 {
            return Ok(());
        }
        // offset just after the newline at-or-before `from` (exclusive);
        // 0 when there is none. Backward 8 KiB chunks: bounded memory.
        let mut prev_newline = |from: u64| -> std::io::Result<u64> {
            let mut pos = from;
            let mut chunk = [0u8; 8192];
            while pos > 0 {
                let take = (chunk.len() as u64).min(pos) as usize;
                pos -= take as u64;
                f.seek(SeekFrom::Start(pos))?;
                f.read_exact(&mut chunk[..take])?;
                for (i, &b) in chunk[..take].iter().enumerate().rev() {
                    if b == b'\n' {
                        return Ok(pos + i as u64 + 1);
                    }
                }
            }
            Ok(0)
        };

        let boundary = prev_newline(len)?;
        let (seg_start, seg_end) = if boundary < len {
            // does NOT end with a newline: the tail after the last one
            (boundary, len)
        } else {
            // ends with a newline: the last RECORD is [prev, len);
            // validate it — garbage that happens to end in a newline
            // must not survive into replay either
            let prev = prev_newline(len - 1)?;
            (prev, len)
        };
        if seg_start == seg_end {
            return Ok(()); // empty file edge already handled above
        }
        let mut seg = vec![0u8; (seg_end - seg_start) as usize];
        f.seek(SeekFrom::Start(seg_start))?;
        f.read_exact(&mut seg)?;
        if seg.last() == Some(&b'\n') {
            seg.pop(); // the terminating newline is not part of the record
        }
        // the file ends exactly on a record boundary iff the scan's
        // boundary reached EOF; otherwise the tail has NO newline and a
        // valid parse means only the terminator is missing
        let ends_with_newline = boundary == len;
        match serde_json::from_slice::<LedgerEvent>(&seg) {
            Ok(_) if ends_with_newline => Ok(()),
            Ok(_) => {
                // complete record, its final newline never landed:
                // recover it so every future append starts on a fresh line
                let mut w = std::fs::File::options().append(true).open(path)?;
                w.write_all(b"\n")?;
                w.flush()?;
                eprintln!(
                    "[ama] ledger: recovered a record missing its final newline ({} bytes)",
                    seg.len()
                );
                Ok(())
            }
            Err(_) => {
                // partial/garbage tail: cut EXACTLY at the record start;
                // every preceding record stays byte-for-byte intact
                let mut w = std::fs::File::options().write(true).open(path)?;
                w.set_len(seg_start)?;
                w.flush()?;
                eprintln!(
                    "[ama] ledger: torn tail repaired ({} bytes truncated)",
                    len - seg_start
                );
                Ok(())
            }
        }
    }

    pub fn open(path: &std::path::Path) -> std::io::Result<Ledger> {
        let temporary = Self::suffixed(path, ".rotate.tmp");
        if !path.try_exists()? && temporary.try_exists()? {
            let snapshot: LedgerEvent =
                serde_json::from_reader(std::fs::File::open(&temporary)?)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if snapshot.ev != "ledger_snapshot" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid rotation recovery snapshot",
                ));
            }
            std::fs::rename(&temporary, path)?;
            Self::sync_parent(path)?;
        }
        Self::repair_tail(path)?;
        let mut checkpoints = HashMap::new();
        let mut sequence = 0;
        let mut snapshot_bytes = 0;
        match std::fs::File::open(path) {
            Ok(file) => {
                for line in BufReader::new(file).lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let event: LedgerEvent = serde_json::from_str(&line)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    if event.ev == "ledger_snapshot" {
                        if sequence != 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "snapshot must start a segment",
                            ));
                        }
                        checkpoints = serde_json::from_value(event.detail["checkpoints"].clone())
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                        snapshot_bytes = line.len() as u64 + 1;
                    }
                    sequence = sequence.max(event.seq);
                    if event.ev == "checkpoint" {
                        if let (Some(uin), Some(state)) =
                            (event.detail["uin"].as_u64(), event.detail.get("state"))
                        {
                            checkpoints.insert(uin, state.clone());
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let seq = AtomicU64::new(sequence);
        Ok(Ledger {
            path: path.to_path_buf(),
            seq,
            writer: Mutex::new(None),
            cp_index: Mutex::new(checkpoints),
            failed: std::sync::atomic::AtomicBool::new(false),
            segment_bytes: AtomicU64::new(64 << 20),
            snapshot_bytes: AtomicU64::new(snapshot_bytes),
            outbound_budget: Arc::new(resources::ByteBudget::new(64 << 20)),
            outbound_agent_limit: AtomicU64::new(OUTBOUND_QUEUE_BYTES as u64),
            agent_outbound_budgets: Mutex::new(HashMap::new()),
        })
    }

    fn open_handle(&self) -> io::Result<std::fs::File> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
    }

    fn suffixed(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        name.into()
    }
    fn sync_parent(path: &std::path::Path) -> io::Result<()> {
        std::fs::File::open(
            path.parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new(".")),
        )?
        .sync_all()
    }
    pub fn set_segment_bytes(&self, bytes: u64) {
        self.segment_bytes.store(bytes, Ordering::Relaxed);
    }
    pub fn is_healthy(&self) -> bool {
        !self.failed.load(Ordering::Acquire)
    }

    pub fn append(&self, ev: &str, detail: Value) -> io::Result<LedgerEvent> {
        self.append_mode(ev, detail, false)
    }
    /// Acknowledgement boundary: append + fsync under ONE generation/writer lock.
    pub fn append_durable(&self, ev: &str, detail: Value) -> io::Result<LedgerEvent> {
        self.append_mode(ev, detail, true)
    }
    fn append_mode(&self, ev: &str, detail: Value, durable: bool) -> io::Result<LedgerEvent> {
        let mut writer = self.writer.lock().unwrap();
        if !self.is_healthy() {
            return Err(io::Error::other("ledger writer failed; recovery required"));
        }
        let result = (|| {
            let disk = std::fs::metadata(&self.path)
                .ok()
                .map(|m| (m.dev(), m.ino()));
            let handle = writer
                .as_ref()
                .and_then(|f| f.metadata().ok())
                .map(|m| (m.dev(), m.ino()));
            if writer.is_none() || disk != handle {
                *writer = Some(self.open_handle()?);
            }
            let limit = self.segment_bytes.load(Ordering::Relaxed);
            if limit > 0
                && writer
                    .as_ref()
                    .unwrap()
                    .metadata()?
                    .len()
                    .saturating_sub(self.snapshot_bytes.load(Ordering::Relaxed))
                    >= limit
            {
                self.rotate_locked(&mut writer)?;
            }
            let event = LedgerEvent {
                seq: self.seq.load(Ordering::Relaxed) + 1,
                ts_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                ev: ev.into(),
                detail,
            };
            let mut bytes = serde_json::to_vec(&event).map_err(io::Error::other)?;
            bytes.push(b'\n');
            let file = writer.as_mut().unwrap();
            file.write_all(&bytes)?;
            if durable {
                file.sync_data()?;
                Self::sync_parent(&self.path)?;
            }
            self.seq.store(event.seq, Ordering::Release);
            if event.ev == "checkpoint" {
                if let (Some(uin), Some(state)) =
                    (event.detail["uin"].as_u64(), event.detail.get("state"))
                {
                    self.cp_index.lock().unwrap().insert(uin, state.clone());
                }
            }
            Ok(event)
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    /// Coordinate a durable checkpoint snapshot and an archived WAL segment.
    /// Archives are retained; deletion/retention is an operator policy.
    pub fn rotate(&self) -> io::Result<()> {
        let mut writer = self.writer.lock().unwrap();
        if !self.is_healthy() {
            return Err(io::Error::other("ledger writer failed"));
        }
        let result = self.rotate_locked(&mut writer);
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    fn rotate_locked(&self, writer: &mut Option<std::fs::File>) -> io::Result<()> {
        let sequence = self.seq.load(Ordering::Acquire);
        if sequence == 0 || !self.path.try_exists()? {
            return Ok(());
        }
        let archive = Self::suffixed(&self.path, &format!(".segment-{sequence:020}.jsonl"));
        if archive.try_exists()? {
            return Ok(());
        }
        if writer.is_none() {
            *writer = Some(self.open_handle()?);
        }
        writer.as_ref().unwrap().sync_data()?;
        let snapshot = LedgerEvent {
            seq: sequence,
            ts_ms: 0,
            ev: "ledger_snapshot".into(),
            detail: json!({"checkpoints": *self.cp_index.lock().unwrap()}),
        };
        let mut bytes = serde_json::to_vec(&snapshot).map_err(io::Error::other)?;
        bytes.push(b'\n');
        let temporary = Self::suffixed(&self.path, ".rotate.tmp");
        {
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        // A crash after archiving but before activation is completed by open().
        std::fs::rename(&self.path, &archive)?;
        Self::sync_parent(&self.path)?;
        std::fs::rename(temporary, &self.path)?;
        Self::sync_parent(&self.path)?;
        *writer = Some(self.open_handle()?);
        self.snapshot_bytes
            .store(bytes.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    pub fn read_all(&self) -> Vec<LedgerEvent> {
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let prefix = format!(
            "{}.segment-",
            self.path.file_name().unwrap_or_default().to_string_lossy()
        );
        let mut files: Vec<_> = std::fs::read_dir(parent)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .map(|e| e.path())
            .collect();
        files.sort();
        files.push(self.path.clone());
        files
            .into_iter()
            .filter_map(|p| std::fs::File::open(p).ok())
            .flat_map(|f| {
                BufReader::new(f)
                    .lines()
                    .map_while(Result::ok)
                    .filter_map(|l| serde_json::from_str::<LedgerEvent>(&l).ok())
                    .collect::<Vec<_>>()
            })
            .filter(|e| e.ev != "ledger_snapshot")
            .collect()
    }

    /// Complete recovery index: hits AND misses are O(1), including after restart.
    pub fn last_checkpoint(&self, uin: u64) -> Option<Value> {
        self.cp_index.lock().unwrap().get(&uin).cloned()
    }
}

// ---------------------------------------------------------------------------
// Process table + capabilities.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ProcState {
    /// F05(item 5): a launch is PENDING — spawned (initially or as a
    /// replacement) but not yet registered. Only `Starting` and
    /// `Registered` are subject to the registration deadline, and a
    /// pending entry never counts as "live" for connection-close
    /// purposes (that is what prevents the duplicate-respawn race).
    Starting,
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
    /// F05: the network-remote transport address this agent was spawned
    /// with — the RESTART path must restore it (respawn used to lose it)
    pub tcp_addr: Option<String>,
    /// F05: live child handles — reaped by the supervisor thread instead
    /// of being dropped (a dropped Child never reports its exit)
    /// measured from here (the watchdog used to skip never-registered
    /// agents FOREVER)
    pub spawned_at: Instant,
    /// F01: TRUSTED capability config from the manifest — when present,
    /// registration IGNORES the task-supplied caps entirely: the kernel,
    /// not the agent's task, owns the grant
    pub manifest_caps: Option<Vec<String>>,
    /// F01: the per-instance registration secret the kernel handed the
    /// spawned process (None for microvm agents — the guest bootstrap
    /// cannot receive it yet)
    pub auth_token: Option<String>,
    /// F01: operator capability policy (ctl_grant/ctl_revoke history) —
    /// SURVIVES re-registration and respawn. Registration merges the
    /// task-supplied caps with this policy instead of replacing it: an
    /// operator revocation cannot be undone by the agent's own task, and
    /// an operator grant cannot be silently dropped by a restart.
    pub granted: Vec<String>,
    pub revoked: Vec<String>,
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
    pub out: Option<Arc<Outbound>>,
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
    /// F05: live child PIDs — the reaper thread collects them with
    /// `waitpid(pid, WNOHANG)` (the `Child` handles themselves are no
    /// longer stored: the reaper is the ONLY reaper, so a handle
    /// dropped at the same pid cannot steal the exit status)
    children: Arc<Mutex<HashMap<u32, ()>>>,
    /// per-agent Firecracker boot script (vm/boot_agent.sh) for the
    /// microVM isolation tier
    pub vm_boot: Option<String>,
    /// delivery audit detail: when false (the default) the `delivered`,
    /// `dtn_*` and `qos_throttled` ledger events carry `bytes` but NOT
    /// the message body — every byte of payload used to be journaled a
    /// SECOND time (once in the frame, once in the journal), doubling
    /// ledger growth. Set true for full forensic audit
    /// (AMA_LEDGER_VERBOSE=1 / manifest kernel.ledger_verbose).
    pub ledger_verbose: bool,
    /// QoS (per-sender token buckets) + DTN (store-and-forward custody
    /// store) — see qos.rs
    pub delivery: Mutex<qos::DeliverySystem>,
    /// DTN routing table: destination name -> relay name (next hop)
    pub routes: std::collections::HashMap<String, String>,
    /// hop budget for a routed bundle
    pub max_hops: u8,
    /// bodies above this size are fragmented (None = never)
    pub max_bundle_bytes: Option<usize>,
    /// F10: the operator credential every control verb must present.
    /// Independent of the OS identity: same-uid agents share the control
    /// socket's file mode but never hold this secret.
    pub operator_token: String,
    pub resource_limits: resources::ResourceLimits,
    connections: Arc<resources::Connections>,
    control_connections: Arc<resources::Connections>,
    delivery_wake: Arc<(Mutex<u64>, std::sync::Condvar)>,
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
            children: Arc::new(Mutex::new(HashMap::new())),
            ledger: Arc::new(Ledger::open(ledger_path)?),
            // delivery audit detail — off by default (see the field docs);
            // the manifest's kernel.ledger_verbose can override it
            ledger_verbose: std::env::var("AMA_LEDGER_VERBOSE").is_ok(),
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
            operator_token: operator_token_from_env(),
            max_hops: default_max_hops_u8(),
            max_bundle_bytes: None,
            resource_limits: resources::ResourceLimits::default(),
            connections: Arc::new(resources::Connections::new(
                resources::ResourceLimits::default(),
            )),
            control_connections: Arc::new(resources::Connections::new(resources::ResourceLimits {
                max_connections: 16,
                max_connections_per_peer: 16,
                ..resources::ResourceLimits::default()
            })),
            delivery_wake: Arc::new((Mutex::new(0), std::sync::Condvar::new())),
        })
    }

    pub fn configure_resources(&mut self, limits: resources::ResourceLimits) -> Result<(), String> {
        limits.validate()?;
        self.ledger
            .outbound_budget
            .set_limit(limits.max_outbound_bytes)?;
        self.ledger.set_segment_bytes(limits.ledger_segment_bytes);
        self.ledger.outbound_agent_limit.store(
            limits.max_outbound_bytes_per_agent as u64,
            Ordering::Relaxed,
        );
        self.connections = Arc::new(resources::Connections::new(limits.clone()));
        let mut control = limits.clone();
        control.max_connections = limits.max_control_connections;
        control.max_connections_per_peer = limits.max_control_connections;
        self.control_connections = Arc::new(resources::Connections::new(control));
        {
            let mut delivery = self.delivery.lock().unwrap();
            delivery.bundles.max_bytes = limits.max_custody_bytes;
            delivery.bundles.max_sender_bytes = limits.max_custody_bytes_per_sender;
            delivery.bundles.max_destination_bytes = limits.max_custody_bytes_per_destination;
        }
        self.resource_limits = limits;
        Ok(())
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
        d.refill_link();
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

    /// F03: resolve the destination's OUTBOUND QUEUE under the table
    /// locks and return it — the caller then enqueues with NOTHING
    /// held. (This replaces `with_peer`, which wrote the socket while
    /// holding the process-table entry lock: a peer that stopped
    /// reading stalled `ama ps`, routing and the watchdog behind it.)
    fn resolve_out(&self, uin: u64) -> Result<Arc<Outbound>, String> {
        let agents = self.agents.lock().unwrap();
        let entry = agents.get(&uin).ok_or("no process table entry")?;
        let e = entry.lock().unwrap();
        e.out.clone().ok_or_else(|| "no connection".to_string())
    }

    /// Enqueue a kernel->agent frame: encoded off-socket, handed to the
    /// connection's single writer. NEVER blocks, never interleaves.
    fn enqueue_to(&self, uin: u64, msg: &Value) -> Result<(), String> {
        self.resolve_out(uin)?.send(msg)
    }

    /// Write a kernel->agent frame to a connected agent (F03: enqueued,
    /// the dedicated writer owns the socket).
    fn write_to(&self, uin: u64, msg: &Value) -> Result<(), String> {
        self.enqueue_to(uin, msg)
    }

    /// Reverse lookup: the destination's NAME — what a relay echoes back
    /// when it forwards the bundle (a relay never sees the kernel's UINs).
    /// O(1) via the process table: the entry already stores the name (the
    /// old path scanned the whole by_name map per call — O(n) on a hot
    /// routing path).
    fn name_of(&self, uin: u64) -> Option<String> {
        let agents = self.agents.lock().unwrap();
        let e = agents.get(&uin)?;
        let name = e.lock().unwrap().name.clone();
        Some(name)
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

    /// Bind a name to a UIN without spawning a process. Probes, tests and
    /// harnesses register hand-built process-table entries through this —
    /// the by-name map is otherwise reachable only via spawn_agent.
    pub fn bind_name(&self, name: &str, uin: u64) {
        self.by_name.lock().unwrap().insert(name.into(), uin);
    }

    /// Spawn an agent process from a manifest entry. The process is the
    /// isolation unit: its own PID, its own ephemeral memory.
    pub fn spawn_agent(&self, name: &str, task_path: &str) -> std::io::Result<()> {
        self.spawn_agent_opts(
            name,
            task_path,
            None,
            Some(Wire::Json),
            None,
            None,
            false,
            None,
        )
    }

    /// `tcp`: connect over the network-remote transport; `wire`: speak
    /// JSON, msgpack, or protobuf (per-agent options); `isolation`:
    /// "microvm" boots the agent inside its own Firecracker microVM
    /// (see vm/boot_agent.sh) instead of an OS process
    #[allow(clippy::too_many_arguments)]
    /// F05 (AgentLaunchSpec): ONE launch builder shared by the initial
    /// spawn and every respawn — transport, wire format, isolation tier,
    /// env and forensics handling MUST be identical, or a restart silently
    /// ships a different process shape than the policy that created it.
    fn build_agent_command(
        &self,
        uin: u64,
        name: &str,
        task_path: &str,
        wire: Wire,
        isolation: Option<&str>,
        tcp_addr: Option<&str>,
        token: &str,
    ) -> Result<Command, String> {
        let microvm = isolation == Some("microvm");
        let mut cmd = if microvm {
            // the VM tier: the "agent process" IS a Firecracker microVM.
            let script = self.vm_boot.as_deref().ok_or_else(|| {
                "isolation 'microvm' requires kernel.vm_boot (vm/boot_agent.sh)".to_string()
            })?;
            let port = self
                .tcp_addr
                .as_ref()
                .and_then(|a| a.rsplit(':').next()?.parse::<u64>().ok())
                .ok_or_else(|| "isolation 'microvm' requires kernel.tcp_port".to_string())?;
            let mut c = Command::new(script);
            // F10: the guest's instance credential travels with the launch
            // it is built for (baked into its private initramfs by this
            // kernel-spawned script) — never through a shared path
            c.args([
                uin.to_string(),
                task_path.into(),
                port.to_string(),
                token.to_string(),
            ]);
            c
        } else {
            let mut c = Command::new(&self.agentd_path);
            c.args([
                "--socket",
                self.socket_path.to_str().unwrap_or("/tmp/ama.sock"),
                "--task",
                task_path,
            ]);
            if let Some(addr) = tcp_addr {
                c.arg("--tcp").arg(addr); // F05: the restart RESTORES transport
            }
            let s = match wire {
                Wire::Json => "json",
                Wire::Msgpack => "msgpack",
                Wire::Proto => "proto",
            };
            c.arg("--wire").arg(s);
            c.env("AMA_UIN", uin.to_string());
            // F01: the fresh instance gets a FRESH registration token
            c.env("AMA_REGISTER_TOKEN", token);
            c
        };
        // F10: the operator credential is not launch policy — children
        // inherit env wholesale, so stripping it here is the only thing
        // that keeps it out of an agent's address space
        cmd.env_remove("AMA_OPERATOR_TOKEN");
        // microVM: the guest's SERIAL CONSOLE is firecracker's STDOUT —
        // nulling it discards the only window into the VM
        if microvm && debug_enabled() {
            // stdout follows the debug path chosen below
        } else {
            cmd.stdout(Stdio::null());
        }
        // debug mode: keep agent stderr in a per-agent file (watchdog
        // forensics) instead of dropping it
        if debug_enabled() {
            let p = std::path::PathBuf::from(format!("/tmp/ama_dbg_agent_{}.stderr", uin));
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
        let _ = name;
        Ok(cmd)
    }

    /// F01: a fresh per-instance registration token.
    /// F10: is this OS pid one of the processes the kernel itself
    /// spawned? The control socket refuses them before reading a single
    /// byte of a request — an agent cannot reach operator authority even
    /// if it somehow obtained the credential.
    pub fn is_agent_pid(&self, pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        if self.children.lock().unwrap().contains_key(&pid) {
            return true;
        }
        let agents = self.agents.lock().unwrap();
        agents.values().any(|e| e.lock().unwrap().pid == pid)
    }

    fn fresh_token(&self) -> String {
        random_token()
    }

    // 9 params by design: the launch policy IS the parameter list —
    // splitting it into a struct would not reduce the information carried
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
        trusted_caps: Option<Vec<String>>,
    ) -> std::io::Result<()> {
        // 8 params by design: name/task/tcp/wire/isolation are the
        // pre-existing spawn surface, qos+dtn are the delivery contract
        let uin = self.next_uin.fetch_add(1, Ordering::SeqCst);
        let tcp_addr = tcp.map(String::from).or_else(|| self.tcp_addr.clone());
        let wire = wire_opt.unwrap_or(Wire::Json);
        let token = self.fresh_token();
        let cmd = self
            .build_agent_command(
                uin,
                name,
                task_path,
                wire,
                isolation,
                tcp_addr.as_deref(),
                &token,
            )
            .map_err(std::io::Error::other)?;
        let mut cmd = cmd;
        let child = cmd.spawn()?;
        let pid = child.id();
        // F05: the reaper thread (waitpid) owns this pid — the Child
        // handle is dropped here and that is fine: dropping a Child does
        // NOT reap it, it only disarms the automatic `wait` on drop, and
        // the reaper is the sole collector of the exit status
        self.children.lock().unwrap().insert(pid, ());
        let entry = Arc::new(Mutex::new(ProcEntry {
            uin,
            name: name.into(),
            pid,
            caps: Vec::new(),
            manifest_caps: trusted_caps,
            auth_token: Some(token), // F10: the guest holds it too
            wire,                    // the spawn declares the wire; register keeps it
            tcp_addr: tcp.map(String::from).or_else(|| self.tcp_addr.clone()),
            spawned_at: Instant::now(),
            granted: Vec::new(),
            revoked: Vec::new(),
            state: ProcState::Starting,
            last_hb: Instant::now(),
            last_step: String::new(),
            last_phase: "executing".into(),
            stuck_sweeps: 0,
            respawns: 0,
            last_checkpoint: None,
            task_path: task_path.into(),
            out: None,
            isolation: isolation.map(String::from),
            priority: qos.and_then(|q| q.priority).unwrap_or(5).min(9),
            dtn,
        }));
        if self.apply_cgroups {
            // F09: a REQUESTED resource limit that silently fails means the
            // effective protection differs from the requested one — journal
            // it (the spawn result never carries the cgroup outcome)
            if let Err(e) = sandbox::apply_cgroup(pid, name) {
                self.ledger
                    .append("cgroup_failed", json!({"uin": uin, "name": name, "err": e}))
                    .ok();
            }
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
        let agents = self.agents.lock().unwrap();
        let entry = agents.get(&uin).ok_or("unknown uin")?;
        // a VERB-level grant (`relay`) covers every target of that verb; a
        // TARGET-level grant (`send:b`) stays target-scoped. P3: the
        // grant test is allocation-free — `format!("{verb}:{target}")` used
        // to heap-allocate on EVERY send; the string is now built only on
        // the (rare) deny path, for the audit record.
        let granted = entry.lock().unwrap().caps.iter().any(|c| {
            c == verb
                || (c.len() == verb.len() + target.len() + 1
                    && c.starts_with(verb)
                    && c.as_bytes()[verb.len()] == b':'
                    && &c[verb.len() + 1..] == target)
        });
        if granted {
            Ok(())
        } else {
            let need = format!("{verb}:{target}");
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
        if !self.ledger.is_healthy() {
            return Err("audit ledger unavailable; recovery required".into());
        }
        let uin = self
            .by_name
            .lock()
            .unwrap()
            .get(to)
            .copied()
            .ok_or_else(|| format!("unknown agent '{to}'"))?;

        // ONE serialization: the encoded body doubles as the byte count for
        // admission AND, on the JSON fast path, is spliced into the frame
        // directly (route_send used to serialize the body a second time
        // inside write_envelope — the body went through serde_json twice
        // per message).
        let body_encoded = serde_json::to_vec(body).unwrap_or_default();
        let bytes = body_encoded.len();

        let (_wire, dest_priority, dest_dtn, deliverable): (Wire, u8, bool, bool) = {
            let agents = self.agents.lock().unwrap();
            let entry = agents.get(&uin).ok_or("no process table entry")?;
            let e = entry.lock().unwrap();
            let deliverable =
                matches!(e.state, ProcState::Running | ProcState::Registered) && e.out.is_some();
            (e.wire, e.priority, e.dtn, deliverable)
        };

        // P5: ADMISSION + QoS + SCHEDULING in ONE locked pass. The
        // delivery mutex used to be taken three times on the fast path
        // (admit, schedule, record); admit and the link/schedule decision
        // need no intervening state — they now share a single guard. The
        // post-send `record_fast_path` stays a separate acquisition by
        // design: it must happen AFTER the bytes are on the wire.
        // NOTE: the guard must be scoped — a MutexGuard held by an
        // `if let` scrutinee lives to the end of the whole `if let`
        // statement, and re-locking inside the block self-deadlocks
        // (std Mutex is not reentrant; this hung the kernel once).
        enum Gate {
            Denied(String),
            Throttled,
            Ok,
        }
        enum GateOut {
            Denied(String),
            Throttled,
            /// deliverable + link idle: fast path, no scheduling side effect
            Fast,
            /// message queued in the WFQ (journaled by the caller)
            Scheduled,
        }
        let gate_out = {
            let mut d = self.delivery.lock().unwrap();
            d.refill_elapsed();
            let queued = deliverable && (d.link_busy() || !d.link_can_fit(bytes));
            let preflight = if deliverable {
                d.validate_link_message(bytes)
            } else {
                Ok(())
            }
            .and_then(|()| {
                if queued {
                    d.validate_queue_size(bytes)
                } else {
                    Ok(())
                }
            });
            let admission = d.admit_bytes(from, bytes).and_then(|()| {
                if preflight.is_err() {
                    d.refund_admission(from, bytes);
                }
                preflight
            });
            let gate = if let Err(reason) = admission {
                d.record_denied();
                Gate::Denied(reason)
            } else if !d.allow(from) {
                d.refund_admission(from, bytes);
                d.record_throttled();
                Gate::Throttled
            } else {
                Gate::Ok
            };
            match gate {
                Gate::Denied(reason) => GateOut::Denied(reason),
                Gate::Throttled => GateOut::Throttled,
                Gate::Ok => {
                    if !deliverable {
                        // DTN / undeliverable: no link decision here
                        GateOut::Fast
                    } else if !queued {
                        let ready = d.link_ready(bytes);
                        debug_assert!(ready);
                        GateOut::Fast
                    } else {
                        match d.schedule_admitted(from, uin, body.clone(), bytes) {
                            Ok(()) => GateOut::Scheduled,
                            Err(e) => GateOut::Denied(e),
                        }
                    }
                }
            }
        };
        match gate_out {
            GateOut::Denied(reason) => {
                self.ledger
                    .append(
                        "admission_denied",
                        json!({"from": from, "to": uin, "bytes": bytes, "reason": reason}),
                    )
                    .map_err(|e| e.to_string())?;
                return Err(format!("admission: {reason}"));
            }
            GateOut::Throttled => {
                self.ledger
                    .append(
                        "qos_throttled",
                        // PERF: bytes by default, body in verbose mode
                        if self.ledger_verbose {
                            json!({"from": from, "to": uin, "bytes": bytes, "body": body})
                        } else {
                            json!({"from": from, "to": uin, "bytes": bytes})
                        },
                    )
                    .map_err(|e| e.to_string())?;
                return Err(format!("qos: sender {from} over its rate limit"));
            }
            GateOut::Scheduled => {
                self.ledger
                    .append(
                        "qos_scheduled",
                        json!({"from": from, "to": uin, "bytes": bytes}),
                    )
                    .map_err(|e| e.to_string())?;
                self.notify_delivery();
                return Ok(());
            }
            GateOut::Fast => {}
        }

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

        // F03: resolve the destination OUT of the tables, then enqueue
        // — the connection's writer thread is the only code that
        // touches the socket, so a reply, the QoS pump and this routing
        // path can never interleave, and nothing here can block on a
        // peer that stopped reading.
        let out = self.resolve_out(uin)?;
        // JSON fast path: splice the envelope around the
        // ALREADY-ENCODED body — no second serialization, no
        // envelope-Value clone. Binary wires encode whole (msgpack
        // can't be spliced).
        if out.wire() == Wire::Json && !body_encoded.is_empty() {
            let mut frame = Vec::with_capacity(bytes + 48);
            frame.extend_from_slice(b"{\"kind\":\"msg\",\"from\":");
            frame.extend_from_slice(from.to_string().as_bytes());
            frame.extend_from_slice(b",\"body\":");
            frame.extend_from_slice(&body_encoded);
            frame.push(b'}');
            frame.push(b'\n');
            out.push(frame)?;
        } else {
            let msg = json!({"kind": "msg", "from": from, "body": body});
            out.send(&msg)?;
        }
        self.delivery
            .lock()
            .unwrap()
            .record_fast_path(from, uin, bytes);
        self.ledger
            .append(
                "delivered",
                // PERF: the body is journaled ONLY in verbose mode —
                // the audit facts (who -> whom, how many bytes) are the
                // default; the payload itself is already on the wire
                // and re-serializing it into the journal doubled ledger
                // growth (and cost ~1.7 us/append at 1 KB)
                if self.ledger_verbose {
                    json!({"from": from, "to": uin, "bytes": bytes, "body": body})
                } else {
                    json!({"from": from, "to": uin, "bytes": bytes})
                },
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn notify_delivery(&self) {
        let (generation, changed) = &*self.delivery_wake;
        *generation.lock().unwrap() += 1;
        changed.notify_one();
    }

    fn start_delivery_scheduler(kernel: &Arc<Self>) {
        let weak = Arc::downgrade(kernel);
        let wake = kernel.delivery_wake.clone();
        std::thread::spawn(move || loop {
            let observed = *wake.0.lock().unwrap();
            let Some(kernel) = weak.upgrade() else {
                break;
            };
            kernel.drain_delivery_queue();
            let delay = if !kernel.ledger.is_healthy() {
                Duration::from_secs(1)
            } else {
                let mut delivery = kernel.delivery.lock().unwrap();
                delivery.refill_elapsed();
                delivery
                    .pending
                    .peek()
                    .map(|m| delivery.next_link_delay(m.0.bytes))
                    .unwrap_or(Duration::from_secs(1))
            };
            drop(kernel);
            let guard = wake.0.lock().unwrap();
            if *guard == observed {
                drop(
                    wake.1
                        .wait_timeout(guard, delay.max(Duration::from_micros(1)))
                        .unwrap(),
                );
            }
        });
    }

    /// Drain WFQ in virtual-finish-tag order from the dedicated scheduler.
    /// No supervisor work or fixed watchdog sleep controls delivery latency.
    pub fn drain_delivery_queue(&self) {
        if !self.ledger.is_healthy() {
            return;
        }
        let mut served = 0usize;
        loop {
            let next = {
                let mut d = self.delivery.lock().unwrap();
                d.refill_elapsed();
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
            // F03: resolve the destination under the table lock, DROP
            // every lock, then enqueue. The old code wrote the socket
            // while holding agents+entry — a stalled peer parked the
            // sweep (and everything waiting on the table) behind it.
            let resolved: Option<Option<Arc<Outbound>>> = {
                let agents = self.agents.lock().unwrap();
                agents.get(&next.to).map(|entry| {
                    let e = entry.lock().unwrap();
                    let deliverable = matches!(e.state, ProcState::Running | ProcState::Registered)
                        && e.out.is_some();
                    if deliverable {
                        e.out.clone()
                    } else {
                        None
                    }
                })
            };
            let target: Option<Result<(), String>> = resolved
                .flatten()
                .map(|out| out.send(&json!({"kind": "msg", "from": next.from, "body": next.body})));
            match target {
                Some(res) => match res {
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
                },
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
                        // PERF: bytes by default, body in verbose mode
                        if self.ledger_verbose {
                            json!({"from": from, "to": to_uin, "next_hop": relay,
                                   "bundle_id": bundle_id, "hops": hops, "body": body})
                        } else {
                            let bytes = serde_json::to_vec(&body).unwrap_or_default().len();
                            json!({"from": from, "to": to_uin, "next_hop": relay,
                                   "bundle_id": bundle_id, "hops": hops, "bytes": bytes})
                        },
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
                // PERF: bytes by default, body in verbose mode
                if self.ledger_verbose {
                    json!({"from": from, "to": to_uin, "priority": priority,
                           "bundle_id": bundle_id, "hops": hops, "body": body})
                } else {
                    let bytes = serde_json::to_vec(&body).unwrap_or_default().len();
                    json!({"from": from, "to": to_uin, "priority": priority,
                           "bundle_id": bundle_id, "hops": hops, "bytes": bytes})
                },
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// DTN flush: called on registration — deliver the destination's held
    /// bundles in PRIORITY order (0 first), journal every delivery and
    /// every expiry. Runs BEFORE the welcome is written so the fresh
    /// agent sees its backlog as its first messages.
    pub fn dtn_flush(&self, uin: u64) -> Result<(), String> {
        let name = {
            let agents = self.agents.lock().unwrap();
            let entry = agents.get(&uin).ok_or("no process table entry")?;
            let e = entry.lock().unwrap();
            if e.out.is_none() {
                return Ok(()); // still no connection — nothing to flush into
            }
            e.name.clone()
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
                    // PERF: bytes by default, body in verbose mode
                    if self.ledger_verbose {
                        json!({"from": b.from, "to": uin, "body": b.body})
                    } else {
                        let bytes = serde_json::to_vec(&b.body).unwrap_or_default().len();
                        json!({"from": b.from, "to": uin, "bytes": bytes})
                    },
                )
                .ok();
        }
        let count = bundles.len();
        // F03: resolve once, enqueue the whole backlog — the FIFO queue
        // keeps the backlog in order with NO table lock held while the
        // frames travel (and a stalled peer cannot stall the flusher)
        let out = self.resolve_out(uin)?;
        for b in &bundles {
            let msg = json!({"kind": "msg", "from": b.from, "body": b.body});
            out.send(&msg)?;
            self.ledger
                .append(
                    "dtn_delivered",
                    // PERF: bytes by default, body in verbose mode
                    if self.ledger_verbose {
                        json!({"from": b.from, "to": uin, "priority": b.priority, "body": b.body})
                    } else {
                        let bytes = serde_json::to_vec(&b.body).unwrap_or_default().len();
                        json!({"from": b.from, "to": uin, "priority": b.priority, "bytes": bytes})
                    },
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
        let (via, via_expired) = {
            let mut delivery = self.delivery.lock().unwrap();
            let via = delivery.drain_via(uin);
            (via, delivery.take_expired_report())
        };
        for bundle in via_expired {
            self.ledger
                .append(
                    "dtn_expired",
                    json!({"from": bundle.from, "to": bundle.to, "body": bundle.body}),
                )
                .ok();
        }
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
                        ProcState::Starting => "starting",
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
        // A valid PID to signal must be strictly positive and fit in a signed 32-bit pid_t.
        // Signaling 0 kills the process group; signaling -1 (or u32::MAX which wraps to -1 as pid_t)
        // broadcasts SIGKILL to all processes belonging to the user slice.
        if child_pid > 0 && (child_pid as i32) > 0 && child_pid != u32::MAX {
            let _ = Command::new("kill")
                .args(["-9", &child_pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
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
        self.respawn_inner(uin, false);
    }

    /// `authorized = true` skips the automatic respawn budget: an
    /// operator-initiated restart is an explicit decision, not a loop
    /// the kernel decided to keep running.
    fn respawn_inner(&self, uin: u64, authorized: bool) {
        let (
            name,
            task,
            respawns,
            checkpoint,
            wire,
            isolation,
            priority,
            dtn,
            tcp_addr,
            manifest_caps,
        ) = {
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
            // F05: the restart restores the FULL launch policy — transport
            // included (respawn used to drop TCP and downgrade to UDS)
            let tcp = e.tcp_addr.clone();
            // F01: the manifest's trusted caps are launch policy too
            let mc = e.manifest_caps.clone();
            (n, t, r, c, w, iso, pr, dn, tcp, mc)
        };
        if !authorized && respawns >= self.max_respawns {
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
        // F01: a fresh token for the fresh instance — the OLD token is
        // dead with the old process
        let token = self.fresh_token();
        let cmd = self.build_agent_command(
            uin,
            &name,
            &task,
            wire,
            isolation.as_deref(),
            tcp_addr.as_deref(),
            &token,
        );
        let mut cmd = match cmd {
            Ok(c) => c,
            Err(e) => {
                self.ledger
                    .append("respawn_failed", json!({"uin": uin, "err": e}))
                    .ok();
                return;
            }
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
        self.children.lock().unwrap().insert(pid, ()); // F05: reaped by the waitpid reaper
        let agents = self.agents.lock().unwrap();
        if let Some(e) = agents.get(&uin) {
            let mut e = e.lock().unwrap();
            e.pid = pid;
            e.respawns += 1;
            // F01: the fresh instance registers with the FRESH token;
            // F10: including the VM tier — the guest received this token
            // in the initramfs its launch assembled
            e.auth_token = Some(token);
            // F05: restart fidelity — reapply the resource policy
            if self.apply_cgroups {
                let _ = sandbox::apply_cgroup(pid, &name);
            }
            // F05(item 5): the replacement is an explicit PENDING
            // launch — `Starting` is covered by the registration
            // deadline (keeping `Killed` here let a replacement that
            // never registers escape it forever) and is NOT "live" for
            // connection-close, which is what actually prevented the
            // duplicate-respawn race the old hack was guarding (the
            // stale EOF of the OLD instance now hits the live-set check
            // and does nothing). Clearing `out` says the same thing:
            // a pending launch has no connection.
            e.state = ProcState::Starting;
            e.out = None;
            e.last_hb = Instant::now();
            e.last_step = String::new();
            e.stuck_sweeps = 0;
            // the fresh instance inherits the ledger checkpoint on register
            e.last_checkpoint = checkpoint.or(e.last_checkpoint.clone());
            e.spawned_at = Instant::now();
            e.manifest_caps = manifest_caps;
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

    /// F05(item 5): one connection went away. The judgement is an
    /// EXPLICIT live-set (Registered | Running), not a negated
    /// judged-set: a PENDING launch (`Starting`) is the OLD instance's
    /// closing connection racing its own replacement, and reacting to
    /// it would trigger the duplicate respawn this state exists to
    /// prevent (the 003-ledger race).
    fn connection_closed(&self, my_uin: Option<u64>) {
        let Some(uin) = my_uin else {
            return;
        };
        let live = {
            let agents = self.agents.lock().unwrap();
            match agents.get(&uin) {
                Some(e) => {
                    let mut e = e.lock().unwrap();
                    let was_live = matches!(e.state, ProcState::Registered | ProcState::Running);
                    if was_live {
                        e.state = ProcState::Killed("process exited".into());
                    }
                    was_live
                }
                None => false,
            }
        };
        if live {
            self.ledger.append("crashed", json!({"uin": uin})).ok();
            self.respawn(uin);
        }
    }

    /// F10: operator-authorized restart of an entry that is NOT live.
    /// Resets the automatic respawn budget (the operator just authorized
    /// a fresh launch) and spawns a fresh instance with a FRESH token —
    /// this is the only way a dead identity comes back, replacing the old
    /// "any process may claim a dead identity" hole.
    pub fn restart_authorized(&self, uin: u64) -> Result<(), String> {
        {
            let agents = self.agents.lock().unwrap();
            let entry = agents.get(&uin).ok_or("no entry")?;
            let mut e = entry.lock().unwrap();
            let live =
                matches!(e.state, ProcState::Running | ProcState::Registered) && e.out.is_some();
            if live {
                return Err(format!(
                    "ctl: agent '{}' is live - nothing to restart",
                    e.name
                ));
            }
            let judged = matches!(e.state, ProcState::Dead | ProcState::Completed);
            let stale_pid = e.pid;
            e.respawns = 0; // the operator authorized a fresh launch
            e.state = ProcState::Killed("operator restart".into());
            e.out = None;
            drop(e);
            drop(agents);
            // a stale process must not survive into the new launch: two
            // processes for one uin is exactly what the table forbids
            if !judged && stale_pid > 0 && (stale_pid as i32) > 0 && stale_pid != u32::MAX {
                let _ = Command::new("kill")
                    .args(["-9", &stale_pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        self.respawn_inner(uin, true);
        Ok(())
    }

    /// Watchdog sweep: heartbeat timeout AND progress-loop detection.
    pub fn sweep(&self) {
        let suspects: Vec<(u64, String)> = {
            let agents = self.agents.lock().unwrap();
            agents
                .values()
                .filter_map(|e| {
                    let mut e = e.lock().unwrap();
                    // F05/F07: an agent that NEVER registers is not given
                    // infinite grace — the registration deadline (spawn +
                    // 3x heartbeat timeout) kills and respawns it. The old
                    // sweep skipped entries without a connection FOREVER,
                    // so a wedged boot left a zombie-shaped entry outside
                    // every timeout path.
                    if e.out.is_none() {
                        let reg_ms =
                            (self.hb_timeout_ms * REGISTRATION_DEADLINE_FACTOR).max(10_000);
                        // F05(item 5): BOTH the initial launch and a
                        // replacement are `Starting` — the deadline is
                        // per-launch (spawned_at is reset on respawn)
                        if matches!(e.state, ProcState::Starting | ProcState::Registered)
                            && e.spawned_at.elapsed().as_millis() as u64 > reg_ms
                        {
                            return Some((
                                e.uin,
                                format!("registration deadline ({} ms, never registered)", reg_ms),
                            ));
                        }
                        return None;
                    }
                    if matches!(
                        e.state,
                        ProcState::Dead | ProcState::Completed | ProcState::Killed(_)
                    ) {
                        return None; // already judged — never re-kill, never re-journal
                    }
                    // F03: the writer already gave up on this peer
                    // (queue full or write deadline) — the connection is
                    // dead even though the reader half may still be open
                    if e.out.as_ref().is_some_and(|o| o.is_closed()) {
                        return Some((
                            e.uin,
                            "outbound writer closed (peer stopped reading)".to_string(),
                        ));
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
        // DTN sweep: bundles whose TTL ran out while the destination
        // never registered — journaled then dropped (never silent)
        {
            let expired = self.delivery.lock().unwrap().sweep_expired();
            for b in expired {
                self.ledger
                    .append(
                        "dtn_expired",
                        // PERF: bytes by default, body in verbose mode
                        if self.ledger_verbose {
                            json!({"from": b.from, "to": b.to, "body": b.body})
                        } else {
                            let bytes = serde_json::to_vec(&b.body).unwrap_or_default().len();
                            json!({"from": b.from, "to": b.to, "bytes": bytes})
                        },
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
    // F01: TRUSTED capability config from the manifest — the kernel owns
    // the grant; the agent's task cannot add to it
    Option<Vec<String>>,
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
                    None,
                )
            })
            .collect();
        Router::serve_full(kernel, &a)
    }

    pub fn serve_full(
        kernel: Kernel,
        agents: &[AgentSpecTuple],
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        // F10: the kernel must not be readable by the agents it spawns
        set_non_dumpable();
        if std::env::var("AMA_OPERATOR_TOKEN")
            .map(|v| v.is_empty())
            .unwrap_or(true)
        {
            eprintln!(
                "[ama] operator token generated (export AMA_OPERATOR_TOKEN to pre-share it): {}",
                kernel.operator_token
            );
        }
        let kernel = Arc::new(kernel);
        Kernel::start_delivery_scheduler(&kernel);
        let _ = std::fs::remove_file(&kernel.socket_path);
        let listener = std::os::unix::net::UnixListener::bind(&kernel.socket_path)?;
        let k = kernel.clone();
        let watchdog = std::thread::spawn(move || loop {
            k.sweep();
            std::thread::sleep(Duration::from_millis(200));
        });
        std::mem::forget(watchdog);
        // F05: reap finished children. The reaper is the SOLE collector
        // of exit status (the spawn sites drop their `Child` handles,
        // which does NOT reap — dropping only disarms the auto-wait).
        // PERF: the old loop polled `try_wait` on every child every
        // 500 ms, holding the children lock the whole time; a dead
        // agent waited on average ~250 ms to be reaped. `waitpid(pid,
        // WNOHANG)` is a single non-blocking syscall per pid that
        // returns immediately, so the lock is only held to snapshot the
        // pid set and to remove the finished ones.
        {
            let k = kernel.clone();
            std::thread::spawn(move || loop {
                let pids: Vec<u32> = k.children.lock().unwrap().keys().copied().collect();
                let mut finished = Vec::new();
                for pid in pids {
                    let mut status: libc::c_int = 0;
                    let r =
                        unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
                    if r == (pid as libc::pid_t) {
                        finished.push(pid);
                    }
                    // r == 0: still running; -1/ECHILD: gone (reaped
                    // elsewhere) — drop it from the table either way
                    // (EINTR just means the next iteration retries)
                }
                if !finished.is_empty() {
                    k.children
                        .lock()
                        .unwrap()
                        .retain(|pid, _| !finished.contains(pid));
                    k.ledger
                        .append("children_reaped", json!({"pids": finished}))
                        .ok();
                }
                // bounded poll: with no children the loop is one cheap
                // lock + no syscalls per tick; with children, one
                // WNOHANG syscall each. 10 ms keeps reap latency low
                // without burning a core
                std::thread::sleep(Duration::from_millis(10));
            });
        }
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
                        Router::spawn_connection(k, Peer::Tcp(stream), false);
                    }
                }
                Err(e) => eprintln!("[ama] tcp listener {addr}: {e}"),
            });
        }
        // F02: dedicated OPERATOR control socket — restrictive file mode
        // (0600) and a Unix peer-credential check (the peer must run as the
        // same uid as the kernel). Control verbs are NEVER served on the
        // agent listeners (UDS or TCP).
        {
            let ctl_path = control_socket_path(&kernel.socket_path);
            let _ = std::fs::remove_file(&ctl_path);
            let ctl_listener = std::os::unix::net::UnixListener::bind(&ctl_path)?;
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&ctl_path, std::fs::Permissions::from_mode(0o600));
            eprintln!("[ama] operator control socket up on {}", ctl_path.display());
            let k = kernel.clone();
            std::thread::spawn(move || {
                for conn in ctl_listener.incoming().flatten() {
                    let k = k.clone();
                    Router::spawn_connection(k, Peer::Unix(conn), true);
                }
            });
        }
        // bind is live now — spawn the manifest's agents
        for (name, task, tcp, wire, iso, qos, dtn, caps) in agents {
            if let Err(e) = kernel.spawn_agent_opts(
                name,
                task,
                tcp.as_deref(),
                *wire,
                iso.as_deref(),
                *qos,
                *dtn,
                caps.clone(),
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
                        Router::spawn_connection(k, Peer::Unix(stream), false);
                    }
                    Err(_) => continue,
                }
            }
        });
        Ok(handle)
    }

    fn spawn_connection(kernel: Arc<Kernel>, peer: Peer, control: bool) {
        let identity = match &peer {
            Peer::Tcp(s) => s
                .peer_addr()
                .map(|a| format!("tcp:{}", a.ip()))
                .unwrap_or_else(|_| "tcp:unknown".into()),
            Peer::Unix(s) => Self::peer_creds(s)
                .map(|c| format!("uid:{}", c.uid))
                .unwrap_or_else(|_| "unix:unknown".into()),
        };
        let admission = if control {
            &kernel.control_connections
        } else {
            &kernel.connections
        };
        let Some(lease) = admission.acquire(identity.clone()) else {
            kernel
                .ledger
                .append(
                    "connection_refused",
                    json!({"peer": identity, "reason": "connection budget exhausted"}),
                )
                .ok();
            return;
        };
        let lease = Arc::new(lease);
        std::thread::spawn(move || {
            let _lease = lease.clone();
            if control {
                if let Peer::Unix(ref s) = peer {
                    if let Err(e) = Self::ctl_door(&kernel, s) {
                        kernel
                            .ledger
                            .append("ctl_refused", json!({"reason": e}))
                            .ok();
                        return;
                    }
                }
                peer.set_read_timeout(Some(Duration::from_millis(
                    kernel.resource_limits.idle_timeout_ms,
                )))
                .ok();
                Self::ctl_connection(kernel, peer, Some(lease));
            } else {
                Self::connection(kernel, peer, Some(lease));
            }
        });
    }

    /// F10: the control socket's DOOR. Two independent gates, both
    /// evaluated before a single byte of the request is read: the peer
    /// must run as the kernel's uid, AND its pid must not be one of the
    /// kernel's own spawned agents. Extracted from the accept loop so a
    /// test can drive it against a live socketpair (SO_PEERCRED reports
    /// the real peer pid there).
    fn ctl_door(kernel: &Kernel, conn: &std::os::unix::net::UnixStream) -> Result<(), String> {
        Router::check_peer_credentials(conn)?;
        let cred = Router::peer_creds(conn)?;
        if kernel.is_agent_pid(cred.pid as u32) {
            return Err(format!(
                "peer PID {} belongs to a spawned agent — the operator socket is not for agents",
                cred.pid
            ));
        }
        Ok(())
    }

    /// Unix peer-credential check: the connecting process must run as the
    /// SAME uid as the kernel. (SO_PEERCRED via libc.)
    fn peer_creds(sock: &std::os::unix::net::UnixStream) -> Result<libc::ucred, String> {
        use std::os::unix::io::AsRawFd;
        let mut cred: libc::ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if r != 0 {
            return Err("SO_PEERCRED unavailable".to_string());
        }
        Ok(cred)
    }

    fn check_peer_credentials(sock: &std::os::unix::net::UnixStream) -> Result<(), String> {
        let cred = Self::peer_creds(sock)?;
        let my_uid = unsafe { libc::getuid() };
        if cred.uid != my_uid {
            return Err(format!("peer uid {} != kernel uid {}", cred.uid, my_uid));
        }
        Ok(())
    }

    /// The operator control connection: JSON lines, ctl verbs ONLY.
    fn ctl_connection(
        kernel: Arc<Kernel>,
        peer: Peer,
        lease: Option<Arc<resources::ConnectionReservation>>,
    ) {
        // plain JSON lines from the FIRST byte — no wire-format magic on
        // the operator socket (F02). F03: replies go through the same
        // bounded-writer machinery as agent connections, so process
        // inspection can never block on a stalled reader either.
        let out = match peer.try_clone() {
            Ok(w) => spawn_writer_reserved(kernel.ledger.clone(), w, Wire::Json, lease),
            Err(_) => return,
        };
        let mut reader = JsonPeer::new_raw(peer);
        let mut line = String::new();
        while reader.read_line_after(&mut line).unwrap_or(false) {
            let trimmed = line.trim().to_string();
            line.clear();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(&trimmed) {
                Ok(v) => {
                    if let Err(e) = Router::handle_ctl_value(&kernel, &out, &v, Wire::Json) {
                        let _ = out.send(&json!({"kind": "error", "reason": e}));
                    }
                }
                Err(e) => {
                    let _ =
                        out.send(&json!({"kind": "error", "reason": format!("invalid json: {e}")}));
                }
            }
        }
        out.close();
    }

    /// One connection, any transport, both wire formats. The FIRST byte
    /// decides the format: `{` = JSON lines (v0.1 contract), 0xFF = the
    /// length-prefixed msgpack frames (§6.2 wire encoding).
    fn connection(
        kernel: Arc<Kernel>,
        mut peer: Peer,
        lease: Option<Arc<resources::ConnectionReservation>>,
    ) {
        peer.set_read_timeout(Some(Duration::from_millis(
            kernel.resource_limits.handshake_timeout_ms,
        )))
        .ok();
        let initial_deadline =
            Instant::now() + Duration::from_millis(kernel.resource_limits.handshake_timeout_ms);
        let mut first = [0u8; 1];
        if PeerDeadline::until(&mut peer, initial_deadline)
            .read(&mut first)
            .unwrap_or(0)
            == 0
        {
            return;
        }
        let wire = match first[0] {
            b'{' => Wire::Json,
            0xFF => Wire::Msgpack,
            0x0A => Wire::Proto,
            _ => {
                // a payload that does not even carry the schema magic is a
                // violation — journal it (never silently drop a rejected
                // connection)
                kernel
                    .ledger
                    .append("malformed", json!({"reason": "invalid json: first byte is not '{' or 0xFF (schema violation)", "seen": first[0]}))
                    .ok();
                return;
            }
        };
        // F03: the dedicated writer owns every byte this connection
        // sends — the reader half never writes the socket again
        let out = match peer.try_clone() {
            Ok(w) => spawn_writer_reserved(kernel.ledger.clone(), w, wire, lease),
            Err(_) => return,
        };
        let my_uin = match wire {
            Wire::Json => {
                let mut reader = JsonPeer::new(peer, first[0]);
                reader.first_deadline = Some(initial_deadline);
                Router::json_loop(kernel.clone(), &mut reader, &out)
            }
            Wire::Msgpack => {
                Router::msgpack_loop(kernel.clone(), peer, true, &out, initial_deadline)
            }
            Wire::Proto => Router::proto_loop(kernel.clone(), peer, &out, initial_deadline),
        };
        // reader gone: stop feeding the writer (queued frames are dropped
        // with the connection)
        out.close();
        // EOF: if this connection belonged to a live agent, the process
        // is gone — fail fast, respawn from the ledger.
        kernel.connection_closed(my_uin);
    }

    fn proto_loop(
        kernel: Arc<Kernel>,
        peer: Peer,
        out: &Arc<Outbound>,
        initial_deadline: Instant,
    ) -> Option<u64> {
        let mut my_uin: Option<u64> = None;
        // PERF: buffered reads — the unbuffered path made every frame 3+
        // syscalls (magic, len, payload), which is a real cost behind
        // TCP (remote agents, microVMs over tap). The MAX_FRAME bound is
        // checked BEFORE the allocation (F07) — wrapping in a
        // BufReader does not change that contract.
        let mut peer = BufReader::with_capacity(1 << 16, peer);
        // first frame: the 0x0A magic byte was already consumed
        let mut v = {
            let mut input = PeerDeadline::until(&mut peer, initial_deadline);
            let mut lenb = [0u8; 4];
            if input.read_exact(&mut lenb).is_err() {
                return None;
            }
            let len = u32::from_le_bytes(lenb) as usize;
            if len > MAX_FRAME {
                kernel
                    .ledger
                    .append(
                        "frame_refused",
                        json!({"reason": "oversized binary frame", "bytes": len}),
                    )
                    .ok();
                return None;
            }
            let mut buf = vec![0u8; len];
            if input.read_exact(&mut buf).is_err() {
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
        if debug_enabled() {
            eprintln!("[proto_loop] first frame: {v}");
        }
        loop {
            match Router::handle_value(&kernel, out, &v, &mut my_uin, Wire::Proto) {
                Ok(()) => {}
                Err(e) => {
                    let _ = out.send(&json!({"kind": "error", "reason": e}));
                }
            }
            let deadline = if my_uin.is_some() {
                Instant::now() + Duration::from_millis(kernel.resource_limits.idle_timeout_ms)
            } else {
                initial_deadline
            };
            match read_proto_frame(&mut PeerDeadline::until(&mut peer, deadline)) {
                Ok(v2) => {
                    if debug_enabled() {
                        eprintln!("[proto_loop] next frame: {v2}");
                    }
                    v = v2;
                }
                Err(error) => {
                    kernel
                        .ledger
                        .append(
                            if error.kind() == io::ErrorKind::InvalidData {
                                "frame_refused"
                            } else {
                                "connection_read_closed"
                            },
                            json!({"reason": error.to_string()}),
                        )
                        .ok();
                    break;
                }
            }
        }
        my_uin
    }

    fn msgpack_loop(
        kernel: Arc<Kernel>,
        peer: Peer,
        _first_magic_seen: bool,
        out: &Arc<Outbound>,
        initial_deadline: Instant,
    ) -> Option<u64> {
        let mut my_uin: Option<u64> = None;
        if debug_enabled() {
            eprintln!("[msgpack_loop] entered");
        }
        // PERF: buffered reads — see proto_loop (3+ syscalls/frame
        // unbuffered; a real cost behind TCP). The MAX_FRAME bound is
        // checked before the allocation (F07).
        let mut peer = BufReader::with_capacity(1 << 16, peer);
        // first frame: the magic byte was already consumed
        let mut v = {
            let mut input = PeerDeadline::until(&mut peer, initial_deadline);
            let mut lenb = [0u8; 4];
            if input.read_exact(&mut lenb).is_err() {
                return None;
            }
            let len = u32::from_le_bytes(lenb) as usize;
            if len > MAX_FRAME {
                kernel
                    .ledger
                    .append(
                        "frame_refused",
                        json!({"reason": "oversized binary frame", "bytes": len}),
                    )
                    .ok();
                return None;
            }
            let mut buf = vec![0u8; len];
            if input.read_exact(&mut buf).is_err() {
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
            match Router::handle_value(&kernel, out, &v, &mut my_uin, last_wire) {
                Ok(()) => {}
                Err(e) => {
                    let _ = out.send(&json!({"kind": "error", "reason": e}));
                }
            }
            let deadline = if my_uin.is_some() {
                Instant::now() + Duration::from_millis(kernel.resource_limits.idle_timeout_ms)
            } else {
                initial_deadline
            };
            match read_msgpack_frame(&mut PeerDeadline::until(&mut peer, deadline)) {
                Ok(v2) => {
                    if debug_enabled() {
                        eprintln!("[msgpack_loop] next frame: {v2}");
                    }
                    v = v2;
                }
                Err(error) => {
                    kernel
                        .ledger
                        .append(
                            if error.kind() == io::ErrorKind::InvalidData {
                                "frame_refused"
                            } else {
                                "connection_read_closed"
                            },
                            json!({"reason": error.to_string()}),
                        )
                        .ok();
                    break;
                }
            }
        }
        let _ = last_wire;
        my_uin
    }

    fn json_loop(kernel: Arc<Kernel>, reader: &mut JsonPeer, out: &Arc<Outbound>) -> Option<u64> {
        let mut my_uin: Option<u64> = None;
        let mut line = String::new();
        // the first '{' was already consumed by the mode detector
        match reader.read_line_after(&mut line) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(error) => {
                kernel
                    .ledger
                    .append("frame_refused", json!({"reason": error.to_string()}))
                    .ok();
                return None;
            }
        }
        // the first '{' is ALREADY in `line` (pushed by the JsonPeer) —
        // prepending a second brace produced `{{kind` → "key must be a
        // string" (caught by experiment 003)
        let first = line.trim_end().to_string();
        if debug_json_enabled() {
            eprintln!("[json_loop] first line = {first:?}");
        }
        let mut v = match serde_json::from_str::<Value>(&first) {
            Ok(v) => {
                if debug_enabled() {
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
            match Router::handle_value(&kernel, out, &v, &mut my_uin, Wire::Json) {
                Ok(()) => {}
                Err(e) => {
                    let _ = out.send(&json!({"kind": "error", "reason": format!("rejected: {e}")}));
                }
            }
            if my_uin.is_some() {
                reader.first_deadline = None;
                reader.timeout = Duration::from_millis(kernel.resource_limits.idle_timeout_ms);
            }
            line.clear();
            match reader.read_line_after(&mut line) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    kernel
                        .ledger
                        .append("frame_refused", json!({"reason": error.to_string()}))
                        .ok();
                    break;
                }
            }
            if debug_json_enabled() {
                eprintln!("[json_loop] line = {:?}", line.trim_end());
            }
            match serde_json::from_str::<Value>(line.trim_end()) {
                Ok(v2) => {
                    if debug_enabled() {
                        eprintln!("[json_loop] frame: {v2}");
                    }
                    v = v2;
                }
                Err(e) => {
                    kernel.ledger.append("malformed", json!({"reason": format!("invalid json: {e}"), "line": line.trim_end()})).ok();
                    let _ = out.send(
                        &json!({"kind": "error", "reason": format!("rejected: invalid json: {e}")}),
                    );
                    continue;
                }
            }
        }
        my_uin
    }

    /// Operator control verbs — served ONLY on the dedicated control
    /// socket (`<socket>.ctl`, mode 0600, peer-credential checked). F02:
    /// being unregistered is NOT authentication; the agent listener
    /// refuses every ctl verb and journals it.
    fn handle_ctl_value(
        kernel: &Kernel,
        out: &Arc<Outbound>,
        v: &Value,
        _wire: Wire,
    ) -> Result<(), String> {
        let kind = v
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("ctl: missing 'kind'")?;
        // F10: operator authority is a CREDENTIAL, not an OS identity.
        // Same-uid agents can open this socket (0600 admits them), so
        // every verb must present the token they were never given.
        let presented = v.get("token").and_then(Value::as_str).unwrap_or("");
        if !credential_eq(presented, &kernel.operator_token) {
            kernel
                .ledger
                .append(
                    "ctl_refused",
                    json!({"kind": kind, "reason": "operator token missing or wrong"}),
                )
                .ok();
            out.send(&json!({"kind": "error", "reason": "operator token required"}))
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
        match kind {
            "ctl_qos" => {
                // bandwidth accounting + queue state, operator-only
                let stats = kernel.delivery.lock().unwrap().stats();
                let reply = json!({"kind": "qos", "stats": stats, "connections": kernel.connections.stats(), "control_connections": kernel.control_connections.stats(), "outbound_bytes": kernel.ledger.outbound_budget.usage().0, "ledger_healthy": kernel.ledger.is_healthy()});
                out.send(&reply).map_err(|e| e.to_string())?;
                Ok(())
            }
            "ctl_ps" => {
                let dump = kernel.ps_dump();
                let reply = json!({"kind": "ps", "agents": dump});
                if debug_json_enabled() {
                    eprintln!("[ctl_ps] reply = {reply}");
                }
                out.send(&reply).map_err(|e| e.to_string())?;
                Ok(())
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
                                    // the grant is POLICY: it
                                    // survives registration and
                                    // respawn
                                    if !e.granted.contains(c) {
                                        e.granted.push(c.clone());
                                    }
                                    e.revoked.retain(|x| x != c);
                                    if !e.caps.contains(c) {
                                        e.caps.push(c.clone());
                                    }
                                }
                            } else {
                                for c in &caps {
                                    if !e.revoked.contains(c) {
                                        e.revoked.push(c.clone());
                                    }
                                }
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
                    out.send(&json!({"kind": ack, "name": name}))
                        .map_err(|e| e.to_string())?;
                    Ok(())
                } else {
                    Err(format!("ctl: unknown agent '{name}'"))
                }
            }
            "ctl_restart" => {
                // F10: the EXPLICITLY AUTHORIZED restart that replaces
                // unauthenticated claims of a dead identity. Only an
                // operator holding the credential can bring a dead entry
                // back — and the fresh launch gets a fresh token.
                let name = v.get("name").and_then(Value::as_str).unwrap_or("");
                let uin = kernel
                    .by_name
                    .lock()
                    .unwrap()
                    .get(name)
                    .copied()
                    .ok_or_else(|| format!("ctl: unknown agent '{name}'"))?;
                kernel
                    .ledger
                    .append("restart_authorized", json!({"uin": uin, "name": name}))
                    .ok();
                kernel.restart_authorized(uin)?;
                out.send(&json!({"kind": "restarted", "name": name}))
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            _ => Err(format!("ctl: unknown control verb '{kind}'")),
        }
    }

    /// Handle ONE decoded envelope (transport- and format-agnostic).
    fn handle_value(
        kernel: &Kernel,
        out: &Arc<Outbound>,
        v: &Value,
        my_uin: &mut Option<u64>,
        wire: Wire,
    ) -> Result<(), String> {
        // F02: control verbs on an AGENT connection are refused — the
        // operator surface is the dedicated `<socket>.ctl` socket with
        // restrictive permissions and peer-credential checks. Being
        // unregistered is not authentication.
        if let Some(kind) = v.get("kind").and_then(Value::as_str) {
            if kind.starts_with("ctl_") {
                kernel
                    .ledger
                    .append(
                        "ctl_refused",
                        json!({"kind": kind,
                               "reason": "control verbs are only served on the operator socket"}),
                    )
                    .ok();
                out.send(
                    &json!({"kind": "error", "reason": "control verbs are only served on the operator socket"}),
                )
                .map_err(|e| e.to_string())?;
                return Ok(());
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
                        // `from` is ROUTING METADATA (the origin the
                        // relay forwards on behalf of), not an identity
                        // claim — the SESSION carries the authority here:
                        // the relay capability was checked above, and the
                        // custody chain (kernel hand-offs only) is what
                        // authenticates the route. Journaled on every
                        // dtn_relayed for audit.
                        let orig = v.get("from").and_then(Value::as_u64).unwrap_or(me);
                        let body = v.get("body").cloned().unwrap_or(Value::Null);
                        let frag_meta = v.get("frag").filter(|f| !f.is_null()).and_then(|f| {
                            Some(qos::FragMeta {
                                id: f.get("id")?.as_u64()?,
                                index: f.get("index")?.as_u64()? as u32,
                                total: f.get("total")?.as_u64()? as u32,
                            })
                        });
                        // F01 (DTN): relaying is a capability like any
                        // other — the SESSION must hold `relay:<to>`
                        kernel.check_cap(me, "relay", to_name)?;
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
                            out.send(&json!({"kind": "acked", "bundle_id": bundle_id}))
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
                        out.send(&json!({"kind": "acked", "bundle_id": bundle_id}))
                            .map_err(|e| e.to_string())?;
                        return Ok(());
                    }
                    "custody_ack" => {
                        let bundle_id = v.get("bundle_id").and_then(Value::as_u64).unwrap_or(0);
                        // CUSTODY TRANSFER: the relay owns the bundle now,
                        // so the kernel deletes its own copy (exactly once).
                        // F01 (DTN): ONLY the entity custody was transferred
                        // TO may acknowledge it — an unrelated relay cannot
                        // release another relay's custody transfer, and an
                        // agent cannot release kernel custody it was never
                        // handed.
                        let frag_index = v
                            .get("frag_index")
                            .and_then(Value::as_u64)
                            .map(|i| i as u32);
                        let released = kernel
                            .delivery
                            .lock()
                            .unwrap()
                            .ack_custody(bundle_id, frag_index, me);
                        if released == 0 {
                            kernel
                                .ledger
                                .append(
                                    "custody_ack_refused",
                                    json!({"by": me, "bundle_id": bundle_id,
                                           "reason": "session is not the current custody holder"}),
                                )
                                .ok();
                            return Err(format!(
                                "custody: uin {me} does not hold custody of bundle {bundle_id}"
                            ));
                        }
                        kernel
                            .ledger
                            .append(
                                "dtn_custody_ack",
                                json!({"bundle_id": bundle_id, "frag_index": frag_index,
                                       "by": me, "released": released}),
                            )
                            .map_err(|e| e.to_string())?;
                        out.send(
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
        // F01: the acting identity is the SESSION (the registered
        // connection), never the envelope's claim — agent A cannot send,
        // checkpoint, complete, heartbeat or note as agent B, and an
        // unregistered connection cannot issue agent operations at all.
        let env = {
            let session = *my_uin;
            let claimed = match &env {
                Envelope::Heartbeat { uin, .. }
                | Envelope::Send { uin, .. }
                | Envelope::Checkpoint { uin, .. }
                | Envelope::Done { uin }
                | Envelope::Note { uin, .. } => Some(*uin),
                _ => None,
            };
            match (claimed, session) {
                (Some(_), None) => {
                    kernel
                        .ledger
                        .append(
                            "identity_refused",
                            json!({"reason": "agent operation on an unregistered connection",
                                   "line": v}),
                        )
                        .ok();
                    return Err("identity: register before agent operations".to_string());
                }
                (Some(claim), Some(sess)) if claim != sess => {
                    kernel
                        .ledger
                        .append(
                            "identity_mismatch",
                            json!({"claimed": claim, "session": sess}),
                        )
                        .ok();
                    return Err(format!(
                        "identity: claimed uin {claim} does not match the session ({sess})"
                    ));
                }
                _ => {}
            }
            // the session uin REWRITES the acting identity — the claim is
            // never trusted even when it matches
            match (session, env) {
                (
                    Some(u),
                    Envelope::Heartbeat {
                        uin: _,
                        step,
                        phase,
                    },
                ) => Envelope::Heartbeat {
                    uin: u,
                    step,
                    phase,
                },
                (Some(u), Envelope::Send { uin: _, to, body }) => {
                    Envelope::Send { uin: u, to, body }
                }
                (Some(u), Envelope::Checkpoint { uin: _, state }) => {
                    Envelope::Checkpoint { uin: u, state }
                }
                (Some(u), Envelope::Done { .. }) => Envelope::Done { uin: u },
                (Some(u), Envelope::Note { uin: _, text }) => Envelope::Note { uin: u, text },
                (_, other) => other,
            }
        };
        match env {
            Envelope::Register {
                name,
                caps,
                pid,
                token,
            } => {
                let uin = kernel
                    .by_name
                    .lock()
                    .unwrap()
                    .get(&name)
                    .copied()
                    .ok_or_else(|| format!("unknown agent '{name}' — not in the manifest"))?;
                // F10: ONE critical section, from the identity check to
                // the state transition. The old code checked under the
                // locks, DROPPED them and re-acquired to mutate — two
                // concurrent claims could both pass the check and both
                // become Running. The entry lock now serializes them: the
                // loser observes the winner's state and is refused.
                {
                    let agents = kernel.agents.lock().unwrap();
                    let entry = agents.get(&uin).ok_or("no entry")?;
                    let mut e = entry.lock().unwrap();
                    // F10: the per-instance token is required in EVERY
                    // lifecycle state — initial registration, reconnect,
                    // restart, and the microVM tier (the credential is
                    // baked into the guest's private initramfs at launch).
                    // Knowing the manifest name, or the pid the readable
                    // ledger prints, is not identity: only the process
                    // this kernel spawned holds the secret. A DEAD entry
                    // is no longer claimable without it — the operator's
                    // explicit ctl_restart is how a dead identity returns.
                    let presented = token.as_deref().unwrap_or("");
                    let token_ok =
                        !presented.is_empty() && Some(presented) == e.auth_token.as_deref();
                    if !token_ok {
                        kernel
                            .ledger
                            .append(
                                "identity_refused",
                                json!({"reason": "registration token missing, wrong, or stale",
                                       "name": name,
                                       "entry_state": format!("{:?}", e.state),
                                       "spawned_pid": e.pid, "claimed_pid": pid}),
                            )
                            .ok();
                        return Err(format!(
                            "register: '{name}' requires this instance's registration token"
                        ));
                    }
                    // F10: the AUTHENTICATED claimer becomes the instance:
                    // record its pid so every pid-based check (the ctl
                    // door, kill, ps) targets the LIVE process instead of
                    // the corpse the ledger last recorded. The VM tier is
                    // excluded — there the watched pid is Firecracker, and
                    // the guest's pid is meaningless on this host.
                    if e.isolation.as_deref() != Some("microvm") {
                        e.pid = pid;
                    }
                    // one live instance per UIN: a second register (stale
                    // process that didn't get the kill, or a duplicate)
                    // is refused — the respawning pid is the authority
                    if let ProcState::Running = e.state {
                        return Err(format!(
                            "agent '{name}' already registered (stale instance refused)"
                        ));
                    }
                    // F10: effective caps = the TRUSTED source + operator
                    // grants - operator revocations. The trusted source is
                    // the manifest's caps when DECLARED; an omitted policy
                    // is no longer "whatever the task asked for" — it is
                    // NO grants (AMA_LEGACY_TRUST_TASK_CAPS=1 keeps the old
                    // fallback while a manifest is migrated). The operator
                    // policy is never lost either way.
                    let source_caps = match &e.manifest_caps {
                        Some(mc) => mc.clone(),
                        None if legacy_trust_task_caps() => caps.clone(),
                        None => Vec::new(),
                    };
                    let mut merged = source_caps;
                    for g in &e.granted {
                        if !merged.contains(g) {
                            merged.push(g.clone());
                        }
                    }
                    merged.retain(|c| !e.revoked.contains(c));
                    e.caps = merged;
                    e.state = ProcState::Running;
                    // F03: the entry holds the connection's QUEUE — the
                    // writer thread behind it is the only socket writer
                    *out.budget.lock().unwrap() = kernel.ledger.agent_budget(uin);
                    if let Some(previous) = e.out.replace(Arc::clone(out)) {
                        previous.close();
                    }
                    e.wire = wire;
                    e.last_hb = Instant::now();
                    e.stuck_sweeps = 0;
                    e.last_step = String::new();
                    drop(e);
                    drop(agents);
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
                out.send(&json!({"kind": "welcome", "uin": uin, "recover": recover}))
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
                if matches!(e.state, ProcState::Starting | ProcState::Registered) {
                    e.state = ProcState::Running;
                }
                Ok(())
            }
            Envelope::Send { uin, to, body } => {
                kernel.check_cap(uin, "send", &to)?;
                kernel.route_send(uin, &to, &body)?;
                out.send(&json!({"kind": "sent", "to": to}))
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Envelope::Checkpoint { uin, state } => {
                let e = kernel
                    .ledger
                    .append_durable("checkpoint", json!({"uin": uin, "state": state}))
                    .map_err(|e| e.to_string())?;
                let agents = kernel.agents.lock().unwrap();
                if let Some(entry) = agents.get(&uin) {
                    entry.lock().unwrap().last_checkpoint = Some(state.clone());
                }
                drop(agents);
                out.send(&json!({"kind": "acked", "seq": e.seq}))
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
                out.send(&json!({"kind": "acked", "note": true}))
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

/// The dedicated operator control socket path (F02): the agent socket path
/// plus the `.ctl` suffix.
fn control_socket_path(socket_path: &std::path::Path) -> std::path::PathBuf {
    let mut p = socket_path.to_path_buf().into_os_string();
    p.push(".ctl");
    std::path::PathBuf::from(p)
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

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Peer::Unix(s) => s.set_read_timeout(timeout),
            Peer::Tcp(s) => s.set_read_timeout(timeout),
        }
    }
    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        match self {
            Peer::Unix(s) => s.read_timeout(),
            Peer::Tcp(s) => s.read_timeout(),
        }
    }

    /// F03: the writer half carries a deadline so a peer that stopped
    /// reading releases the writer thread instead of parking it.
    pub fn set_write_timeout(&self, t: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            Peer::Unix(s) => s.set_write_timeout(t),
            Peer::Tcp(s) => s.set_write_timeout(t),
        }
    }
}

/// A whole-frame deadline, not a fresh timeout for each trickled byte.
trait DeadlineRead: Read {
    fn deadline_timeout(&self, timeout: Duration) -> io::Result<()>;
}
impl DeadlineRead for Peer {
    fn deadline_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }
}
impl DeadlineRead for BufReader<Peer> {
    fn deadline_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.get_ref().set_read_timeout(Some(timeout))
    }
}
struct PeerDeadline<'a, R: DeadlineRead> {
    peer: &'a mut R,
    deadline: Instant,
}
impl<'a, R: DeadlineRead> PeerDeadline<'a, R> {
    fn until(peer: &'a mut R, deadline: Instant) -> Self {
        Self { peer, deadline }
    }
}
impl<R: DeadlineRead> Read for PeerDeadline<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "frame read deadline exceeded")
            })?;
        self.peer.deadline_timeout(remaining)?;
        self.peer.read(buf)
    }
}

/// A JSON peer whose first byte was consumed by the mode detector.
struct JsonPeer {
    peer: BufReader<Peer>,
    first: Option<u8>,
    done: bool,
    timeout: Duration,
    first_deadline: Option<Instant>,
    /// Scratch buffer for bounded bulk reads — owned here so the capacity is
    /// reused across lines (a fresh Vec::new() per line paid a heap
    /// allocation per frame; microbench: 8190 us/line vs 0.23 us/line
    /// for a reused buffer)
    line_buf: Vec<u8>,
}

impl JsonPeer {
    fn new(peer: Peer, first: u8) -> JsonPeer {
        let timeout = peer
            .read_timeout()
            .ok()
            .flatten()
            .unwrap_or(Duration::from_secs(30));
        JsonPeer {
            // buffered: per-byte read() made every JSON line a syscall storm
            // (microbench: 23.45 us/line unbuffered vs 1.30 us/line buffered)
            peer: BufReader::with_capacity(1 << 16, peer),
            first: Some(first),
            done: false,
            timeout,
            first_deadline: None,
            line_buf: Vec::new(),
        }
    }
    /// No magic first byte: plain JSON lines from the first byte on (the
    /// operator control connection, F02).
    fn new_raw(peer: Peer) -> JsonPeer {
        let timeout = peer
            .read_timeout()
            .ok()
            .flatten()
            .unwrap_or(Duration::from_secs(30));
        JsonPeer {
            peer: BufReader::with_capacity(1 << 16, peer),
            first: None,
            done: false,
            timeout,
            first_deadline: None,
            line_buf: Vec::new(),
        }
    }
    /// read one JSON line; the stored first byte is prepended on the
    /// first call; returns Ok(false) on EOF.
    /// PERF: the old loop pulled ONE byte per `read()` — every byte of a
    /// 4 KB envelope paid a function call + branch on top of the
    /// BufReader (microbench: 3.32 us/line vs 0.33 us for a buffered
    /// line read, 10x). Bulk scans only re-enter the kernel when the
    /// buffer is drained; the scratch
    /// Vec is reused across lines so steady state is one scan + one
    /// memcpy (no per-line heap allocation).
    fn read_line_after(&mut self, line: &mut String) -> std::io::Result<bool> {
        // F07: bound each buffered chunk before growing the line.
        const MAX_LINE: usize = 16 * 1024 * 1024;
        if self.done {
            return Ok(false);
        }
        line.clear();
        if let Some(b) = self.first.take() {
            // the mode detector already consumed this byte (the '{' of
            // the first line) — splice it back in front of the rest
            line.push(b as char);
        }
        let deadline = self
            .first_deadline
            .unwrap_or_else(|| Instant::now() + self.timeout);
        let buf = &mut self.line_buf;
        buf.clear();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "json frame deadline exceeded")
                })?;
            self.peer.get_ref().set_read_timeout(Some(remaining))?;
            let available = self.peer.fill_buf()?;
            if available.is_empty() {
                self.done = true;
                line.push_str(&String::from_utf8_lossy(buf));
                return Ok(!line.is_empty());
            }
            let newline = available.iter().position(|b| *b == b'\n');
            let count = newline.unwrap_or(available.len());
            if line.len() + buf.len() + count > MAX_LINE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "json line exceeds the size limit",
                ));
            }
            buf.extend_from_slice(&available[..count]);
            self.peer.consume(count + usize::from(newline.is_some()));
            if newline.is_some() {
                line.push_str(&String::from_utf8_lossy(buf));
                return Ok(true);
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
    #[serde(default)]
    pub resources: resources::ResourceLimits,
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
    /// true = journal the full message body in the delivery audit
    /// events (`delivered`, `dtn_*`, `qos_throttled`). Absent/false =
    /// the audit carries `bytes` only — the payload is already on the
    /// wire, and re-serializing it into the ledger doubled its growth.
    /// Set true for a full forensic trail. (AMA_LEDGER_VERBOSE=1 is the
    /// env fallback when this field is absent.)
    #[serde(default)]
    pub ledger_verbose: Option<bool>,
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
    /// F01: TRUSTED capabilities declared by the OPERATOR in the manifest.
    /// When present, the agent's task cannot add capabilities — the kernel
    /// owns the grant.
    #[serde(default)]
    pub caps: Option<Vec<String>>,
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

#[cfg(test)]
mod ledger_perf_tests {
    use super::*;

    #[test]
    fn append_roundtrip_and_persistent_handle() {
        let dir = std::env::temp_dir().join(format!("ama-ledger-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.jsonl");
        let ledger = Ledger::open(&path).unwrap();
        for i in 0..100 {
            ledger.append("event", json!({"i": i})).unwrap();
        }
        // reopen from scratch: seq continues past the persisted lines
        let ledger2 = Ledger::open(&path).unwrap();
        let e = ledger2.append("event", json!({"i": 100})).unwrap();
        assert_eq!(e.seq, 101); // 100 persisted lines, this is the 101st event
                                // all 101 events parse back
        let all = ledger2.read_all();
        assert_eq!(all.len(), 101);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_survives_parent_dir_removal_midflight() {
        // the documented contract: the ledger must survive its parent dir
        // being removed mid-flight. The persistent handle makes this a
        // reopen-on-write-error path — this test IS the contract.
        let dir = std::env::temp_dir().join(format!("ama-ledger-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.jsonl");
        let ledger = Ledger::open(&path).unwrap();
        ledger.append("warmup", json!({"n": 0})).unwrap();
        // the handle is now open and cached; destroy the directory anyway
        std::fs::remove_dir_all(&dir).unwrap();
        let e = ledger.append("after_removal", json!({"n": 1})).unwrap();
        assert!(e.seq >= 1);
        // the file is back, and the event is IN it
        let all = Ledger::open(&path).unwrap().read_all();
        assert!(all.iter().any(|x| x.ev == "after_removal"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_checkpoint_matches_full_scan() {
        // the tail-scan must agree with a brute-force reverse scan for
        // LAST-wins semantics, across sizes that cross the 8 KB chunk
        let dir = std::env::temp_dir().join(format!("ama-ledger-cp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n_events in [5usize, 300, 1200] {
            let path = dir.join(format!("cp{n_events}.jsonl"));
            let ledger = Ledger::open(&path).unwrap();
            // checkpoints interleaved with noise; uin 3 checkpoints BEFORE uin 7
            for i in 0..n_events {
                ledger.append("noise", json!({"i": i})).unwrap();
                if i == n_events / 3 {
                    ledger
                        .append("checkpoint", json!({"uin": 3, "state": {"v": "old"}}))
                        .unwrap();
                }
                if i == n_events - 2 {
                    ledger
                        .append("checkpoint", json!({"uin": 3, "state": {"v": "latest"}}))
                        .unwrap();
                    ledger
                        .append("checkpoint", json!({"uin": 9, "state": {"v": "other"}}))
                        .unwrap();
                }
            }
            let got = ledger.last_checkpoint(3).unwrap();
            assert_eq!(got, json!({"v": "latest"}), "n_events={n_events}");
            assert_eq!(
                ledger.last_checkpoint(7),
                None,
                "uin without a checkpoint must be None, n_events={n_events}"
            );
        }
        // torn final line (crash mid-write): the tail-scan must skip it
        let path = dir.join("torn.jsonl");
        let ledger = Ledger::open(&path).unwrap();
        ledger
            .append("checkpoint", json!({"uin": 1, "state": {"v": "good"}}))
            .unwrap();
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"{\"seq\":99,\"ts_ms\":1,\"ev\":\"checkpo")
                .unwrap(); // torn
        }
        assert_eq!(ledger.last_checkpoint(1).unwrap(), json!({"v": "good"}));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod f10_authority_tests {
    //! F10 gates: operator authority is a credential + a pid check, not
    //! an OS identity; registration is authenticated in every lifecycle
    //! state; an omitted capability policy grants nothing.

    use super::*;

    fn temp_kernel(tag: &str) -> (Kernel, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ama-f10-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let k = Kernel::new(
            &dir.join("k.sock"),
            &dir.join("ledger.jsonl"),
            "/bin/true",
            150,
            5000,
            2,
        )
        .unwrap();
        (k, dir)
    }

    fn entry(
        pid: u32,
        manifest_caps: Option<Vec<String>>,
        token: &str,
        state: ProcState,
    ) -> ProcEntry {
        ProcEntry {
            uin: 7,
            name: "alice".into(),
            pid,
            caps: Vec::new(),
            tcp_addr: None,
            spawned_at: Instant::now(),
            manifest_caps,
            auth_token: Some(token.into()),
            granted: Vec::new(),
            revoked: Vec::new(),
            state,
            last_hb: Instant::now(),
            last_step: String::new(),
            last_phase: String::new(),
            stuck_sweeps: 0,
            respawns: 0,
            last_checkpoint: None,
            task_path: "tasks/alice.json".into(),
            out: None,
            wire: Wire::Json,
            isolation: None,
            priority: 5,
            dtn: false,
        }
    }

    fn insert(k: &Kernel, name: &str, e: ProcEntry) {
        let uin = e.uin;
        k.agents
            .lock()
            .unwrap()
            .insert(uin, Arc::new(Mutex::new(e)));
        k.by_name.lock().unwrap().insert(name.into(), uin);
    }

    /// the ctl socket's DOOR over a REAL socketpair (SO_PEERCRED reports
    /// the true peer pid there): a pid in the agent table is refused
    /// even when the uid matches.
    #[test]
    fn ctl_door_refuses_a_pid_that_belongs_to_a_spawned_agent() {
        let (k, _dir) = temp_kernel("door-agent");
        let (_a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        insert(
            &k,
            "alice",
            entry(std::process::id(), None, "t", ProcState::Running),
        );
        let err = Router::ctl_door(&k, &b).expect_err("own pid must be refused");
        assert!(err.contains("spawned agent"), "unexpected: {err}");
        assert!(k.is_agent_pid(std::process::id()));
    }

    #[test]
    fn ctl_door_admits_a_non_agent_same_uid_peer() {
        let (k, _dir) = temp_kernel("door-plain");
        let (_a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(!k.is_agent_pid(std::process::id()));
        Router::ctl_door(&k, &b).expect("a non-agent peer must pass the door");
    }

    fn read_reply(client: &std::os::unix::net::UnixStream) -> Value {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(client)
            .read_line(&mut line)
            .expect("reply line");
        serde_json::from_str(line.trim()).expect("reply json")
    }

    #[test]
    fn control_verbs_require_the_operator_credential() {
        let (mut k, _dir) = temp_kernel("ctl-token");
        k.operator_token = "s3cret-operator".into();
        insert(
            &k,
            "alice",
            entry(
                4242,
                Some(vec!["send:b".into()]),
                "agent-tok",
                ProcState::Running,
            ),
        );

        // wrong credential: refused, and NOTHING changes
        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let out = spawn_writer(k.ledger.clone(), Peer::Unix(server), Wire::Json);
        let v = json!({"kind": "ctl_grant", "name": "alice", "caps": ["send:x"],
                       "token": "wrong"});
        Router::handle_ctl_value(&k, &out, &v, Wire::Json).unwrap();
        let r = read_reply(&client);
        assert_eq!(r["kind"], "error", "wrong token must be refused: {r}");
        assert!(
            r["reason"].as_str().unwrap_or("").contains("token"),
            "reason: {r}"
        );
        assert!(!k.agents.lock().unwrap()[&7]
            .lock()
            .unwrap()
            .caps
            .contains(&"send:x".to_string()));
        let kinds: Vec<String> = k.ledger.read_all().iter().map(|e| e.ev.clone()).collect();
        assert!(
            kinds.contains(&"ctl_refused".to_string()),
            "journalled: {kinds:?}"
        );

        // correct credential: the same verb is served
        let (client2, server2) = std::os::unix::net::UnixStream::pair().unwrap();
        let out2 = spawn_writer(k.ledger.clone(), Peer::Unix(server2), Wire::Json);
        let v2 = json!({"kind": "ctl_grant", "name": "alice", "caps": ["send:x"],
                        "token": "s3cret-operator"});
        Router::handle_ctl_value(&k, &out2, &v2, Wire::Json).unwrap();
        let r2 = read_reply(&client2);
        assert_eq!(r2["kind"], "granted", "valid token must be served: {r2}");
        assert!(k.agents.lock().unwrap()[&7]
            .lock()
            .unwrap()
            .caps
            .contains(&"send:x".to_string()));
        let _ = std::fs::remove_dir_all(&_dir);
    }

    fn try_register(k: &Kernel, token: Option<&str>, caps: &[&str]) -> Result<(), String> {
        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let out = spawn_writer(k.ledger.clone(), Peer::Unix(server), Wire::Json);
        // keep `client` alive: a successful register enqueues the welcome
        // and the writer thread must be able to deliver it
        let _keep = client;
        let v = json!({"kind": "register", "name": "alice",
                       "caps": caps, "pid": 9999, "token": token});
        let mut my_uin: Option<u64> = None;
        Router::handle_value(k, &out, &v, &mut my_uin, Wire::Json)
    }

    #[test]
    fn registration_requires_the_instance_token_in_every_state() {
        let states = [
            ProcState::Registered,
            ProcState::Running,
            ProcState::Killed("boom".into()),
            ProcState::Dead,
            ProcState::Completed,
        ];
        for state in states {
            let (k, _dir) = temp_kernel(&format!("reg-{state:?}"));
            insert(
                &k,
                "alice",
                entry(
                    1111,
                    Some(vec!["send:b".into()]),
                    "real-token",
                    state.clone(),
                ),
            );
            for bad in [None, Some("forged"), Some("")] {
                let err = try_register(&k, bad, &["send:x"])
                    .expect_err(&format!("state {state:?}, token {bad:?} must be refused"));
                assert!(
                    err.contains("registration token"),
                    "state {state:?}, token {bad:?}: {err}"
                );
            }
            // correct token: refused ONLY where the contract says so —
            // a Running instance cannot be taken twice; every other state
            // admits the authenticated holder (that IS the restart path)
            let outcome = try_register(&k, Some("real-token"), &["send:x"]);
            if matches!(state, ProcState::Running) {
                let err = outcome.expect_err("a Running instance must not be taken twice");
                assert!(err.contains("already registered"), "{err}");
            } else {
                if let Err(e) = outcome {
                    panic!("the CURRENT token holder must be admitted in state {state:?}: {e}");
                }
                assert_eq!(
                    k.agents.lock().unwrap()[&7].lock().unwrap().caps,
                    vec!["send:b".to_string()],
                    "declared caps, not the task's request"
                );
            }
            let _ = std::fs::remove_dir_all(&_dir);
        }
    }

    #[test]
    fn omitted_manifest_policy_yields_no_grants() {
        let (k, _dir) = temp_kernel("caps-default");
        // manifest_caps: None (the policy key is absent) — the task still
        // ASKS for send:x; an omitted policy must grant nothing
        insert(
            &k,
            "alice",
            entry(2222, None, "real-token", ProcState::Killed("x".into())),
        );
        try_register(&k, Some("real-token"), &["send:x"])
            .expect("authenticated registration must succeed");
        let caps = k.agents.lock().unwrap()[&7].lock().unwrap().caps.clone();
        assert!(
            caps.is_empty(),
            "omitted policy must grant nothing, got {caps:?}"
        );

        // declared policy wins over what the task asks for
        insert(
            &k,
            "alice",
            entry(
                3333,
                Some(vec!["send:b".into()]),
                "real-token",
                ProcState::Killed("x".into()),
            ),
        );
        try_register(&k, Some("real-token"), &["send:x"])
            .expect("authenticated registration must succeed");
        let caps = k.agents.lock().unwrap()[&7].lock().unwrap().caps.clone();
        assert_eq!(
            caps,
            vec!["send:b".to_string()],
            "declared caps are the source"
        );
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn operator_grant_and_revocation_merge_survive_reregistration() {
        let (k, _dir) = temp_kernel("policy-merge");
        let mut e = entry(
            5555,
            Some(vec!["send:a".into()]),
            "real-token",
            ProcState::Killed("x".into()),
        );
        e.revoked = vec!["send:a".into()];
        e.granted = vec!["send:c".into()];
        insert(&k, "alice", e);
        try_register(&k, Some("real-token"), &["send:a", "send:x"]).unwrap();
        let caps = k.agents.lock().unwrap()[&7].lock().unwrap().caps.clone();
        assert!(
            caps.contains(&"send:c".to_string()),
            "grant survives: {caps:?}"
        );
        assert!(
            !caps.contains(&"send:a".to_string()),
            "revocation survives: {caps:?}"
        );
        assert!(
            !caps.contains(&"send:x".to_string()),
            "task caps are not grants: {caps:?}"
        );
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn credential_compare_is_exact() {
        assert!(credential_eq("abc", "abc"));
        assert!(!credential_eq("abc", "abd"));
        assert!(!credential_eq("abc", "abcd"));
        assert!(!credential_eq("", "x"));
        assert!(credential_eq("", ""));
    }
}

#[cfg(test)]
mod f03_outbound_tests {
    //! Item 3 gates: one writer per connection, bounded queue, framing
    //! preserved under concurrency, and a peer that stops reading can
    //! never stall the kernel.

    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader};
    use std::time::{Duration, Instant};

    fn temp_ledger(tag: &str) -> (Arc<Ledger>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ama-f03-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ledger = Arc::new(Ledger::open(&dir.join("l.jsonl")).unwrap());
        (ledger, dir)
    }

    fn outbound_no_writer(ledger: Arc<Ledger>, wire: Wire, cap: usize) -> Arc<Outbound> {
        Arc::new(Outbound {
            wire,
            cap,
            state: Mutex::new(OutboundState {
                frames: std::collections::VecDeque::new(),
                bytes: 0,
            }),
            idle: std::sync::Condvar::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
            budget: Mutex::new(Arc::new(resources::ByteBudget::new(cap))),
            ledger,
        })
    }

    /// The queue is a BOUND, not a wish: pushes stop (with an error)
    /// instead of growing memory, and they never block the caller —
    /// that is what keeps a stalled peer out of the sweep's way.
    #[test]
    fn outbound_queue_is_bounded_and_push_never_blocks() {
        let (ledger, _dir) = temp_ledger("bound");
        let out = outbound_no_writer(ledger.clone(), Wire::Json, 1024);
        let frame = vec![b'x'; 200];
        let started = Instant::now();
        let mut accepted = 0usize;
        for _ in 0..100 {
            if out.push(frame.clone()).is_ok() {
                accepted += 1;
            }
        }
        let elapsed = started.elapsed();
        assert!(
            accepted > 0 && accepted <= 5,
            "cap 1024 / 200B frames => at most 5 accepted, got {accepted}"
        );
        assert!(
            elapsed < Duration::from_millis(50),
            "push must never block on a slow peer (took {elapsed:?})"
        );
        // queue-full is DEFINED: refuse, close, journal
        assert!(out.is_closed(), "queue-full closes the connection");
        assert!(out.push(frame).is_err(), "closed queue refuses frames");
        let kinds: Vec<String> = ledger.read_all().iter().map(|e| e.ev.clone()).collect();
        assert!(
            kinds.contains(&"outbound_queue_full".to_string()),
            "journal: {kinds:?}"
        );
    }

    /// Concurrent producers (routing, QoS pump, replies, DTN flush — the
    /// real kernel callers) never interleave: every frame decodes on its
    /// own wire and per-producer order is preserved (FIFO queue).
    fn framing_case(wire: Wire, tag: &str) {
        let (ledger, _dir) = temp_ledger(tag);
        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let out = spawn_writer(ledger, Peer::Unix(server), wire);

        let mut producers = Vec::new();
        for t in 0..4u64 {
            let o = Arc::clone(&out);
            producers.push(std::thread::spawn(move || {
                for i in 0..25u64 {
                    // `text` (not `i`): the proto encoder only knows the
                    // envelope's real fields and refuses unknown ones
                    o.send(&json!({"kind": "note", "from": t, "text": i.to_string()}))
                        .expect("enqueue must succeed well under the cap");
                }
            }));
        }
        for h in producers {
            h.join().unwrap();
        }

        let mut per_producer: HashMap<u64, Vec<u64>> = HashMap::new();
        // ONE reader per wire for the whole session: a fresh BufReader
        // per line would swallow (and discard) the bytes buffered
        // beyond it — a classic self-inflicted hang
        let mut collect = |v: Value| {
            assert_eq!(v["kind"], "note");
            let from = v["from"].as_u64().unwrap();
            let i: u64 = v["text"].as_str().unwrap().parse().unwrap();
            per_producer.entry(from).or_default().push(i);
        };
        match wire {
            Wire::Json => {
                let mut reader = BufReader::new(client);
                for _ in 0..100 {
                    let mut line = String::new();
                    reader.read_line(&mut line).expect("JSON line");
                    collect(serde_json::from_str(line.trim()).expect("JSON line must parse whole"));
                }
            }
            Wire::Msgpack => {
                let mut r = client;
                for _ in 0..100 {
                    collect(read_msgpack_frame(&mut r).expect("msgpack frame intact"));
                }
            }
            Wire::Proto => {
                let mut r = client;
                for _ in 0..100 {
                    collect(read_proto_frame(&mut r).expect("proto frame intact"));
                }
            }
        }
        for (producer, seq) in &per_producer {
            let mut sorted = seq.clone();
            sorted.sort();
            assert_eq!(
                seq, &sorted,
                "producer {producer}: FIFO order must survive concurrency"
            );
        }
        assert_eq!(per_producer.len(), 4, "all producers' frames arrived");
    }

    #[test]
    fn json_frames_never_interleave_under_concurrency() {
        framing_case(Wire::Json, "json");
    }

    #[test]
    fn msgpack_frames_never_interleave_under_concurrency() {
        framing_case(Wire::Msgpack, "msgpack");
    }

    #[test]
    fn proto_frames_never_interleave_under_concurrency() {
        framing_case(Wire::Proto, "proto");
    }

    /// A peer that stops reading: the socket buffer fills, the writer
    /// hits its deadline, and the connection is closed — while every
    /// kernel-side push in the meantime returned immediately. Nothing
    /// about this peer reaches the sweep, `ama ps`, or other agents.
    #[test]
    fn a_peer_that_stops_reading_is_disconnected_without_stalling_the_kernel() {
        let (ledger, _dir) = temp_ledger("slow");
        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let out = spawn_writer(ledger.clone(), Peer::Unix(server), Wire::Json);

        // 128 x 8 KiB = 1 MiB queued: over the socket buffer, under the
        // 4 MiB cap — the writer will block on write and hit the deadline
        let frame = json!({"kind": "note", "text": "x".repeat(8 * 1024)});
        let started = Instant::now();
        for _ in 0..128 {
            out.send(&frame).expect("under cap: must not block");
        }
        let enqueue_time = started.elapsed();
        assert!(
            enqueue_time < Duration::from_millis(200),
            "kernel-side enqueue must not wait on the stalled peer ({enqueue_time:?})"
        );

        // the writer's deadline closes it (the client never reads)
        let deadline = Instant::now() + Duration::from_millis(3000);
        while !out.is_closed() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            out.is_closed(),
            "write deadline must release the writer and close the connection"
        );
        let kinds: Vec<String> = ledger.read_all().iter().map(|e| e.ev.clone()).collect();
        assert!(
            kinds.contains(&"outbound_write_failed".to_string()),
            "journal must record why: {kinds:?}"
        );
        drop(client);
    }
}

#[cfg(test)]
mod f04_ledger_tail_tests {
    //! Item 4 gates: a crash-torn tail is repaired at EXACT byte
    //! boundaries — with or without a trailing newline — valid records
    //! are preserved, a repair failure is an error (never a silent
    //! "repaired"), and replay still finds the last checkpoint.

    use super::*;
    use std::io::Write;

    const VALID1: &str = r#"{"seq":1,"ts_ms":10,"ev":"spawned","detail":{"uin":7}}"#;
    const VALID2: &str = r#"{"seq":2,"ts_ms":20,"ev":"completed","detail":{"uin":7}}"#;

    fn mk(tag: &str, bytes: &[u8]) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ama-f04-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("l.jsonl");
        std::fs::write(&path, bytes).unwrap();
        (path, dir)
    }

    fn text(path: &std::path::Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    /// The case the old repair got wrong: a torn record WITHOUT a
    /// trailing newline. `line.len() + 1` overshot and deleted the
    /// PREVIOUS record's newline; the exact-boundary cut keeps it, so
    /// the next append cannot concatenate two records on one line.
    #[test]
    fn torn_tail_without_newline_cuts_exactly_at_the_boundary() {
        let bytes = format!("{VALID1}\n{{\"seq\":2,\"ts_ms\":20,\"ev\":\"checkp").into_bytes();
        let (path, dir) = mk("no-nl", &bytes);

        Ledger::open(&path).expect("repair must succeed");
        assert_eq!(
            text(&path),
            format!("{VALID1}\n"),
            "valid record + its newline intact"
        );

        let l = Ledger::open(&path).expect("reopen after repair");
        let e = l.append("x", json!({"i": 9})).expect("append works");
        assert_eq!(e.seq, 2, "the repaired ledger counts ONE surviving record");
        let all = l.read_all();
        assert_eq!(all.len(), 2, "both records parse independently: {all:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Defensive case the review also asks for: garbage that DOES end in
    /// a newline (something wrote a non-record line) is cut at ITS start.
    #[test]
    fn tail_with_trailing_newline_is_cut_at_the_record_start() {
        let bytes = format!("{VALID1}\nP@RTIAL-GARBAGE\n").into_bytes();
        let (path, dir) = mk("with-nl", &bytes);
        Ledger::open(&path).expect("repair must succeed");
        assert_eq!(text(&path), format!("{VALID1}\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_ledger_is_a_noop() {
        let (path, dir) = mk("empty", b"");
        let l = Ledger::open(&path).expect("empty ledger opens");
        let e = l.append("x", json!({})).unwrap();
        assert_eq!(e.seq, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A crash mid-first-record: nothing is valid, the file becomes
    /// empty rather than keeping one unparseable line.
    #[test]
    fn single_partial_record_truncates_to_empty() {
        let (path, dir) = mk("single", b"{\"seq\":1,\"ts_ms\":1,\"ev\":");
        Ledger::open(&path).expect("repair must succeed");
        assert_eq!(text(&path), "", "no valid prefix survives");
        let l = Ledger::open(&path).unwrap();
        let e = l.append("x", json!({})).unwrap();
        assert_eq!(e.seq, 1, "seq counting restarts from the empty file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The crash landed BETWEEN the line write and the newline write:
    /// the record itself is complete and must be KEPT (with its newline
    /// restored) — dropping it would lose a committed event.
    #[test]
    fn complete_record_missing_final_newline_is_recovered() {
        let bytes = format!("{VALID1}\n{VALID2}").into_bytes();
        let (path, dir) = mk("reco", &bytes);
        Ledger::open(&path).expect("repair must succeed");
        assert_eq!(
            text(&path),
            format!("{VALID1}\n{VALID2}\n"),
            "the complete record is kept and its newline restored"
        );
        let l = Ledger::open(&path).unwrap();
        assert_eq!(l.read_all().len(), 2, "both records parse independently");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The backward scan reads 8 KiB chunks — a record far larger than
    /// one chunk must still have its boundary found exactly.
    #[test]
    fn large_record_crossing_the_scan_chunk_is_cut_exactly() {
        let big = format!(
            r#"{{"seq":1,"ts_ms":10,"ev":"note","detail":{{"blob":"{}"}}}}"#,
            "y".repeat(40_000)
        );
        let bytes = format!("{big}\n{{\"seq\":2,\"ev\":torn").into_bytes();
        let (path, dir) = mk("large", &bytes);
        Ledger::open(&path).expect("repair must succeed");
        assert_eq!(
            text(&path).len(),
            big.len() + 1,
            "boundary exactly after the 40 KiB record"
        );
        let l = Ledger::open(&path).unwrap();
        assert_eq!(l.read_all().len(), 1, "the large record survives whole");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Replay after a torn tail: the last committed checkpoint must
    /// still be the one recovery resumes from.
    #[test]
    fn replay_after_repair_finds_the_last_checkpoint() {
        let dir = std::env::temp_dir().join(format!("ama-f04-replay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("l.jsonl");
        {
            let l = Ledger::open(&path).unwrap();
            l.append("checkpoint", json!({"uin": 7, "state": {"n": 0}}))
                .unwrap();
            l.append("checkpoint", json!({"uin": 7, "state": {"n": 1}}))
                .unwrap();
        }
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            write!(f, "{{\"seq\":3,\"ts_ms\":99,\"ev\":\"checkp").unwrap();
        }
        let l = Ledger::open(&path).expect("repair before replay");
        let last = l
            .last_checkpoint(7)
            .expect("checkpoint survives the repair");
        let n = last["state"]["n"].as_u64().or(last["n"].as_u64());
        assert_eq!(n, Some(1), "replay resumes from n=1, got {last}");
        let all = l.read_all();
        assert_eq!(all.len(), 2, "every retained record parses: {all:?}");
        assert_eq!(all.last().unwrap().ev, "checkpoint");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A repair that cannot be performed must FAIL the open — the old
    /// code ignored set_len's result and printed "torn tail repaired"
    /// unconditionally, i.e. a no-op failure reported success.
    #[test]
    fn repair_failure_is_an_error_never_a_silent_success() {
        let dir = std::env::temp_dir().join(format!("ama-f04-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // a DIRECTORY as the ledger: scanning it cannot succeed, so the
        // open must surface the error instead of pretending to repair
        let res = Ledger::open(&dir);
        assert!(res.is_err(), "a failed repair must be an Err, not Ok");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod f05_launch_deadline_tests {
    //! Item 5 gates: a pending launch (initial OR replacement) that
    //! never registers is judged by the deadline, and a stale
    //! connection close cannot restart a pending launch.

    use super::*;

    fn temp_kernel(tag: &str) -> (Kernel, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ama-f05-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let k = Kernel::new(
            &dir.join("k.sock"),
            &dir.join("ledger.jsonl"),
            "/bin/true", // respawn's spawn "succeeds" without real agents
            150,
            5000,
            2,
        )
        .unwrap();
        (k, dir)
    }

    /// A pending entry: no connection, a pid that cannot signal
    /// anything real (u32::MAX is outside the default pid_max), and a
    /// launch time the test controls.
    fn pending(state: ProcState, spawned_ago: Duration) -> ProcEntry {
        ProcEntry {
            uin: 7,
            name: "wedged".into(),
            pid: u32::MAX,
            caps: Vec::new(),
            tcp_addr: None,
            spawned_at: Instant::now() - spawned_ago,
            manifest_caps: Some(Vec::new()),
            auth_token: Some("tok".into()),
            granted: Vec::new(),
            revoked: Vec::new(),
            state,
            last_hb: Instant::now(),
            last_step: String::new(),
            last_phase: String::new(),
            stuck_sweeps: 0,
            respawns: 0,
            last_checkpoint: None,
            task_path: "tasks/wedged.json".into(),
            out: None,
            wire: Wire::Json,
            isolation: None,
            priority: 5,
            dtn: false,
        }
    }

    fn insert(k: &Kernel, e: ProcEntry) {
        let uin = e.uin;
        k.agents
            .lock()
            .unwrap()
            .insert(uin, Arc::new(Mutex::new(e)));
        k.by_name.lock().unwrap().insert("wedged".into(), uin);
    }

    fn kinds(k: &Kernel) -> Vec<String> {
        k.ledger.read_all().iter().map(|e| e.ev.clone()).collect()
    }

    fn reason_of(k: &Kernel, ev: &str) -> Option<String> {
        k.ledger.read_all().iter().find(|e| e.ev == ev).map(|e| {
            e.detail
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        })
    }

    /// Grace first: a fresh pending launch is NOT judged before its
    /// per-launch deadline (spawned_at + 3x hb, floor 10s).
    #[test]
    fn a_fresh_pending_launch_is_not_judged() {
        let (k, _dir) = temp_kernel("grace");
        insert(&k, pending(ProcState::Starting, Duration::from_millis(0)));
        k.sweep();
        let _agents = k.agents.lock().unwrap();
        let e = _agents[&7].lock().unwrap();
        assert!(
            matches!(e.state, ProcState::Starting),
            "untouched: {:?}",
            e.state
        );
        assert_eq!(e.respawns, 0);
        assert!(
            kinds(&k).is_empty(),
            "no judgement journaled: {:?}",
            kinds(&k)
        );
    }

    /// THE FIX: a REPLACEMENT launch (state `Starting`, no connection,
    /// spawned_at reset by respawn) that never registers hits the SAME
    /// deadline the initial launch does — killed with the reason and
    /// respawned within budget. Before this change respawn left the
    /// entry in `Killed`, whose branch the deadline never matched: the
    /// replacement escaped it forever.
    #[test]
    fn a_replacement_that_never_registers_hits_the_deadline() {
        let (k, _dir) = temp_kernel("replacement");
        insert(&k, pending(ProcState::Starting, Duration::from_secs(60)));
        k.sweep();
        let ks = kinds(&k);
        assert!(ks.contains(&"killed".to_string()), "journaled: {ks:?}");
        assert!(
            reason_of(&k, "killed")
                .unwrap()
                .contains("registration deadline"),
            "reason: {:?}",
            reason_of(&k, "killed")
        );
        // the failed launch CONSUMED budget and the retry is pending
        let _agents = k.agents.lock().unwrap();
        let e = _agents[&7].lock().unwrap();
        assert_eq!(e.respawns, 1, "each failed launch counts once");
        assert!(
            matches!(e.state, ProcState::Starting),
            "retry is pending: {:?}",
            e.state
        );
        assert!(e.out.is_none(), "a pending launch has no connection");
    }

    /// The initial launch takes the same path (both pending kinds are
    /// covered by one branch — this pins the OTHER caller of it).
    #[test]
    fn an_initial_launch_that_never_registers_hits_the_deadline() {
        let (k, _dir) = temp_kernel("initial");
        // spawn_agent_opts starts entries at Starting; age it as if the
        // boot wedged for a minute
        insert(&k, pending(ProcState::Starting, Duration::from_secs(60)));
        k.sweep();
        assert!(
            kinds(&k).contains(&"killed".to_string())
                && kinds(&k).contains(&"respawned".to_string()),
            "killed + respawned: {:?}",
            kinds(&k)
        );
    }

    /// End-to-end through the REAL respawn path (not a hand-built
    /// state): respawn produces a pending launch, and only after the
    /// deadline does the sweep judge it.
    #[test]
    fn respawn_output_is_pending_until_its_deadline() {
        let (k, _dir) = temp_kernel("respawn");
        let mut e = pending(
            ProcState::Killed("process exited".into()),
            Duration::from_secs(60),
        );
        e.out = None;
        insert(&k, e);

        k.respawn(7); // the real replacement launch
        {
            let _agents = k.agents.lock().unwrap();
            let e = _agents[&7].lock().unwrap();
            assert!(
                matches!(e.state, ProcState::Starting),
                "respawn is PENDING: {:?}",
                e.state
            );
            assert!(e.out.is_none(), "pending launches hold no connection");
            assert_eq!(e.respawns, 1);
        }
        // fresh launch time: not judged yet
        k.agents.lock().unwrap()[&7].lock().unwrap().spawned_at = Instant::now();
        k.sweep();
        assert!(
            !kinds(&k).contains(&"killed".to_string()),
            "grace: {:?}",
            kinds(&k)
        );
        // ...and judged once the deadline passes
        k.agents.lock().unwrap()[&7].lock().unwrap().spawned_at =
            Instant::now() - Duration::from_secs(60);
        k.sweep();
        assert!(
            kinds(&k).contains(&"killed".to_string()),
            "deadline: {:?}",
            kinds(&k)
        );
    }

    /// Stale-EOF protection (the reason the old code kept `Killed`):
    /// the OLD instance's connection closing while its replacement is
    /// pending must NOT journal a crash or trigger a second respawn.
    #[test]
    fn a_stale_connection_close_does_not_restart_a_pending_launch() {
        let (k, _dir) = temp_kernel("stale-eof");
        insert(&k, pending(ProcState::Starting, Duration::from_millis(0)));
        k.connection_closed(Some(7));
        let ks = kinds(&k);
        assert!(ks.is_empty(), "no crash, no respawn: {ks:?}");
        let _agents = k.agents.lock().unwrap();
        let e = _agents[&7].lock().unwrap();
        assert!(
            matches!(e.state, ProcState::Starting),
            "untouched: {:?}",
            e.state
        );
        assert_eq!(e.respawns, 0, "no duplicate respawn");
    }

    /// ...while a LIVE agent's connection closing still fails fast.
    #[test]
    fn a_live_connection_close_fails_fast_to_a_respawn() {
        let (k, _dir) = temp_kernel("live-eof");
        insert(&k, pending(ProcState::Running, Duration::from_secs(60)));
        k.connection_closed(Some(7));
        let ks = kinds(&k);
        assert!(ks.contains(&"crashed".to_string()), "journaled: {ks:?}");
        assert!(ks.contains(&"respawned".to_string()), "respawned: {ks:?}");
        let _agents = k.agents.lock().unwrap();
        let e = _agents[&7].lock().unwrap();
        assert!(
            matches!(e.state, ProcState::Starting),
            "retry pending: {:?}",
            e.state
        );
        assert_eq!(e.respawns, 1);
    }

    /// The process table tells the operator a launch is pending.
    #[test]
    fn ps_reports_a_pending_launch_as_starting() {
        let (k, _dir) = temp_kernel("ps");
        insert(&k, pending(ProcState::Starting, Duration::from_millis(0)));
        let dump = k.ps_dump();
        assert_eq!(dump[0]["state"], "starting");
    }
}

#[cfg(test)]
mod enterprise_tests;
