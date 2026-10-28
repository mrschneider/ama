//! QoS (scheduling + admission + accounting) and DTN (delay-tolerant
//! store-and-forward) message delivery.
//!
//! QoS is a real scheduling stack, not a single throttle:
//!
//! - **Weighted Fair Queueing (WFQ)** — when the kernel's delivery link
//!   is backlogged, pending messages are served in order of their
//!   virtual finish tag `F = max(V, F_flow) + len / weight`, with the
//!   virtual clock `V` advancing by `len / capacity` per transmission
//!   (self-clocked / start-time fair queueing). An agent with weight 3
//!   gets three times the link of an agent with weight 1 — the classic
//!   WFQ guarantee, checked by a unit test and by the ledger order.
//! - **Admission control** — a byte-rate token bucket PER SENDER
//!   (`max_bytes_per_sec`) plus a hard bound on the delivery queue
//!   (`max_queue_bytes`). A refused message is journaled
//!   `admission_denied`; it is never silently dropped and never
//!   queued "to be safe".
//! - **Bandwidth accounting** — bytes sent/delivered per agent, queue
//!   depth and peak depth, throttled/denied counters, exposed on the
//!   control channel (`ama qos`) and journaled as `qos_accounting`.
//!
//! WFQ only means something if the link can actually be short of
//! capacity, so the kernel models one: `link_bytes_per_tick` is the
//! budget the delivery link may carry per watchdog tick (unlimited by
//! default). A message that fits the remaining budget and finds the
//! queue empty is written straight through (work-conserving, no added
//! latency); anything else waits in the WFQ queue. With a finite link
//! the backlog is real, and the virtual-finish-tag order is what the
//! destination actually observes.
//!
//! QoS: every agent declares `qos: { priority, max_msgs_per_sec }` in
//! the manifest. Delivery is scheduled by priority (0 = highest); each
//! SENDER gets a token bucket so a bursty agent cannot starve the
//! others. Refused sends are journaled as `qos_throttled` — never
//! silently dropped (same rule as `cap_denied`).
//!
//! DTN ROUTING (multi-hop custody):
//!
//! - **Relays** — a manifest `routes` entry says "to reach `far`, hand
//!   the bundle to `relay`". The kernel forwards custody to the relay as
//!   a `bundle` frame; the relay re-emits it with the `relay` envelope
//!   and the kernel consults the table again. Every hop increments
//!   `hops`; at `max_hops` the bundle is dropped with `dtn_hop_limit`
//!   journaled (no silent loops, no unbounded storage).
//! - **Custody acknowledgements** — a relay that accepts custody sends
//!   `custody_ack { bundle_id }`; the kernel then DELETES its own copy
//!   (custody transferred, exactly-once) and journals `dtn_custody_ack`.
//! - **Fragmentation / reassembly** — a body larger than
//!   `max_bundle_bytes` is split into numbered fragments, each routed
//!   independently. The receiving kernel holds them and delivers ONE
//!   reassembled message when the set is complete (`dtn_reassembled`);
//!   an incomplete set expires like any other bundle.
//!
//! DTN: a send to an agent that is not currently connected (dead,
//! killed, or pre-registered) is NOT an error when DTN is enabled:
//! the kernel takes CUSTODY of the message, stores it with a TTL, and
//! delivers it when the target registers again. Custody transfers are
//! journaled (`dtn_stored` / `dtn_delivered` / `dtn_expired`) — the
//! sender's `sent` ack already returned, so the kernel owns the bundle
//! until delivery or expiry. This is the Bundle-protocol idea
//! (custody transfer + store-and-forward) reduced to what the ama
//! kernel can honestly implement.

use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};

/// Priority ordering: LOWER number = delivered EARLIER. BinaryHeap is a
/// max-heap, so the Ord is INVERTED on purpose.
#[derive(Debug, Clone)]
pub struct DtnBundle {
    pub from: u64,
    pub to: u64,
    pub body: Value,
    pub priority: u8,
    pub stored_at: Instant,
    pub expires_at: Instant,
    /// stable id of the LOGICAL bundle: every fragment of one message
    /// shares it, and custody acks name it
    pub bundle_id: u64,
    /// hops already travelled (0 = originated here)
    pub hops: u8,
    /// when set, this bundle is a custody hand-off for a relay
    pub next_hop: Option<u64>,
    /// fragment coordinates when the body was split
    pub frag: Option<FragMeta>,
}

/// Where a fragment sits in its logical bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragMeta {
    pub id: u64,
    pub index: u32,
    pub total: u32,
}

/// Partially received logical bundles (fragments waiting for the rest).
#[derive(Default)]
pub struct ReassemblyStore {
    parts: HashMap<u64, (u32, Vec<Option<Value>>, Instant)>,
}

impl ReassemblyStore {
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Take one fragment in. Returns the full body once every fragment
    /// of that logical bundle has arrived, None while still incomplete.
    pub fn insert(&mut self, meta: &FragMeta, body: Value) -> Option<Value> {
        let entry = self
            .parts
            .entry(meta.id)
            .or_insert_with(|| (meta.total, vec![None; meta.total as usize], Instant::now()));
        if entry.1.len() != meta.total as usize {
            // a bundle id reused with a different fragment count: drop the
            // stale assembly rather than mixing two messages
            *entry = (meta.total, vec![None; meta.total as usize], Instant::now());
        }
        let idx = meta.index as usize;
        if idx < entry.1.len() {
            entry.1[idx] = Some(body);
        }
        let complete = entry.1.iter().all(|p| p.is_some());
        if complete {
            let (_, parts, _) = self.parts.remove(&meta.id)?;
            let assembled: Vec<Value> = parts.into_iter().flatten().collect();
            return Some(Value::Array(assembled));
        }
        None
    }

    /// Assemblies that have been waiting longer than `ttl`.
    pub fn sweep(&mut self, ttl: Duration) -> Vec<u64> {
        let now = Instant::now();
        let stale: Vec<u64> = self
            .parts
            .iter()
            .filter(|(_, (_, _, at))| now.duration_since(*at) > ttl)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale {
            self.parts.remove(id);
        }
        stale
    }
}

impl DtnBundle {
    pub fn new(from: u64, to: u64, body: Value, priority: u8, ttl: Duration) -> Self {
        Self {
            from,
            to,
            body,
            priority,
            stored_at: Instant::now(),
            expires_at: Instant::now() + ttl,
            bundle_id: 0,
            hops: 0,
            next_hop: None,
            frag: None,
        }
    }
}

impl PartialEq for DtnBundle {
    fn eq(&self, other: &Self) -> bool {
        self.bundle_id == other.bundle_id
            && self.priority == other.priority
            && self.stored_at == other.stored_at
            && self.frag == other.frag
    }
}
impl Eq for DtnBundle {}
impl PartialOrd for DtnBundle {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for DtnBundle {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // invert: min-priority first, then FIFO within a priority
        other
            .priority
            .cmp(&self.priority)
            .then(other.stored_at.cmp(&self.stored_at))
    }
}

/// Per-SENDER token bucket: `max_msgs_per_sec` refill per second,
/// capacity = the same number (a full second of credit max).
#[derive(Debug)]
pub struct TokenBucket {
    pub rate: u32,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate: u32) -> Self {
        Self {
            rate,
            tokens: rate as f64,
            last: Instant::now(),
        }
    }

    /// Take one token; false = the sender is over its rate (throttle).
    pub fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate as f64).min(self.rate as f64);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Weighted Fair Queueing scheduler (start-time fair queueing).
///
/// Each FLOW is a sender UIN with a declared weight. A message of
/// `len` bytes from flow `f` gets the virtual finish tag
/// `F = max(V, F_f) + len / w_f`; the smallest tag is served first.
/// The virtual clock advances by `len / capacity` for every byte the
/// link actually serves, so a flow that was idle cannot bank credit it
/// never earned (no tag below the current virtual time).
#[derive(Debug)]
pub struct WfqScheduler {
    /// bytes the link serves per virtual tick (the C in len/C)
    capacity: f64,
    virtual_time: f64,
    weights: HashMap<u64, f64>,
    last_finish: HashMap<u64, f64>,
}

impl WfqScheduler {
    pub fn new(capacity: f64) -> Self {
        Self {
            capacity: if capacity > 0.0 { capacity } else { 1.0 },
            virtual_time: 0.0,
            weights: HashMap::new(),
            last_finish: HashMap::new(),
        }
    }

    /// Declare a flow's weight (1.0 = the reference share).
    pub fn set_weight(&mut self, flow: u64, weight: f64) {
        let w = if weight > 0.0 { weight } else { 1.0 };
        self.weights.insert(flow, w);
    }

    pub fn weight_of(&self, flow: u64) -> f64 {
        self.weights.get(&flow).copied().unwrap_or(1.0)
    }

    /// Compute the virtual finish tag for a message without committing
    /// to it (used by tests) — `commit` advances the flow's tag.
    pub fn peek_tag(&self, flow: u64, bytes: usize) -> f64 {
        let w = self.weight_of(flow);
        let start = self
            .last_finish
            .get(&flow)
            .copied()
            .unwrap_or(self.virtual_time)
            .max(self.virtual_time);
        start + bytes as f64 / w
    }

    /// Assign the finish tag for a message about to be queued.
    pub fn tag(&mut self, flow: u64, bytes: usize) -> f64 {
        let f = self.peek_tag(flow, bytes);
        self.last_finish.insert(flow, f);
        f
    }

    /// The link served `bytes`: advance the virtual clock.
    pub fn serve(&mut self, bytes: usize) {
        self.virtual_time += bytes as f64 / self.capacity;
    }

    pub fn virtual_time(&self) -> f64 {
        self.virtual_time
    }
}

/// Byte-rate token bucket (buckets in BYTES, not messages): the
/// admission-control form of a rate limit.
#[derive(Debug)]
pub struct ByteBucket {
    pub rate: u32,
    tokens: f64,
    last: Instant,
}

impl ByteBucket {
    pub fn new(rate: u32) -> Self {
        Self {
            rate,
            tokens: rate as f64,
            last: Instant::now(),
        }
    }

    /// Reserve `bytes`; false = the reservation is over the rate.
    pub fn take(&mut self, bytes: usize) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        let cap = self.rate as f64;
        self.tokens = (self.tokens + elapsed * cap).min(cap);
        let want = bytes as f64;
        if self.tokens >= want {
            self.tokens -= want;
            true
        } else {
            false
        }
    }

    /// Tokens actually available right now (for stats).
    pub fn available(&self) -> f64 {
        self.tokens
    }
}

/// Admission control: may this message enter the kernel's delivery path
/// at all? Two independent limits, both journaled when they refuse:
/// per-sender byte rate, and the global queue bound.
#[derive(Debug)]
pub struct AdmissionPolicy {
    /// per-sender byte rate (None = unlimited)
    pub max_bytes_per_sec: Option<u32>,
    /// hard bound on the bytes the kernel may hold in its delivery queue
    pub max_queue_bytes: u64,
    buckets: HashMap<u64, ByteBucket>,
}

impl AdmissionPolicy {
    pub fn new(max_bytes_per_sec: Option<u32>, max_queue_bytes: u64) -> Self {
        Self {
            max_bytes_per_sec,
            max_queue_bytes,
            buckets: HashMap::new(),
        }
    }

    /// Per-sender override from the agent's manifest (`qos.max_bytes_per_sec`).
    pub fn set_sender_rate(&mut self, uin: u64, rate: Option<u32>) {
        match rate {
            Some(r) if r > 0 => {
                self.buckets.insert(uin, ByteBucket::new(r));
            }
            _ => {
                self.buckets.remove(&uin);
            }
        }
    }

    /// Admit a message of `bytes` from `from`, given the queue currently
    /// holds `queued` bytes. `Err` carries the reason to journal.
    pub fn admit(&mut self, from: u64, bytes: usize, queued: u64) -> Result<(), String> {
        if queued + bytes as u64 > self.max_queue_bytes {
            return Err(format!(
                "admission: delivery queue at capacity ({queued}+{bytes} > {} bytes)",
                self.max_queue_bytes
            ));
        }
        // the sender's own rate: explicit per-agent value wins, else the
        // kernel-wide default
        if let Some(b) = self.buckets.get_mut(&from) {
            if !b.take(bytes) {
                return Err(format!(
                    "admission: sender {from} over its byte rate ({} B/s, {} B available)",
                    b.rate,
                    b.available() as u64
                ));
            }
            return Ok(());
        }
        if let Some(rate) = self.max_bytes_per_sec {
            let b = self
                .buckets
                .entry(from)
                .or_insert_with(|| ByteBucket::new(rate));
            if !b.take(bytes) {
                return Err(format!(
                    "admission: sender {from} over the kernel byte rate ({rate} B/s)"
                ));
            }
        }
        Ok(())
    }
}

/// Bandwidth accounting: what the link actually carried, per agent.
#[derive(Debug, Default, Clone)]
pub struct Accounting {
    /// sender UIN -> bytes accepted into the delivery path
    pub bytes_in: HashMap<u64, u64>,
    /// destination UIN -> bytes delivered
    pub bytes_out: HashMap<u64, u64>,
    pub msgs_accepted: u64,
    pub msgs_delivered: u64,
    pub msgs_throttled: u64,
    pub msgs_denied: u64,
    pub msgs_scheduled: u64,
    pub queued_bytes: u64,
    pub peak_queued_bytes: u64,
    pub bytes_dropped: u64,
}

impl Accounting {
    pub fn snapshot(&self) -> Value {
        let mut per_sender: Vec<Value> = self
            .bytes_in
            .iter()
            .map(|(uin, b)| {
                serde_json::json!({"uin": uin, "bytes_in": b,
                "bytes_out": self.bytes_out.get(uin).copied().unwrap_or(0)})
            })
            .collect();
        per_sender.sort_by_key(|v| v["uin"].as_u64().unwrap_or(0));
        serde_json::json!({
            "msgs_accepted": self.msgs_accepted,
            "msgs_delivered": self.msgs_delivered,
            "msgs_throttled": self.msgs_throttled,
            "msgs_denied": self.msgs_denied,
            "msgs_scheduled": self.msgs_scheduled,
            "queued_bytes": self.queued_bytes,
            "peak_queued_bytes": self.peak_queued_bytes,
            "bytes_dropped": self.bytes_dropped,
            "per_agent": per_sender,
        })
    }
}

/// A message waiting in the kernel's delivery queue, ordered by its WFQ
/// virtual finish tag.
#[derive(Debug, Clone)]
pub struct PendingMsg {
    pub from: u64,
    pub to: u64,
    pub body: Value,
    pub bytes: usize,
    pub tag: f64,
    pub seq: u64,
}

impl PartialEq for PendingMsg {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}
impl Eq for PendingMsg {}
impl PartialOrd for PendingMsg {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for PendingMsg {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.tag
            .total_cmp(&other.tag)
            .then(self.seq.cmp(&other.seq))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in b.chunks(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}

/// Split a body into numbered fragments whose encoded payload is at most
/// `max_bytes` each. One fragment means "no fragmentation needed".
pub fn fragment_body(
    body: &Value,
    max_bytes: usize,
    bundle_id: u64,
) -> Result<Vec<(FragMeta, Value)>, String> {
    let raw = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let encoded = hex_encode(&raw);
    let chunk = max_bytes.max(2);
    let pieces: Vec<&str> = encoded
        .as_bytes()
        .chunks(chunk)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    let total = pieces.len().max(1) as u32;
    Ok(pieces
        .into_iter()
        .enumerate()
        .map(|(i, piece)| {
            (
                FragMeta {
                    id: bundle_id,
                    index: i as u32,
                    total,
                },
                serde_json::json!({"__frag_data": piece}),
            )
        })
        .collect())
}

/// Put the fragments of one logical bundle back together.
pub fn reassemble_parts(mut parts: Vec<Value>) -> Option<Value> {
    let mut hex = String::new();
    for p in parts.drain(..) {
        hex.push_str(p.get("__frag_data")?.as_str()?);
    }
    let bytes = hex_decode(&hex)?;
    serde_json::from_slice(&bytes).ok()
}

/// The kernel's delivery subsystem. `max_bundles` bounds custody memory:
/// the kernel is not a mailbox of unbounded size.
pub struct DeliverySystem {
    /// destination UIN -> bundles awaiting its registration
    pub bundles: BinaryHeap<DtnBundle>,
    pub max_bundles: usize,
    pub default_ttl: Duration,
    /// sender UIN -> token bucket (None = unlimited)
    buckets: HashMap<u64, TokenBucket>,
    /// bundles expired inside the most recent drain_for call, for the
    /// caller to journal (never silently dropped)
    pub expired_report: Vec<DtnBundle>,
    /// fragments waiting for the rest of their logical bundle
    pub reassembly: ReassemblyStore,
    /// how many logical bundles were reassembled in the last drain
    pub reassembled_report: Vec<()>,
    /// id handed to the next logical bundle
    next_bundle_id: u64,
    /// WFQ scheduler for the contended delivery link
    pub wfq: WfqScheduler,
    /// admission control (byte rate + queue bound)
    pub admission: AdmissionPolicy,
    /// what the link actually carried
    pub accounting: Accounting,
    /// queue of messages waiting for the link, WFQ-ordered
    pub pending: BinaryHeap<Reverse<PendingMsg>>,
    next_seq: u64,
    /// bytes the delivery link may carry per watchdog tick (None = the
    /// link is infinitely fast; WFQ is then only a tie-breaker)
    pub link_bytes_per_tick: Option<u64>,
    /// bytes left in the current tick's link budget
    link_budget: u64,
}

impl DeliverySystem {
    pub fn new(max_bundles: usize, default_ttl: Duration) -> Self {
        Self {
            bundles: BinaryHeap::new(),
            max_bundles,
            default_ttl,
            buckets: HashMap::new(),
            expired_report: Vec::new(),
            reassembly: ReassemblyStore::default(),
            reassembled_report: Vec::new(),
            next_bundle_id: 1,
            wfq: WfqScheduler::new(16384.0),
            admission: AdmissionPolicy::new(None, 16 * 1024 * 1024),
            accounting: Accounting::default(),
            pending: BinaryHeap::new(),
            next_seq: 0,
            link_bytes_per_tick: None,
            link_budget: u64::MAX,
        }
    }

    // ---- QoS suite: scheduling, admission, accounting ----

    /// The delivery queue is non-empty → the link is contended and the
    /// next message must be scheduled, not written straight through.
    pub fn link_busy(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn queued_len(&self) -> usize {
        self.pending.len()
    }

    /// Refill the link's per-tick byte budget (called at the top of each
    /// watchdog tick, before draining).
    pub fn refill_link(&mut self) {
        self.link_budget = self.link_bytes_per_tick.unwrap_or(u64::MAX);
    }

    /// May the link carry `bytes` right now? Deducts the budget when it
    /// can — a false answer is backpressure, not an error.
    pub fn link_ready(&mut self, bytes: usize) -> bool {
        let b = bytes as u64;
        if self.link_budget >= b {
            self.link_budget -= b;
            true
        } else {
            false
        }
    }

    pub fn link_budget_left(&self) -> u64 {
        self.link_budget
    }

    /// Admit and schedule a message on the WFQ link. `Err` is the
    /// admission refusal reason (the caller journals it).
    pub fn schedule(
        &mut self,
        from: u64,
        to: u64,
        body: Value,
        bytes: usize,
    ) -> Result<(), String> {
        self.admission
            .admit(from, bytes, self.accounting.queued_bytes)?;
        let tag = self.wfq.tag(from, bytes);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.pending.push(Reverse(PendingMsg {
            from,
            to,
            body,
            bytes,
            tag,
            seq,
        }));
        self.accounting.msgs_accepted += 1;
        self.accounting.msgs_scheduled += 1;
        *self.accounting.bytes_in.entry(from).or_insert(0) += bytes as u64;
        self.accounting.queued_bytes += bytes as u64;
        self.accounting.peak_queued_bytes = self
            .accounting
            .peak_queued_bytes
            .max(self.accounting.queued_bytes);
        Ok(())
    }

    /// Pop the next message to serve — smallest virtual finish tag first,
    /// i.e. the WFQ order. Advances the virtual clock by what it served.
    pub fn pop_next(&mut self) -> Option<PendingMsg> {
        let m = self.pending.pop().map(|Reverse(m)| m)?;
        self.accounting.queued_bytes = self.accounting.queued_bytes.saturating_sub(m.bytes as u64);
        self.wfq.serve(m.bytes);
        Some(m)
    }

    /// The link carried `m`: count it (called by the kernel after the
    /// write to the destination succeeded).
    pub fn record_delivery(&mut self, m: &PendingMsg) {
        self.accounting.msgs_delivered += 1;
        *self.accounting.bytes_out.entry(m.to).or_insert(0) += m.bytes as u64;
    }

    /// A message was written straight through on the unqueued fast path:
    /// it still counts as accepted + delivered.
    pub fn record_fast_path(&mut self, from: u64, to: u64, bytes: usize) {
        self.accounting.msgs_accepted += 1;
        self.accounting.msgs_delivered += 1;
        *self.accounting.bytes_in.entry(from).or_insert(0) += bytes as u64;
        *self.accounting.bytes_out.entry(to).or_insert(0) += bytes as u64;
    }

    pub fn record_throttled(&mut self) {
        self.accounting.msgs_throttled += 1;
    }

    pub fn record_denied(&mut self) {
        self.accounting.msgs_denied += 1;
    }

    pub fn record_queued_drop(&mut self, bytes: usize) {
        self.accounting.queued_bytes = self.accounting.queued_bytes.saturating_sub(bytes as u64);
        self.accounting.bytes_dropped += bytes as u64;
    }

    /// Admission probe without scheduling (used by the kernel's fast
    /// path, so a throttled sender is refused before the write too).
    pub fn admit_bytes(&mut self, from: u64, bytes: usize) -> Result<(), String> {
        // the queue bound does not apply to the unqueued fast path
        self.admission.admit(from, bytes, 0)
    }

    pub fn set_weight(&mut self, uin: u64, weight: f64) {
        self.wfq.set_weight(uin, weight);
    }

    pub fn set_byte_rate(&mut self, uin: u64, rate: Option<u32>) {
        self.admission.set_sender_rate(uin, rate);
    }

    pub fn stats(&self) -> Value {
        self.accounting.snapshot()
    }

    /// Declare a sender's rate limit (called at registration when the
    /// manifest gives the agent a `qos.max_msgs_per_sec`).
    pub fn set_rate(&mut self, uin: u64, rate: Option<u32>) {
        match rate {
            Some(r) if r > 0 => {
                self.buckets.insert(uin, TokenBucket::new(r));
            }
            _ => {
                self.buckets.remove(&uin);
            }
        }
    }

    /// QoS gate: false = this sender is over its declared rate.
    pub fn allow(&mut self, from: u64) -> bool {
        match self.buckets.get_mut(&from) {
            Some(b) => b.take(),
            None => true, // no declared limit = unlimited
        }
    }

    /// Take custody of a bundle for a not-yet-connected destination.
    /// Returns Err when custody memory is exhausted — the sender's
    /// `send` fails loudly instead of the kernel dropping silently.
    pub fn store(
        &mut self,
        from: u64,
        to: u64,
        body: Value,
        priority: u8,
        ttl: Option<Duration>,
    ) -> Result<(), String> {
        let id = self.next_bundle_id;
        self.next_bundle_id += 1;
        self.store_routed(from, to, body, priority, ttl, None, 0, id, None)
    }

    /// Take custody of a bundle with its routing coordinates: the next
    /// hop it is handed to, how many hops it has already travelled, and
    /// the fragment slot it occupies.
    #[allow(clippy::too_many_arguments)]
    pub fn store_routed(
        &mut self,
        from: u64,
        to: u64,
        body: Value,
        priority: u8,
        ttl: Option<Duration>,
        next_hop: Option<u64>,
        hops: u8,
        bundle_id: u64,
        frag: Option<FragMeta>,
    ) -> Result<(), String> {
        if self.bundles.len() >= self.max_bundles {
            return Err(format!(
                "dtn custody store full ({} bundles) — refusing new custody",
                self.max_bundles
            ));
        }
        let mut b = DtnBundle::new(from, to, body, priority, ttl.unwrap_or(self.default_ttl));
        b.bundle_id = bundle_id;
        b.hops = hops;
        b.next_hop = next_hop;
        b.frag = frag;
        self.bundles.push(b);
        Ok(())
    }

    /// A fresh logical-bundle id (fragments of one message share it).
    pub fn new_bundle_id(&mut self) -> u64 {
        let id = self.next_bundle_id;
        self.next_bundle_id += 1;
        id
    }

    /// CUSTODY TRANSFER: the relay holding the bundle now owns it, so the
    /// kernel deletes its own copy. `frag_index` names the exact fragment
    /// (fragments of one logical bundle are independent custody units).
    /// F01 (DTN): only the CURRENT custody holder may acknowledge — the
    /// entity the bundle was transferred to (`next_hop`), or the
    /// destination the kernel holds it for (destination registration
    /// flushes custody separately, never through this path). Returns how
    /// many were released; 0 means the caller does not hold custody.
    pub fn ack_custody(&mut self, bundle_id: u64, frag_index: Option<u32>, by: u64) -> usize {
        let before = self.bundles.len();
        let kept: Vec<DtnBundle> = self
            .bundles
            .drain()
            .filter(|b| {
                if b.bundle_id != bundle_id {
                    return true; // other bundles stay
                }
                // OWNERSHIP: the acking session must be the holder the
                // bundle was transferred to
                if b.next_hop != Some(by) {
                    return true; // not the caller's custody — stays
                }
                match (frag_index, b.frag) {
                    (Some(i), Some(m)) => m.index != i, // keep the others
                    (Some(_), None) => false,           // the whole one goes
                    (None, _) => false,                 // release them all
                }
            })
            .collect();
        for b in kept {
            self.bundles.push(b);
        }
        before - self.bundles.len()
    }

    /// Bundles handed to `uin` as the next hop (custody for a relay).
    pub fn drain_via(&mut self, uin: u64) -> Vec<DtnBundle> {
        let now = Instant::now();
        let mut kept: Vec<DtnBundle> = Vec::new();
        let mut out: Vec<DtnBundle> = Vec::new();
        let mut expired: Vec<DtnBundle> = Vec::new();
        while let Some(b) = self.bundles.pop() {
            if b.expires_at <= now {
                expired.push(b);
            } else if b.next_hop == Some(uin) {
                out.push(b);
            } else {
                kept.push(b);
            }
        }
        for b in kept {
            self.bundles.push(b);
        }
        self.expired_report.extend(expired);
        out.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then(a.stored_at.cmp(&b.stored_at))
        });
        out
    }

    /// Drain every bundle addressed to `uin` whose TTL is still valid,
    /// in priority order. Called when the destination registers.
    pub fn drain_for(&mut self, uin: u64) -> Vec<DtnBundle> {
        let now = Instant::now();
        let mut kept: Vec<DtnBundle> = Vec::new();
        let mut expired: Vec<DtnBundle> = Vec::new();
        let mut out: Vec<DtnBundle> = Vec::new();
        while let Some(b) = self.bundles.pop() {
            if b.to == uin {
                if b.expires_at > now {
                    out.push(b);
                } else {
                    expired.push(b);
                }
            } else if b.expires_at > now {
                kept.push(b);
            } else {
                expired.push(b);
            }
        }
        for b in kept {
            self.bundles.push(b);
        }
        // FRAGMENT REASSEMBLY: a message split into fragments becomes one
        // message again when its set is complete; an incomplete set stays
        // in custody (it can still complete on a later delivery).
        let mut plain: Vec<DtnBundle> = Vec::new();
        let mut partial: std::collections::BTreeMap<u64, Vec<DtnBundle>> =
            std::collections::BTreeMap::new();
        for b in out.drain(..) {
            match b.frag {
                Some(meta) => partial.entry(meta.id).or_default().push(b),
                None => plain.push(b),
            }
        }
        let mut reassembled = 0usize;
        for (_id, mut group) in partial {
            let total = group[0].frag.map(|m| m.total).unwrap_or(1) as usize;
            let mut seen: Vec<u32> = group
                .iter()
                .filter_map(|b| b.frag.map(|m| m.index))
                .collect();
            seen.sort_unstable();
            seen.dedup();
            if group.len() >= total && seen.len() == total {
                // order the parts by index before joining them
                group.sort_by_key(|b| b.frag.map(|m| m.index).unwrap_or(0));
                let parts: Vec<Value> = group.iter().map(|b| b.body.clone()).collect();
                if let Some(body) = reassemble_parts(parts) {
                    let mut whole = DtnBundle::new(
                        group[0].from,
                        group[0].to,
                        body,
                        group[0].priority,
                        self.default_ttl,
                    );
                    whole.bundle_id = group[0].bundle_id;
                    whole.hops = group.iter().map(|b| b.hops).max().unwrap_or(0);
                    plain.push(whole);
                    reassembled += 1;
                } else {
                    // corrupt set: drop it, but never silently
                    self.expired_report.extend(group);
                }
            } else {
                // incomplete: keep the fragments for a later attempt
                for b in group {
                    self.bundles.push(b);
                }
            }
        }
        self.reassembled_report
            .extend(std::iter::repeat_n((), reassembled));
        // report expired bundles so the caller can journal them
        self.expired_report.extend(expired);
        plain
    }

    /// Take the bundles expired inside the last `drain_for` call.
    pub fn take_expired_report(&mut self) -> Vec<DtnBundle> {
        std::mem::take(&mut self.expired_report)
    }

    /// Bundles whose TTL ran out while their destination never came
    /// back — swept by the kernel's watchdog (journal + drop).
    pub fn sweep_expired(&mut self) -> Vec<DtnBundle> {
        let now = Instant::now();
        let mut kept: Vec<DtnBundle> = Vec::new();
        let mut expired: Vec<DtnBundle> = Vec::new();
        while let Some(b) = self.bundles.pop() {
            if b.expires_at > now {
                kept.push(b);
            } else {
                expired.push(b);
            }
        }
        for b in kept {
            self.bundles.push(b);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bucket_allows_burst_then_refills() {
        let mut b = TokenBucket::new(3);
        assert!(b.take() && b.take() && b.take());
        assert!(!b.take(), "4th send over a 3-token bucket must be refused");
        // refill after the window: a fresh bucket without waiting is
        // equivalent to elapsing one second of refill
        let mut b2 = TokenBucket::new(3);
        b2.tokens = 0.0;
        b2.last = Instant::now() - Duration::from_secs(1);
        assert!(b2.take(), "one full second must refill the bucket");
    }

    #[test]
    fn rate_is_per_sender_not_global() {
        let mut d = DeliverySystem::new(16, Duration::from_secs(60));
        d.set_rate(1, Some(2));
        d.set_rate(2, Some(2));
        assert!(d.allow(1) && d.allow(1));
        assert!(!d.allow(1), "sender 1 exhausted its own bucket");
        assert!(d.allow(2), "sender 2 must be unaffected by sender 1");
    }

    #[test]
    fn unlimited_sender_is_never_throttled() {
        let mut d = DeliverySystem::new(16, Duration::from_secs(60));
        d.set_rate(7, None);
        for _ in 0..500 {
            assert!(d.allow(7));
        }
    }

    #[test]
    fn dtn_stores_and_drains_by_priority() {
        let mut d = DeliverySystem::new(16, Duration::from_secs(60));
        // priority 0 = highest: it must come out FIRST regardless of order
        d.store(1, 9, json!({"n": "low"}), 9, None).unwrap();
        d.store(2, 9, json!({"n": "high"}), 0, None).unwrap();
        d.store(3, 9, json!({"n": "mid"}), 5, None).unwrap();
        let out = d.drain_for(9);
        let order: Vec<_> = out.iter().map(|b| b.body["n"].as_str().unwrap()).collect();
        assert_eq!(order, vec!["high", "mid", "low"]);
        assert!(d.drain_for(9).is_empty(), "drain must empty the queue");
    }

    #[test]
    fn dtn_ttl_expiry_is_reported_not_silent() {
        let mut d = DeliverySystem::new(16, Duration::from_millis(1));
        d.store(1, 9, json!({"n": 1}), 5, None).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let expired = d.sweep_expired();
        assert_eq!(expired.len(), 1, "expired bundle must be reported");
        assert!(
            d.drain_for(9).is_empty(),
            "an expired bundle is not delivered"
        );
    }

    // ---- QoS suite: WFQ, admission, accounting ----

    #[test]
    fn wfq_shares_the_link_by_weight() {
        let mut d = DeliverySystem::new(64, Duration::from_secs(60));
        d.set_weight(1, 1.0);
        d.set_weight(2, 3.0);
        // backlogs in the WEIGHT ratio (1:3) so both flows stay backlogged
        // for the whole run — that is the regime WFQ makes a promise about
        for i in 0..12 {
            d.schedule(2, 9, json!({"f": 2, "i": i}), 100).unwrap();
            if i % 3 == 0 {
                d.schedule(1, 9, json!({"f": 1, "i": i}), 100).unwrap();
            }
        }
        let mut served = [0usize; 3];
        let mut order = Vec::new();
        while let Some(m) = d.pop_next() {
            served[m.from as usize] += 1;
            order.push(m.from);
        }
        assert_eq!(served[1], 4, "weight 1 flow: {order:?}");
        assert_eq!(served[2], 12, "weight 3 flow: {order:?}");
        // the heavy flow must be INTERLEAVED at 3:1: the longest run of
        // it is 3 services (it can never monopolise the link), and the
        // last message of the light flow is never starved
        let mut streak = 0usize;
        let mut worst = 0usize;
        for f in &order {
            if *f == 2 {
                streak += 1;
                worst = worst.max(streak);
            } else {
                streak = 0;
            }
        }
        // SFQ (not WF2Q) bounds the run while the light flow still has
        // traffic queued; once its last message is in flight the heavy
        // flow legitimately drains its remainder.
        assert!(
            worst <= 4,
            "the heavy flow must not monopolise the link for long: {order:?}"
        );
        assert!(
            order[..4].contains(&1),
            "the light flow must be served early, not starved: {order:?}"
        );
        assert_eq!(
            *order.last().unwrap(),
            1,
            "light flow must not starve: {order:?}"
        );
    }

    #[test]
    fn wfq_idle_flow_earns_no_backlog_credit() {
        let mut d = DeliverySystem::new(64, Duration::from_secs(60));
        d.set_weight(1, 1.0);
        for _ in 0..10 {
            d.schedule(1, 9, json!({"f": 1}), 1000).unwrap();
        }
        while d.pop_next().is_some() {}
        // a flow that was never backlogged cannot get a tag below the
        // current virtual time, so it cannot jump ahead of a busy flow
        let tag = d.wfq.peek_tag(2, 100);
        assert!(
            tag >= d.wfq.virtual_time(),
            "idle flow must not bank credit ({tag} < {})",
            d.wfq.virtual_time()
        );
    }

    #[test]
    fn admission_control_refuses_over_the_byte_rate() {
        let mut d = DeliverySystem::new(16, Duration::from_secs(60));
        d.admission.max_bytes_per_sec = Some(1000);
        assert!(d.admit_bytes(1, 800).is_ok());
        let err = d.admit_bytes(1, 800).unwrap_err();
        assert!(err.contains("byte rate"), "unexpected refusal: {err}");
        // another sender is unaffected
        assert!(d.admit_bytes(2, 800).is_ok());
    }

    #[test]
    fn admission_control_refuses_when_the_queue_is_full() {
        let mut d = DeliverySystem::new(16, Duration::from_secs(60));
        d.admission.max_queue_bytes = 250;
        assert!(d.schedule(1, 9, json!({"n": 0}), 100).is_ok());
        assert!(d.schedule(1, 9, json!({"n": 1}), 100).is_ok());
        let err = d.schedule(1, 9, json!({"n": 2}), 100).unwrap_err();
        assert!(err.contains("at capacity"), "unexpected refusal: {err}");
        assert_eq!(
            d.accounting.msgs_denied, 0,
            "denials are counted by the caller"
        );
    }

    #[test]
    fn accounting_tracks_bytes_and_queue_depth() {
        let mut d = DeliverySystem::new(16, Duration::from_secs(60));
        d.schedule(1, 7, json!({"a": 1}), 300).unwrap();
        d.schedule(2, 7, json!({"b": 2}), 200).unwrap();
        assert_eq!(d.accounting.queued_bytes, 500);
        assert_eq!(d.accounting.peak_queued_bytes, 500);
        while let Some(m) = d.pop_next() {
            d.record_delivery(&m);
        }
        assert_eq!(d.accounting.queued_bytes, 0);
        assert_eq!(d.accounting.msgs_delivered, 2);
        assert_eq!(d.accounting.bytes_in.get(&1), Some(&300));
        assert_eq!(d.accounting.bytes_out.get(&7), Some(&500));
        let snap = d.stats();
        assert_eq!(snap["msgs_delivered"], 2);
        assert_eq!(snap["peak_queued_bytes"], 500);
    }

    // ---- DTN routing: fragmentation, custody transfer, relays ----

    #[test]
    fn fragmentation_roundtrip_is_lossless() {
        let body = json!({"msg": "x".repeat(400), "n": 7});
        let frags = fragment_body(&body, 100, 42).unwrap();
        assert!(
            frags.len() > 1,
            "a 400-byte body must fragment: {}",
            frags.len()
        );
        assert!(frags.iter().all(|(m, _)| m.id == 42));
        assert!(frags.iter().all(|(m, _)| m.total as usize == frags.len()));
        let rebuilt = reassemble_parts(frags.into_iter().map(|(_, p)| p).collect()).unwrap();
        assert_eq!(rebuilt, body, "reassembly must be lossless");
    }

    #[test]
    fn drain_for_reassembles_only_complete_sets() {
        let mut d = DeliverySystem::new(32, Duration::from_secs(60));
        let body = json!({"msg": "y".repeat(300)});
        let frags = fragment_body(&body, 80, 9).unwrap();
        let total = frags.len();
        assert!(total >= 3);
        // deliver all but the last fragment: nothing comes out
        for (meta, piece) in frags.iter().take(total - 1) {
            d.store_routed(1, 5, piece.clone(), 5, None, None, 0, 9, Some(*meta))
                .unwrap();
        }
        assert!(
            d.drain_for(5).is_empty(),
            "an incomplete set must not deliver"
        );
        // the last fragment completes the message
        let (meta, piece) = frags.last().unwrap();
        d.store_routed(1, 5, piece.clone(), 5, None, None, 0, 9, Some(*meta))
            .unwrap();
        let out = d.drain_for(5);
        assert_eq!(
            out.len(),
            1,
            "a complete set must deliver exactly one message"
        );
        assert_eq!(out[0].body, body);
        assert!(out[0].frag.is_none(), "the delivered bundle is whole");
    }

    #[test]
    fn custody_ack_deletes_the_kernels_copy() {
        let mut d = DeliverySystem::new(16, Duration::from_secs(60));
        d.store_routed(1, 5, json!({"n": 1}), 5, None, Some(7), 0, 77, None)
            .unwrap();
        assert_eq!(d.bundles.len(), 1);
        assert_eq!(
            d.ack_custody(77, None, 7),
            1,
            "the relay's ack must release exactly one bundle"
        );
        assert_eq!(
            d.bundles.len(),
            0,
            "custody transferred: the kernel no longer holds it"
        );
        assert_eq!(d.ack_custody(77, None, 7), 0, "a second ack is a no-op");
    }

    #[test]
    fn custody_ack_only_releases_the_holders_transfer() {
        // F01 (DTN): an unrelated relay cannot acknowledge another relay's
        // custody transfer — the kernel keeps holding it
        let mut d = DeliverySystem::new(16, Duration::from_secs(60));
        d.store_routed(1, 5, json!({"n": 1}), 5, None, Some(7), 0, 77, None)
            .unwrap();
        assert_eq!(
            d.ack_custody(77, None, 9),
            0,
            "a different session is not the custody holder"
        );
        assert_eq!(d.bundles.len(), 1, "the kernel keeps holding the bundle");
        assert_eq!(
            d.ack_custody(77, None, 7),
            1,
            "the actual holder's ack releases it"
        );
    }

    #[test]
    fn drain_via_hands_only_the_relays_bundles() {
        let mut d = DeliverySystem::new(16, Duration::from_secs(60));
        d.store_routed(1, 5, json!({"a": 1}), 5, None, Some(7), 0, 1, None)
            .unwrap();
        d.store_routed(1, 5, json!({"a": 2}), 5, None, Some(8), 0, 2, None)
            .unwrap();
        d.store_routed(1, 5, json!({"a": 3}), 5, None, None, 0, 3, None)
            .unwrap();
        let via7 = d.drain_via(7);
        assert_eq!(via7.len(), 1, "only the bundles routed through 7");
        assert_eq!(via7[0].bundle_id, 1);
        assert_eq!(d.bundles.len(), 2, "the others stay in custody");
        // the relay's copy leaves the queue; a re-registration must not
        // hand it over twice
        assert!(d.drain_via(7).is_empty());
    }

    #[test]
    fn dtn_bounded_by_max_bundles() {
        let mut d = DeliverySystem::new(2, Duration::from_secs(60));
        d.store(1, 9, json!({"n": 1}), 5, None).unwrap();
        d.store(1, 9, json!({"n": 2}), 5, None).unwrap();
        assert!(
            d.store(1, 9, json!({"n": 3}), 5, None).is_err(),
            "the custody store must refuse past its bound, not grow unbounded"
        );
    }
}
