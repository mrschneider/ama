//! QoS (priority + rate limiting) and DTN (delay-tolerant
//! store-and-forward) message delivery.
//!
//! QoS: every agent declares `qos: { priority, max_msgs_per_sec }` in
//! the manifest. Delivery is scheduled by priority (0 = highest); each
//! SENDER gets a token bucket so a bursty agent cannot starve the
//! others. Refused sends are journaled as `qos_throttled` — never
//! silently dropped (same rule as `cap_denied`).
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
use std::collections::BinaryHeap;
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
}

impl PartialEq for DtnBundle {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.stored_at == other.stored_at
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

/// The kernel's delivery subsystem. `max_bundles` bounds custody memory:
/// the kernel is not a mailbox of unbounded size.
pub struct DeliverySystem {
    /// destination UIN -> bundles awaiting its registration
    pub bundles: BinaryHeap<DtnBundle>,
    pub max_bundles: usize,
    pub default_ttl: Duration,
    /// sender UIN -> token bucket (None = unlimited)
    buckets: std::collections::HashMap<u64, TokenBucket>,
    /// bundles expired inside the most recent drain_for call, for the
    /// caller to journal (never silently dropped)
    pub expired_report: Vec<DtnBundle>,
}

impl DeliverySystem {
    pub fn new(max_bundles: usize, default_ttl: Duration) -> Self {
        Self {
            bundles: BinaryHeap::new(),
            max_bundles,
            default_ttl,
            buckets: std::collections::HashMap::new(),
            expired_report: Vec::new(),
        }
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
        if self.bundles.len() >= self.max_bundles {
            return Err(format!(
                "dtn custody store full ({} bundles) — refusing new custody",
                self.max_bundles
            ));
        }
        self.bundles.push(DtnBundle {
            from,
            to,
            body,
            priority,
            stored_at: Instant::now(),
            expires_at: Instant::now() + ttl.unwrap_or(self.default_ttl),
        });
        Ok(())
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
        // report expired bundles so the caller can journal them
        self.expired_report.extend(expired);
        out
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
