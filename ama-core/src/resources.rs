//! Shared, configurable admission budgets. Reservations release on drop.
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ResourceLimits {
    pub max_connections: usize,
    pub max_connections_per_peer: usize,
    pub max_control_connections: usize,
    pub handshake_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub max_outbound_bytes: usize,
    pub max_outbound_bytes_per_agent: usize,
    pub max_custody_bytes: usize,
    pub max_custody_bytes_per_sender: usize,
    pub max_custody_bytes_per_destination: usize,
    /// Zero disables automatic WAL segmentation.
    pub ledger_segment_bytes: u64,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_connections: 512,
            max_connections_per_peer: 128,
            max_control_connections: 16,
            handshake_timeout_ms: 5000,
            idle_timeout_ms: 30000,
            max_outbound_bytes: 64 << 20,
            max_outbound_bytes_per_agent: 4 << 20,
            max_custody_bytes: 64 << 20,
            max_custody_bytes_per_sender: 16 << 20,
            max_custody_bytes_per_destination: 32 << 20,
            ledger_segment_bytes: 64 << 20,
        }
    }
}
impl ResourceLimits {
    pub fn validate(&self) -> Result<(), String> {
        if [
            self.max_connections,
            self.max_connections_per_peer,
            self.max_control_connections,
            self.max_outbound_bytes,
            self.max_outbound_bytes_per_agent,
            self.max_custody_bytes,
            self.max_custody_bytes_per_sender,
            self.max_custody_bytes_per_destination,
        ]
        .contains(&0)
            || self.handshake_timeout_ms == 0
            || self.idle_timeout_ms == 0
        {
            return Err("resource budgets and deadlines must be positive".into());
        }
        Ok(())
    }
}

pub struct ByteBudget {
    state: Mutex<(usize, usize)>,
}
impl ByteBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            state: Mutex::new((0, limit)),
        }
    }
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Option<ByteReservation> {
        let mut s = self.state.lock().unwrap();
        if bytes > s.1.saturating_sub(s.0) {
            return None;
        }
        s.0 += bytes;
        Some(ByteReservation {
            budget: self.clone(),
            bytes,
        })
    }
    pub fn set_limit(&self, limit: usize) -> Result<(), String> {
        let mut s = self.state.lock().unwrap();
        if limit == 0 || limit < s.0 {
            return Err("byte limit is below current usage".into());
        }
        s.1 = limit;
        Ok(())
    }
    pub fn usage(&self) -> (usize, usize) {
        *self.state.lock().unwrap()
    }
}
pub struct ByteReservation {
    budget: Arc<ByteBudget>,
    bytes: usize,
}
impl Drop for ByteReservation {
    fn drop(&mut self) {
        self.budget.state.lock().unwrap().0 -= self.bytes;
    }
}

pub struct Connections {
    state: Mutex<HashMap<String, usize>>,
    limits: ResourceLimits,
}
impl Connections {
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            limits,
        }
    }
    pub fn acquire(self: &Arc<Self>, peer: String) -> Option<ConnectionReservation> {
        let mut s = self.state.lock().unwrap();
        if s.values().sum::<usize>() >= self.limits.max_connections
            || s.get(&peer).copied().unwrap_or(0) >= self.limits.max_connections_per_peer
        {
            return None;
        }
        *s.entry(peer.clone()).or_default() += 1;
        Some(ConnectionReservation {
            budget: self.clone(),
            peer,
        })
    }
    pub fn stats(&self) -> Value {
        let s = self.state.lock().unwrap();
        json!({"active": s.values().sum::<usize>(), "by_peer": *s,
            "limit": self.limits.max_connections, "per_peer_limit": self.limits.max_connections_per_peer})
    }
}
pub struct ConnectionReservation {
    budget: Arc<Connections>,
    peer: String,
}
impl Drop for ConnectionReservation {
    fn drop(&mut self) {
        let mut s = self.budget.state.lock().unwrap();
        if let Some(n) = s.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                s.remove(&self.peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ResourceLimits::validate ──────────────────────────────────────

    #[test]
    fn validate_rejects_zero_budgets() {
        let l = ResourceLimits {
            max_connections: 0,
            ..Default::default()
        };
        assert!(l.validate().is_err());

        let l = ResourceLimits {
            max_custody_bytes: 0,
            ..Default::default()
        };
        assert!(l.validate().is_err());

        let l = ResourceLimits {
            handshake_timeout_ms: 0,
            ..Default::default()
        };
        assert!(l.validate().is_err());

        let l = ResourceLimits {
            idle_timeout_ms: 0,
            ..Default::default()
        };
        assert!(l.validate().is_err());
    }

    #[test]
    fn validate_accepts_defaults() {
        assert!(ResourceLimits::default().validate().is_ok());
    }

    // ── ByteBudget ────────────────────────────────────────────────────

    #[test]
    fn byte_budget_reserve_and_release() {
        let bb = Arc::new(ByteBudget::new(100));
        assert_eq!(bb.usage(), (0, 100));

        let r = bb.reserve(60).expect("should fit");
        assert_eq!(bb.usage(), (60, 100));

        // 60 used + 50 requested > 100 → reject
        assert!(bb.reserve(50).is_none());

        // 60 used + 40 requested ≤ 100 → ok
        let r2 = bb.reserve(40).expect("should fit");
        assert_eq!(bb.usage(), (100, 100));

        // at limit → reject
        assert!(bb.reserve(1).is_none());

        drop(r);
        assert_eq!(bb.usage(), (40, 100));
        drop(r2);
        assert_eq!(bb.usage(), (0, 100));
    }

    #[test]
    fn byte_budget_set_limit() {
        let bb = Arc::new(ByteBudget::new(100));
        let _r = bb.reserve(80).unwrap();

        // cannot lower below current usage
        assert!(bb.set_limit(50).is_err());
        // cannot set to zero
        assert!(bb.set_limit(0).is_err());
        // can raise
        assert!(bb.set_limit(200).is_ok());
        assert_eq!(bb.usage(), (80, 200));
    }

    // ── Connections ───────────────────────────────────────────────────

    #[test]
    fn connections_per_peer_limit() {
        let limits = ResourceLimits {
            max_connections: 10,
            max_connections_per_peer: 2,
            ..Default::default()
        };
        let c = Arc::new(Connections::new(limits));

        let _a = c.acquire("p1".into()).expect("1st");
        let _b = c.acquire("p1".into()).expect("2nd");
        // per-peer limit reached
        assert!(c.acquire("p1".to_string()).is_none());
        // other peer still allowed
        let _c = c.acquire("p2".into()).expect("other peer");

        drop(_a);
        // one slot freed for p1
        let _d = c.acquire("p1".into()).expect("after drop");

        drop(_b);
        drop(_c);
        drop(_d);
        assert_eq!(c.stats()["active"], 0);
    }

    #[test]
    fn connections_global_limit() {
        let limits = ResourceLimits {
            max_connections: 2,
            max_connections_per_peer: 100,
            ..Default::default()
        };
        let c = Arc::new(Connections::new(limits));
        let _a = c.acquire("a".into()).unwrap();
        let _b = c.acquire("b".into()).unwrap();
        assert!(c.acquire("c".to_string()).is_none());
    }
}
