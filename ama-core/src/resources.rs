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
