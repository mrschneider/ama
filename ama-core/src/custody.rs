//! Indexed custody inventory. Body byte budgets are measured on encoded JSON.
use crate::qos::DtnBundle;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap};
use std::time::Instant;

pub struct CustodyStore {
    items: HashMap<u64, (DtnBundle, usize)>,
    destinations: HashMap<u64, BTreeSet<u64>>,
    relays: HashMap<u64, BTreeSet<u64>>,
    logical: HashMap<u64, BTreeSet<u64>>,
    expiry: BinaryHeap<Reverse<(Instant, u64)>>,
    next: u64,
    bytes: usize,
    sender_bytes: HashMap<u64, usize>,
    destination_bytes: HashMap<u64, usize>,
    pub max_bytes: usize,
    pub max_sender_bytes: usize,
    pub max_destination_bytes: usize,
}
impl Default for CustodyStore {
    fn default() -> Self {
        Self {
            items: HashMap::new(),
            destinations: HashMap::new(),
            relays: HashMap::new(),
            logical: HashMap::new(),
            expiry: BinaryHeap::new(),
            next: 0,
            bytes: 0,
            sender_bytes: HashMap::new(),
            destination_bytes: HashMap::new(),
            max_bytes: 64 << 20,
            max_sender_bytes: 16 << 20,
            max_destination_bytes: 32 << 20,
        }
    }
}
impl CustodyStore {
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn insert(&mut self, bundle: DtnBundle) -> Result<(), String> {
        let size = serde_json::to_vec(&bundle.body)
            .map_err(|e| e.to_string())?
            .len();
        let sender = self.sender_bytes.get(&bundle.from).copied().unwrap_or(0);
        let target = self.destination_bytes.get(&bundle.to).copied().unwrap_or(0);
        if size > self.max_bytes.saturating_sub(self.bytes)
            || size > self.max_sender_bytes.saturating_sub(sender)
            || size > self.max_destination_bytes.saturating_sub(target)
        {
            return Err("dtn custody byte budget exhausted".into());
        }
        self.insert_sized(bundle, size);
        Ok(())
    }
    /// Restore a previously-held incomplete fragment, under the same
    /// delivery lock.  Returns `Err` when the byte budgets no longer
    /// have room (the caller must journal the lost bundle).
    pub fn restore(&mut self, bundle: DtnBundle) -> Result<(), String> {
        let size = serde_json::to_vec(&bundle.body)
            .map_err(|e| format!("custody restore: cannot re-encode body: {e}"))?
            .len();
        let sender = self
            .sender_bytes
            .get(&bundle.from)
            .copied()
            .unwrap_or(0);
        let target = self
            .destination_bytes
            .get(&bundle.to)
            .copied()
            .unwrap_or(0);
        if size > self.max_bytes.saturating_sub(self.bytes)
            || size > self.max_sender_bytes.saturating_sub(sender)
            || size > self.max_destination_bytes.saturating_sub(target)
        {
            return Err("dtn custody byte budget exhausted on restore".into());
        }
        self.insert_sized(bundle, size);
        Ok(())
    }
    fn insert_sized(&mut self, bundle: DtnBundle, size: usize) {
        let id = self.next;
        self.next += 1;
        self.destinations.entry(bundle.to).or_default().insert(id);
        if let Some(relay) = bundle.next_hop {
            self.relays.entry(relay).or_default().insert(id);
        }
        self.logical.entry(bundle.bundle_id).or_default().insert(id);
        self.expiry.push(Reverse((bundle.expires_at, id)));
        self.bytes += size;
        *self.sender_bytes.entry(bundle.from).or_default() += size;
        *self.destination_bytes.entry(bundle.to).or_default() += size;
        self.items.insert(id, (bundle, size));
    }
    fn unindex(index: &mut HashMap<u64, BTreeSet<u64>>, key: u64, id: u64) {
        if let Some(ids) = index.get_mut(&key) {
            ids.remove(&id);
            if ids.is_empty() {
                index.remove(&key);
            }
        }
    }
    fn uncharge(index: &mut HashMap<u64, usize>, key: u64, bytes: usize) {
        if let Some(usage) = index.get_mut(&key) {
            *usage -= bytes;
            if *usage == 0 {
                index.remove(&key);
            }
        }
    }
    fn remove(&mut self, id: u64) -> Option<DtnBundle> {
        let (bundle, size) = self.items.remove(&id)?;
        self.bytes -= size;
        Self::uncharge(&mut self.sender_bytes, bundle.from, size);
        Self::uncharge(&mut self.destination_bytes, bundle.to, size);
        Self::unindex(&mut self.destinations, bundle.to, id);
        Self::unindex(&mut self.logical, bundle.bundle_id, id);
        if let Some(relay) = bundle.next_hop {
            Self::unindex(&mut self.relays, relay, id);
        }
        if self.expiry.len() > self.items.len().saturating_mul(2) + 64 {
            self.expiry = self
                .items
                .iter()
                .map(|(id, (b, _))| Reverse((b.expires_at, *id)))
                .collect();
        }
        Some(bundle)
    }
    pub fn expire(&mut self, now: Instant) -> Vec<DtnBundle> {
        let mut out = Vec::new();
        while let Some(Reverse((expiry, id))) = self.expiry.peek().copied() {
            if expiry > now {
                break;
            }
            self.expiry.pop();
            if let Some(bundle) = self.remove(id) {
                out.push(bundle);
            }
        }
        out
    }
    fn ordered(mut bundles: Vec<DtnBundle>) -> Vec<DtnBundle> {
        bundles.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then(a.stored_at.cmp(&b.stored_at))
                .then(a.bundle_id.cmp(&b.bundle_id))
        });
        bundles
    }
    pub fn drain_for(&mut self, target: u64) -> Vec<DtnBundle> {
        let ids = self.destinations.get(&target).cloned().unwrap_or_default();
        let bundles = ids.into_iter().filter_map(|id| self.remove(id)).collect();
        Self::ordered(bundles)
    }
    pub fn drain_via(&mut self, relay: u64) -> Vec<DtnBundle> {
        let ids = self.relays.get(&relay).cloned().unwrap_or_default();
        let bundles = ids.into_iter().filter_map(|id| self.remove(id)).collect();
        Self::ordered(bundles)
    }
    pub fn acknowledge(&mut self, logical: u64, fragment: Option<u32>, owner: u64) -> usize {
        let ids = self.logical.get(&logical).cloned().unwrap_or_default();
        let selected: Vec<_> = ids
            .into_iter()
            .filter(|id| {
                let b = &self.items[id].0;
                b.next_hop == Some(owner)
                    && match (fragment, b.frag) {
                        (Some(i), Some(meta)) => meta.index == i,
                        _ => true,
                    }
            })
            .collect();
        let count = selected.len();
        for id in selected {
            self.remove(id);
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qos::FragMeta;
    use serde_json::json;
    use std::time::Duration;

    /// Build a minimal test bundle.
    fn mk_bundle(from: u64, to: u64, bundle_id: u64, next_hop: Option<u64>) -> DtnBundle {
        DtnBundle {
            from,
            to,
            body: json!({"hello": "world"}),
            priority: 5,
            stored_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
            bundle_id,
            hops: 0,
            next_hop,
            frag: None,
        }
    }

    // ── insert / byte budgets ─────────────────────────────────────────

    #[test]
    fn insert_tracks_bytes() {
        let mut s = CustodyStore::default();
        let b = mk_bundle(1, 2, 100, None);
        let size = serde_json::to_vec(&b.body).unwrap().len();
        s.insert(b).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.bytes(), size);
    }

    #[test]
    fn insert_rejects_when_total_budget_full() {
        let mut s = CustodyStore {
            max_bytes: 10, // tiny
            ..Default::default()
        };
        // body encodes to > 10 bytes
        assert!(s.insert(mk_bundle(1, 2, 100, None)).is_err());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn insert_rejects_when_sender_budget_full() {
        let mut s = CustodyStore {
            max_sender_bytes: 10,
            ..Default::default()
        };
        assert!(s.insert(mk_bundle(1, 2, 100, None)).is_err());
    }

    #[test]
    fn insert_rejects_when_destination_budget_full() {
        let mut s = CustodyStore {
            max_destination_bytes: 10,
            ..Default::default()
        };
        assert!(s.insert(mk_bundle(1, 2, 100, None)).is_err());
    }

    // ── restore ───────────────────────────────────────────────────────

    #[test]
    fn restore_succeeds_when_room_available() {
        let mut s = CustodyStore::default();
        let b = mk_bundle(1, 2, 100, None);
        let size = serde_json::to_vec(&b.body).unwrap().len();
        s.insert(b).unwrap();
        // remove it (simulating a drain)
        let drained = s.drain_for(2);
        assert_eq!(drained.len(), 1);
        assert_eq!(s.bytes(), 0);
        // restore it back
        s.restore(drained.into_iter().next().unwrap()).unwrap();
        assert_eq!(s.bytes(), size);
    }

    #[test]
    fn restore_fails_when_budget_exhausted() {
        let mut s = CustodyStore {
            max_bytes: 10,
            ..Default::default()
        };
        let b = mk_bundle(1, 2, 100, None);
        // body is > 10 bytes, so restore must fail
        assert!(s.restore(b).is_err());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn restore_fails_when_sender_budget_full() {
        let mut s = CustodyStore {
            max_sender_bytes: 10,
            ..Default::default()
        };
        let b = mk_bundle(1, 2, 100, None);
        assert!(s.restore(b).is_err());
    }

    #[test]
    fn restore_fails_when_destination_budget_full() {
        let mut s = CustodyStore {
            max_destination_bytes: 10,
            ..Default::default()
        };
        let b = mk_bundle(1, 2, 100, None);
        assert!(s.restore(b).is_err());
    }

    // ── expire ────────────────────────────────────────────────────────

    #[test]
    fn expire_removes_stale_bundles() {
        let mut s = CustodyStore::default();
        let b = DtnBundle {
            expires_at: Instant::now() - Duration::from_secs(1),
            ..mk_bundle(1, 2, 100, None)
        };
        s.insert(b).unwrap();
        assert_eq!(s.len(), 1);
        let expired = s.expire(Instant::now());
        assert_eq!(expired.len(), 1);
        assert_eq!(s.len(), 0);
        assert_eq!(s.bytes(), 0);
    }

    #[test]
    fn expire_keeps_fresh_bundles() {
        let mut s = CustodyStore::default();
        let b = mk_bundle(1, 2, 100, None); // expires in 1 h
        s.insert(b).unwrap();
        let expired = s.expire(Instant::now());
        assert!(expired.is_empty());
        assert_eq!(s.len(), 1);
    }

    // ── drain_for / drain_via ─────────────────────────────────────────

    #[test]
    fn drain_for_returns_bundles_for_target() {
        let mut s = CustodyStore::default();
        s.insert(mk_bundle(1, 2, 100, None)).unwrap();
        s.insert(mk_bundle(1, 3, 101, None)).unwrap();
        let drained = s.drain_for(2);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].to, 2);
        assert_eq!(s.len(), 1); // the other bundle remains
    }

    #[test]
    fn drain_via_returns_bundles_for_relay() {
        let mut s = CustodyStore::default();
        s.insert(mk_bundle(1, 2, 100, Some(99))).unwrap();
        s.insert(mk_bundle(1, 2, 101, None)).unwrap();
        let drained = s.drain_via(99);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].next_hop, Some(99));
        assert_eq!(s.len(), 1);
    }

    // ── acknowledge ───────────────────────────────────────────────────

    #[test]
    fn acknowledge_removes_matching_fragments() {
        let mut s = CustodyStore::default();
        let b1 = DtnBundle {
            frag: Some(FragMeta { id: 200, index: 0, total: 2 }),
            ..mk_bundle(1, 2, 200, Some(50))
        };
        let b2 = DtnBundle {
            frag: Some(FragMeta { id: 200, index: 1, total: 2 }),
            ..mk_bundle(1, 2, 200, Some(50))
        };
        s.insert(b1).unwrap();
        s.insert(b2).unwrap();
        assert_eq!(s.len(), 2);

        // ack fragment 0 from owner 50
        let n = s.acknowledge(200, Some(0), 50);
        assert_eq!(n, 1);
        assert_eq!(s.len(), 1);

        // ack fragment 1
        let n = s.acknowledge(200, Some(1), 50);
        assert_eq!(n, 1);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn acknowledge_no_match_returns_zero() {
        let mut s = CustodyStore::default();
        s.insert(mk_bundle(1, 2, 100, Some(50))).unwrap();
        // wrong owner
        assert_eq!(s.acknowledge(100, None, 999), 0);
        // wrong logical id
        assert_eq!(s.acknowledge(999, None, 50), 0);
        assert_eq!(s.len(), 1);
    }

    // ── byte accounting consistency ───────────────────────────────────

    #[test]
    fn bytes_return_to_zero_after_full_drain() {
        let mut s = CustodyStore::default();
        for i in 0..5 {
            s.insert(mk_bundle(1, 2, i, None)).unwrap();
        }
        let total = s.bytes();
        assert!(total > 0);
        let drained = s.drain_for(2);
        assert_eq!(drained.len(), 5);
        assert_eq!(s.bytes(), 0);
        assert!(s.is_empty());
    }
}
