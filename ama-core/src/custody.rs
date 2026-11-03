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
    /// Restore a previously-held incomplete fragment, under the same delivery lock.
    pub fn restore(&mut self, bundle: DtnBundle) {
        let size = serde_json::to_vec(&bundle.body)
            .expect("previously encoded JSON")
            .len();
        self.insert_sized(bundle, size);
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
