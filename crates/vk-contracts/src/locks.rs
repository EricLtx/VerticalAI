//! Lock surface (spec §3.4): LEASE for work-in-progress mutual exclusion (AP
//! semantics, exclusive within a partition), fences issued by a lock home for
//! irreversible actions. APPROVAL lives in `principal.rs`.
use crate::principal::Principal;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Lease {
    pub id: String,
    pub resource: String,
    pub holder: Principal,
    pub granted_at_ms: u64,
    pub ttl_ms: u64,
    pub fence: u64,
    /// Diagnostic only (spec §3.4): which connected partition granted it.
    pub partition: String,
}

impl Lease {
    pub fn expired(&self, now_ms: u64) -> bool {
        now_ms > self.granted_at_ms + self.ttl_ms
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LockError {
    #[error("resource is held by another principal")]
    Held,
}

/// Per-resource-class fence issuer. Default: the creating node (spec D5).
#[derive(Default)]
pub struct LockHome {
    next: BTreeMap<String, u64>,
}

impl LockHome {
    pub fn issue_fence(&mut self, resource: &str) -> u64 {
        let f = self.next.entry(resource.to_string()).or_insert(0);
        *f += 1;
        *f
    }
    /// Reinstate the highest fence a restart must not reissue. Fences are only
    /// useful if they are monotonic for the life of the resource, not for the
    /// life of the process, so the kernel replays the persisted value on boot.
    pub fn restore(&mut self, resource: &str, fence: u64) {
        let f = self.next.entry(resource.to_string()).or_insert(0);
        *f = (*f).max(fence);
    }
    pub fn is_stale(&self, resource: &str, fence: u64) -> bool {
        self.next
            .get(resource)
            .map(|latest| fence < *latest)
            .unwrap_or(true)
    }
}

#[derive(Default)]
pub struct LockTable {
    leases: BTreeMap<String, Lease>,
    counter: u64,
}

impl LockTable {
    pub fn acquire(
        &mut self,
        resource: &str,
        holder: Principal,
        now_ms: u64,
        ttl_ms: u64,
        partition: &str,
        home: &mut LockHome,
    ) -> Result<Lease, LockError> {
        if let Some(existing) = self
            .leases
            .values()
            .find(|l| l.resource == resource && l.partition == partition)
        {
            if !existing.expired(now_ms) && existing.holder != holder {
                return Err(LockError::Held);
            }
        }
        self.leases
            .retain(|_, l| !(l.resource == resource && l.partition == partition));
        self.counter += 1;
        let lease = Lease {
            id: format!("lease-{}", self.counter),
            resource: resource.into(),
            holder,
            granted_at_ms: now_ms,
            ttl_ms,
            fence: home.issue_fence(resource),
            partition: partition.into(),
        };
        self.leases.insert(lease.id.clone(), lease.clone());
        Ok(lease)
    }
    /// Reinstate a lease granted before a restart, without re-running mutual
    /// exclusion: a past `acquire` already decided this. Keeps the id counter
    /// ahead of every restored id so a later `acquire` cannot mint a duplicate.
    pub fn restore(&mut self, lease: Lease) {
        if let Some(n) = lease
            .id
            .strip_prefix("lease-")
            .and_then(|s| s.parse::<u64>().ok())
        {
            self.counter = self.counter.max(n);
        }
        self.leases.insert(lease.id.clone(), lease);
    }
    pub fn release(&mut self, lease_id: &str) {
        self.leases.remove(lease_id);
    }
    pub fn holder_of(&self, resource: &str, partition: &str, now_ms: u64) -> Option<&Principal> {
        self.leases
            .values()
            .find(|l| l.resource == resource && l.partition == partition && !l.expired(now_ms))
            .map(|l| &l.holder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(n: &str) -> Principal {
        Principal::Machine {
            node_id: n.into(),
            lease_id: format!("l-{n}"),
        }
    }

    #[test]
    fn second_holder_in_same_partition_is_refused_until_expiry() {
        let mut home = LockHome::default();
        let mut t = LockTable::default();
        let a = t
            .acquire("doc:1", m("a"), 0, 1_000, "p1", &mut home)
            .unwrap();
        assert_eq!(
            t.acquire("doc:1", m("b"), 500, 1_000, "p1", &mut home),
            Err(LockError::Held)
        );
        assert!(a.expired(1_001));
        assert!(t
            .acquire("doc:1", m("b"), 1_001, 1_000, "p1", &mut home)
            .is_ok());
    }

    #[test]
    fn fences_are_monotonic_and_stale_ones_detectable() {
        let mut home = LockHome::default();
        let f1 = home.issue_fence("invoice:42");
        let f2 = home.issue_fence("invoice:42");
        assert!(f2 > f1);
        assert!(home.is_stale("invoice:42", f1));
        assert!(!home.is_stale("invoice:42", f2));
    }

    #[test]
    fn release_frees_the_resource() {
        let mut home = LockHome::default();
        let mut t = LockTable::default();
        let a = t
            .acquire("doc:1", m("a"), 0, 1_000, "p1", &mut home)
            .unwrap();
        t.release(&a.id);
        assert!(t
            .acquire("doc:1", m("b"), 1, 1_000, "p1", &mut home)
            .is_ok());
        assert!(t.holder_of("doc:1", "p1", 1).is_some());
    }
}
