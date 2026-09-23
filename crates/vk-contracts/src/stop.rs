//! STOP as a kernel primitive and the autonomy liveness lease (spec §3.5, I4).
use crate::principal::Principal;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StopEvent {
    pub id: String,
    pub scope: String,
    pub issuer: Principal,
    pub hlc_ms: u64,
    pub causal_heads: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResumeEvent {
    pub id: String,
    pub cites: String,
    pub issuer: Principal,
    pub hlc_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LivenessLease {
    pub business: String,
    pub renewed_by_device: String,
    pub expires_at_ms: u64,
}

impl LivenessLease {
    pub fn alive(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StopError {
    #[error("STOP and RESUME require a human principal")]
    NotHuman,
    #[error("RESUME cites an unknown STOP")]
    UnknownStop,
}

/// Grow-only sets; `stopped` is a pure function of causal state (spec §3.5).
#[derive(Default, Debug, Clone)]
pub struct StopSet {
    stops: BTreeMap<String, StopEvent>,
    resumes: BTreeMap<String, ResumeEvent>,
}

impl StopSet {
    pub fn try_add_stop(&mut self, e: StopEvent) -> Result<(), StopError> {
        if !e.issuer.is_human() {
            return Err(StopError::NotHuman);
        }
        self.stops.insert(e.id.clone(), e);
        Ok(())
    }
    /// Convenience for tests and channels that already authenticated a human.
    pub fn add_stop(&mut self, e: StopEvent) {
        self.try_add_stop(e).expect("human-issued stop");
    }

    pub fn add_resume(&mut self, e: ResumeEvent) -> Result<(), StopError> {
        if !e.issuer.is_human() {
            return Err(StopError::NotHuman);
        }
        if !self.stops.contains_key(&e.cites) {
            return Err(StopError::UnknownStop);
        }
        self.resumes.insert(e.id.clone(), e);
        Ok(())
    }

    /// Is this STOP id known? A RESUME must cite one, and a caller has to be
    /// able to ask *before* it writes anything down: a resume refused after the
    /// fact still leaves a row that a later STOP taking that id would inherit.
    pub fn has_stop(&self, stop_id: &str) -> bool {
        self.stops.contains_key(stop_id)
    }

    pub fn stopped(&self, scope: &str) -> bool {
        let resumed: BTreeSet<&String> = self.resumes.values().map(|r| &r.cites).collect();
        self.stops
            .values()
            .any(|s| s.scope == scope && !resumed.contains(&s.id))
    }

    /// Union of both grow-only sets. Never removes anything (I3-compatible).
    pub fn merge(&mut self, other: &StopSet) {
        for (k, v) in &other.stops {
            self.stops.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, v) in &other.resumes {
            if self.stops.contains_key(&v.cites) {
                self.resumes.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::Principal;

    fn human() -> Principal {
        Principal::Human {
            device_id: "phone-1".into(),
        }
    }
    fn stop(id: &str, scope: &str) -> StopEvent {
        StopEvent {
            id: id.into(),
            scope: scope.into(),
            issuer: human(),
            hlc_ms: 1,
            causal_heads: vec![],
        }
    }
    fn resume(id: &str, cites: &str) -> ResumeEvent {
        ResumeEvent {
            id: id.into(),
            cites: cites.into(),
            issuer: human(),
            hlc_ms: 2,
        }
    }

    #[test]
    fn stop_is_effective_until_a_resume_cites_it() {
        let mut s = StopSet::default();
        s.add_stop(stop("s1", "business:acme"));
        assert!(s.stopped("business:acme"));
        s.add_resume(resume("r1", "s1")).unwrap();
        assert!(!s.stopped("business:acme"));
    }

    #[test]
    fn resume_without_a_known_stop_is_invalid() {
        let mut s = StopSet::default();
        assert_eq!(
            s.add_resume(resume("r1", "ghost")),
            Err(StopError::UnknownStop)
        );
    }

    #[test]
    fn machine_issued_stop_is_rejected_but_any_human_presence_suffices() {
        let mut s = StopSet::default();
        let m = StopEvent {
            issuer: Principal::Machine {
                node_id: "n".into(),
                lease_id: "l".into(),
            },
            ..stop("s1", "x")
        };
        assert_eq!(s.try_add_stop(m), Err(StopError::NotHuman));
        assert_eq!(s.try_add_stop(stop("s2", "x")), Ok(()));
    }

    #[test]
    fn merge_is_grow_only_so_a_stop_survives_concurrent_resume_of_another_stop() {
        let mut a = StopSet::default();
        a.add_stop(stop("s1", "x"));
        let mut b = StopSet::default();
        b.add_stop(stop("s2", "x"));
        b.add_resume(resume("r2", "s2")).unwrap();
        a.merge(&b);
        assert!(a.stopped("x"), "s1 was never resumed");
    }

    #[test]
    fn liveness_lease_expires() {
        let l = LivenessLease {
            business: "acme".into(),
            renewed_by_device: "phone-1".into(),
            expires_at_ms: 100,
        };
        assert!(l.alive(99));
        assert!(!l.alive(100));
    }
}
