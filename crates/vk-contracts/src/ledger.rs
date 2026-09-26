//! Per-node hash-chained ledger (spec §3.9): three stamps per event, retention
//! class per event type, receive guard against clock poisoning.
use crate::hash_canonical;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u32,
    pub node: String,
}

pub struct HlcClock {
    node: String,
    last: Hlc,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("clock anomaly from {node}: remote wall {remote_wall_ms} vs local {local_wall_ms}")]
pub struct ClockAnomaly {
    pub node: String,
    pub remote_wall_ms: u64,
    pub local_wall_ms: u64,
}

impl HlcClock {
    pub fn new(node: &str) -> Self {
        Self {
            node: node.into(),
            last: Hlc {
                wall_ms: 0,
                counter: 0,
                node: node.into(),
            },
        }
    }

    /// A clock that continues from `last` — the newest stamp on this node's
    /// record — so that after a restart on a wall clock that went backwards
    /// the next `now` still sorts after everything already appended (SP1a
    /// review M3). The stamp is taken as the clock's own: same wall, same
    /// counter, this node's name.
    pub fn resume(node: &str, last: &Hlc) -> Self {
        Self {
            node: node.into(),
            last: Hlc {
                wall_ms: last.wall_ms,
                counter: last.counter,
                node: node.into(),
            },
        }
    }

    pub fn now(&mut self, wall_ms: u64) -> Hlc {
        if wall_ms > self.last.wall_ms {
            self.last = Hlc {
                wall_ms,
                counter: 0,
                node: self.node.clone(),
            };
        } else {
            self.last.counter += 1;
        }
        self.last.clone()
    }

    /// Spec §3.9: ignore the physical component of any message beyond `max_skew_ms` ahead.
    pub fn receive(
        &mut self,
        remote: &Hlc,
        wall_ms: u64,
        max_skew_ms: u64,
    ) -> Result<Hlc, ClockAnomaly> {
        if remote.wall_ms > wall_ms + max_skew_ms {
            return Err(ClockAnomaly {
                node: remote.node.clone(),
                remote_wall_ms: remote.wall_ms,
                local_wall_ms: wall_ms,
            });
        }
        let max_wall = wall_ms.max(self.last.wall_ms).max(remote.wall_ms);
        let counter = if max_wall == self.last.wall_ms && max_wall == remote.wall_ms {
            self.last.counter.max(remote.counter) + 1
        } else if max_wall == self.last.wall_ms {
            self.last.counter + 1
        } else if max_wall == remote.wall_ms {
            remote.counter + 1
        } else {
            0
        };
        self.last = Hlc {
            wall_ms: max_wall,
            counter,
            node: self.node.clone(),
        };
        Ok(self.last.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClockQuality {
    Synced,
    Unsynced,
    ManualChangeDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    Ephemeral,
    Operational90d,
    Compliance6m,
    Compliance10y,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LedgerEvent {
    pub seq: u64,
    pub prev_hash: String,
    pub hash: String,
    pub kind: String,
    pub retention: RetentionClass,
    pub wall_ms: u64,
    pub clock_quality: ClockQuality,
    pub hlc: Hlc,
    pub causal_heads: Vec<String>,
    /// Commits to ciphertext, never to plaintext (spec §3.9).
    pub payload_hash: String,
}

#[derive(Serialize)]
struct Unhashed<'a> {
    seq: u64,
    prev_hash: &'a str,
    kind: &'a str,
    retention: RetentionClass,
    wall_ms: u64,
    clock_quality: ClockQuality,
    hlc: &'a Hlc,
    causal_heads: &'a [String],
    payload_hash: &'a str,
}

#[derive(Default)]
pub struct Ledger {
    events: Vec<LedgerEvent>,
}

impl Ledger {
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        kind: &str,
        retention: RetentionClass,
        wall_ms: u64,
        clock_quality: ClockQuality,
        hlc: Hlc,
        causal_heads: Vec<String>,
        payload_hash: String,
    ) -> &LedgerEvent {
        let seq = self.events.len() as u64;
        let prev_hash = self
            .events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "sha256:genesis".into());
        let hash = hash_canonical(&Unhashed {
            seq,
            prev_hash: &prev_hash,
            kind,
            retention,
            wall_ms,
            clock_quality,
            hlc: &hlc,
            causal_heads: &causal_heads,
            payload_hash: &payload_hash,
        });
        self.events.push(LedgerEvent {
            seq,
            prev_hash,
            hash,
            kind: kind.into(),
            retention,
            wall_ms,
            clock_quality,
            hlc,
            causal_heads,
            payload_hash,
        });
        self.events.last().unwrap()
    }

    pub fn verify_chain(&self) -> bool {
        self.verify_from(0)
    }

    /// Does the chain hold from `from` on, given a prefix that does? Every
    /// link and every hash of `events[from..]` is recomputed, the first of
    /// them against the hash of `events[from - 1]` (or genesis). A store that
    /// has already verified a prefix asks only about what was appended since
    /// (SP1a review M13); `verify_chain` is this from zero.
    pub fn verify_from(&self, from: usize) -> bool {
        let from = from.min(self.events.len());
        let mut prev = match from.checked_sub(1) {
            None => "sha256:genesis".to_string(),
            Some(i) => self.events[i].hash.clone(),
        };
        for e in &self.events[from..] {
            if e.prev_hash != prev {
                return false;
            }
            let recomputed = hash_canonical(&Unhashed {
                seq: e.seq,
                prev_hash: &e.prev_hash,
                kind: &e.kind,
                retention: e.retention,
                wall_ms: e.wall_ms,
                clock_quality: e.clock_quality,
                hlc: &e.hlc,
                causal_heads: &e.causal_heads,
                payload_hash: &e.payload_hash,
            });
            if recomputed != e.hash {
                return false;
            }
            prev = e.hash.clone();
        }
        true
    }

    pub fn events(&self) -> &[LedgerEvent] {
        &self.events
    }

    /// Re-load a persisted event without recomputing it (used by on-disk segments).
    pub fn push_verified(&mut self, e: LedgerEvent) {
        self.events.push(e);
    }

    #[doc(hidden)]
    pub fn tamper_for_test(&mut self, idx: usize, payload_hash: &str) {
        self.events[idx].payload_hash = payload_hash.into();
    }
}

/// Ledger event kinds this system emits. Previously tracked only in prose
/// (the SP1a plan's list of every kind a task may append); `boot.forced`
/// (founder decision 2026-09-24) is the first kind added here instead.
/// `LedgerEvent::kind` stays a plain string on the wire — a node must be able
/// to read a kind appended by a newer version it does not otherwise
/// understand, so `append` never rejects one — but a caller that is about to
/// mint a new kind of event, or a test guarding against a typo, checks it
/// against this list first.
pub const ALLOWED_KINDS: &[&str] = &[
    "boot",
    "boot.forced",
    "task.submitted",
    "task.step",
    "artefact.released",
    "register.written",
    "infer",
    "infer.projected",
    "lease.granted",
    "approval.recorded",
    "stop",
    "resume",
    "automation.ran",
    "module.promoted",
    "module.exported",
    "arch.mounted",
    "arch.unmounted",
    "device.enrolled",
    // The egress a confined harness made while it ran (founder decision
    // 2026-09-24, SP1b Task 4): one event per harness run, naming the endpoints
    // it talked to, whether the kernel contained it, and how it ended. Its own
    // kind rather than a field on `task.step` so an auditor can find every run's
    // network activity by kind alone; `kind` stays a free string on the wire, so
    // this changes no schema, exactly as `boot.forced` did.
    "harness.connections",
    "shred",
];

/// Is `kind` one this node knows how to append?
pub fn is_allowed_kind(kind: &str) -> bool {
    ALLOWED_KINDS.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_is_monotonic_even_if_wall_clock_goes_backwards() {
        let mut c = HlcClock::new("n1");
        let a = c.now(1_000);
        let b = c.now(900);
        assert!(b > a);
    }

    #[test]
    fn receive_guard_rejects_far_future_and_flags_anomaly() {
        let mut c = HlcClock::new("n1");
        let remote = Hlc {
            wall_ms: 10_000_000,
            counter: 0,
            node: "evil".into(),
        };
        assert!(matches!(
            c.receive(&remote, 1_000, 5_000),
            Err(ClockAnomaly { .. })
        ));
        let ok = Hlc {
            wall_ms: 1_500,
            counter: 0,
            node: "peer".into(),
        };
        assert!(c.receive(&ok, 1_000, 5_000).is_ok());
    }

    /// M3: a resumed clock never hands out a stamp below the one it was
    /// resumed from, whatever the wall clock says.
    #[test]
    fn a_resumed_clock_continues_from_the_stamp_it_was_given() {
        let last = Hlc {
            wall_ms: 5_000,
            counter: 3,
            node: "n1".into(),
        };
        let mut c = HlcClock::resume("n1", &last);
        let next = c.now(900);
        assert!(next > last, "{next:?} must sort after {last:?}");
        assert_eq!((next.wall_ms, next.counter), (5_000, 4));
        let later = c.now(6_000);
        assert_eq!((later.wall_ms, later.counter), (6_000, 0));
        // The clock keeps its own name even when resumed from another's stamp.
        let mut other = HlcClock::resume(
            "n2",
            &Hlc {
                wall_ms: 1,
                counter: 0,
                node: "n1".into(),
            },
        );
        assert_eq!(other.now(1).node, "n2");
    }

    /// M13: a chain verified from `from` checks the link into the prefix it
    /// was given and everything after it, and nothing before.
    #[test]
    fn verify_from_checks_the_suffix_and_its_link_into_the_prefix() {
        let mut l = Ledger::default();
        let mut c = HlcClock::new("n1");
        for n in 1..=4 {
            l.append(
                "boot",
                RetentionClass::Operational90d,
                n,
                ClockQuality::Synced,
                c.now(n),
                vec![],
                format!("sha256:p{n}"),
            );
        }
        assert!(l.verify_from(0));
        assert!(l.verify_from(2));
        assert!(l.verify_from(4), "an empty suffix holds");
        assert!(l.verify_from(9), "past the end is an empty suffix");
        l.tamper_for_test(1, "sha256:evil");
        assert!(!l.verify_from(0));
        assert!(!l.verify_from(1));
        // Rewritten event 1 changes nothing about events 2..: their links
        // and hashes still recompute among themselves.
        assert!(l.verify_from(2));
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let mut l = Ledger::default();
        let mut c = HlcClock::new("n1");
        l.append(
            "task.submitted",
            RetentionClass::Operational90d,
            1,
            ClockQuality::Synced,
            c.now(1),
            vec![],
            "sha256:p1".into(),
        );
        l.append(
            "lease.granted",
            RetentionClass::Operational90d,
            2,
            ClockQuality::Synced,
            c.now(2),
            vec![],
            "sha256:p2".into(),
        );
        assert!(l.verify_chain());
        l.tamper_for_test(0, "sha256:evil");
        assert!(!l.verify_chain());
    }

    /// Founder decision 2026-09-24: the daemon's `--force` override is itself
    /// on the record, so `boot.forced` must be a kind this node knows how to
    /// append.
    #[test]
    fn boot_forced_is_an_allowed_kind() {
        assert!(is_allowed_kind("boot.forced"));
    }

    #[test]
    fn an_unlisted_kind_is_not_allowed() {
        assert!(!is_allowed_kind("not.a.real.kind"));
    }

    /// Founder decision 2026-09-24 (SP1b Task 4): a confined harness's egress is
    /// its own ledger kind, so `record_harness_connection` can append it.
    #[test]
    fn harness_connections_is_an_allowed_kind() {
        assert!(is_allowed_kind("harness.connections"));
    }
}
