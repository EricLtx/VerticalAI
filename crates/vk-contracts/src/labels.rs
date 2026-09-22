//! Information-flow labels (spec §3.2, §4.2). A `Label` is a join-semilattice
//! element; every object written by a task carries the join of what the task read.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Ordered low → high. `Holdout` is the top: readable only by the rehearsal verifier role.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Public,
    Vertical,
    Business,
    Personal,
    Holdout,
}

/// Ordered low → high; `Unknown` is treated as third-party and is the most restrictive.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Own,
    ThirdPartyMandated,
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    OwnerAuthored,
    OwnerShipped,
    ThirdPartyInbound,
    Web,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Label {
    pub scope: Scope,
    pub data_class: DataClass,
    pub origins: BTreeSet<Origin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Clearance {
    pub max_scope: Scope,
    pub third_party_allowed: bool,
}

impl Label {
    pub fn bottom() -> Label {
        Label {
            scope: Scope::Public,
            data_class: DataClass::Own,
            origins: BTreeSet::new(),
        }
    }

    pub fn join(&self, other: &Label) -> Label {
        Label {
            scope: self.scope.max(other.scope),
            data_class: self.data_class.max(other.data_class),
            origins: self.origins.union(&other.origins).copied().collect(),
        }
    }

    /// I2 predicate: may an object with this label be projected to a principal with `clearance`?
    pub fn flows_to(&self, clearance: &Clearance) -> bool {
        if self.scope == Scope::Holdout {
            return false;
        }
        let scope_ok = self.scope <= clearance.max_scope;
        let class_ok = self.data_class == DataClass::Own || clearance.third_party_allowed;
        scope_ok && class_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_takes_the_maximum_scope_and_unions_origins() {
        let a = Label {
            scope: Scope::Business,
            data_class: DataClass::Own,
            origins: [Origin::OwnerAuthored].into(),
        };
        let b = Label {
            scope: Scope::Personal,
            data_class: DataClass::Unknown,
            origins: [Origin::Web].into(),
        };
        let j = a.join(&b);
        assert_eq!(j.scope, Scope::Personal);
        assert_eq!(j.data_class, DataClass::Unknown);
        assert_eq!(j.origins.len(), 2);
    }

    #[test]
    fn join_is_idempotent_and_bottom_is_identity() {
        let a = Label {
            scope: Scope::Vertical,
            data_class: DataClass::ThirdPartyMandated,
            origins: [Origin::ThirdPartyInbound].into(),
        };
        assert_eq!(a.join(&a), a);
        assert_eq!(a.join(&Label::bottom()), a);
    }

    #[test]
    fn holdout_never_flows_to_any_clearance() {
        let l = Label {
            scope: Scope::Holdout,
            data_class: DataClass::Own,
            origins: Default::default(),
        };
        let c = Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        };
        assert!(!l.flows_to(&c));
    }

    #[test]
    fn third_party_data_needs_explicit_clearance() {
        let l = Label {
            scope: Scope::Business,
            data_class: DataClass::Unknown,
            origins: Default::default(),
        };
        assert!(!l.flows_to(&Clearance {
            max_scope: Scope::Business,
            third_party_allowed: false
        }));
        assert!(l.flows_to(&Clearance {
            max_scope: Scope::Business,
            third_party_allowed: true
        }));
    }
}
