//! The task-state IR (spec §3.2): the only thing that crosses arch boundaries.
use crate::labels::Label;
use crate::labels::Origin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct RegisterId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub content: String,
    pub origin: Origin,
    pub source_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtefactRef {
    pub hash: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Register {
    pub id: RegisterId,
    pub task_id: String,
    pub label: Label,
    pub goal: String,
    pub constraints: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub decisions: Vec<String>,
    pub open_questions: Vec<String>,
    pub artefacts: Vec<ArtefactRef>,
}

impl Register {
    /// Information-flow rule: a task that reads `other` taints everything it writes.
    pub fn with_read(&mut self, other: &Label) {
        self.label = self.label.join(other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::*;

    fn reg() -> Register {
        Register {
            id: RegisterId("r1".into()),
            task_id: "t1".into(),
            label: Label::bottom(),
            goal: "draft a quote".into(),
            constraints: vec![],
            evidence: vec![],
            decisions: vec![],
            open_questions: vec![],
            artefacts: vec![],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let r = reg();
        let s = serde_json::to_string(&r).unwrap();
        let back: Register = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn reading_a_higher_label_raises_the_register_label() {
        let mut r = reg();
        r.with_read(&Label {
            scope: Scope::Personal,
            data_class: DataClass::Own,
            origins: [Origin::Web].into(),
        });
        assert_eq!(r.label.scope, Scope::Personal);
        assert!(r.label.origins.contains(&Origin::Web));
    }
}
