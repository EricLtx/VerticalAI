//! Module, validator and gate-verdict formats (spec §4.1, §4.3, D11).
use crate::labels::Origin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    Skill,
    Process,
    Automation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AutonomyProfile {
    pub human_required_kinds: BTreeSet<String>,
    pub auto_approve_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Provenance {
    pub content_hash: String,
    pub lineage: Vec<String>,
    pub signer: String,
    pub arch_compat: Vec<String>,
    pub origin_taints: BTreeSet<Origin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ModuleManifest {
    pub name: String,
    pub kind: ModuleKind,
    pub version: String,
    pub machine_evolved: bool,
    pub files: Vec<String>,
    pub provenance: Provenance,
    pub pool_epoch: Option<String>,
    pub autonomy_profile: Option<AutonomyProfile>,
    pub tags: BTreeSet<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModuleError {
    #[error("machine-evolved module contains a script: {0}")]
    ScriptInEvolvedModule(String),
    #[error("machine-evolved module contains a validator: {0}")]
    ValidatorInEvolvedModule(String),
    #[error("modules tagged decision_about_person cannot allow auto-approval (GDPR Art. 22)")]
    AutoApproveForbidden,
}

const SCRIPT_EXTENSIONS: &[&str] = &[
    "py", "sh", "ps1", "bat", "cmd", "js", "ts", "exe", "dll", "so", "dylib", "wasm", "rb", "php",
];

impl ModuleManifest {
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.machine_evolved {
            for f in &self.files {
                let ext = f.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
                if SCRIPT_EXTENSIONS.contains(&ext.as_str()) {
                    return Err(ModuleError::ScriptInEvolvedModule(f.clone()));
                }
                if f.starts_with("validators/") {
                    return Err(ModuleError::ValidatorInEvolvedModule(f.clone()));
                }
            }
        }
        if self.tags.contains("decision_about_person") {
            if let Some(p) = &self.autonomy_profile {
                if p.auto_approve_allowed {
                    return Err(ModuleError::AutoApproveForbidden);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnchorCase {
    pub input_hash: String,
    pub expected_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ValidatorManifest {
    pub name: String,
    pub artefact_type: String,
    pub anchor_suite: Vec<AnchorCase>,
    pub signers: Vec<String>,
    pub community: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidatorError {
    #[error("community validators require two signers")]
    CommunityNeedsTwoSigners,
}

impl ValidatorManifest {
    pub fn validate(&self) -> Result<(), ValidatorError> {
        if self.community && self.signers.len() < 2 {
            return Err(ValidatorError::CommunityNeedsTwoSigners);
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GateKind {
    AnnexIii,
    Declassification,
    OutputMarking,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GateVerdict {
    pub gate: GateKind,
    pub subject_hash: String,
    pub pass: bool,
    pub evidence_hash: String,
    pub signer: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill(files: &[&str], evolved: bool) -> ModuleManifest {
        ModuleManifest {
            name: "quote-drafter".into(),
            kind: ModuleKind::Skill,
            version: "0.1.0".into(),
            machine_evolved: evolved,
            files: files.iter().map(|s| s.to_string()).collect(),
            provenance: Provenance {
                content_hash: "sha256:c".into(),
                lineage: vec![],
                signer: "founder".into(),
                arch_compat: vec![],
                origin_taints: Default::default(),
            },
            pool_epoch: None,
            autonomy_profile: None,
            tags: Default::default(),
        }
    }

    #[test]
    fn machine_evolved_modules_may_not_contain_scripts_or_validators() {
        assert!(skill(&["SKILL.md", "references/style.md"], true)
            .validate()
            .is_ok());
        assert_eq!(
            skill(&["SKILL.md", "scripts/run.py"], true).validate(),
            Err(ModuleError::ScriptInEvolvedModule("scripts/run.py".into()))
        );
        assert_eq!(
            skill(&["SKILL.md", "validators/totals.json"], true).validate(),
            Err(ModuleError::ValidatorInEvolvedModule(
                "validators/totals.json".into()
            ))
        );
        assert!(
            skill(&["SKILL.md", "scripts/run.py"], false)
                .validate()
                .is_ok(),
            "human-authored modules may ship scripts"
        );
    }

    #[test]
    fn decision_about_person_modules_cannot_be_auto_approved() {
        let mut m = skill(&["SKILL.md"], false);
        m.tags.insert("decision_about_person".into());
        m.autonomy_profile = Some(AutonomyProfile {
            human_required_kinds: Default::default(),
            auto_approve_allowed: true,
        });
        assert_eq!(m.validate(), Err(ModuleError::AutoApproveForbidden));
    }

    #[test]
    fn community_validators_need_two_signers() {
        let v = ValidatorManifest {
            name: "quote-totals".into(),
            artefact_type: "quote".into(),
            anchor_suite: vec![],
            signers: vec!["a".into()],
            community: true,
        };
        assert_eq!(v.validate(), Err(ValidatorError::CommunityNeedsTwoSigners));
    }
}
