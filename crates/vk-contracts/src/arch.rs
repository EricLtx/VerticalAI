//! Arch manifests (spec §3.7). An arch is any AI system behind an adapter.
use crate::hash_canonical;
use crate::labels::Clearance;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Generate,
    Embed,
    Predict,
    Perceive,
    Plan,
    Judge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Locality {
    Local,
    OnPrem,
    Peer,
    Cloud,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Determinism {
    SeededDeterministic,
    NonDeterministic,
}

/// Everything that changes model behaviour. Any change = a new arch id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArchIdentity {
    pub weights_sha256: String,
    pub engine: String,
    pub engine_version: String,
    pub backend: String,
    pub quant: String,
    pub kv_cache: String,
    pub threads: u32,
    pub batch: u32,
    pub sampling: BTreeMap<String, String>,
    pub seed: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArchManifest {
    pub name: String,
    pub capabilities: BTreeSet<Capability>,
    pub locality: Locality,
    /// ISO 3166 country code, or "EU".
    pub jurisdiction: String,
    pub retention_days: Option<u32>,
    /// What a thousand prompt tokens cost on this arch, in euros — or `None`
    /// when this node has no price list for it.
    ///
    /// `None` is not zero and must never be rendered as one (SP1b Task 2b fix
    /// round 1, Ruling 30). `Some(0.0)` is a claim: nothing is billed, which
    /// is true of a local model and of a subscription. `None` is the absence
    /// of a claim — the Bedrock arch, whose prices are AWS's and which this
    /// node has not read — and an operator shown `0` there would believe the
    /// calls were free. `vk top` prints `?`.
    pub cost_per_1k_tokens_eur: Option<f64>,
    pub latency_ms_p50: u32,
    pub context_ceiling: u32,
    pub determinism: Determinism,
    pub identity: ArchIdentity,
    pub clearance: Clearance,
    /// True only if the kernel launched and contains the inference process (spec §3.3).
    pub governed: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArchError {
    #[error("manifest declares no capabilities")]
    NoCapabilities,
    #[error("context_ceiling must be > 0")]
    ZeroContext,
}

impl ArchManifest {
    pub fn arch_id(&self) -> String {
        hash_canonical(&self.identity)
    }

    pub fn validate(&self) -> Result<(), ArchError> {
        if self.capabilities.is_empty() {
            return Err(ArchError::NoCapabilities);
        }
        if self.context_ceiling == 0 {
            return Err(ArchError::ZeroContext);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::*;

    fn gemma() -> ArchManifest {
        ArchManifest {
            name: "gemma-4-9b".into(),
            capabilities: [Capability::Generate, Capability::Plan].into(),
            locality: Locality::Local,
            jurisdiction: "FR".into(),
            retention_days: None,
            cost_per_1k_tokens_eur: Some(0.0),
            latency_ms_p50: 900,
            context_ceiling: 8192,
            determinism: Determinism::SeededDeterministic,
            identity: ArchIdentity {
                weights_sha256: "sha256:abc".into(),
                engine: "llama-server".into(),
                engine_version: "b5000".into(),
                backend: "cuda".into(),
                quant: "Q4_K_M".into(),
                kv_cache: "f16".into(),
                threads: 8,
                batch: 512,
                sampling: Default::default(),
                seed: Some(7),
            },
            clearance: Clearance {
                max_scope: Scope::Personal,
                third_party_allowed: true,
            },
            governed: true,
        }
    }

    #[test]
    fn arch_id_changes_when_any_identity_field_changes() {
        let a = gemma();
        let mut b = gemma();
        b.identity.quant = "Q8_0".into();
        let mut c = gemma();
        c.identity.seed = Some(8);
        assert_ne!(a.arch_id(), b.arch_id());
        assert_ne!(a.arch_id(), c.arch_id());
        assert_eq!(a.arch_id(), gemma().arch_id());
    }

    #[test]
    fn arch_id_ignores_non_identity_fields() {
        let a = gemma();
        let mut b = gemma();
        b.latency_ms_p50 = 5;
        assert_eq!(a.arch_id(), b.arch_id());
    }

    #[test]
    fn manifest_must_declare_at_least_one_capability() {
        let mut a = gemma();
        a.capabilities.clear();
        assert!(a.validate().is_err());
    }
}
