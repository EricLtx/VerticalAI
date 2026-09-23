//! VerticalAI kernel contracts.
//!
//! Every public type here is a contract: its JSON Schema is generated into
//! `contracts/schemas/` and checked for drift in tests.

pub mod arch;
pub mod federation;
pub mod interceptors;
pub mod labels;
pub mod ledger;
pub mod locks;
pub mod module;
pub mod principal;
pub mod register;
pub mod stop;
pub mod storage;
pub mod syscalls;
pub mod testing;

use sha2::{Digest, Sha256};

/// Every contract type, by schema file name. Extend this in each task.
pub fn schema_registry() -> Vec<(&'static str, schemars::Schema)> {
    vec![
        ("label", schemars::schema_for!(labels::Label)),
        ("clearance", schemars::schema_for!(labels::Clearance)),
        ("register", schemars::schema_for!(register::Register)),
        ("arch_manifest", schemars::schema_for!(arch::ArchManifest)),
        ("principal", schemars::schema_for!(principal::Principal)),
        ("challenge", schemars::schema_for!(principal::Challenge)),
        ("approval", schemars::schema_for!(principal::Approval)),
        ("lease", schemars::schema_for!(locks::Lease)),
        ("stop_event", schemars::schema_for!(stop::StopEvent)),
        ("resume_event", schemars::schema_for!(stop::ResumeEvent)),
        ("liveness_lease", schemars::schema_for!(stop::LivenessLease)),
        ("ledger_event", schemars::schema_for!(ledger::LedgerEvent)),
        (
            "blob_envelope",
            schemars::schema_for!(storage::BlobEnvelope),
        ),
        ("shred_event", schemars::schema_for!(storage::ShredEvent)),
        (
            "module_manifest",
            schemars::schema_for!(module::ModuleManifest),
        ),
        (
            "validator_manifest",
            schemars::schema_for!(module::ValidatorManifest),
        ),
        ("gate_verdict", schemars::schema_for!(module::GateVerdict)),
        ("syscall_ctx", schemars::schema_for!(syscalls::Ctx)),
        ("tuf_root", schemars::schema_for!(federation::SignedRoot)),
    ]
}

/// SHA-256 over canonical JSON of `value`, rendered as `sha256:<hex>`.
/// Canonical = `serde_json::to_vec`; struct field order is declaration order.
pub fn hash_canonical<T: serde::Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("contract types always serialize");
    hash_bytes(&bytes)
}

/// SHA-256 over raw bytes, rendered as `sha256:<hex>`.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_prefixed() {
        let h = hash_bytes(b"verticalai");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64);
        assert_eq!(h, hash_bytes(b"verticalai"));
    }
}
