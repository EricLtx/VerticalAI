//! Federation trust roles (spec §4.4, D10): TUF-style root with threshold signatures.
use crate::hash_canonical;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RootRole {
    pub keys: BTreeMap<String, String>,
    pub threshold: u8,
    pub expires_at_ms: u64,
}

impl RootRole {
    pub fn digest(&self) -> Vec<u8> {
        hash_canonical(self).into_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SignedRoot {
    pub root: RootRole,
    pub signatures: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FederationError {
    #[error("root expired; failing closed")]
    Expired,
    #[error("threshold not met: {have} of {need}")]
    ThresholdNotMet { have: usize, need: usize },
}

impl SignedRoot {
    pub fn verify(&self, now_ms: u64) -> Result<(), FederationError> {
        if now_ms >= self.root.expires_at_ms {
            return Err(FederationError::Expired);
        }
        let msg = self.root.digest();
        let mut valid = 0usize;
        for (key_id, sig_hex) in &self.signatures {
            let Some(vk_hex) = self.root.keys.get(key_id) else {
                continue;
            };
            let (Ok(vk_bytes), Ok(sig_bytes)) = (hex::decode(vk_hex), hex::decode(sig_hex)) else {
                continue;
            };
            let (Ok(vk_arr), Ok(sig_arr)) = (
                <[u8; 32]>::try_from(vk_bytes),
                <[u8; 64]>::try_from(sig_bytes),
            ) else {
                continue;
            };
            let Ok(vk) = VerifyingKey::from_bytes(&vk_arr) else {
                continue;
            };
            if vk.verify(&msg, &Signature::from_bytes(&sig_arr)).is_ok() {
                valid += 1;
            }
        }
        let need = self.root.threshold as usize;
        if valid < need {
            return Err(FederationError::ThresholdNotMet { have: valid, need });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::{HumanKey, SoftwareHumanKey};

    fn signed(n_sign: usize, now: u64) -> SignedRoot {
        let keys: Vec<SoftwareHumanKey> = (0..3)
            .map(|i| SoftwareHumanKey::generate(&format!("k{i}")))
            .collect();
        let root = RootRole {
            keys: keys
                .iter()
                .map(|k| (k.device_id(), hex::encode(k.verifying_key_bytes())))
                .collect(),
            threshold: 2,
            expires_at_ms: now + 1,
        };
        let msg = root.digest();
        let signatures = keys
            .iter()
            .take(n_sign)
            .map(|k| (k.device_id(), hex::encode(k.sign(&msg))))
            .collect();
        SignedRoot { root, signatures }
    }

    #[test]
    fn two_of_three_verifies_one_does_not() {
        assert_eq!(signed(2, 100).verify(100), Ok(()));
        assert_eq!(
            signed(1, 100).verify(100),
            Err(FederationError::ThresholdNotMet { have: 1, need: 2 })
        );
    }

    #[test]
    fn expired_root_fails_closed() {
        assert_eq!(signed(3, 100).verify(101), Err(FederationError::Expired));
    }
}
