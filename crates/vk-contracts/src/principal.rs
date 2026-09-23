//! Principals and the human approval ceremony (spec §3.6, invariant I1).
//! The kernel never accepts a caller-asserted principal; `Principal` values are
//! constructed by the channel layer. `SoftwareHumanKey` is the test stand-in for
//! TPM / Secure Enclave keys; production keys implement `HumanKey`.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Principal {
    Machine { node_id: String, lease_id: String },
    Human { device_id: String },
}

impl Principal {
    pub fn is_human(&self) -> bool {
        matches!(self, Principal::Human { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Challenge {
    pub resource: String,
    pub action_digest: String,
    pub nonce: String,
    pub expires_at_ms: u64,
}

impl Challenge {
    /// H(resource || action_digest || nonce || expiry) — what the hardware key signs.
    pub fn digest(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(self.resource.as_bytes());
        h.update(b"|");
        h.update(self.action_digest.as_bytes());
        h.update(b"|");
        h.update(self.nonce.as_bytes());
        h.update(b"|");
        h.update(self.expires_at_ms.to_be_bytes());
        h.finalize().to_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    Test,
    Audit,
    Human,
}

/// An immutable, signed, mergeable record. Promotion = a valid approval exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Approval {
    pub subject_hash: String,
    pub kind: ApprovalKind,
    pub approver: Principal,
    pub challenge: Option<Challenge>,
    pub signature_hex: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PrincipalError {
    #[error("approval of kind human requires a human principal")]
    NotHuman,
    #[error("challenge expired")]
    Expired,
    #[error("challenge or signature missing")]
    Incomplete,
    #[error("device not enrolled")]
    UnknownDevice,
    #[error("signature does not verify")]
    BadSignature,
    #[error("approval subject does not match challenge action")]
    SubjectMismatch,
}

pub trait HumanKey {
    fn device_id(&self) -> String;
    fn sign(&self, msg: &[u8]) -> [u8; 64];
    fn verifying_key_bytes(&self) -> [u8; 32];
}

/// Software ed25519 key — tests and development only.
pub struct SoftwareHumanKey {
    device_id: String,
    key: SigningKey,
}

impl SoftwareHumanKey {
    pub fn generate(device_id: &str) -> Self {
        Self {
            device_id: device_id.to_string(),
            key: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }
}

impl HumanKey for SoftwareHumanKey {
    fn device_id(&self) -> String {
        self.device_id.clone()
    }
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }
    fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

/// Enrolled devices (spec §3.6): populated only by the admin enrolment flow.
#[derive(Default)]
pub struct DeviceRegistry {
    keys: BTreeMap<String, [u8; 32]>,
}

impl DeviceRegistry {
    pub fn register(&mut self, device_id: String, vk: [u8; 32]) {
        self.keys.insert(device_id, vk);
    }
    /// Which devices are enrolled, sorted. Ids only: a verifying key is a
    /// public value, but nothing outside the registry needs it, and a report
    /// that carries one invites it into a log.
    pub fn ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }
    pub fn verify(
        &self,
        device_id: &str,
        msg: &[u8],
        sig: &[u8; 64],
    ) -> Result<(), PrincipalError> {
        let vk_bytes = self
            .keys
            .get(device_id)
            .ok_or(PrincipalError::UnknownDevice)?;
        let vk = VerifyingKey::from_bytes(vk_bytes).map_err(|_| PrincipalError::BadSignature)?;
        vk.verify(msg, &Signature::from_bytes(sig))
            .map_err(|_| PrincipalError::BadSignature)
    }
}

impl Approval {
    /// I1 check for human approvals. Machine approvals (test/audit) are verified elsewhere.
    pub fn verify_human(
        &self,
        devices: &DeviceRegistry,
        now_ms: u64,
    ) -> Result<(), PrincipalError> {
        let device_id = match &self.approver {
            Principal::Human { device_id } => device_id,
            _ => return Err(PrincipalError::NotHuman),
        };
        let (ch, sig_hex) = match (&self.challenge, &self.signature_hex) {
            (Some(c), Some(s)) => (c, s),
            _ => return Err(PrincipalError::Incomplete),
        };
        if ch.action_digest != self.subject_hash {
            return Err(PrincipalError::SubjectMismatch);
        }
        if now_ms >= ch.expires_at_ms {
            return Err(PrincipalError::Expired);
        }
        let sig_vec = hex::decode(sig_hex).map_err(|_| PrincipalError::BadSignature)?;
        let sig: [u8; 64] = sig_vec
            .try_into()
            .map_err(|_| PrincipalError::BadSignature)?;
        devices.verify(device_id, &ch.digest(), &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(exp: u64) -> Challenge {
        Challenge {
            resource: "invoice:42".into(),
            action_digest: "sha256:deadbeef".into(),
            nonce: "n1".into(),
            expires_at_ms: exp,
        }
    }

    fn approval(subject: &str, ch: Challenge, sig: [u8; 64]) -> Approval {
        Approval {
            subject_hash: subject.into(),
            kind: ApprovalKind::Human,
            approver: Principal::Human {
                device_id: "phone-1".into(),
            },
            challenge: Some(ch),
            signature_hex: Some(hex::encode(sig)),
        }
    }

    #[test]
    fn human_approval_verifies_with_enrolled_device_key() {
        let key = SoftwareHumanKey::generate("phone-1");
        let mut reg = DeviceRegistry::default();
        reg.register(key.device_id(), key.verifying_key_bytes());
        let ch = challenge(10_000);
        let sig = key.sign(&ch.digest());
        assert_eq!(
            approval("sha256:deadbeef", ch, sig).verify_human(&reg, 5_000),
            Ok(())
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let key = SoftwareHumanKey::generate("phone-1");
        let mut reg = DeviceRegistry::default();
        reg.register(key.device_id(), key.verifying_key_bytes());
        let ch = challenge(1_000);
        let sig = key.sign(&ch.digest());
        assert_eq!(
            approval("sha256:deadbeef", ch, sig).verify_human(&reg, 5_000),
            Err(PrincipalError::Expired)
        );
    }

    #[test]
    fn forged_or_unenrolled_signature_is_rejected() {
        let key = SoftwareHumanKey::generate("phone-1");
        let impostor = SoftwareHumanKey::generate("phone-1");
        let mut reg = DeviceRegistry::default();
        reg.register(key.device_id(), key.verifying_key_bytes());
        let ch = challenge(10_000);
        let sig = impostor.sign(&ch.digest());
        assert_eq!(
            approval("sha256:deadbeef", ch, sig).verify_human(&reg, 5_000),
            Err(PrincipalError::BadSignature)
        );
    }

    #[test]
    fn machine_principal_cannot_carry_a_human_approval() {
        let reg = DeviceRegistry::default();
        let ap = Approval {
            subject_hash: "sha256:x".into(),
            kind: ApprovalKind::Human,
            approver: Principal::Machine {
                node_id: "n1".into(),
                lease_id: "l1".into(),
            },
            challenge: None,
            signature_hex: None,
        };
        assert_eq!(ap.verify_human(&reg, 0), Err(PrincipalError::NotHuman));
    }

    #[test]
    fn approval_subject_must_match_challenge_action() {
        let key = SoftwareHumanKey::generate("phone-1");
        let mut reg = DeviceRegistry::default();
        reg.register(key.device_id(), key.verifying_key_bytes());
        let ch = challenge(10_000);
        let sig = key.sign(&ch.digest());
        assert_eq!(
            approval("sha256:other", ch, sig).verify_human(&reg, 5_000),
            Err(PrincipalError::SubjectMismatch)
        );
    }
}
