//! The passkey verifier (SP1b Task 5): `webauthn-rs`, configured for the one
//! origin the pages are served on, and the small amount of naming around it.
//!
//! Nothing here decides who is human. `webauthn-rs` checks a registration or
//! an assertion against what the browser and the authenticator produced —
//! origin, relying-party id, challenge, signature over the authenticator data
//! with the enrolled public key, user verification, signature counter — and
//! hands back a credential or a verdict; the handlers in `lib.rs` turn that
//! into a kernel call, and the kernel turns it into a record. The kernel never
//! parses a credential: it holds `Passkey` as opaque JSON the way it holds a
//! verifying key for the device registry.
use anyhow::{Context, Result};
use base64::Engine;
use vk_kernel::{PasskeyRow, PASSKEY_DEVICE_PREFIX};
use webauthn_rs::prelude::{CredentialID, Passkey, Url, Uuid, Webauthn, WebauthnBuilder};

/// The relying-party id. `localhost` is the one hostname a browser treats as
/// a secure context over plain `http`, which is what lets the ceremony run
/// on a loopback page without a certificate (the plan's "loopback secure
/// context").
pub const RP_ID: &str = "localhost";

/// What the passkey is shown as in the platform's credential manager.
pub const RP_NAME: &str = "VerticalAI kernel";

/// The pages' origin for `port`: `http://localhost:<port>`. It is the only
/// origin the verifier accepts, so a page opened as `127.0.0.1` — a different
/// origin to a browser — is refused rather than served.
pub fn origin(port: u16) -> String {
    format!("http://localhost:{port}")
}

/// The verifier for the pages on `port`.
pub fn webauthn(port: u16) -> Result<Webauthn> {
    let rp_origin = Url::parse(&origin(port)).context("rp origin")?;
    WebauthnBuilder::new(RP_ID, &rp_origin)
        .context("webauthn relying party")?
        .rp_name(RP_NAME)
        .build()
        .context("webauthn verifier")
}

/// The user handle every passkey on this node is enrolled under: the node's
/// operator, derived from the node id rather than stored. A passkey is a
/// credential *for an account at a relying party*; this node has one account
/// — whoever holds the human ceremony — and the id has to be the same on every
/// enrolment so a platform lists them together.
pub fn operator_uuid(node_id: &str) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("vk:node:{node_id}:operator").as_bytes(),
    )
}

/// The device id a credential is enrolled as: `passkey:<credential id,
/// base64url>`. The credential id is the authenticator's own name for the
/// key, unique per enrolment, so two passkeys can never share a device id.
pub fn device_id_of(cred_id: &CredentialID) -> String {
    format!(
        "{PASSKEY_DEVICE_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_id.as_ref())
    )
}

/// The enrolled passkeys the kernel holds, parsed for the verifier. A row
/// the verifier cannot read — one written by a later version, say — is
/// logged and left out rather than failing every approval on the node: it
/// cannot answer a challenge, so leaving it out changes nothing it could do.
pub fn load(rows: Vec<PasskeyRow>) -> Vec<(String, Passkey)> {
    rows.into_iter()
        .filter_map(|row| match serde_json::from_value::<Passkey>(row.credential) {
            Ok(passkey) => Some((row.device_id, passkey)),
            Err(e) => {
                tracing::warn!(device = %row.device_id, error = %e, "an enrolled passkey could not be read by this verifier; it cannot approve until it is re-enrolled");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_origin_is_localhost_on_the_port_and_the_verifier_accepts_it() {
        assert_eq!(origin(7734), "http://localhost:7734");
        let w = webauthn(7734).unwrap();
        assert_eq!(
            w.get_allowed_origins(),
            &[Url::parse("http://localhost:7734").unwrap()]
        );
    }

    #[test]
    fn the_operator_handle_is_fixed_per_node_and_the_device_id_names_the_credential() {
        assert_eq!(operator_uuid("n1"), operator_uuid("n1"));
        assert_ne!(operator_uuid("n1"), operator_uuid("n2"));
        let id = CredentialID::from(vec![0xfb, 0xff, 0xfe]);
        assert_eq!(device_id_of(&id), "passkey:-__-");
    }
}
