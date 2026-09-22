# Phone thin-node bootstrap (spec §3.6, D6)

Goal: enrol a phone as an approval channel with a hardware-backed key, without the phone ever holding registers or secrets.

1. On a full node, the business admin (human ceremony) issues an **invitation ticket**: `{business_id, ticket_nonce, expires_at_ms}` signed by the admin key, plus a 6-digit out-of-band code shown on the full node's screen.
2. The phone generates a key pair in Secure Enclave / StrongBox (non-exportable, user-verification required). It sends `{ticket, device_public_key, device_attestation}` to the full node over the LAN or the business relay (ciphertext only).
3. The full node checks the ticket signature and expiry, and the admin types the 6-digit code on the phone (proves physical co-presence). The admin approves enrolment with a human ceremony.
4. The full node writes `device.enrolled {device_id, public_key, trust_class: "thin", attestation_hash}` — a ledger event and a metadata write that replicates to the business.
5. From then on the phone can: issue STOP (presence only), sign approval challenges (`Challenge::digest`), renew the autonomy liveness lease, and act as a channel into `submit_task`. It cannot: hold a lock home, read registers above `Scope::Public`, or store any secret.
6. Revocation: `device.revoked {device_id}` signed by the admin key; propagates and wins merges; all approvals signed after the revocation HLC are invalid.
