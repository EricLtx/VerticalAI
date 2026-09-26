//! Master key and per-subject data-encryption keys (spec §3.9). The master key
//! never leaves the OS keyring except through the test/CI file source.
use anyhow::{Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::io::Write as _;
use std::path::PathBuf;

pub enum KeySource {
    Keyring { service: String, user: String },
    File(PathBuf),
}

#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn load_or_create(source: KeySource) -> Result<MasterKey> {
        match source {
            KeySource::Keyring { service, user } => {
                let entry = keyring::Entry::new(&service, &user)?;
                match entry.get_password() {
                    Ok(b64) => Ok(MasterKey(decode(&b64)?)),
                    Err(keyring::Error::NoEntry) => {
                        let k = fresh();
                        entry.set_password(&base64::engine::general_purpose::STANDARD.encode(k))?;
                        Ok(MasterKey(k))
                    }
                    Err(e) => Err(e.into()),
                }
            }
            KeySource::File(path) => {
                // Atomic create: `create_new` fails with `AlreadyExists` if the
                // file is already there, so there is no exists()-then-write
                // TOCTOU window, and on Unix the file is born 0o600 instead of
                // being briefly world-readable between `write` and
                // `set_permissions`.
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                match opts.open(&path) {
                    Ok(mut file) => {
                        let k = fresh();
                        file.write_all(
                            base64::engine::general_purpose::STANDARD
                                .encode(k)
                                .as_bytes(),
                        )
                        .with_context(|| format!("write {}", path.display()))?;
                        Ok(MasterKey(k))
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let mode = std::fs::metadata(&path)?.permissions().mode();
                            if mode & 0o077 != 0 {
                                anyhow::bail!("{} is readable by others; refusing", path.display());
                            }
                        }
                        Ok(MasterKey(decode(std::fs::read_to_string(&path)?.trim())?))
                    }
                    Err(err) => Err(err).with_context(|| format!("create {}", path.display())),
                }
            }
        }
    }

    pub fn fingerprint(&self) -> String {
        vk_contracts::hash_bytes(&self.0)[..23].to_string()
    }

    /// Wrap a DEK: nonce || ciphertext.
    pub fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>> {
        seal(&self.0, &[], dek)
    }
    pub fn unwrap_dek(&self, wrapped: &[u8]) -> Result<[u8; 32]> {
        let v = open(&self.0, &[], wrapped)?;
        v.try_into().map_err(|_| anyhow::anyhow!("bad DEK length"))
    }
}

/// Refuse a key file anybody but its owner can read.
///
/// A secret in a file is a secret everyone who can open the file has, so a
/// file-backed key is only as private as its permissions — the same rule
/// [`MasterKey::load_or_create`] applies to the master key, made available to
/// the other file seams (`vkd --anthropic-key-file`, SP1b Task 2b, Ruling 30).
/// On Unix that is the mode; on Windows it is the owner and the DACL.
///
/// `allowed_owners` is the caller's list of SIDs, ignored on Unix. It must be
/// the *deployment's* set and not a fixed three, because the service case is
/// the one this check is most likely to fire on: a key file put there by an
/// administrator is owned by that administrator, who is neither SYSTEM, nor
/// the `Administrators` group, nor the service account. `vkd` passes
/// `service_dir_owners()`, the same set the state directory is audited
/// against, so a file the installer created does not stop the service from
/// starting (fix round 2, Minor B).
pub fn check_private_file(path: &std::path::Path, allowed_owners: &[&str]) -> Result<()> {
    anyhow::ensure!(path.is_file(), "{} is not a file", path.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("read the permissions of {}", path.display()))?
            .permissions()
            .mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "{} is mode {:o}: a key file must be readable by its owner only (chmod 600)",
            path.display(),
            mode & 0o777
        );
    }
    #[cfg(unix)]
    let _ = allowed_owners;
    #[cfg(windows)]
    {
        // Whatever the caller named, plus the three every VerticalAI object
        // admits, so a caller that passes nothing still gets the old rule.
        let mut allowed: Vec<String> = allowed_owners.iter().map(|s| s.to_string()).collect();
        for fixed in [
            crate::win_acl::LOCAL_SYSTEM_SID.to_string(),
            crate::win_acl::ADMINISTRATORS_SID.to_string(),
            crate::win_acl::current_process_sid()?,
        ] {
            if !allowed.iter().any(|a| a.eq_ignore_ascii_case(&fixed)) {
                allowed.push(fixed);
            }
        }
        let refs: Vec<&str> = allowed.iter().map(String::as_str).collect();
        crate::win_acl::audit_protected_dir(path, &refs).with_context(|| {
            format!(
                "{} is a key file and must be readable by this account only. Reset it with \
                 `icacls \"{}\" /inheritance:r /grant *{}:F`, or put the key in this account's \
                 keyring instead and drop the flag",
                path.display(),
                path.display(),
                refs[0]
            )
        })?;
    }
    Ok(())
}

fn fresh() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

fn decode(b64: &str) -> Result<[u8; 32]> {
    let v = base64::engine::general_purpose::STANDARD.decode(b64)?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("master key must be 32 bytes"))
}

/// Seal `plaintext` under `key`: nonce || ciphertext, with `aad` bound into
/// the authentication tag. The tag then vouches not only for the bytes but
/// for the context they were sealed in — a blob's storage address, say — so
/// a ciphertext moved under another name fails to open there.
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The inverse of `seal`, under the same `aad`; any other associated data,
/// key or altered byte fails the tag.
pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(sealed.len() > 24, "sealed blob too short");
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&sealed[..24]),
            Payload {
                msg: &sealed[24..],
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("decrypt failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key file must be readable by its owner and nobody else — the rule
    /// `vkd --anthropic-key-file` is held to before the store opens
    /// (Ruling 30).
    #[cfg(unix)]
    #[test]
    fn a_key_file_is_private_at_0600_and_refused_at_0644() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().expect("tempdir");
        let f = d.path().join("anthropic.key");
        std::fs::write(&f, "sk-ant-not-a-real-key").expect("write");

        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        check_private_file(&f, &[]).expect("0600 is private");

        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = check_private_file(&f, &[]).expect_err("0644 is not");
        let text = format!("{err:#}");
        assert!(text.contains("644"), "say the mode: {text}");
        assert!(text.contains("chmod 600"), "say the remedy: {text}");

        // And a directory is not a key file.
        assert!(check_private_file(d.path(), &[]).is_err());
    }

    /// The same on Windows, where privacy is the owner and the DACL rather
    /// than a mode. The file is made inside a directory this process
    /// protected, so it inherits a known DACL instead of whatever `%TEMP%`
    /// happens to carry.
    #[cfg(windows)]
    #[test]
    fn a_key_file_is_private_to_its_owner_and_the_accounts_the_caller_names() {
        let d = tempfile::tempdir().expect("tempdir");
        let dir = d.path().join("keys");
        let me = crate::win_acl::current_process_sid().expect("this account's SID");
        let allowed = [
            crate::win_acl::LOCAL_SYSTEM_SID,
            crate::win_acl::ADMINISTRATORS_SID,
            me.as_str(),
        ];
        crate::win_acl::create_protected_dir(&dir, &allowed).expect("protected dir");
        let f = dir.join("anthropic.key");
        std::fs::write(&f, "sk-ant-not-a-real-key").expect("write");

        // Owned by this account, under a DACL naming only the three.
        check_private_file(&f, &allowed).expect("a file under a protected directory is private");
        // The three are added whatever the caller passes, so an empty list is
        // the same answer rather than a refusal.
        check_private_file(&f, &[]).expect("the fixed three are always allowed");
        // A list that admits somebody this file's DACL does not name is still
        // fine — the audit refuses strangers *in* the DACL, not absent ones.
        check_private_file(&f, &["S-1-5-21-1-2-3-1001"]).expect("a wider list still passes");

        // A directory is not a key file.
        assert!(check_private_file(&dir, &allowed).is_err());
        // And a path that is not there at all says so rather than passing.
        assert!(check_private_file(&dir.join("nope.key"), &allowed).is_err());
    }
}
