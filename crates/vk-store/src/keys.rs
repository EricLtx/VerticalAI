//! Master key and per-subject data-encryption keys (spec §3.9). The master key
//! never leaves the OS keyring except through the test/CI file source.
use anyhow::{Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::io::Write as _;
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub enum KeySource {
    Keyring { service: String, user: String },
    File(PathBuf),
}

/// Thirty-two bytes of key material that are wiped when they are dropped
/// (SP1a review M4): a subject's DEK between its unwrap and the seal, the
/// master key's bytes while they are being loaded, the node seed. `Zeroizing`
/// derefs to the array, so every consumer takes `&[u8; 32]` as before; what
/// changes is that no owned copy outlives its use unwiped.
pub type KeyBytes = Zeroizing<[u8; 32]>;

/// The master key. Deliberately **not** `Clone`: the store holds the one
/// copy that was loaded, and it is zeroed when the store lets go of it.
///
/// ```compile_fail
/// fn take(k: vk_store::keys::MasterKey) -> vk_store::keys::MasterKey {
///     k.clone()
/// }
/// ```
pub struct MasterKey([u8; 32]);

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for MasterKey {}

impl MasterKey {
    pub fn load_or_create(source: KeySource) -> Result<MasterKey> {
        match source {
            KeySource::Keyring { service, user } => {
                let entry = keyring::Entry::new(&service, &user)?;
                match entry.get_password() {
                    // The base64 the keyring hands back is the key: wiped
                    // with the bytes it decodes to.
                    Ok(b64) => Ok(MasterKey(*decode(&Zeroizing::new(b64))?)),
                    Err(keyring::Error::NoEntry) => {
                        let k = fresh();
                        entry.set_password(&encode(&k))?;
                        Ok(MasterKey(*k))
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
                        file.write_all(encode(&k).as_bytes())
                            .with_context(|| format!("write {}", path.display()))?;
                        Ok(MasterKey(*k))
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
                        let text = Zeroizing::new(std::fs::read_to_string(&path)?);
                        Ok(MasterKey(*decode(text.trim())?))
                    }
                    Err(err) => Err(err).with_context(|| format!("create {}", path.display())),
                }
            }
        }
    }

    pub fn fingerprint(&self) -> String {
        vk_contracts::hash_bytes(&self.0)[..23].to_string()
    }

    /// Wrap a subject's DEK: nonce || ciphertext, with the **subject id as
    /// associated data** (SP1a review N4). The tag then vouches for the
    /// subject as well as the bytes, so a `.dek` file copied or renamed
    /// under another subject's name does not unwrap there — and a `shred` of
    /// that subject cannot be tricked into destroying somebody else's key.
    pub fn wrap(&self, key_id: &str, dek: &[u8; 32]) -> Result<Vec<u8>> {
        seal(&self.0, key_id.as_bytes(), dek)
    }

    /// The inverse, under the same subject id. Fails for any other subject,
    /// any other master key and any altered byte alike; the caller says which
    /// of those it thinks it is looking at.
    pub fn unwrap_dek(&self, key_id: &str, wrapped: &[u8]) -> Result<KeyBytes> {
        let v = Zeroizing::new(open(&self.0, key_id.as_bytes(), wrapped)?);
        anyhow::ensure!(v.len() == 32, "bad DEK length");
        let mut dek = Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(&v);
        Ok(dek)
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
        // Canonicalised on the way in, so a duplicate is recognised by value
        // (Ruling 35) — the audit below compares canonical SIDs too.
        let mut allowed: Vec<String> = allowed_owners
            .iter()
            .map(|s| crate::win_acl::canonical_sid(s))
            .collect::<Result<_>>()?;
        for fixed in [
            crate::win_acl::LOCAL_SYSTEM_SID.to_string(),
            crate::win_acl::ADMINISTRATORS_SID.to_string(),
            crate::win_acl::current_process_sid()?,
        ] {
            if !allowed.contains(&fixed) {
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

/// Thirty-two random bytes, born in a wiped-on-drop container.
pub fn fresh() -> KeyBytes {
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *k);
    k
}

/// The base64 form a keyring or a key file holds — wiped with the key.
fn encode(k: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(k))
}

fn decode(b64: &str) -> Result<KeyBytes> {
    let v = Zeroizing::new(base64::engine::general_purpose::STANDARD.decode(b64)?);
    anyhow::ensure!(v.len() == 32, "master key must be 32 bytes");
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&v);
    Ok(k)
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

    /// The key types wipe themselves when dropped (review M4). A bound, not a
    /// memory probe: reading freed memory is undefined behaviour, and the
    /// promise this checks is that the types carry the trait that zeroes them.
    #[test]
    fn key_material_is_wiped_on_drop() {
        fn wiped<T: ZeroizeOnDrop>() {}
        wiped::<MasterKey>();
        wiped::<KeyBytes>();
        wiped::<Zeroizing<String>>();
        let fresh_key = fresh();
        assert_ne!(*fresh_key, [0u8; 32]);
    }

    /// The subject id is the AEAD's associated data: the same wrapped bytes
    /// open under their own subject and under no other.
    #[test]
    fn a_dek_unwraps_under_its_own_subject_only() {
        let master = MasterKey(*fresh());
        let dek = fresh();
        let wrapped = master.wrap("task:1", &dek).unwrap();
        assert_eq!(*master.unwrap_dek("task:1", &wrapped).unwrap(), *dek);
        assert!(master.unwrap_dek("task:2", &wrapped).is_err());
        assert!(master.unwrap_dek("", &wrapped).is_err());
        let other = MasterKey(*fresh());
        assert!(other.unwrap_dek("task:1", &wrapped).is_err());
    }

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
