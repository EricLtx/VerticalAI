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
/// the other file seams (`vkd --anthropic-key-file`, SP1b Task 2b fix round 1,
/// Ruling 30). On Unix that is the mode; on Windows it is the DACL, audited
/// against the same three accounts a protected state directory admits.
pub fn check_private_file(path: &std::path::Path) -> Result<()> {
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
    #[cfg(windows)]
    {
        let mut allowed = vec![
            crate::win_acl::LOCAL_SYSTEM_SID.to_string(),
            crate::win_acl::ADMINISTRATORS_SID.to_string(),
        ];
        allowed.push(crate::win_acl::current_process_sid()?);
        let refs: Vec<&str> = allowed.iter().map(String::as_str).collect();
        crate::win_acl::audit_protected_dir(path, &refs).with_context(|| {
            format!(
                "{} is readable by an account that is not this one: a key file must not be",
                path.display()
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
