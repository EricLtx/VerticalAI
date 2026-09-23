//! Master key and per-subject data-encryption keys (spec §3.9). The master key
//! never leaves the OS keyring except through the test/CI file source.
use anyhow::{Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
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
                if path.exists() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = std::fs::metadata(&path)?.permissions().mode();
                        if mode & 0o077 != 0 {
                            anyhow::bail!("{} is readable by others; refusing", path.display());
                        }
                    }
                    Ok(MasterKey(decode(std::fs::read_to_string(&path)?.trim())?))
                } else {
                    let k = fresh();
                    std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode(k))
                        .with_context(|| format!("write {}", path.display()))?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                    }
                    Ok(MasterKey(k))
                }
            }
        }
    }

    pub fn fingerprint(&self) -> String {
        vk_contracts::hash_bytes(&self.0)[..23].to_string()
    }

    /// Wrap a DEK: nonce || ciphertext.
    pub fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>> {
        seal(&self.0, dek)
    }
    pub fn unwrap_dek(&self, wrapped: &[u8]) -> Result<[u8; 32]> {
        let v = open(&self.0, wrapped)?;
        v.try_into().map_err(|_| anyhow::anyhow!("bad DEK length"))
    }
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

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("encrypt"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(sealed.len() > 24, "sealed blob too short");
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(&sealed[..24]), &sealed[24..])
        .map_err(|_| anyhow::anyhow!("decrypt failed"))
}
