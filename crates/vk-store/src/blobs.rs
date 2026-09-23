//! Encrypted, content-addressed payload tier (spec §3.9, D7). One DEK per
//! subject key id; shred = delete the wrapped DEK (and remember that we did).
use crate::keys::{open, seal, MasterKey};
use anyhow::{Context, Result};
use rand::RngCore;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use vk_contracts::labels::Label;
use vk_contracts::storage::{BlobEnvelope, ShredEvent, StorageError};

pub struct BlobStore {
    dir: PathBuf,
    master: MasterKey,
    // Interior mutability: `shred` is called through a shared `&BlobStore`
    // (the store is handed out as a read-mostly handle), so the shredded set
    // cannot live behind `&mut self`.
    shredded: Mutex<BTreeSet<String>>,
}

impl BlobStore {
    pub fn open(dir: &Path, master: MasterKey) -> Result<BlobStore> {
        std::fs::create_dir_all(dir.join("keys"))?;
        std::fs::create_dir_all(dir.join("shredded"))?;
        let shredded = std::fs::read_dir(dir.join("shredded"))?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        Ok(BlobStore {
            dir: dir.to_path_buf(),
            master,
            shredded: Mutex::new(shredded),
        })
    }

    fn blob_path(&self, hash: &str) -> PathBuf {
        self.dir
            .join(hash.trim_start_matches("sha256:"))
            .with_extension("bin")
    }
    fn env_path(&self, hash: &str) -> PathBuf {
        self.dir
            .join(hash.trim_start_matches("sha256:"))
            .with_extension("json")
    }
    fn dek_path(&self, key_id: &str) -> PathBuf {
        self.dir.join("keys").join(format!("{key_id}.dek"))
    }

    fn dek_for(&self, key_id: &str, create: bool) -> Result<[u8; 32], StorageError> {
        if self.shredded.lock().unwrap().contains(key_id) {
            return Err(StorageError::Shredded);
        }
        let p = self.dek_path(key_id);
        if p.exists() {
            let wrapped = std::fs::read(&p).map_err(|_| StorageError::NotFound)?;
            return self
                .master
                .unwrap_dek(&wrapped)
                .map_err(|_| StorageError::NotFound);
        }
        if !create {
            return Err(StorageError::NotFound);
        }
        let mut dek = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut dek);
        let wrapped = self.master.wrap(&dek).map_err(|_| StorageError::NotFound)?;
        std::fs::write(&p, wrapped).map_err(|_| StorageError::NotFound)?;
        Ok(dek)
    }

    pub fn put(&self, key_id: &str, label: Label, plaintext: &[u8]) -> Result<BlobEnvelope> {
        let dek = self
            .dek_for(key_id, true)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let hash = vk_contracts::hash_bytes(plaintext);
        let sealed = seal(&dek, plaintext)?;
        let env = BlobEnvelope {
            hash: hash.clone(),
            key_id: key_id.into(),
            alg: "xchacha20poly1305".into(),
            ciphertext_len: sealed.len() as u64,
            label,
        };
        std::fs::write(self.blob_path(&hash), &sealed).context("write blob")?;
        std::fs::write(self.env_path(&hash), serde_json::to_vec(&env)?)
            .context("write envelope")?;
        Ok(env)
    }

    pub fn envelope(&self, hash: &str) -> Result<BlobEnvelope, StorageError> {
        let text = std::fs::read(self.env_path(hash)).map_err(|_| StorageError::NotFound)?;
        serde_json::from_slice(&text).map_err(|_| StorageError::NotFound)
    }

    pub fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let env = self.envelope(hash)?;
        let dek = self.dek_for(&env.key_id, false)?;
        let sealed = std::fs::read(self.blob_path(hash)).map_err(|_| StorageError::NotFound)?;
        open(&dek, &sealed).map_err(|_| StorageError::NotFound)
    }

    pub fn shred(&self, e: ShredEvent) -> Result<()> {
        let _ = std::fs::remove_file(self.dek_path(&e.key_id));
        std::fs::write(
            self.dir.join("shredded").join(&e.key_id),
            serde_json::to_vec(&e)?,
        )?;
        self.shredded.lock().unwrap().insert(e.key_id);
        Ok(())
    }

    pub fn is_shredded(&self, key_id: &str) -> bool {
        self.shredded.lock().unwrap().contains(key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeySource, MasterKey};
    use vk_contracts::labels::Label;
    use vk_contracts::principal::Principal;
    use vk_contracts::storage::{ShredEvent, StorageError};

    fn store() -> (tempfile::TempDir, BlobStore) {
        let d = tempfile::tempdir().unwrap();
        let master =
            MasterKey::load_or_create(KeySource::File(d.path().join("master.key"))).unwrap();
        let s = BlobStore::open(&d.path().join("blobs"), master).unwrap();
        (d, s)
    }

    #[test]
    fn round_trip_is_content_addressed_and_encrypted_at_rest() {
        let (d, s) = store();
        let env = s.put("subject-1", Label::bottom(), b"hello").unwrap();
        assert_eq!(env.hash, vk_contracts::hash_bytes(b"hello"));
        assert_eq!(s.get(&env.hash).unwrap(), b"hello".to_vec());
        let raw = std::fs::read(
            d.path()
                .join("blobs")
                .join(env.hash.trim_start_matches("sha256:"))
                .with_extension("bin"),
        )
        .unwrap();
        assert!(
            !raw.windows(5).any(|w| w == b"hello"),
            "plaintext must not be on disk"
        );
    }

    #[test]
    fn shred_makes_every_blob_of_the_subject_unreadable_and_survives_reopen() {
        let (d, s) = store();
        let a = s.put("subject-1", Label::bottom(), b"a").unwrap();
        let b = s.put("subject-2", Label::bottom(), b"b").unwrap();
        s.shred(ShredEvent {
            key_id: "subject-1".into(),
            issuer: Principal::Human {
                device_id: "d".into(),
            },
            hlc_ms: 1,
        })
        .unwrap();
        assert_eq!(s.get(&a.hash), Err(StorageError::Shredded));
        assert_eq!(s.get(&b.hash).unwrap(), b"b".to_vec());
        drop(s);
        let master =
            MasterKey::load_or_create(KeySource::File(d.path().join("master.key"))).unwrap();
        let s2 = BlobStore::open(&d.path().join("blobs"), master).unwrap();
        assert_eq!(s2.get(&a.hash), Err(StorageError::Shredded));
        assert!(s2.is_shredded("subject-1"));
    }

    #[test]
    fn master_key_file_is_stable_across_loads() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("master.key");
        let k1 = MasterKey::load_or_create(KeySource::File(p.clone())).unwrap();
        let k2 = MasterKey::load_or_create(KeySource::File(p)).unwrap();
        assert_eq!(k1.fingerprint(), k2.fingerprint());
    }
}
