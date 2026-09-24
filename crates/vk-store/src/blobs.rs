//! Encrypted, content-addressed payload tier (spec §3.9, D7). One DEK per
//! subject key id; shred = delete the wrapped DEK (and remember that we did).
//! The storage address is subject-scoped (`sha256(key_id || 0x00 || plaintext)`),
//! not a plain hash of the plaintext: see `put`.
use crate::keys::{open, seal, MasterKey};
use anyhow::{Context, Result};
use rand::RngCore;
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use vk_contracts::labels::Label;
use vk_contracts::storage::{BlobEnvelope, ShredEvent, StorageError};

pub struct BlobStore {
    dir: PathBuf,
    master: MasterKey,
    // Interior mutability: `shred` and `dek_for` are called through a shared
    // `&BlobStore`. The same mutex that guards this set is also held across
    // the whole of `dek_for` (shredded check + DEK read-or-create) and the
    // whole of `shred` (DEK removal + tombstone write + insert), so the two
    // can never interleave (see the check-then-act race fixed in review).
    shredded: Mutex<BTreeSet<String>>,
}

impl BlobStore {
    pub fn open(dir: &Path, master: MasterKey) -> Result<BlobStore> {
        std::fs::create_dir_all(dir.join("keys"))?;
        std::fs::create_dir_all(dir.join("shredded"))?;
        let mut shredded = BTreeSet::new();
        for entry in std::fs::read_dir(dir.join("shredded"))? {
            // No `.flatten()`: a per-entry read error must fail `open`, not
            // silently drop a tombstone (which would un-shred the subject).
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .with_context(|| format!("non-utf8 shredded tombstone {:?}", entry.path()))?;
            let bytes = hex::decode(name)
                .with_context(|| format!("malformed shredded tombstone filename {name}"))?;
            let key_id = String::from_utf8(bytes)
                .with_context(|| format!("shredded tombstone {name} is not hex-of-utf8"))?;
            shredded.insert(key_id);
        }
        Ok(BlobStore {
            dir: dir.to_path_buf(),
            master,
            shredded: Mutex::new(shredded),
        })
    }

    fn blob_path(&self, hex_hash: &str) -> PathBuf {
        self.dir.join(hex_hash).with_extension("bin")
    }
    fn env_path(&self, hex_hash: &str) -> PathBuf {
        self.dir.join(hex_hash).with_extension("json")
    }
    // Key ids are hex-encoded before becoming path components: later tasks use
    // ids like `task:<id>` (':' is illegal in Windows filenames), and an
    // unvalidated key id would otherwise let a caller traverse (`../`) out of
    // `keys/` or `shredded/`. Hex can never contain a path separator.
    fn dek_path(&self, key_id: &str) -> PathBuf {
        self.dir
            .join("keys")
            .join(format!("{}.dek", hex::encode(key_id.as_bytes())))
    }
    fn shred_path(&self, key_id: &str) -> PathBuf {
        self.dir
            .join("shredded")
            .join(hex::encode(key_id.as_bytes()))
    }

    fn dek_for(&self, key_id: &str, create: bool) -> Result<[u8; 32], StorageError> {
        // Held for the entire check + read-or-create: see the `shredded` field doc.
        let shredded = self
            .shredded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if shredded.contains(key_id) {
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

    /// The fingerprint of the master key this store opens its DEKs with, for
    /// the boot log: a keyring entry replaced or deleted since the blobs were
    /// written turns every read into "not found", and this is the one line
    /// that tells that case from a missing blob.
    pub fn master_fingerprint(&self) -> String {
        self.master.fingerprint()
    }

    /// The address `put(key_id, _, plaintext)` would store these bytes at,
    /// without storing them: `sha256(key_id || 0x00 || plaintext)`. What a
    /// caller compares a register's `ArtefactRef.hash` against to learn whether
    /// a file is already attached under this subject — a bare hash of the bytes
    /// never matches an address (SP1b Task 4 review, I5).
    pub fn address_of(&self, key_id: &str, plaintext: &[u8]) -> String {
        address(key_id, plaintext)
    }

    /// `BlobEnvelope.hash` is the storage address — `sha256(key_id || 0x00 ||
    /// plaintext)` — not a hash of the plaintext alone. Two subjects that
    /// `put` byte-identical plaintext land at two different addresses, so
    /// neither overwrites the other's blob/envelope files and shredding one
    /// subject cannot leave the other's (same-looking) ciphertext unreadable
    /// or vice versa.
    ///
    /// The address is also the ciphertext's associated data: the AEAD tag
    /// binds these bytes to this name, so a `.bin` swapped with another of
    /// the same subject — same DEK, so it would otherwise decrypt cleanly —
    /// fails to open under the address it was moved to (see `get`).
    pub fn put(&self, key_id: &str, label: Label, plaintext: &[u8]) -> Result<BlobEnvelope> {
        let dek = self.dek_for(key_id, true).map_err(anyhow::Error::from)?;
        let hash = address(key_id, plaintext);
        let hex_hash = hash.trim_start_matches("sha256:");
        let sealed = seal(&dek, hash.as_bytes(), plaintext)?;
        let env = BlobEnvelope {
            hash: hash.clone(),
            key_id: key_id.into(),
            alg: "xchacha20poly1305".into(),
            ciphertext_len: sealed.len() as u64,
            label,
        };
        std::fs::write(self.blob_path(hex_hash), &sealed).context("write blob")?;
        std::fs::write(self.env_path(hex_hash), serde_json::to_vec(&env)?)
            .context("write envelope")?;
        Ok(env)
    }

    pub fn envelope(&self, hash: &str) -> Result<BlobEnvelope, StorageError> {
        let hex_hash = validate_hash(hash)?;
        let text = std::fs::read(self.env_path(hex_hash)).map_err(|_| StorageError::NotFound)?;
        serde_json::from_slice(&text).map_err(|_| StorageError::NotFound)
    }

    /// The plaintext at `hash` — and only that: what comes back is held to
    /// the address it was asked for, three times over. The envelope must name
    /// it; the ciphertext must open under it as associated data; and the
    /// plaintext must derive it again. A blob that fails any of these is an
    /// integrity failure, reported as its own error (downcastable to neither
    /// `NotFound` nor `Shredded`): the store has the bytes, and they are not
    /// the ones the name promised — a swapped or restored `.bin`, a flipped
    /// byte, an envelope pointed elsewhere. A missing or shredded blob is
    /// still a `StorageError`, reachable through `downcast_ref`.
    pub fn get(&self, hash: &str) -> Result<Vec<u8>> {
        let hex_hash = validate_hash(hash)?;
        let env = self.envelope(hash)?;
        anyhow::ensure!(
            env.hash == hash,
            "blob {hash} failed its integrity check: its envelope names {}",
            env.hash
        );
        let dek = self.dek_for(&env.key_id, false)?;
        let sealed = std::fs::read(self.blob_path(hex_hash)).map_err(|_| StorageError::NotFound)?;
        let plaintext = open(&dek, hash.as_bytes(), &sealed).map_err(|_| {
            anyhow::anyhow!(
                "blob {hash} failed its integrity check: the ciphertext on disk was not sealed \
                 under this address"
            )
        })?;
        let derived = address(&env.key_id, &plaintext);
        anyhow::ensure!(
            derived == hash,
            "blob {hash} failed its integrity check: its plaintext derives {derived}"
        );
        Ok(plaintext)
    }

    pub fn shred(&self, e: ShredEvent) -> Result<()> {
        // Held for the entire remove + tombstone-write + insert: see the
        // `shredded` field doc.
        let mut shredded = self
            .shredded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dek_path = self.dek_path(&e.key_id);
        match std::fs::remove_file(&dek_path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("remove {}", dek_path.display())),
        }
        std::fs::write(self.shred_path(&e.key_id), serde_json::to_vec(&e)?)?;
        shredded.insert(e.key_id);
        Ok(())
    }

    pub fn is_shredded(&self, key_id: &str) -> bool {
        self.shredded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(key_id)
    }
}

/// The storage address of `plaintext` under `key_id`: `sha256(key_id || 0x00
/// || plaintext)`. Computed by `put` to name the blob and again by `get` to
/// check that what decrypted is what the name says.
fn address(key_id: &str, plaintext: &[u8]) -> String {
    let mut input = Vec::with_capacity(key_id.len() + 1 + plaintext.len());
    input.extend_from_slice(key_id.as_bytes());
    input.push(0u8);
    input.extend_from_slice(plaintext);
    vk_contracts::hash_bytes(&input)
}

/// `hash` is caller-supplied and, before this check, was used directly to
/// build a filesystem path — letting a caller pass `../../etc/passwd`-style
/// or absolute-path values. It must be `sha256:` followed by exactly 64
/// lowercase hex chars; anything else is rejected as `NotFound` before any
/// path is built or any file touched.
fn validate_hash(hash: &str) -> Result<&str, StorageError> {
    let hex_part = hash.strip_prefix("sha256:").ok_or(StorageError::NotFound)?;
    let valid = hex_part.len() == 64
        && hex_part
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !valid {
        return Err(StorageError::NotFound);
    }
    Ok(hex_part)
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

    /// A failed `get` that carries `expected` as its `StorageError`; an
    /// integrity failure is a different error and would downcast to none.
    fn assert_storage_error(r: Result<Vec<u8>>, expected: StorageError) {
        let err = r.expect_err("expected a storage error");
        assert_eq!(err.downcast_ref::<StorageError>(), Some(&expected), "{err}");
    }

    fn integrity_failure(r: Result<Vec<u8>>) -> String {
        let err = r.expect_err("a blob that is not what its address says must not be returned");
        assert!(
            err.downcast_ref::<StorageError>().is_none(),
            "an integrity failure is neither not-found nor shredded: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("integrity"), "{msg}");
        msg
    }

    #[test]
    fn round_trip_is_content_addressed_and_encrypted_at_rest() {
        let (d, s) = store();
        let env = s.put("subject-1", Label::bottom(), b"hello").unwrap();
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
    fn same_plaintext_under_different_subjects_gets_distinct_addresses_and_shreds_independently() {
        let (_d, s) = store();
        let a = s
            .put("subject-1", Label::bottom(), b"same-payload")
            .unwrap();
        let b = s
            .put("subject-2", Label::bottom(), b"same-payload")
            .unwrap();
        assert_ne!(
            a.hash, b.hash,
            "the storage address must be scoped to the subject, not just the plaintext"
        );
        s.shred(ShredEvent {
            key_id: "subject-1".into(),
            issuer: Principal::Human {
                device_id: "d".into(),
            },
            hlc_ms: 1,
        })
        .unwrap();
        assert_storage_error(s.get(&a.hash), StorageError::Shredded);
        assert_eq!(s.get(&b.hash).unwrap(), b"same-payload".to_vec());
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
        assert_storage_error(s.get(&a.hash), StorageError::Shredded);
        assert_eq!(s.get(&b.hash).unwrap(), b"b".to_vec());
        let err = s.put("subject-1", Label::bottom(), b"c").unwrap_err();
        assert_eq!(
            err.downcast_ref::<StorageError>(),
            Some(&StorageError::Shredded)
        );
        drop(s);
        let master =
            MasterKey::load_or_create(KeySource::File(d.path().join("master.key"))).unwrap();
        let s2 = BlobStore::open(&d.path().join("blobs"), master).unwrap();
        assert_storage_error(s2.get(&a.hash), StorageError::Shredded);
        assert!(s2.is_shredded("subject-1"));
    }

    /// Two blobs of one subject share a DEK, so either's ciphertext decrypts
    /// under the other's name — and the address would then hand out the wrong
    /// bytes to an approval, a release, a reader. Swapped `.bin` files, and
    /// swapped `.bin`+`.json` pairs, are both refused; put back, both read.
    #[test]
    fn a_blob_swapped_with_another_of_the_same_subject_is_refused() {
        let (d, s) = store();
        let a = s.put("subject-1", Label::bottom(), b"alpha").unwrap();
        let b = s.put("subject-1", Label::bottom(), b"bravo").unwrap();
        let file = |hash: &str, ext: &str| {
            d.path()
                .join("blobs")
                .join(hash.trim_start_matches("sha256:"))
                .with_extension(ext)
        };
        let swap = |ext: &str| {
            let tmp = d.path().join("swap.tmp");
            std::fs::rename(file(&a.hash, ext), &tmp).unwrap();
            std::fs::rename(file(&b.hash, ext), file(&a.hash, ext)).unwrap();
            std::fs::rename(&tmp, file(&b.hash, ext)).unwrap();
        };

        swap("bin");
        for hash in [&a.hash, &b.hash] {
            integrity_failure(s.get(hash));
        }
        // The envelopes swapped as well, as a restore of one blob's pair over
        // the other's would leave them: the envelope now names the wrong
        // address, and that is caught before anything is decrypted.
        swap("json");
        for hash in [&a.hash, &b.hash] {
            let msg = integrity_failure(s.get(hash));
            assert!(msg.contains("envelope names"), "{msg}");
        }
        swap("bin");
        swap("json");
        assert_eq!(s.get(&a.hash).unwrap(), b"alpha".to_vec());
        assert_eq!(s.get(&b.hash).unwrap(), b"bravo".to_vec());
    }

    #[test]
    fn a_ciphertext_with_one_byte_changed_is_refused() {
        let (d, s) = store();
        let env = s
            .put("subject-1", Label::bottom(), b"the approved text")
            .unwrap();
        let bin = d
            .path()
            .join("blobs")
            .join(env.hash.trim_start_matches("sha256:"))
            .with_extension("bin");
        let mut bytes = std::fs::read(&bin).unwrap();
        // Past the 24-byte nonce, inside the ciphertext proper.
        bytes[30] ^= 0x01;
        std::fs::write(&bin, &bytes).unwrap();
        integrity_failure(s.get(&env.hash));
        bytes[30] ^= 0x01;
        std::fs::write(&bin, &bytes).unwrap();
        assert_eq!(s.get(&env.hash).unwrap(), b"the approved text".to_vec());
    }

    #[test]
    fn master_key_file_is_stable_across_loads() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("master.key");
        let k1 = MasterKey::load_or_create(KeySource::File(p.clone())).unwrap();
        let k2 = MasterKey::load_or_create(KeySource::File(p)).unwrap();
        assert_eq!(k1.fingerprint(), k2.fingerprint());
    }

    #[test]
    fn malformed_hash_is_rejected_without_touching_the_store() {
        let (_d, s) = store();
        assert_storage_error(s.get("../../x"), StorageError::NotFound);
        assert_storage_error(s.get("sha256:zz"), StorageError::NotFound);
    }
}
