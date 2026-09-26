//! Encrypted, content-addressed payload tier (spec §3.9, D7). One DEK per
//! subject key id; shred = delete the wrapped DEK (and remember that we did).
//! The storage address is subject-scoped (`sha256(key_id || 0x00 || plaintext)`),
//! not a plain hash of the plaintext: see `put`.
use crate::keys::{open, seal, KeyBytes, MasterKey};
use anyhow::{Context, Result};
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
    /// Open the tier under `dir`, making its three directories — the
    /// ciphertext and envelopes, the wrapped keys, the tombstones — the
    /// owner's alone (`0700` on Unix, new or not; review N2). The files are
    /// born `0600` by `write_private`; the directories above them are what is
    /// re-applied on every open, because that is what an older version's
    /// umask would have left open and what a walk of the whole tier at boot
    /// need not be spent on.
    pub fn open(dir: &Path, master: MasterKey) -> Result<BlobStore> {
        for sub in [dir.to_path_buf(), dir.join("keys"), dir.join("shredded")] {
            crate::paths::private_dir(&sub).with_context(|| format!("create {}", sub.display()))?;
        }
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

    /// The subject's DEK, unwrapped — a wiped-on-drop value that lives for
    /// one seal or one open. `NotFound` and `Shredded` come back as
    /// `StorageError` (reachable through `downcast_ref`); a key on file that
    /// does not unwrap **for this subject** is an integrity failure of the key
    /// tier and is reported as its own error, because the store has a key
    /// under that name and it is not the subject's (review N4).
    fn dek_for(&self, key_id: &str, create: bool) -> Result<KeyBytes> {
        // Held for the entire check + read-or-create: see the `shredded` field doc.
        let shredded = self
            .shredded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if shredded.contains(key_id) {
            return Err(StorageError::Shredded.into());
        }
        let p = self.dek_path(key_id);
        if p.exists() {
            let wrapped = std::fs::read(&p).map_err(|_| StorageError::NotFound)?;
            return self.unwrap_for(key_id, &wrapped);
        }
        if !create {
            return Err(StorageError::NotFound.into());
        }
        let dek = crate::keys::fresh();
        let wrapped = self.master.wrap(key_id, &dek)?;
        write_private(&p, &wrapped)?;
        Ok(dek)
    }

    /// Unwrap what is filed under `key_id` as `key_id`'s key, naming the
    /// subject when it is not: the same words `get`, `shred` and `fsck` all
    /// use for it.
    fn unwrap_for(&self, key_id: &str, wrapped: &[u8]) -> Result<KeyBytes> {
        self.master.unwrap_dek(key_id, wrapped).map_err(|_| {
            anyhow::anyhow!(
                "the wrapped key filed under {key_id} failed its integrity check: it was not \
                 wrapped for this subject under this master key (a .dek file moved from another \
                 subject, or a master key that is not the one it was written with)"
            )
        })
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
        let dek = self.dek_for(key_id, true)?;
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
        write_private(&self.blob_path(hex_hash), &sealed).context("write blob")?;
        write_private(&self.env_path(hex_hash), &serde_json::to_vec(&env)?)
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

    /// Erase a subject: delete its wrapped DEK and remember that it was done.
    ///
    /// **The key is verified before it is destroyed** (review N4): what is
    /// filed under the subject must unwrap *as that subject's* — a file moved
    /// there from another subject is refused, left in place and not recorded
    /// as shredded, because destroying it would erase somebody else while
    /// claiming to erase this one. A subject with no key on file (never
    /// written to, or shredded already) is recorded as shredded all the same:
    /// there is nothing to destroy and the tombstone is what stops a later
    /// `put` from minting it a fresh key.
    pub fn shred(&self, e: ShredEvent) -> Result<()> {
        // Held for the entire verify + remove + tombstone-write + insert: see
        // the `shredded` field doc.
        let mut shredded = self
            .shredded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dek_path = self.dek_path(&e.key_id);
        match std::fs::read(&dek_path) {
            Ok(wrapped) => {
                self.unwrap_for(&e.key_id, &wrapped)
                    .with_context(|| format!("refusing to shred {}", e.key_id))?;
                std::fs::remove_file(&dek_path)
                    .with_context(|| format!("remove {}", dek_path.display()))?;
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("read {}", dek_path.display())),
        }
        write_private(&self.shred_path(&e.key_id), &serde_json::to_vec(&e)?)?;
        shredded.insert(e.key_id);
        Ok(())
    }

    pub fn is_shredded(&self, key_id: &str) -> bool {
        self.shredded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(key_id)
    }

    /// The envelope `put(key_id, _, plaintext)` wrote, found by re-deriving
    /// the address rather than by remembering it. What a caller that still
    /// has the bytes uses to name the blob again.
    pub fn envelope_of(
        &self,
        key_id: &str,
        plaintext: &[u8],
    ) -> Result<BlobEnvelope, StorageError> {
        self.envelope(&address(key_id, plaintext))
    }

    /// Every blob this store holds, by address, in the order the filesystem
    /// gives them. Read off the envelopes, which are the tier's index: a
    /// `.bin` with no `.json` beside it is a blob nothing can name, and is
    /// reported by [`BlobStore::orphans`] rather than silently walked.
    ///
    /// For `fsck`, which is the only caller that has any business enumerating
    /// the payload tier: every other read comes by an address a register
    /// already holds.
    pub fn addresses(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in
            std::fs::read_dir(&self.dir).with_context(|| format!("read {}", self.dir.display()))?
        {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    out.push(format!("sha256:{stem}"));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Ciphertext with no envelope beside it: bytes this store cannot name,
    /// let alone open. Not an integrity failure of any blob — there is no
    /// blob — but a leftover of a crash between the two writes `put` makes,
    /// and `fsck` says so rather than counting nothing.
    pub fn orphans(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in
            std::fs::read_dir(&self.dir).with_context(|| format!("read {}", self.dir.display()))?
        {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "bin") && !path.with_extension("json").exists()
            {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    out.push(format!("sha256:{stem}"));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Every subject this store holds a wrapped DEK for. The filenames are
    /// hex of the key id, exactly as [`BlobStore::dek_path`] writes them.
    pub fn key_ids(&self) -> Result<Vec<String>> {
        let dir = self.dir.join("keys");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "dek") {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .with_context(|| format!("non-utf8 DEK filename {}", path.display()))?;
                let bytes =
                    hex::decode(stem).with_context(|| format!("malformed DEK filename {stem}"))?;
                out.push(
                    String::from_utf8(bytes)
                        .with_context(|| format!("DEK filename {stem} is not hex-of-utf8"))?,
                );
            }
        }
        out.sort();
        Ok(out)
    }

    /// Does this subject's DEK still come back out of its wrapping under the
    /// master key? The one question `fsck`'s key tier asks, and the one a
    /// replaced keyring entry or a restored-from-the-wrong-backup key file
    /// answers `no` to — which otherwise shows up as every blob of that
    /// subject having gone missing.
    pub fn dek_unwraps(&self, key_id: &str) -> Result<()> {
        let p = self.dek_path(key_id);
        let wrapped = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
        self.unwrap_for(key_id, &wrapped)?;
        Ok(())
    }
}

/// One file of the payload tier, written whole: born `0600` on Unix rather
/// than with the umask (review N2 — the wrapped DEKs are exactly the material
/// the rest of the state directory was tightened for), truncated if it is
/// already there.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut opts = crate::paths::private_file_options();
    opts.write(true).create(true).truncate(true);
    let mut f = opts
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))
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

    /// `dek_for` hands out a wiped-on-drop key, never a bare array.
    #[test]
    fn a_subjects_key_is_handed_out_wiped_on_drop() {
        fn wiped(_: &KeyBytes) {}
        let (_d, s) = store();
        let dek = s.dek_for("subject-1", true).unwrap();
        wiped(&dek);
        assert_eq!(*s.dek_for("subject-1", false).unwrap(), *dek);
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

    /// The wrapped DEK is bound to its subject (review N4): a `.dek` file
    /// copied or renamed under another subject's name — a restore from the
    /// wrong backup, or a hand that moved it — is refused on read as an
    /// integrity failure of the key tier, and `shred` refuses to destroy it,
    /// because the key filed under that subject is not that subject's. A
    /// `shred` that went ahead would have destroyed subject-1's key while
    /// claiming to erase subject-2.
    #[test]
    fn a_wrapped_key_copied_to_another_subject_is_refused_and_not_shredded() {
        let (d, s) = store();
        let a = s.put("subject-1", Label::bottom(), b"alpha").unwrap();
        let b = s.put("subject-2", Label::bottom(), b"bravo").unwrap();
        let dek_of = |key_id: &str| {
            d.path()
                .join("blobs")
                .join("keys")
                .join(format!("{}.dek", hex::encode(key_id.as_bytes())))
        };
        std::fs::copy(dek_of("subject-1"), dek_of("subject-2")).unwrap();

        // The read: not "not found", not "shredded" — the store has a key on
        // file for subject-2 and it is not subject-2's.
        let msg = integrity_failure(s.get(&b.hash));
        assert!(msg.contains("subject-2"), "the subject is named: {msg}");
        // fsck's key tier says the same.
        let why = s
            .dek_unwraps("subject-2")
            .expect_err("a moved key does not unwrap");
        assert!(why.to_string().contains("subject-2"), "{why:#}");

        // The shred: refused, nothing destroyed, nothing recorded.
        let err = s
            .shred(ShredEvent {
                key_id: "subject-2".into(),
                issuer: Principal::Human {
                    device_id: "d".into(),
                },
                hlc_ms: 1,
            })
            .expect_err("shredding a subject whose key on file is not its own must be refused");
        assert!(err.to_string().contains("subject-2"), "{err:#}");
        assert!(
            dek_of("subject-2").exists(),
            "the file is left for a human to look at"
        );
        assert!(!s.is_shredded("subject-2"), "no tombstone was written");
        assert!(!d
            .path()
            .join("blobs")
            .join("shredded")
            .join(hex::encode(b"subject-2"))
            .exists());

        // Subject-1's own key is untouched by all of it.
        assert_eq!(s.get(&a.hash).unwrap(), b"alpha".to_vec());
        s.shred(ShredEvent {
            key_id: "subject-1".into(),
            issuer: Principal::Human {
                device_id: "d".into(),
            },
            hlc_ms: 2,
        })
        .expect("a subject whose key is its own is shredded as before");
        assert_storage_error(s.get(&a.hash), StorageError::Shredded);
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
