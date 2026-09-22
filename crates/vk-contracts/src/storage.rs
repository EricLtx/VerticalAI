//! Storage tiering (spec §3.9): payloads are encrypted, content-addressed blobs
//! under per-subject keys; erasure = shred the key. Metadata documents merge
//! without silent loss (invariant I3): conflicts are surfaced, never resolved by
//! last-writer-wins.
use crate::labels::Label;
use crate::principal::Principal;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BlobEnvelope {
    pub hash: String,
    pub key_id: String,
    pub alg: String,
    pub ciphertext_len: u64,
    pub label: Label,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShredEvent {
    pub key_id: String,
    pub issuer: Principal,
    pub hlc_ms: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("blob not found")]
    NotFound,
    #[error("key shredded; ciphertext unreadable")]
    Shredded,
}

/// In-memory stand-in: real encryption arrives in SP1; the contract is the key/shred semantics.
#[derive(Default)]
pub struct BlobStore {
    blobs: BTreeMap<String, (BlobEnvelope, Vec<u8>)>,
    shredded: BTreeSet<String>,
}

impl BlobStore {
    pub fn put(&mut self, envelope: BlobEnvelope, bytes: Vec<u8>) {
        self.blobs.insert(envelope.hash.clone(), (envelope, bytes));
    }
    pub fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let (env, bytes) = self.blobs.get(hash).ok_or(StorageError::NotFound)?;
        if self.shredded.contains(&env.key_id) {
            return Err(StorageError::Shredded);
        }
        Ok(bytes.clone())
    }
    pub fn shred(&mut self, e: ShredEvent) {
        self.shredded.insert(e.key_id);
    }
    pub fn is_shredded(&self, key_id: &str) -> bool {
        self.shredded.contains(key_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict<T> {
    pub key: String,
    pub values: Vec<(String, T)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeReport {
    pub kept: usize,
    pub conflicts_surfaced: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataDoc<T: Clone + PartialEq> {
    pub writes: BTreeMap<String, T>,
    pub authors: BTreeMap<String, String>,
    pub conflicts: Vec<Conflict<T>>,
}

impl<T: Clone + PartialEq> MetadataDoc<T> {
    pub fn write(&mut self, key: &str, value: T, node: &str) {
        self.writes.insert(key.into(), value);
        self.authors.insert(key.into(), node.into());
    }

    /// I3: every write from `other` is either adopted, already present, or recorded as a conflict.
    pub fn merge(&mut self, other: &MetadataDoc<T>) -> MergeReport {
        let mut kept = 0;
        let mut conflicts_surfaced = 0;
        for (k, v) in &other.writes {
            match self.writes.get(k) {
                None => {
                    self.writes.insert(k.clone(), v.clone());
                    self.authors.insert(k.clone(), other.authors[k].clone());
                    kept += 1;
                }
                Some(mine) if mine == v => {
                    kept += 1;
                }
                Some(mine) => {
                    self.conflicts.push(Conflict {
                        key: k.clone(),
                        values: vec![
                            (self.authors[k].clone(), mine.clone()),
                            (other.authors[k].clone(), v.clone()),
                        ],
                    });
                    conflicts_surfaced += 1;
                }
            }
        }
        for c in &other.conflicts {
            if !self.conflicts.contains(c) {
                self.conflicts.push(c.clone());
            }
        }
        MergeReport {
            kept,
            conflicts_surfaced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::Label;
    use crate::principal::Principal;

    fn env(hash: &str, key: &str) -> BlobEnvelope {
        BlobEnvelope {
            hash: hash.into(),
            key_id: key.into(),
            alg: "xchacha20poly1305".into(),
            ciphertext_len: 3,
            label: Label::bottom(),
        }
    }

    #[test]
    fn shred_makes_every_blob_under_that_key_unreadable() {
        let mut s = BlobStore::default();
        s.put(env("sha256:a", "subject-1"), b"abc".to_vec());
        s.put(env("sha256:b", "subject-2"), b"def".to_vec());
        s.shred(ShredEvent {
            key_id: "subject-1".into(),
            issuer: Principal::Human {
                device_id: "d".into(),
            },
            hlc_ms: 1,
        });
        assert_eq!(s.get("sha256:a"), Err(StorageError::Shredded));
        assert_eq!(s.get("sha256:b"), Ok(b"def".to_vec()));
        assert!(s.is_shredded("subject-1"));
    }

    #[test]
    fn merge_never_drops_a_write_and_surfaces_conflicts() {
        let mut a = MetadataDoc::<String>::default();
        let mut b = MetadataDoc::<String>::default();
        a.write("k1", "from-a".into(), "node-a");
        b.write("k1", "from-b".into(), "node-b");
        b.write("k2", "only-b".into(), "node-b");
        let report = a.merge(&b);
        assert_eq!(report.conflicts_surfaced, 1);
        assert_eq!(a.conflicts.len(), 1);
        assert!(a.writes.contains_key("k2"));
        let all: Vec<&String> = a.conflicts[0].values.iter().map(|(_, v)| v).collect();
        assert!(all.contains(&&"from-a".to_string()) && all.contains(&&"from-b".to_string()));
    }
}
