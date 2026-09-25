//! Storage tiering (spec §3.9).
pub mod blobs;
pub mod db;
pub mod keys;
pub mod ledger_fs;
pub mod lock;
pub mod paths;
pub mod sid;
/// The state directory's own ACL, for a daemon that is not any one person's
/// (SP1b Task 6). Windows only: on Unix `paths::private_dir`'s `0700` is the
/// same rule, and it is already applied to every state directory.
#[cfg(windows)]
pub mod win_acl;

use anyhow::{Context, Result};
use vk_contracts::ledger::{ClockQuality, Hlc, LedgerEvent, RetentionClass};

/// The `kv` key under which the store records the ledger's head after every
/// append: `{seq, hash}` of the newest event. A hash chain proves that no
/// line was rewritten; it says nothing about how long the chain should be,
/// so a tail cut off the newest segment would otherwise pass as a record
/// that verifies. The head is kept in SQLite, the other tier of the same
/// store, and compared on open.
pub const LEDGER_HEAD: &str = "ledger.head";

/// `{seq, hash}` of a ledger event, as recorded under `LEDGER_HEAD`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LedgerHead {
    pub seq: u64,
    pub hash: String,
}

impl LedgerHead {
    fn of(e: &LedgerEvent) -> LedgerHead {
        LedgerHead {
            seq: e.seq,
            hash: e.hash.clone(),
        }
    }
}

/// What `open` found when it compared the ledger on disk with the head this
/// store last recorded. Fixed for the store's lifetime: the ledger can only
/// be repaired from a backup, not by the process that found it short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadVerdict {
    /// No head on record: a first open, or a store from before heads were
    /// kept. The next append records one.
    Unrecorded,
    /// The chain contains the recorded head, at its seq and with its hash.
    /// It may be longer by the event a crash cut off between the append
    /// (already synced) and the record of it.
    Intact,
    /// The chain is shorter than the recorded head, or carries a different
    /// event at its seq: the tail of the record has been cut or rewritten
    /// since this store last wrote it.
    Diverged {
        recorded: LedgerHead,
        found: Option<LedgerHead>,
    },
}

pub struct Store {
    pub db: db::Db,
    pub blobs: blobs::BlobStore,
    pub ledger: ledger_fs::LedgerFs,
    pub state_dir: std::path::PathBuf,
    /// The verdict of `open` on the recorded ledger head.
    pub ledger_head: HeadVerdict,
    /// The single-writer lock on `state_dir`, held for the store's lifetime.
    /// Declared last so it is released last.
    _lock: lock::StoreLock,
}

impl Store {
    /// Opens all three storage tiers under `state_dir`, after taking the
    /// single-writer lock on it: a second open of the same directory — by
    /// this process or another — fails here, before anything is written.
    ///
    /// Does **not** verify the ledger's hash chain; the boot sequence does
    /// that — call `store.ledger.verify()`. It does compare the chain's
    /// length with the head it last recorded: see `ledger_head`.
    pub fn open(state_dir: &std::path::Path, key_source: keys::KeySource) -> Result<Store> {
        paths::private_dir(state_dir).with_context(|| format!("create {}", state_dir.display()))?;
        let lock = lock::StoreLock::acquire(&state_dir.join("lock"))?;
        let master = keys::MasterKey::load_or_create(key_source)?;
        let db = db::Db::open(&state_dir.join("vk.sqlite"))?;
        let ledger = ledger_fs::LedgerFs::open(&state_dir.join("ledger"))?;
        let ledger_head = head_verdict(&db, &ledger)?;
        Ok(Store {
            db,
            blobs: blobs::BlobStore::open(&state_dir.join("blobs"), master)?,
            ledger,
            state_dir: state_dir.to_path_buf(),
            ledger_head,
            _lock: lock,
        })
    }

    /// Append one event to the ledger and record the new head. The segment
    /// write is synced before the head is written; a crash between the two
    /// leaves the chain one event ahead of the record, which `open` accepts.
    ///
    /// On a store whose chain was found to have diverged from its recorded
    /// head, the head is left where it was: recording the head of a chain
    /// already known to be cut would make the next open call it intact.
    ///
    /// The seven parameters are the event's own fields as the contract
    /// orders them, the same signature as `LedgerFs::append` underneath.
    #[allow(clippy::too_many_arguments)]
    pub fn append_event(
        &mut self,
        kind: &str,
        retention: RetentionClass,
        wall_ms: u64,
        quality: ClockQuality,
        hlc: Hlc,
        causal_heads: Vec<String>,
        payload_hash: String,
    ) -> Result<LedgerEvent> {
        let e = self.ledger.append(
            kind,
            retention,
            wall_ms,
            quality,
            hlc,
            causal_heads,
            payload_hash,
        )?;
        if !matches!(self.ledger_head, HeadVerdict::Diverged { .. }) {
            self.db
                .kv_set(LEDGER_HEAD, &serde_json::to_string(&LedgerHead::of(&e))?)
                .context("record the ledger head")?;
        }
        Ok(e)
    }
}

fn head_verdict(db: &db::Db, ledger: &ledger_fs::LedgerFs) -> Result<HeadVerdict> {
    let Some(json) = db.kv_get(LEDGER_HEAD)? else {
        return Ok(HeadVerdict::Unrecorded);
    };
    let recorded: LedgerHead =
        serde_json::from_str(&json).with_context(|| format!("malformed {LEDGER_HEAD} record"))?;
    // A chain that verifies has `seq == index`, so the event the head names
    // is looked up by position and then held to both its seq and its hash.
    let at = usize::try_from(recorded.seq)
        .ok()
        .and_then(|i| ledger.events().get(i));
    Ok(match at {
        Some(e) if e.seq == recorded.seq && e.hash == recorded.hash => HeadVerdict::Intact,
        _ => HeadVerdict::Diverged {
            recorded,
            found: ledger.events().last().map(LedgerHead::of),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_contracts::ledger::{ClockQuality, Hlc, RetentionClass};

    fn open(dir: &std::path::Path) -> Store {
        Store::open(dir, keys::KeySource::File(dir.join("master.key"))).unwrap()
    }

    fn append(s: &mut Store, kind: &str, n: u64) -> LedgerEvent {
        s.append_event(
            kind,
            RetentionClass::Operational90d,
            n,
            ClockQuality::Synced,
            Hlc {
                wall_ms: n,
                counter: 0,
                node: "n1".into(),
            },
            vec![],
            format!("sha256:p{n}"),
        )
        .unwrap()
    }

    /// The scenario the lock exists for: a second daemon over a store one is
    /// already serving. It fails at `open`, naming the lock file, before it
    /// has read or written anything; when the first goes, the next open works.
    #[test]
    fn a_state_directory_is_opened_by_one_store_at_a_time() {
        let d = tempfile::tempdir().unwrap();
        let first = open(d.path());
        let err = match Store::open(d.path(), keys::KeySource::File(d.path().join("master.key"))) {
            Ok(_) => panic!("a second store over a served directory must be refused"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains(&d.path().join("lock").display().to_string()),
            "the refusal must name the lock file: {msg}"
        );
        assert!(msg.contains("already open"), "{msg}");
        drop(first);
        open(d.path());
    }

    #[test]
    fn every_append_records_the_head_and_a_cut_tail_is_found_on_reopen() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut s = open(d.path());
            assert_eq!(s.ledger_head, HeadVerdict::Unrecorded);
            append(&mut s, "boot", 1);
            append(&mut s, "stop", 2);
            let last = append(&mut s, "resume", 3);
            let recorded: LedgerHead =
                serde_json::from_str(&s.db.kv_get(LEDGER_HEAD).unwrap().unwrap()).unwrap();
            assert_eq!(recorded, LedgerHead::of(&last));
        }
        {
            let s = open(d.path());
            assert_eq!(s.ledger_head, HeadVerdict::Intact);
            assert_eq!(s.ledger.len(), 3);
        }
        // The last two lines removed: still a chain that verifies, but not the
        // one the store last saw.
        let seg = d.path().join("ledger").join("seg-000000.jsonl");
        let mut lines: Vec<String> = std::fs::read_to_string(&seg)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines.truncate(lines.len() - 2);
        std::fs::write(&seg, format!("{}\n", lines.join("\n"))).unwrap();
        {
            let mut s = open(d.path());
            assert!(
                s.ledger.verify(),
                "what is left of the chain still verifies"
            );
            match &s.ledger_head {
                HeadVerdict::Diverged { recorded, found } => {
                    assert_eq!(recorded.seq, 2);
                    assert_eq!(found.as_ref().map(|h| h.seq), Some(0));
                }
                other => panic!("a cut tail must be found: {other:?}"),
            }
            // Appending onto the cut chain does not move the head: what the
            // next open finds is still the divergence, not a fresh record.
            append(&mut s, "boot", 4);
        }
        let s = open(d.path());
        assert!(matches!(s.ledger_head, HeadVerdict::Diverged { .. }));
    }

    /// A rewritten line at the recorded head is a divergence too, even though
    /// the chain's length is right — and a chain that runs *past* the head is
    /// not: that is the shape a crash between the append and the record leaves.
    #[test]
    fn the_head_is_held_to_its_hash_and_a_longer_chain_is_accepted() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut s = open(d.path());
            append(&mut s, "boot", 1);
            append(&mut s, "stop", 2);
        }
        // One event appended behind the store's back, as a crash after the
        // segment sync but before the head record would leave it.
        {
            let mut l = ledger_fs::LedgerFs::open(&d.path().join("ledger")).unwrap();
            l.append(
                "resume",
                RetentionClass::Operational90d,
                3,
                ClockQuality::Synced,
                Hlc {
                    wall_ms: 3,
                    counter: 0,
                    node: "n1".into(),
                },
                vec![],
                "sha256:p3".into(),
            )
            .unwrap();
        }
        assert_eq!(open(d.path()).ledger_head, HeadVerdict::Intact);

        // The record cut back to its first event and a *different* second
        // event chained onto it with a correctly computed hash — a rewrite
        // of the tail that the chain itself cannot see, since nothing links
        // after it. The recorded head can.
        let seg = d.path().join("ledger").join("seg-000000.jsonl");
        let text = std::fs::read_to_string(&seg).unwrap();
        let first: LedgerEvent = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        let mut forged = vk_contracts::ledger::Ledger::default();
        forged.push_verified(first);
        forged.append(
            "resume",
            RetentionClass::Operational90d,
            2,
            ClockQuality::Synced,
            Hlc {
                wall_ms: 2,
                counter: 0,
                node: "n1".into(),
            },
            vec![],
            "sha256:forged".into(),
        );
        let lines: Vec<String> = forged
            .events()
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        std::fs::write(&seg, format!("{}\n", lines.join("\n"))).unwrap();
        let s = open(d.path());
        assert!(s.ledger.verify(), "the forged tail links correctly");
        assert!(matches!(s.ledger_head, HeadVerdict::Diverged { .. }));
    }

    /// A store written before heads were recorded opens as `Unrecorded`, is
    /// served, and has a head from its first append onwards.
    #[test]
    fn a_ledger_from_before_heads_were_recorded_is_accepted_and_then_recorded() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("ledger")).unwrap();
        {
            let mut l = ledger_fs::LedgerFs::open(&d.path().join("ledger")).unwrap();
            l.append(
                "boot",
                RetentionClass::Operational90d,
                1,
                ClockQuality::Synced,
                Hlc {
                    wall_ms: 1,
                    counter: 0,
                    node: "n1".into(),
                },
                vec![],
                "sha256:p1".into(),
            )
            .unwrap();
        }
        let mut s = open(d.path());
        assert_eq!(s.ledger_head, HeadVerdict::Unrecorded);
        assert!(s.db.kv_get(LEDGER_HEAD).unwrap().is_none());
        let e = append(&mut s, "boot", 2);
        let recorded: LedgerHead =
            serde_json::from_str(&s.db.kv_get(LEDGER_HEAD).unwrap().unwrap()).unwrap();
        assert_eq!(recorded, LedgerHead::of(&e));
        assert_eq!(e.seq, 1);
    }

    /// Unix only: the state directory and every file the store writes are
    /// the owner's alone — including ones a previous version left open to
    /// others, which are tightened on open rather than trusted.
    #[cfg(unix)]
    #[test]
    fn the_state_directory_and_the_files_in_it_are_private_to_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        {
            let mut s = open(d.path());
            append(&mut s, "boot", 1);
        }
        let files = [
            "vk.sqlite",
            "vk.sqlite-wal",
            "vk.sqlite-shm",
            "lock",
            "ledger/seg-000000.jsonl",
        ];
        // As a careless `mkdir`, an older version and a permissive umask
        // would have left them.
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        for f in files {
            let p = d.path().join(f);
            if p.exists() {
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        let s = open(d.path());
        assert_eq!(mode(d.path()), 0o700, "state dir");
        for f in files {
            assert_eq!(mode(&d.path().join(f)), 0o600, "{f}");
        }
        drop(s);
    }
}
