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
    /// No head on record and no record either: a store nothing has ever
    /// been appended to. The first append records a head.
    Unrecorded,
    /// A record, and **no head recorded for it** (SP1b Task 8 review,
    /// Critical 1).
    ///
    /// This cannot arise honestly. `append_event` records the head on every
    /// single append, so a non-empty chain always has one — unless the row
    /// was removed, which is precisely how somebody cuts a tail without
    /// being caught: the chain still links, and the one thing that knows how
    /// long it should be is gone. Treated exactly like `Diverged`: the node
    /// does not serve on it without `--force`, `fsck` fails the head tier,
    /// and later appends do not record a head over it — only a human's
    /// `vk fsck --rebase-head` does.
    ///
    /// (A store written by a build from before heads were recorded at all
    /// lands here too, and is told so by name rather than waved through.)
    Missing {
        /// Where the chain now ends, which is what a rebase would record.
        found: LedgerHead,
    },
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
    /// head — or to have no recorded head at all — the head is left as it
    /// was: recording the head of a chain already known to be cut, or
    /// writing a fresh one over a row somebody removed, would make the next
    /// open call it intact. Only `rebase_head`, which is a human act, moves
    /// it from either state.
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
        if !matches!(
            self.ledger_head,
            HeadVerdict::Diverged { .. } | HeadVerdict::Missing { .. }
        ) {
            self.db
                .kv_set(LEDGER_HEAD, &serde_json::to_string(&LedgerHead::of(&e))?)
                .context("record the ledger head")?;
        }
        Ok(e)
    }
}

/// One tier of the whole-store check `vk fsck` runs.
///
/// A tier is a kind of damage, not a directory: which repair an operator
/// has to reach for depends entirely on *which* of these failed, and a single
/// "the store is broken" would tell them nothing. `checked` is what was
/// actually looked at, `skipped` what was deliberately not (a shredded
/// subject's ciphertext is meant to be unreadable), and `problems` is a
/// bounded sample — `failed` is the true count.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FsckTier {
    pub tier: String,
    pub checked: u64,
    pub skipped: u64,
    pub failed: u64,
    pub ok: bool,
    pub problems: Vec<String>,
}

/// How many problems one tier reports in full. A store with ten thousand
/// damaged blobs has one fault, not ten thousand answers: the count is exact
/// and the list is a sample, so an answer stays a thing a person can read and
/// a pipe can carry.
const MAX_PROBLEMS: usize = 16;

impl FsckTier {
    /// A tier's verdict from what went wrong in it. Public because the
    /// kernel adds a tier of its own (`mounts`) that the store cannot check.
    pub fn new(tier: &str, checked: u64, skipped: u64, mut problems: Vec<String>) -> FsckTier {
        let failed = problems.len() as u64;
        if problems.len() > MAX_PROBLEMS {
            let rest = problems.len() - MAX_PROBLEMS;
            problems.truncate(MAX_PROBLEMS);
            problems.push(format!("… and {rest} more"));
        }
        FsckTier {
            tier: tier.into(),
            checked,
            skipped,
            failed,
            ok: failed == 0,
            problems,
        }
    }
}

/// What `fsck` found, tier by tier. `ok` is the conjunction: one failing tier
/// is a store that does not verify, and `vk fsck` exits non-zero on it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FsckReport {
    pub ok: bool,
    pub tiers: Vec<FsckTier>,
}

impl FsckReport {
    /// Fold more tiers in — the kernel's own (`mounts`), which the store
    /// cannot check because it does not know what a mount is.
    pub fn with(mut self, tiers: impl IntoIterator<Item = FsckTier>) -> FsckReport {
        self.tiers.extend(tiers);
        self.ok = self.tiers.iter().all(|t| t.ok);
        self
    }
}

/// What a `--rebase-head` did: the head that was on record and the one now
/// recorded in its place.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeadRebase {
    /// `None` on a store that had no head recorded at all.
    pub from: Option<LedgerHead>,
    pub to: LedgerHead,
}

impl Store {
    /// Verify the whole store, tier by tier (SP1b Task 8, review
    /// recommendation 8 / N1).
    ///
    /// `vk ledger verify` answers one question — does the chain recompute —
    /// and a node can pass it with every blob on disk unreadable. This is the
    /// other three:
    ///
    /// - **ledger**: every link and every hash recomputes, and the first
    ///   event that does not is named.
    /// - **head**: the chain still reaches the head this store last recorded,
    ///   so a tail cut off by a restore is caught even though what is left
    ///   links perfectly.
    /// - **blobs**: every blob opens *at the address it is filed under* —
    ///   `BlobStore::get`'s own three checks (the envelope names it, the AEAD
    ///   tag binds the ciphertext to it, the plaintext derives it again), run
    ///   over everything rather than over the one blob somebody read.
    /// - **keys**: every wrapped DEK still unwraps under the master key.
    ///
    /// Read-only. Nothing here writes, so an operator can run it on a store
    /// they are afraid of.
    pub fn fsck(&self) -> FsckReport {
        let tiers = vec![
            self.fsck_ledger(),
            self.fsck_head(),
            self.fsck_blobs(),
            self.fsck_keys(),
        ];
        FsckReport {
            ok: tiers.iter().all(|t| t.ok),
            tiers,
        }
    }

    fn fsck_ledger(&self) -> FsckTier {
        let events = self.ledger.events();
        let problems = match first_bad_seq(events) {
            None => vec![],
            Some(seq) => vec![format!(
                "the hash chain does not recompute from seq {seq} on; the record has been \
                 rewritten since this node wrote it"
            )],
        };
        FsckTier::new("ledger", events.len() as u64, 0, problems)
    }

    fn fsck_head(&self) -> FsckTier {
        // Recomputed rather than read off `self.ledger_head`, so a rebase in
        // this same process is reflected instead of the verdict `open` froze.
        let problems = match head_verdict(&self.db, &self.ledger) {
            Err(e) => vec![format!("the recorded ledger head cannot be read: {e:#}")],
            Ok(HeadVerdict::Unrecorded | HeadVerdict::Intact) => vec![],
            // The row is written on every append, so a record with no head
            // recorded for it is a row that was removed — the second half of
            // cutting a tail without being caught (review Critical 1).
            Ok(HeadVerdict::Missing { found }) => vec![format!(
                "no recorded head for a non-empty chain: this node has {} events and nothing \
                 saying where its record ended. The head is written on every append, so the \
                 row has been removed; the chain now ends at seq {} ({})",
                self.ledger.len(),
                found.seq,
                short(&found.hash)
            )],
            Ok(HeadVerdict::Diverged { recorded, found }) => vec![format!(
                "the record no longer contains the head this node last wrote (seq {}, {}); \
                 it now ends at {}",
                recorded.seq,
                short(&recorded.hash),
                match &found {
                    Some(h) => format!("seq {} ({})", h.seq, short(&h.hash)),
                    None => "nothing at all".into(),
                }
            )],
        };
        FsckTier::new("head", 1, 0, problems)
    }

    fn fsck_blobs(&self) -> FsckTier {
        let (mut checked, mut skipped, mut problems) = (0u64, 0u64, Vec::new());
        match self.blobs.addresses() {
            Err(e) => problems.push(format!("the payload tier cannot be listed: {e:#}")),
            Ok(addresses) => {
                for hash in addresses {
                    // A shredded subject is not damage: its DEK was deleted on
                    // purpose and its ciphertext is meant to stay unreadable.
                    // Counting erasure as corruption would make every lawful
                    // erasure request break `fsck` for ever.
                    if self
                        .blobs
                        .envelope(&hash)
                        .is_ok_and(|e| self.blobs.is_shredded(&e.key_id))
                    {
                        skipped += 1;
                        continue;
                    }
                    checked += 1;
                    if let Err(e) = self.blobs.get(&hash) {
                        problems.push(format!("{hash}: {e}"));
                    }
                }
            }
        }
        match self.blobs.orphans() {
            Err(e) => problems.push(format!("the payload tier cannot be listed: {e:#}")),
            Ok(orphans) => problems.extend(
                orphans
                    .into_iter()
                    .map(|h| format!("{h}: ciphertext with no envelope beside it")),
            ),
        }
        FsckTier::new("blobs", checked, skipped, problems)
    }

    fn fsck_keys(&self) -> FsckTier {
        let (mut checked, mut problems) = (0u64, Vec::new());
        match self.blobs.key_ids() {
            Err(e) => problems.push(format!("the key tier cannot be listed: {e:#}")),
            Ok(ids) => {
                for key_id in ids {
                    checked += 1;
                    if let Err(e) = self.blobs.dek_unwraps(&key_id) {
                        problems.push(format!("{key_id}: {e}"));
                    }
                }
            }
        }
        FsckTier::new("keys", checked, 0, problems)
    }

    /// Re-record the ledger head from the chain as it is on disk now — the
    /// recovery path after a **legitimate** restore, and nothing else.
    ///
    /// A restore from a backup puts back a shorter record than the one this
    /// store last wrote, which is exactly the shape of a tail somebody cut:
    /// the store cannot tell them apart, so it refuses to serve on either
    /// until a human says which this is. That is what this is — the human's
    /// statement, written down.
    ///
    /// Refused on a chain that does not itself verify: re-recording a head
    /// onto a record already known to be rewritten would make the next open
    /// call it intact, which is the one outcome this whole mechanism exists
    /// to prevent. Refused on an empty record for the same reason — there is
    /// no head to name.
    ///
    /// The caller is responsible for the ceremony (`vk fsck --rebase-head
    /// --force`, a presence proof and a typed confirmation) and for putting
    /// the operation on the record.
    pub fn rebase_head(&mut self) -> Result<HeadRebase> {
        anyhow::ensure!(
            self.ledger.verify(),
            "the ledger chain does not verify, so there is no head worth recording: rebasing \
             one would only make the next open call a rewritten record intact. Restore the \
             record itself"
        );
        let to = self
            .ledger
            .events()
            .last()
            .map(LedgerHead::of)
            .context("the ledger has no events, so there is no head to record")?;
        let from = match self.db.kv_get(LEDGER_HEAD)? {
            Some(json) => serde_json::from_str(&json).ok(),
            None => None,
        };
        self.db
            .kv_set(LEDGER_HEAD, &serde_json::to_string(&to)?)
            .context("record the rebased ledger head")?;
        // The verdict this store has been carrying since `open` is now
        // wrong: without this, every append for the rest of this process
        // would still refuse to move the head (see `append_event`).
        self.ledger_head = HeadVerdict::Intact;
        Ok(HeadRebase { from, to })
    }
}

/// The seq of the first event whose chain no longer recomputes, or `None`
/// when the whole chain holds.
///
/// Found by bisection on the prefix: `verify_chain` is a whole-chain verdict
/// and the hashing rule lives in the contract, so the way to ask "how far
/// does it hold?" without a second copy of that rule here is to ask the
/// contract about prefixes. `log₂ n` verifications rather than `n`, because
/// `fsck` runs on stores whose record is the whole history of a node.
fn first_bad_seq(events: &[vk_contracts::ledger::LedgerEvent]) -> Option<u64> {
    let holds = |n: usize| {
        let mut chain = vk_contracts::ledger::Ledger::default();
        for e in &events[..n] {
            chain.push_verified(e.clone());
        }
        chain.verify_chain()
    };
    if events.is_empty() || holds(events.len()) {
        return None;
    }
    // `holds(lo)` is true (the empty prefix always is), `holds(hi)` is false.
    let (mut lo, mut hi) = (0usize, events.len());
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if holds(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some(events[hi - 1].seq)
}

/// A hash as a person compares it: the first twelve hex digits.
fn short(hash: &str) -> String {
    let hex = hash.trim_start_matches("sha256:");
    hex.get(..12).unwrap_or(hex).to_string()
}

fn head_verdict(db: &db::Db, ledger: &ledger_fs::LedgerFs) -> Result<HeadVerdict> {
    // An empty value counts as absent: `kv_set(k, "")` is how this store
    // has always emptied a key, and a head that is gone is gone however it
    // was removed.
    let Some(json) = db.kv_get(LEDGER_HEAD)?.filter(|j| !j.trim().is_empty()) else {
        // No row. Whether that is innocent depends entirely on whether there
        // is a record: a fresh store has neither, and a store with a chain
        // and no head has had the head taken off it.
        return Ok(match ledger.events().last() {
            None => HeadVerdict::Unrecorded,
            Some(e) => HeadVerdict::Missing {
                found: LedgerHead::of(e),
            },
        });
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

    /// One tier of a report, by name.
    fn tier<'a>(r: &'a FsckReport, name: &str) -> &'a FsckTier {
        r.tiers
            .iter()
            .find(|t| t.tier == name)
            .unwrap_or_else(|| panic!("no {name} tier in {r:?}"))
    }

    /// A store with something in every tier: a chain, two subjects' blobs and
    /// therefore two DEKs.
    fn furnished(dir: &std::path::Path) -> Store {
        let mut s = open(dir);
        append(&mut s, "boot", 1);
        append(&mut s, "stop", 2);
        s.blobs
            .put("subject-a", vk_contracts::labels::Label::bottom(), b"alpha")
            .unwrap();
        s.blobs
            .put("subject-b", vk_contracts::labels::Label::bottom(), b"beta")
            .unwrap();
        s
    }

    /// The healthy case, which is the one an operator runs first: every tier
    /// is named, every tier is `ok`, and the counts are the things that were
    /// actually looked at rather than a bare "fine".
    #[test]
    fn fsck_checks_every_tier_of_a_healthy_store() {
        let d = tempfile::tempdir().unwrap();
        let s = furnished(d.path());
        let r = s.fsck();
        assert!(r.ok, "{r:?}");
        let names: Vec<&str> = r.tiers.iter().map(|t| t.tier.as_str()).collect();
        assert_eq!(names, ["ledger", "head", "blobs", "keys"], "{r:?}");
        assert_eq!(tier(&r, "ledger").checked, 2, "{r:?}");
        assert_eq!(tier(&r, "head").checked, 1, "{r:?}");
        assert_eq!(tier(&r, "blobs").checked, 2, "{r:?}");
        assert_eq!(tier(&r, "keys").checked, 2, "{r:?}");
        for t in &r.tiers {
            assert_eq!(t.failed, 0, "{t:?}");
            assert!(t.problems.is_empty(), "{t:?}");
        }
    }

    /// The two ways a record goes wrong are two different tiers, and each must
    /// name its own: a cut tail links perfectly and only the recorded head
    /// catches it, while a rewritten line breaks the chain itself.
    #[test]
    fn fsck_tells_a_cut_tail_from_a_rewritten_line() {
        let d = tempfile::tempdir().unwrap();
        drop(furnished(d.path()));
        let seg = d.path().join("ledger").join("seg-000000.jsonl");
        let text = std::fs::read_to_string(&seg).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        // Cut: the chain still verifies, the head no longer matches.
        std::fs::write(&seg, format!("{}\n", lines[0])).unwrap();
        let r = open(d.path()).fsck();
        assert!(!r.ok, "a cut tail is a failure: {r:?}");
        assert!(tier(&r, "ledger").ok, "what is left still links: {r:?}");
        let head = tier(&r, "head");
        assert!(!head.ok, "{head:?}");
        assert_eq!(head.failed, 1, "{head:?}");
        assert!(
            head.problems.iter().any(|p| p.contains("seq 1")),
            "the head tier must name the head it could not find: {head:?}"
        );

        // Rewritten: valid JSON, a chain that no longer recomputes.
        let mut first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        first["payload_hash"] = serde_json::Value::String("sha256:tampered".into());
        std::fs::write(
            &seg,
            format!("{}\n{}\n", serde_json::to_string(&first).unwrap(), lines[1]),
        )
        .unwrap();
        let r = open(d.path()).fsck();
        assert!(!r.ok, "{r:?}");
        let chain = tier(&r, "ledger");
        assert!(!chain.ok, "{chain:?}");
        assert!(
            chain.problems.iter().any(|p| p.contains("seq 0")),
            "the ledger tier must name the first event that does not recompute: {chain:?}"
        );
    }

    /// A blob whose bytes are not what its address says. The store's own `get`
    /// is what decides — AEAD under the address, then the address derived
    /// again from the plaintext — so `fsck` is the same check, run over
    /// everything rather than over the one blob somebody happened to read.
    #[test]
    fn fsck_finds_a_blob_that_is_not_what_its_address_says() {
        let d = tempfile::tempdir().unwrap();
        let s = furnished(d.path());
        let env = s.blobs.envelope_of("subject-a", b"alpha").unwrap();
        drop(s);
        let bin = d
            .path()
            .join("blobs")
            .join(env.hash.trim_start_matches("sha256:"))
            .with_extension("bin");
        let mut bytes = std::fs::read(&bin).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&bin, bytes).unwrap();

        let r = open(d.path()).fsck();
        assert!(!r.ok, "{r:?}");
        let blobs = tier(&r, "blobs");
        assert_eq!(blobs.checked, 2, "both were looked at: {blobs:?}");
        assert_eq!(blobs.failed, 1, "{blobs:?}");
        assert!(
            blobs.problems.iter().any(|p| p.contains(&env.hash)),
            "the failing blob is named: {blobs:?}"
        );
        assert!(tier(&r, "keys").ok, "the keys are untouched: {r:?}");
    }

    /// A DEK that no longer unwraps under the master key — a keyring entry
    /// replaced, a file restored from the wrong backup. Its own tier, because
    /// it is a different repair from a damaged blob.
    #[test]
    fn fsck_finds_a_dek_that_no_longer_unwraps() {
        let d = tempfile::tempdir().unwrap();
        drop(furnished(d.path()));
        let dek = d
            .path()
            .join("blobs")
            .join("keys")
            .join(format!("{}.dek", hex::encode(b"subject-b")));
        assert!(dek.exists(), "{}", dek.display());
        std::fs::write(&dek, b"not a wrapped key").unwrap();

        let r = open(d.path()).fsck();
        assert!(!r.ok, "{r:?}");
        let keys = tier(&r, "keys");
        assert_eq!(keys.checked, 2, "{keys:?}");
        assert_eq!(keys.failed, 1, "{keys:?}");
        assert!(
            keys.problems.iter().any(|p| p.contains("subject-b")),
            "the subject whose key is gone is named: {keys:?}"
        );
    }

    /// A shredded subject is not damage: its DEK was deleted on purpose and
    /// its ciphertext is meant to be unreadable for ever. `fsck` counts it as
    /// skipped and stays green, or erasure would read as corruption.
    #[test]
    fn fsck_counts_a_shredded_subject_as_skipped_not_failed() {
        let d = tempfile::tempdir().unwrap();
        let s = furnished(d.path());
        s.blobs
            .shred(vk_contracts::storage::ShredEvent {
                key_id: "subject-b".into(),
                issuer: vk_contracts::principal::Principal::Machine {
                    node_id: "n1".into(),
                    lease_id: "test".into(),
                },
                hlc_ms: 9,
            })
            .unwrap();
        drop(s);
        let r = open(d.path()).fsck();
        assert!(r.ok, "a shredded subject is not a fault: {r:?}");
        let blobs = tier(&r, "blobs");
        assert_eq!(blobs.skipped, 1, "{blobs:?}");
        assert_eq!(blobs.failed, 0, "{blobs:?}");
    }

    /// The recovery path after a legitimate restore, and its one refusal: the
    /// head may be re-recorded from a chain that still links, never from one
    /// that does not — re-recording a head onto a record known to be broken
    /// would only make the next open call it intact.
    #[test]
    fn the_head_is_rebased_only_from_a_chain_that_still_verifies() {
        let d = tempfile::tempdir().unwrap();
        drop(furnished(d.path()));
        let seg = d.path().join("ledger").join("seg-000000.jsonl");
        let text = std::fs::read_to_string(&seg).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        // A rewritten line: the rebase is refused, and the head is left alone.
        let mut first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        first["payload_hash"] = serde_json::Value::String("sha256:tampered".into());
        std::fs::write(
            &seg,
            format!("{}\n{}\n", serde_json::to_string(&first).unwrap(), lines[1]),
        )
        .unwrap();
        {
            let mut s = open(d.path());
            let why = s.rebase_head().expect_err("a broken chain is not rebased");
            assert!(why.to_string().contains("does not verify"), "{why:#}");
        }

        // A cut tail: the rebase records the head the chain now ends at, and
        // the store opens `Intact` afterwards.
        std::fs::write(&seg, format!("{}\n", lines[0])).unwrap();
        let rebase = {
            let mut s = open(d.path());
            assert!(matches!(s.ledger_head, HeadVerdict::Diverged { .. }));
            let rebase = s.rebase_head().expect("a chain that links is rebased");
            // In this process too: the appends that follow record the head
            // again rather than leaving it where a divergence froze it.
            assert_eq!(s.ledger_head, HeadVerdict::Intact);
            assert!(s.fsck().ok, "the store verifies once the head is right");
            rebase
        };
        assert_eq!(rebase.from.as_ref().map(|h| h.seq), Some(1), "{rebase:?}");
        assert_eq!(rebase.to.seq, 0, "{rebase:?}");
        let s = open(d.path());
        assert_eq!(s.ledger_head, HeadVerdict::Intact);
        assert!(s.fsck().ok, "{:?}", s.fsck());
    }

    /// Nothing to rebase onto is a refusal, not a head recorded over an empty
    /// record.
    #[test]
    fn an_empty_ledger_cannot_be_rebased_onto() {
        let d = tempfile::tempdir().unwrap();
        let mut s = open(d.path());
        let why = s.rebase_head().expect_err("an empty ledger is not a head");
        assert!(why.to_string().contains("no events"), "{why:#}");
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

    /// A record with no head recorded for it is `Missing`, not `Unrecorded`
    /// (SP1b Task 8 review, Critical 1).
    ///
    /// The head is written on every append, so this state cannot arise
    /// honestly — the row was removed, which is exactly how a cut tail is
    /// hidden. It is therefore treated like a divergence: later appends do
    /// **not** quietly record a head over it, and only a human's
    /// `rebase_head` moves it. A store written by a build from before heads
    /// existed lands here too and is told so rather than waved through; the
    /// same one command lets it in.
    #[test]
    fn a_record_with_no_recorded_head_is_missing_and_stays_missing() {
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
        assert!(
            matches!(s.ledger_head, HeadVerdict::Missing { .. }),
            "{:?}",
            s.ledger_head
        );
        assert!(s.db.kv_get(LEDGER_HEAD).unwrap().is_none());
        let r = s.fsck();
        assert!(!r.ok, "{r:?}");
        assert!(
            tier(&r, "head")
                .problems
                .iter()
                .any(|p| p.contains("no recorded head for a non-empty chain")),
            "{r:?}"
        );

        // Appending does not paper over it: the head stays unrecorded, so a
        // second open finds the same thing rather than an intact store.
        let e = append(&mut s, "boot", 2);
        assert_eq!(e.seq, 1);
        assert!(s.db.kv_get(LEDGER_HEAD).unwrap().is_none());
        drop(s);
        let mut s = open(d.path());
        assert!(matches!(s.ledger_head, HeadVerdict::Missing { .. }));

        // The rebase is the way in, and it names no previous head.
        let done = s.rebase_head().expect("a chain that links is rebased");
        assert_eq!(done.from, None, "{done:?}");
        assert_eq!(done.to.seq, 1, "{done:?}");
        assert!(s.fsck().ok, "{:?}", s.fsck());
    }

    /// And an empty store, which has neither a record nor a head, is not
    /// damage: that is `Unrecorded`, and the first append records a head.
    #[test]
    fn a_store_with_no_record_at_all_is_unrecorded_and_verifies() {
        let d = tempfile::tempdir().unwrap();
        let mut s = open(d.path());
        assert_eq!(s.ledger_head, HeadVerdict::Unrecorded);
        assert!(s.fsck().ok, "{:?}", s.fsck());
        let e = append(&mut s, "boot", 1);
        let recorded: LedgerHead =
            serde_json::from_str(&s.db.kv_get(LEDGER_HEAD).unwrap().unwrap()).unwrap();
        assert_eq!(recorded, LedgerHead::of(&e));
        assert!(s.fsck().ok);
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
