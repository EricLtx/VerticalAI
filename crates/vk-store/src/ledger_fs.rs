//! Per-node hash-chained ledger on disk (spec §3.9): JSONL segments of
//! `LedgerEvent`, one line per event, the SP0 `Ledger` chain logic underneath.
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use vk_contracts::ledger::{ClockQuality, Hlc, Ledger, LedgerEvent, RetentionClass};

const SEGMENT_EVENTS: u64 = 10_000;

pub struct LedgerFs {
    dir: PathBuf,
    chain: Ledger,
    pub recovered_partial_line: bool,
}

impl LedgerFs {
    /// Reads and replays every on-disk segment. Tolerates exactly one kind of
    /// damage: an unterminated (no trailing `\n`) final line of the newest
    /// segment, which is a crash mid-`append` — that line is dropped and the
    /// file is truncated back to the last complete line, so a later `append`
    /// never lands mid-line. Any other unparseable line (not the last line of
    /// the last segment, or the last line but properly newline-terminated) is
    /// treated as corruption and fails `open` with an error naming the
    /// segment and line.
    ///
    /// Does **not** verify the hash chain; the boot sequence does that — call
    /// `ledger.verify()` after `open`.
    pub fn open(dir: &Path) -> Result<LedgerFs> {
        std::fs::create_dir_all(dir)?;
        let mut segs: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|x| x == "jsonl").unwrap_or(false) {
                // Owner-only, including a segment an older version created
                // with the umask; new ones are born that way in `append`.
                crate::paths::restrict_file(&path)?;
                segs.push(path);
            }
        }
        segs.sort();
        let mut chain = Ledger::default();
        let mut recovered_partial_line = false;
        let last_seg_idx = segs.len().checked_sub(1);
        for (seg_idx, seg) in segs.iter().enumerate() {
            let text = std::fs::read_to_string(seg)?;
            let raw_lines: Vec<&str> = text.split_inclusive('\n').collect();
            let last_line_idx = raw_lines.len().checked_sub(1);
            let mut offset: usize = 0;
            for (line_idx, raw_line) in raw_lines.iter().enumerate() {
                let line_start = offset;
                offset += raw_line.len();
                let line = raw_line.trim_end_matches('\n');
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<LedgerEvent>(line) {
                    Ok(e) => chain.push_verified(e),
                    Err(err) => {
                        let is_last_segment = Some(seg_idx) == last_seg_idx;
                        let is_last_line = Some(line_idx) == last_line_idx;
                        let is_unterminated = !raw_line.ends_with('\n');
                        if is_last_segment && is_last_line && is_unterminated {
                            recovered_partial_line = true;
                            let f = std::fs::OpenOptions::new()
                                .write(true)
                                .open(seg)
                                .with_context(|| {
                                    format!("truncate partial line in {}", seg.display())
                                })?;
                            f.set_len(line_start as u64)?;
                            break;
                        }
                        return Err(anyhow::anyhow!(
                            "ledger corruption in {} line {}: {}",
                            seg.display(),
                            line_idx + 1,
                            err
                        ));
                    }
                }
            }
        }
        Ok(LedgerFs {
            dir: dir.to_path_buf(),
            chain,
            recovered_partial_line,
        })
    }

    fn segment_path(&self, seq: u64) -> PathBuf {
        self.dir
            .join(format!("seg-{:06}.jsonl", seq / SEGMENT_EVENTS))
    }

    /// Append one event: the line is written and synced to its segment, and
    /// only a line that reached the disk stays in the in-memory chain. On any
    /// failure the chain is exactly as it was, so the next append computes
    /// its `seq` and `prev_hash` from the last event the file really has —
    /// a phantom head in memory would put a gap in the file that no later
    /// open could verify past.
    ///
    /// The seven parameters are the event's own fields as the contract
    /// orders them; a struct would be built here only to be taken apart.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        kind: &str,
        retention: RetentionClass,
        wall_ms: u64,
        quality: ClockQuality,
        hlc: Hlc,
        causal_heads: Vec<String>,
        payload_hash: String,
    ) -> Result<LedgerEvent> {
        // The chain computes the event (its seq and prev_hash come from the
        // head, and its hash is the contract's to compute); it is the only
        // way to build one, so it is built in place and rolled back below if
        // the disk refuses it.
        let e = self
            .chain
            .append(
                kind,
                retention,
                wall_ms,
                quality,
                hlc,
                causal_heads,
                payload_hash,
            )
            .clone();
        if let Err(err) = self.write_line(&e) {
            self.roll_back(e.seq);
            return Err(err);
        }
        Ok(e)
    }

    /// One serialised event, newline-terminated, to its segment, synced. A
    /// segment created here is also made durable in its directory (Unix: a
    /// directory fsync; NTFS journals the metadata), so a crash right after
    /// the first append into a fresh segment does not lose the file — which
    /// would read afterwards as a clean cut of the record's tail.
    fn write_line(&self, e: &LedgerEvent) -> Result<()> {
        let path = self.segment_path(e.seq);
        let fresh = !path.exists();
        let mut opts = crate::paths::private_file_options();
        opts.create(true).append(true);
        let mut f = opts
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let mut line = serde_json::to_vec(e)?;
        line.push(b'\n');
        let len_before = f.metadata()?.len();
        let written = f.write_all(&line).and_then(|()| f.sync_data());
        if let Err(err) = written {
            // Whatever part of the line landed is taken off again, so the
            // next append does not start mid-line. Best effort: if this too
            // fails, `open` drops an unterminated last line anyway.
            let _ = f.set_len(len_before);
            return Err(err).with_context(|| format!("append to {}", path.display()));
        }
        if fresh {
            sync_dir(&self.dir)?;
        }
        Ok(())
    }

    /// Undo the in-memory append of the event at `seq`: the chain has no
    /// `pop`, so it is rebuilt from the events before it.
    fn roll_back(&mut self, seq: u64) {
        let kept: Vec<LedgerEvent> = self.chain.events()[..seq as usize].to_vec();
        let mut chain = Ledger::default();
        for e in kept {
            chain.push_verified(e);
        }
        self.chain = chain;
    }

    pub fn tail(&self, n: usize) -> Vec<LedgerEvent> {
        let ev = self.chain.events();
        ev[ev.len().saturating_sub(n)..].to_vec()
    }
    pub fn verify(&self) -> bool {
        self.chain.verify_chain()
    }
    pub fn len(&self) -> usize {
        self.chain.events().len()
    }
    pub fn is_empty(&self) -> bool {
        self.chain.events().is_empty()
    }
    pub fn events(&self) -> &[LedgerEvent] {
        self.chain.events()
    }
    pub fn chain(&self) -> &Ledger {
        &self.chain
    }
}

/// Make a new directory entry durable. On Unix that is an fsync of the
/// directory itself; Windows has no equivalent to call and journals the
/// metadata on NTFS.
fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("sync {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_contracts::ledger::{ClockQuality, Hlc, RetentionClass};

    fn hlc(n: u64) -> Hlc {
        Hlc {
            wall_ms: n,
            counter: 0,
            node: "n1".into(),
        }
    }

    /// Undo a `set_readonly(true)`: back to the owner-only mode on Unix; the
    /// read-only attribute cleared on Windows.
    #[cfg(unix)]
    fn make_writable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    // The lint guards against widening a Unix mode to world-writable, which
    // has no counterpart in clearing a Windows attribute.
    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    fn make_writable(path: &Path) {
        let mut rw = std::fs::metadata(path).unwrap().permissions();
        rw.set_readonly(false);
        std::fs::set_permissions(path, rw).unwrap();
    }

    #[test]
    fn appends_persist_and_chain_verifies_after_reopen() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut l = LedgerFs::open(d.path()).unwrap();
            l.append(
                "boot",
                RetentionClass::Operational90d,
                1,
                ClockQuality::Synced,
                hlc(1),
                vec![],
                "sha256:p".into(),
            )
            .unwrap();
            l.append(
                "task.submitted",
                RetentionClass::Operational90d,
                2,
                ClockQuality::Synced,
                hlc(2),
                vec![],
                "sha256:q".into(),
            )
            .unwrap();
        }
        let l = LedgerFs::open(d.path()).unwrap();
        assert_eq!(l.len(), 2);
        assert!(l.verify());
        assert_eq!(l.tail(1)[0].kind, "task.submitted");
    }

    #[test]
    fn partial_trailing_line_is_ignored_not_fatal() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut l = LedgerFs::open(d.path()).unwrap();
            l.append(
                "boot",
                RetentionClass::Operational90d,
                1,
                ClockQuality::Synced,
                hlc(1),
                vec![],
                "sha256:p".into(),
            )
            .unwrap();
        }
        let seg = d.path().join("seg-000000.jsonl");
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        use std::io::Write;
        f.write_all(b"{\"seq\":1,\"prev_hash\":\"x\"").unwrap();
        let l = LedgerFs::open(d.path()).unwrap();
        assert_eq!(l.len(), 1);
        assert!(l.recovered_partial_line);
        assert!(l.verify());
    }

    #[test]
    fn tampering_is_detected() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut l = LedgerFs::open(d.path()).unwrap();
            l.append(
                "boot",
                RetentionClass::Operational90d,
                1,
                ClockQuality::Synced,
                hlc(1),
                vec![],
                "sha256:p".into(),
            )
            .unwrap();
        }
        let seg = d.path().join("seg-000000.jsonl");
        let text = std::fs::read_to_string(&seg)
            .unwrap()
            .replace("sha256:p", "sha256:evil");
        std::fs::write(&seg, text).unwrap();
        assert!(!LedgerFs::open(d.path()).unwrap().verify());
    }

    #[test]
    fn append_after_partial_line_recovery_keeps_the_chain_valid() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut l = LedgerFs::open(d.path()).unwrap();
            l.append(
                "boot",
                RetentionClass::Operational90d,
                1,
                ClockQuality::Synced,
                hlc(1),
                vec![],
                "sha256:p".into(),
            )
            .unwrap();
        }
        let seg = d.path().join("seg-000000.jsonl");
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        use std::io::Write;
        f.write_all(b"{\"seq\":1,\"prev_hash\":\"x\"").unwrap();
        drop(f);
        {
            let mut l = LedgerFs::open(d.path()).unwrap();
            assert_eq!(l.len(), 1);
            assert!(l.recovered_partial_line);
            l.append(
                "task.submitted",
                RetentionClass::Operational90d,
                2,
                ClockQuality::Synced,
                hlc(2),
                vec![],
                "sha256:q".into(),
            )
            .unwrap();
            l.append(
                "task.done",
                RetentionClass::Operational90d,
                3,
                ClockQuality::Synced,
                hlc(3),
                vec![],
                "sha256:r".into(),
            )
            .unwrap();
        }
        let l = LedgerFs::open(d.path()).unwrap();
        assert_eq!(l.len(), 3);
        assert!(l.verify());
        assert!(!l.recovered_partial_line);
        let text = std::fs::read_to_string(&seg).unwrap();
        assert!(text.ends_with('\n'));
    }

    /// A write the disk refuses leaves the chain as it was: no phantom head
    /// in memory, so the next append that does land chains onto the last
    /// event the file really has, and a reopen verifies the lot.
    #[test]
    fn a_failed_write_leaves_the_chain_unchanged_and_later_appends_verify() {
        let d = tempfile::tempdir().unwrap();
        let seg = d.path().join("seg-000000.jsonl");
        let mut l = LedgerFs::open(d.path()).unwrap();
        l.append(
            "boot",
            RetentionClass::Operational90d,
            1,
            ClockQuality::Synced,
            hlc(1),
            vec![],
            "sha256:p".into(),
        )
        .unwrap();
        let before = std::fs::read(&seg).unwrap();

        // The segment made unwritable: the append must fail, and fail clean.
        let mut ro = std::fs::metadata(&seg).unwrap().permissions();
        ro.set_readonly(true);
        std::fs::set_permissions(&seg, ro).unwrap();
        let err = match l.append(
            "stop",
            RetentionClass::Operational90d,
            2,
            ClockQuality::Synced,
            hlc(2),
            vec![],
            "sha256:q".into(),
        ) {
            Ok(_) => panic!("an append the disk refused must not report success"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("seg-000000.jsonl"), "{err}");
        assert_eq!(l.chain().events().len(), 1, "no phantom event in memory");
        assert_eq!(l.len(), 1);
        assert!(l.verify());
        assert_eq!(
            std::fs::read(&seg).unwrap(),
            before,
            "nothing landed on disk"
        );

        // Writable again: the next append takes seq 1, and the file verifies
        // on a reopen — no gap where the refused event would have been.
        make_writable(&seg);
        let e = l
            .append(
                "resume",
                RetentionClass::Operational90d,
                3,
                ClockQuality::Synced,
                hlc(3),
                vec![],
                "sha256:r".into(),
            )
            .unwrap();
        assert_eq!(e.seq, 1);
        assert_eq!(l.len(), 2);
        drop(l);
        let l = LedgerFs::open(d.path()).unwrap();
        assert_eq!(l.len(), 2);
        assert!(l.verify());
        assert_eq!(l.tail(1)[0].kind, "resume");
    }

    #[test]
    fn middle_corruption_is_an_error_not_recovery() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut l = LedgerFs::open(d.path()).unwrap();
            l.append(
                "boot",
                RetentionClass::Operational90d,
                1,
                ClockQuality::Synced,
                hlc(1),
                vec![],
                "sha256:p".into(),
            )
            .unwrap();
            l.append(
                "task.submitted",
                RetentionClass::Operational90d,
                2,
                ClockQuality::Synced,
                hlc(2),
                vec![],
                "sha256:q".into(),
            )
            .unwrap();
        }
        let seg = d.path().join("seg-000000.jsonl");
        let mut lines: Vec<String> = std::fs::read_to_string(&seg)
            .unwrap()
            .lines()
            .map(|s| s.to_string())
            .collect();
        lines[0] = "{not json".to_string();
        let mut content = lines.join("\n");
        content.push('\n');
        std::fs::write(&seg, content).unwrap();
        let err = match LedgerFs::open(d.path()) {
            Ok(_) => panic!("expected middle-line corruption to fail open"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("corruption"),
            "unexpected error: {err}"
        );
    }
}
