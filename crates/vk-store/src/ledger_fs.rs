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
        let path = self.segment_path(e.seq);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        f.write_all(serde_json::to_string(&e)?.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_data()?;
        Ok(e)
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
