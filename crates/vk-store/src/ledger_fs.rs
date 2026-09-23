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
    pub fn open(dir: &Path) -> Result<LedgerFs> {
        std::fs::create_dir_all(dir)?;
        let mut segs: Vec<PathBuf> = std::fs::read_dir(dir)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "jsonl").unwrap_or(false))
            .collect();
        segs.sort();
        let mut chain = Ledger::default();
        let mut recovered_partial_line = false;
        for seg in &segs {
            let text = std::fs::read_to_string(seg)?;
            for line in text.split('\n') {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<LedgerEvent>(line) {
                    Ok(e) => chain.push_verified(e),
                    Err(_) => {
                        recovered_partial_line = true;
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
}
