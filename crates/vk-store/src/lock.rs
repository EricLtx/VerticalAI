//! The single-writer lock on a state directory.
//!
//! Two daemons over one store would each mint ids from a counter they loaded
//! once and each chain events onto a ledger head the other is moving: the
//! record stops verifying and rows overwrite each other. So a `Store` holds an
//! exclusive OS lock on `<state_dir>/lock` for its whole life, taken before
//! anything is read or written, and a second open of the same directory fails
//! at once with the lock file's name in the message. The lock is advisory
//! against other `vk` processes only, which is the case it exists for —
//! "is it running? let me start it again" — not a defence against a process
//! that ignores it.
//!
//! Windows: the file is opened with an empty share mode, so a second
//! `CreateFile` on it fails with `ERROR_SHARING_VIOLATION` while the first
//! handle is open. Unix: `flock(LOCK_EX | LOCK_NB)` on the open descriptor,
//! which a second descriptor — in this process or another — cannot take.
//! Both are released by the OS when the handle closes, so a killed daemon
//! leaves no lock behind.
use anyhow::{Context, Result};
use std::fs::File;
use std::path::Path;

pub struct StoreLock {
    /// Kept open for the lock's lifetime: closing it is what releases the lock.
    _file: File,
}

impl StoreLock {
    pub fn acquire(path: &Path) -> Result<StoreLock> {
        let mut opts = crate::paths::private_file_options();
        opts.read(true).write(true).create(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.share_mode(0);
        }
        let file = opts.open(path).map_err(|e| refusal(path, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: `flock` on a descriptor that `file` owns and keeps open
            // for as long as this lock lives.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                return Err(refusal(path, std::io::Error::last_os_error()));
            }
        }
        crate::paths::restrict_file(path)
            .with_context(|| format!("restrict {}", path.display()))?;
        Ok(StoreLock { _file: file })
    }
}

/// The OS said "somebody holds it": `ERROR_SHARING_VIOLATION` on Windows,
/// `EWOULDBLOCK` from a non-blocking `flock` on Unix.
fn held_by_another(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        e.raw_os_error() == Some(32)
    }
    #[cfg(unix)]
    {
        e.kind() == std::io::ErrorKind::WouldBlock
    }
}

fn refusal(path: &Path, e: std::io::Error) -> anyhow::Error {
    if held_by_another(&e) {
        let dir = path.parent().unwrap_or(path);
        anyhow::anyhow!(
            "state directory {} is already open by another vkd: {} is locked by another process; \
             stop that daemon or choose another --state-dir",
            dir.display(),
            path.display()
        )
    } else {
        anyhow::Error::new(e).context(format!("take the single-writer lock {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_lock_on_the_same_file_is_refused_until_the_first_is_dropped() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("lock");
        let first = StoreLock::acquire(&path).unwrap();
        let err = match StoreLock::acquire(&path) {
            Ok(_) => panic!("a second lock on a held file must be refused"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains(&path.display().to_string()) && msg.contains("already open"),
            "{msg}"
        );
        drop(first);
        StoreLock::acquire(&path).expect("released with its holder");
    }
}
