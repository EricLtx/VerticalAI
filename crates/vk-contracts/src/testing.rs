//! Test-only hooks every kernel implementation exposes so the invariant property
//! tests run unchanged against the stub and the real kernel — and the one
//! piece of test support the whole workspace shares, the temp-directory leak
//! guard.
use crate::arch::ArchManifest;
use crate::labels::Label;
use crate::principal::{Approval, Challenge};
use crate::stop::StopSet;
use crate::syscalls::{Ctx, Kernel};

pub trait KernelTestHooks: Kernel {
    fn register_arch(&mut self, m: ArchManifest) -> String;
    fn enroll_device(&mut self, device_id: &str, vk: [u8; 32]);
    fn renew_liveness(&mut self, business: &str, device_id: &str, expires_at_ms: u64);
    fn set_context_budget(&mut self, arch_id: &str, tokens: u32);
    fn approvals_for(&self, subject_hash: &str) -> Vec<Approval>;
    fn hot_modules(&self) -> Vec<String>;
    fn infer_log(&self) -> Vec<(String, Label)>;
    fn stops(&self) -> StopSet;
    /// Mint the challenge a human approval of `action_digest` on `resource`
    /// must answer, as the kernel would for a task waiting at its approve
    /// step — without the task (SP1a review M16). A test hook of the same
    /// standing as `enroll_device`: it exists so the I1 property can perform
    /// one valid human approval per run, against both kernels.
    fn mint_challenge(
        &mut self,
        ctx: &Ctx,
        resource: &str,
        action_digest: &str,
        ttl_ms: u64,
    ) -> Challenge;
}

/// The state-directory leak guard (SP1a review, the Windows temp-dir leak).
///
/// On Windows a directory cannot be removed while a file in it is open — a
/// store's lock file, its SQLite database — so a test that lets its `TempDir`
/// drop while its kernel (or a task, or a child process) still holds the
/// store open leaks a `.tmp*` directory into `%TEMP%` and notices nothing:
/// `TempDir::drop` swallows the error. Two thousand of them were found.
///
/// A test opens its store under a directory; it calls [`guard_state_dir`]
/// with that directory, which records it and, once per test binary, arms a
/// check that runs when the process exits. Any recorded directory that still
/// exists at exit is a store that was open when its `TempDir` tried to go:
/// the process names it and exits `101`, which fails `cargo test`.
///
/// Only the directories **this** process registered are checked — never a
/// bare scan of `%TEMP%` — so the test binaries `cargo test` runs in parallel
/// cannot mistake one another's live directories for a leak. A no-op off
/// Windows: other platforms remove an open file's directory happily, and the
/// leak is a Windows one.
pub fn guard_state_dir(dir: &std::path::Path) {
    #[cfg(windows)]
    leak_guard::register(dir);
    #[cfg(not(windows))]
    let _ = dir;
}

#[cfg(windows)]
mod leak_guard {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, Once};

    static ARMED: Once = Once::new();
    static REGISTERED: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

    extern "C" {
        fn atexit(cb: extern "C" fn()) -> i32;
        fn _exit(code: i32) -> !;
    }

    pub fn register(dir: &Path) {
        // The absolute path, so a check at exit (run from wherever) still finds
        // it; the raw path if it cannot be made absolute.
        let abs = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
        REGISTERED
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(abs);
        ARMED.call_once(|| {
            // SAFETY: `atexit` takes a plain `extern "C"` function of no
            // arguments and calls it once when the process exits; `check`
            // touches only its own statics.
            unsafe {
                atexit(check);
            }
        });
    }

    extern "C" fn check() {
        let registered = REGISTERED.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let leaked: Vec<PathBuf> = registered.into_iter().filter(|d| d.exists()).collect();
        if leaked.is_empty() {
            return;
        }
        eprintln!(
            "state-directory leak guard: {} test state director{} still on disk at exit — a              store was open when its TempDir dropped (a kernel, a connection task or a child              process still held it):",
            leaked.len(),
            if leaked.len() == 1 { "y is" } else { "ies are" }
        );
        for dir in &leaked {
            let contents: Vec<String> = std::fs::read_dir(dir)
                .map(|it| {
                    it.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            eprintln!("  {}: {}", dir.display(), contents.join(", "));
        }
        // `exit` may not be called from an `atexit` handler; `_exit` ends the
        // process now, with the code `cargo test` reads as a failure.
        // SAFETY: `_exit` never returns and runs no further handlers.
        unsafe { _exit(101) }
    }
}
