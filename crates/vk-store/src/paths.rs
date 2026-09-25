//! State directory resolution (plan Global Constraints): local app data, never a sync folder.
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

const SYNC_MARKERS: &[&str] = &[
    "onedrive",
    "dropbox",
    "icloud",
    "com~apple~clouddocs",
    "google drive",
    "googledrive",
];

pub fn state_dir(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    let dir = resolve_state_dir(override_dir)?;
    private_dir(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

/// Create `dir` if it is missing and, on Unix, make it — new or not —
/// reachable by its owner alone (`0700`). Registers, the ledger and released
/// plaintext all live under the state directory, and on a shared machine
/// every other account could otherwise read them. Windows leaves it to the
/// ACL of the parent, which is per user for `%LOCALAPPDATA%`.
pub fn private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// `OpenOptions` for a file the store creates: born `0600` on Unix rather
/// than briefly world-readable between creation and a later `chmod`. The
/// caller still chooses the access mode and the disposition.
#[cfg(unix)]
pub fn private_file_options() -> std::fs::OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.mode(0o600);
    opts
}

/// Windows: the file takes the ACL of its directory, which is per user for
/// `%LOCALAPPDATA%`; there is no mode to set.
#[cfg(not(unix))]
pub fn private_file_options() -> std::fs::OpenOptions {
    std::fs::OpenOptions::new()
}

/// Owner-only (`0600`) on Unix for a file that already exists — one a
/// previous version created with the umask, or one SQLite made beside its
/// database. A no-op on Windows.
pub fn restrict_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Where the state directory *would* be: resolved and refused for the same
/// reasons as `state_dir`, but nothing is created. A caller that may still
/// decline to use it (`vk boot`, which first asks what the daemon already on
/// this endpoint is serving) must not leave an empty directory behind when it
/// refuses.
pub fn resolve_state_dir(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    let dir = match override_dir {
        Some(d) => resolve_override(&d, &std::env::current_dir()?),
        None => directories::ProjectDirs::from("ai", "VerticalAI", "vk")
            .context("no home directory")?
            .data_local_dir()
            .to_path_buf(),
    };
    refuse_sync_folder(&dir)?;
    Ok(dir)
}

/// Absolutise a `--state-dir` override against `cwd` without touching the filesystem
/// (an override can be a path that doesn't exist yet, so `Path::canonicalize` won't do).
/// An empty `raw` therefore resolves to `cwd` itself.
pub fn resolve_override(raw: &Path, cwd: &Path) -> PathBuf {
    if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    }
}

/// Public because it is not only the state directory that must not live in a
/// synced folder: `vkd-service install` refuses to register a binary from one
/// too, since OneDrive may replace or dehydrate the file a service starts from.
pub fn refuse_sync_folder(dir: &Path) -> Result<()> {
    let lower = dir.to_string_lossy().to_lowercase().replace('\\', "/");
    if let Some(m) = SYNC_MARKERS.iter().find(|m| lower.contains(*m)) {
        bail!("state directory {} is inside a synced folder ({m}); use --state-dir to choose a local path", dir.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_sync_folders() {
        for bad in [
            "C:/Users/x/OneDrive/vk",
            "/home/x/Dropbox/vk",
            "/Users/x/Library/Mobile Documents/com~apple~CloudDocs/vk",
        ] {
            assert!(
                state_dir(Some(std::path::PathBuf::from(bad))).is_err(),
                "{bad} must be refused"
            );
        }
    }
    #[test]
    fn accepts_explicit_local_dir() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(state_dir(Some(d.path().to_path_buf())).unwrap(), d.path());
    }
    #[test]
    fn relative_override_inside_synced_cwd_is_refused() {
        let resolved =
            resolve_override(Path::new("vk-data"), Path::new("C:/Users/x/OneDrive/repo"));
        assert!(
            refuse_sync_folder(&resolved).is_err(),
            "relative override under a synced cwd must be refused"
        );
    }
    #[test]
    fn absolute_override_is_kept() {
        let d = tempfile::tempdir().unwrap();
        let resolved = resolve_override(d.path(), Path::new("C:/some/other/cwd"));
        assert_eq!(resolved, d.path());
    }
    #[test]
    fn resolving_does_not_create_the_directory() {
        let d = tempfile::tempdir().unwrap();
        let wanted = d.path().join("not-yet");
        assert_eq!(resolve_state_dir(Some(wanted.clone())).unwrap(), wanted);
        assert!(!wanted.exists(), "resolution must not create anything");
        assert_eq!(state_dir(Some(wanted.clone())).unwrap(), wanted);
        assert!(wanted.exists(), "but opening it does");
    }

    #[test]
    fn empty_override_resolves_to_cwd() {
        let cwd = Path::new("C:/Users/x/project");
        let resolved = resolve_override(Path::new(""), cwd);
        assert_eq!(resolved, cwd);
    }
}
