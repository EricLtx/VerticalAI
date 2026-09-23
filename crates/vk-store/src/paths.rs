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
    let dir = match override_dir {
        Some(d) => d,
        None => directories::ProjectDirs::from("ai", "VerticalAI", "vk")
            .context("no home directory")?
            .data_local_dir()
            .to_path_buf(),
    };
    refuse_sync_folder(&dir)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

fn refuse_sync_folder(dir: &Path) -> Result<()> {
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
}
