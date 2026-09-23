//! Storage tiering (spec §3.9).
pub mod blobs;
pub mod db;
pub mod keys;
pub mod ledger_fs;
pub mod paths;

pub struct Store {
    pub db: db::Db,
    pub blobs: blobs::BlobStore,
    pub ledger: ledger_fs::LedgerFs,
    pub state_dir: std::path::PathBuf,
}

impl Store {
    /// Opens all three storage tiers under `state_dir`. Does **not** verify
    /// the ledger's hash chain; the boot sequence does that — call
    /// `store.ledger.verify()`.
    pub fn open(state_dir: &std::path::Path, key_source: keys::KeySource) -> anyhow::Result<Store> {
        let master = keys::MasterKey::load_or_create(key_source)?;
        Ok(Store {
            db: db::Db::open(&state_dir.join("vk.sqlite"))?,
            blobs: blobs::BlobStore::open(&state_dir.join("blobs"), master)?,
            ledger: ledger_fs::LedgerFs::open(&state_dir.join("ledger"))?,
            state_dir: state_dir.to_path_buf(),
        })
    }
}
