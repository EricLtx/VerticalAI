# SP1a — Kernel Core, Store, IPC and the `vk` Shell — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the SP0 contracts and stub into a real single-node kernel daemon (`vkd`) with persistent storage, a local syscall transport, and the `vk` shell — usable end-to-end with a mock arch before any real model is wired in, so use cases can be exercised from the CLI as early as possible.

**Architecture:** `vk-kernel` implements the same `Kernel` trait as the stub, over `vk-store` (SQLite metadata, encrypted content-addressed blobs, hash-chained ledger segments). SP0's property tests are made generic over the trait and run against both kernels. `vk-ipc` exposes the syscalls as newline-delimited JSON-RPC on a named pipe (Windows) / Unix socket, deriving the principal from the connection and upgrading it to a human principal only through a signed presence/approval challenge. `vk-cli` is the OS surface: namespace paths, `boot / ps / top / stop / resume / approve / ls / mount / dmesg / man`.

**Tech Stack:** Rust stable (MSVC on Windows), tokio, rusqlite (bundled SQLite), chacha20poly1305, keyring, clap 4, tracing, serde/serde_json, anyhow, directories, uuid. Existing crates: vk-contracts, vk-stub, vk-props.

**Spec:** `docs/superpowers/specs/2026-09-22-verticalai-design.md` §3 (kernel), §3.9 (storage), §3.11 (syscalls), §5 (implementation), SP1 row of §6; SP1 design as approved in chat on 2026-09-23 (crates, transport, storage, `vk` shell, OS namespace). Companion plan: `2026-09-23-sp1b-arches-harness-passkeys-service-demo.md`.

## Execution tiering (requested by the founder)

| Tier | Model / effort | Tasks |
|---|---|---|
| Hard — invariants, crypto, concurrency, principal derivation | Fable 5.1 / high–xhigh | 2, 4, 6, 7 |
| Standard — persistence, scheduler, generic test refactor | Opus 5 / high | 1, 3, 5 |
| Mechanical — CLI plumbing, man pages, docs, boot sequence | Sonnet 5 / medium | 0, 8, 9 |
| Review between tasks | Opus 5 / high (spec-compliance reviewer), Sonnet 5 / medium (code-quality reviewer) | all |

## Global Constraints

- Same as SP0: edition 2021, `rust-toolchain.toml` stable, MSVC on Windows, `CARGO_TARGET_DIR` outside OneDrive, LF endings, conventional commits ending with the session attribution line.
- **No caller-asserted principal.** `Ctx` is built only inside `vk-ipc` from the authenticated connection; every RPC handler receives it, never constructs it from request fields.
- **Secrets never in registers, blobs, the ledger or the IPC payloads.** The master key lives in the OS keyring (`keyring` crate) under the daemon's account; `VK_MASTER_KEY_FILE` is a test/CI escape hatch only and must refuse to run if the file is world-readable on Unix.
- **State directory:** `%LOCALAPPDATA%\VerticalAI\vk` on Windows (`directories::ProjectDirs::from("ai", "VerticalAI", "vk")` → data_local_dir), `~/.local/share/vk` on Linux, `~/Library/Application Support/vk` on macOS. Refuse a path under a OneDrive/Dropbox/iCloud folder (substring match on the canonical path) with a clear error.
- Every ledger event kind used in this plan is one of: `task.submitted`, `task.step`, `artefact.released`, `register.written`, `infer`, `infer.projected`, `lease.granted`, `approval.recorded`, `stop`, `resume`, `automation.ran`, `module.promoted`, `module.exported`, `arch.mounted`, `arch.unmounted`, `device.enrolled`, `boot`, `shred`.
- SP0 invariants I1–I4′ must stay green on **both** kernels after every task (`cargo test --workspace`).
- Work happens in the `sp1-kernel` worktree/branch; merge to `master` only through the finishing-a-development-branch skill.

---

## File structure

```
crates/vk-contracts/src/testing.rs          KernelTestHooks trait (shared by stub and real kernel)
crates/vk-contracts/src/interceptors.rs     moved from vk-stub (mechanism-only checks)
crates/vk-store/
  Cargo.toml
  src/lib.rs                                Store { db, blobs, ledger } + open(state_dir)
  src/paths.rs                              state directory resolution + sync-folder refusal
  src/db.rs                                 SQLite schema, migrations, typed accessors
  src/keys.rs                               master key (keyring | file), DEK wrap/unwrap
  src/blobs.rs                              encrypted content-addressed blob store + shred
  src/ledger_fs.rs                          hash-chained ledger segments on disk
crates/vk-kernel/
  Cargo.toml
  src/lib.rs                                RealKernel (implements Kernel + KernelTestHooks)
  src/arch.rs                               ArchAdapter trait, MockAdapter, lowering/raising
  src/tasks.rs                              Task, Step, sequential scheduler, ps/top views
  src/ns.rs                                 namespace resolver (/arches, /tasks, /artefacts, /devices, /ledger)
  src/presence.rs                           node device key (enrolled at first boot), presence challenge
crates/vk-ipc/
  Cargo.toml
  src/lib.rs                                JSON-RPC types, method names, error codes
  src/server.rs                             pipe/socket listener, per-connection Ctx, dispatch
  src/client.rs                             blocking client used by vk-cli
  src/transport.rs                          named pipe (Windows) / Unix socket (others)
crates/vk-cli/
  Cargo.toml
  src/main.rs                               `vk` shell (clap)
  src/render.rs                             tables for ps/top/ls/dmesg
  src/man.rs                                man pages from contracts/schemas
crates/vkd/
  Cargo.toml
  src/main.rs                               daemon entry: boot sequence, serve IPC
crates/vk-props/tests/*.rs                  made generic; run against stub and real kernel
```

---

### Task 0: Worktree, crates skeleton, workspace dependencies, shared test hooks

**Files:**
- Create: `crates/vk-store/Cargo.toml`, `crates/vk-store/src/lib.rs`, `crates/vk-kernel/Cargo.toml`, `crates/vk-kernel/src/lib.rs`, `crates/vk-ipc/Cargo.toml`, `crates/vk-ipc/src/lib.rs`, `crates/vk-cli/Cargo.toml`, `crates/vk-cli/src/main.rs`, `crates/vkd/Cargo.toml`, `crates/vkd/src/main.rs`, `crates/vk-contracts/src/testing.rs`
- Modify: `Cargo.toml` (workspace deps), `crates/vk-contracts/src/lib.rs` (`pub mod testing;`), `crates/vk-stub/src/lib.rs` (implement `KernelTestHooks`)

**Interfaces:**
- Produces: `vk_contracts::testing::KernelTestHooks` with exactly the methods the SP0 stub already exposes:

```rust
pub trait KernelTestHooks: Kernel {
    fn register_arch(&mut self, m: ArchManifest) -> String;
    fn enroll_device(&mut self, device_id: &str, vk: [u8; 32]);
    fn renew_liveness(&mut self, business: &str, device_id: &str, expires_at_ms: u64);
    fn set_context_budget(&mut self, arch_id: &str, tokens: u32);
    fn approvals_for(&self, subject_hash: &str) -> Vec<Approval>;
    fn hot_modules(&self) -> Vec<String>;
    fn infer_log(&self) -> Vec<(String, Label)>;
    fn stops(&self) -> StopSet;
}
```

- [ ] **Step 1: Worktree**

```bash
git worktree add .worktrees/sp1-kernel -b sp1-kernel master
cd .worktrees/sp1-kernel
```
(`.worktrees/` is git-ignored. Build with `CARGO_TARGET_DIR=%USERPROFILE%\.cargo-target\verticalai-sp1`.)

- [ ] **Step 2: Workspace dependencies**

Append to `[workspace.dependencies]` in `Cargo.toml`:
```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "process", "sync", "time", "fs"] }
rusqlite = { version = "0.32", features = ["bundled"] }
chacha20poly1305 = "0.10"
keyring = { version = "3", features = ["windows-native", "apple-native", "sync-secret-service"] }
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1"
directories = "5"
uuid = { version = "1", features = ["v4"] }
base64 = "0.22"
rand = "0.8"
```

- [ ] **Step 3: Crate skeletons**

`crates/vk-store/Cargo.toml`:
```toml
[package]
name = "vk-store"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "VerticalAI storage tiering: SQLite metadata, encrypted blobs, ledger segments"

[dependencies]
vk-contracts = { path = "../vk-contracts" }
serde.workspace = true
serde_json.workspace = true
rusqlite.workspace = true
chacha20poly1305.workspace = true
keyring.workspace = true
anyhow.workspace = true
directories.workspace = true
base64.workspace = true
rand.workspace = true
sha2.workspace = true
hex.workspace = true
thiserror.workspace = true

[dev-dependencies]
tempfile = "3"
```
`crates/vk-store/src/lib.rs`: `//! Storage tiering (spec §3.9).` plus `pub mod paths;` (others added per task).

`crates/vk-kernel/Cargo.toml`: name `vk-kernel`, deps `vk-contracts`, `vk-store`, `serde`, `serde_json`, `anyhow`, `thiserror`, `uuid`, `tracing`, `rand`, `hex`; dev-dep `tempfile = "3"`.
`crates/vk-ipc/Cargo.toml`: name `vk-ipc`, deps `vk-contracts`, `vk-kernel`, `tokio`, `serde`, `serde_json`, `anyhow`, `thiserror`, `tracing`, `directories`, `rand`, `hex`.
`crates/vk-cli/Cargo.toml`: name `vk-cli`, `[[bin]] name = "vk", path = "src/main.rs"`, deps `vk-contracts`, `vk-ipc`, `clap`, `serde_json`, `anyhow`.
`crates/vkd/Cargo.toml`: name `vkd`, `[[bin]] name = "vkd"`, deps `vk-kernel`, `vk-store`, `vk-ipc`, `tokio`, `tracing`, `tracing-subscriber`, `anyhow`, `clap`.
Each `src/lib.rs` / `src/main.rs` starts as a one-line doc comment (`fn main() {}` for binaries).

- [ ] **Step 4: Shared test hooks — failing compile first**

`crates/vk-contracts/src/testing.rs`:
```rust
//! Test-only hooks every kernel implementation exposes so the invariant property
//! tests run unchanged against the stub and the real kernel.
use crate::arch::ArchManifest;
use crate::labels::Label;
use crate::principal::Approval;
use crate::stop::StopSet;
use crate::syscalls::Kernel;

pub trait KernelTestHooks: Kernel {
    fn register_arch(&mut self, m: ArchManifest) -> String;
    fn enroll_device(&mut self, device_id: &str, vk: [u8; 32]);
    fn renew_liveness(&mut self, business: &str, device_id: &str, expires_at_ms: u64);
    fn set_context_budget(&mut self, arch_id: &str, tokens: u32);
    fn approvals_for(&self, subject_hash: &str) -> Vec<Approval>;
    fn hot_modules(&self) -> Vec<String>;
    fn infer_log(&self) -> Vec<(String, Label)>;
    fn stops(&self) -> StopSet;
}
```
Add `pub mod testing;` to `vk-contracts/src/lib.rs`. In `vk-stub/src/lib.rs`, replace the inherent helper methods with `impl KernelTestHooks for StubKernel { … }` (bodies unchanged; `infer_log` returns `self.infer_log.clone()`, `stops` returns `self.stops.clone()`). Keep `StubKernel::new`.

Run: `cargo test --workspace` — expected: compile errors in `vk-props` (`infer_log()` now returns `Vec`, and tests call inherent methods). Fix the four test files by adding `use vk_contracts::testing::KernelTestHooks;` and iterating `k.infer_log().iter()`. Expected afterwards: all 45 tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates
git commit -m "chore(sp1): crate skeletons, workspace deps, KernelTestHooks shared by stub and real kernel"
```

---

### Task 1: State directory resolution and SQLite schema

**Files:**
- Create: `crates/vk-store/src/paths.rs`, `crates/vk-store/src/db.rs`
- Modify: `crates/vk-store/src/lib.rs`

**Interfaces:**
- Produces: `paths::state_dir(override: Option<PathBuf>) -> anyhow::Result<PathBuf>` (refuses sync folders), `Db::open(path) -> Result<Db>`, `Db::migrate()`, typed accessors: `put_json(table, key, &T)`, `get_json<T>(table, key) -> Option<T>`, `list_json<T>(table) -> Vec<(String, T)>`, `delete(table, key)`, `kv_get/kv_set`.

- [ ] **Step 1: Failing tests** (`crates/vk-store/src/paths.rs` bottom and `db.rs` bottom)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_sync_folders() {
        for bad in ["C:/Users/x/OneDrive/vk", "/home/x/Dropbox/vk", "/Users/x/Library/Mobile Documents/com~apple~CloudDocs/vk"] {
            assert!(state_dir(Some(std::path::PathBuf::from(bad))).is_err(), "{bad} must be refused");
        }
    }
    #[test]
    fn accepts_explicit_local_dir() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(state_dir(Some(d.path().to_path_buf())).unwrap(), d.path());
    }
}
```
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Thing { n: u32 }
    #[test]
    fn json_round_trip_and_list() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("vk.sqlite")).unwrap();
        db.put_json("kv_test", "a", &Thing { n: 1 }).unwrap();
        db.put_json("kv_test", "b", &Thing { n: 2 }).unwrap();
        assert_eq!(db.get_json::<Thing>("kv_test", "a").unwrap(), Some(Thing { n: 1 }));
        assert_eq!(db.list_json::<Thing>("kv_test").unwrap().len(), 2);
        db.delete("kv_test", "a").unwrap();
        assert_eq!(db.get_json::<Thing>("kv_test", "a").unwrap(), None);
    }
    #[test]
    fn migrate_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("vk.sqlite")).unwrap();
        db.migrate().unwrap();
        db.migrate().unwrap();
        assert_eq!(db.kv_get("schema_version").unwrap().as_deref(), Some("1"));
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p vk-store` → compile errors.

- [ ] **Step 3: Implement**

`paths.rs`:
```rust
//! State directory resolution (plan Global Constraints): local app data, never a sync folder.
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

const SYNC_MARKERS: &[&str] = &["onedrive", "dropbox", "icloud", "com~apple~clouddocs", "google drive", "googledrive"];

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
```

`db.rs`:
```rust
//! SQLite metadata tier (spec §3.9). Generic JSON tables keep the schema small;
//! typed wrappers live in vk-kernel.
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub const TABLES: &[&str] = &["arches", "registers", "tasks", "leases", "approvals", "stops", "resumes", "liveness", "devices", "hot", "kv_test"];

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let db = Db { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn migrate(&self) -> Result<()> {
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);")?;
        for t in TABLES {
            self.conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS {t} (key TEXT PRIMARY KEY, json TEXT NOT NULL, updated_ms INTEGER NOT NULL DEFAULT 0);"
            ))?;
        }
        self.kv_set("schema_version", "1")?;
        Ok(())
    }

    fn check_table(table: &str) -> Result<()> {
        anyhow::ensure!(TABLES.contains(&table), "unknown table {table}");
        Ok(())
    }

    pub fn put_json<T: serde::Serialize>(&self, table: &str, key: &str, value: &T) -> Result<()> {
        Self::check_table(table)?;
        let json = serde_json::to_string(value)?;
        self.conn.execute(
            &format!("INSERT INTO {table} (key, json) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET json = excluded.json"),
            params![key, json],
        )?;
        Ok(())
    }

    pub fn get_json<T: serde::de::DeserializeOwned>(&self, table: &str, key: &str) -> Result<Option<T>> {
        Self::check_table(table)?;
        let json: Option<String> = self
            .conn
            .query_row(&format!("SELECT json FROM {table} WHERE key = ?1"), params![key], |r| r.get(0))
            .optional()?;
        Ok(match json { Some(j) => Some(serde_json::from_str(&j)?), None => None })
    }

    pub fn list_json<T: serde::de::DeserializeOwned>(&self, table: &str) -> Result<Vec<(String, T)>> {
        Self::check_table(table)?;
        let mut stmt = self.conn.prepare(&format!("SELECT key, json FROM {table} ORDER BY key"))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows { let (k, j) = row?; out.push((k, serde_json::from_str(&j)?)); }
        Ok(out)
    }

    pub fn delete(&self, table: &str, key: &str) -> Result<()> {
        Self::check_table(table)?;
        self.conn.execute(&format!("DELETE FROM {table} WHERE key = ?1"), params![key])?;
        Ok(())
    }

    pub fn kv_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| r.get(0)).optional()?)
    }

    pub fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute("INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![key, value])?;
        Ok(())
    }
}
```
`lib.rs`: `pub mod db; pub mod paths;`.

- [ ] **Step 4: Run** — `cargo test -p vk-store` → 4 passed. **Step 5: Commit** — `git commit -am "feat(store): state dir resolution and SQLite metadata tier"` (after `git add crates/vk-store Cargo.lock`).

---

### Task 2: Master key, per-subject DEKs, encrypted content-addressed blobs, shred

**Files:**
- Create: `crates/vk-store/src/keys.rs`, `crates/vk-store/src/blobs.rs`
- Modify: `crates/vk-store/src/lib.rs`

**Interfaces:**
- Produces: `MasterKey::load_or_create(source: KeySource) -> Result<MasterKey>` with `KeySource::{Keyring{service,user}, File(PathBuf)}`; `BlobStore::open(dir, master) -> Result<BlobStore>`; `put(subject_key_id, label, plaintext) -> Result<BlobEnvelope>` (hash = sha256 of plaintext); `get(hash) -> Result<Vec<u8>, StorageError>`; `shred(ShredEvent) -> Result<()>`; `is_shredded(key_id)`.

- [ ] **Step 1: Failing tests** (`blobs.rs` bottom)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeySource, MasterKey};
    use vk_contracts::labels::Label;
    use vk_contracts::principal::Principal;
    use vk_contracts::storage::{ShredEvent, StorageError};

    fn store() -> (tempfile::TempDir, BlobStore) {
        let d = tempfile::tempdir().unwrap();
        let master = MasterKey::load_or_create(KeySource::File(d.path().join("master.key"))).unwrap();
        let s = BlobStore::open(&d.path().join("blobs"), master).unwrap();
        (d, s)
    }

    #[test]
    fn round_trip_is_content_addressed_and_encrypted_at_rest() {
        let (d, s) = store();
        let env = s.put("subject-1", Label::bottom(), b"hello").unwrap();
        assert_eq!(env.hash, vk_contracts::hash_bytes(b"hello"));
        assert_eq!(s.get(&env.hash).unwrap(), b"hello".to_vec());
        let raw = std::fs::read(d.path().join("blobs").join(env.hash.trim_start_matches("sha256:")).with_extension("bin")).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"hello"), "plaintext must not be on disk");
    }

    #[test]
    fn shred_makes_every_blob_of_the_subject_unreadable_and_survives_reopen() {
        let (d, s) = store();
        let a = s.put("subject-1", Label::bottom(), b"a").unwrap();
        let b = s.put("subject-2", Label::bottom(), b"b").unwrap();
        s.shred(ShredEvent { key_id: "subject-1".into(), issuer: Principal::Human { device_id: "d".into() }, hlc_ms: 1 }).unwrap();
        assert_eq!(s.get(&a.hash), Err(StorageError::Shredded));
        assert_eq!(s.get(&b.hash).unwrap(), b"b".to_vec());
        drop(s);
        let master = MasterKey::load_or_create(KeySource::File(d.path().join("master.key"))).unwrap();
        let s2 = BlobStore::open(&d.path().join("blobs"), master).unwrap();
        assert_eq!(s2.get(&a.hash), Err(StorageError::Shredded));
        assert!(s2.is_shredded("subject-1"));
    }

    #[test]
    fn master_key_file_is_stable_across_loads() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("master.key");
        let k1 = MasterKey::load_or_create(KeySource::File(p.clone())).unwrap();
        let k2 = MasterKey::load_or_create(KeySource::File(p)).unwrap();
        assert_eq!(k1.fingerprint(), k2.fingerprint());
    }
}
```

- [ ] **Step 2: Run to verify failure** — compile errors.

- [ ] **Step 3: Implement**

`keys.rs`:
```rust
//! Master key and per-subject data-encryption keys (spec §3.9). The master key
//! never leaves the OS keyring except through the test/CI file source.
use anyhow::{bail, Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::path::PathBuf;

pub enum KeySource {
    Keyring { service: String, user: String },
    File(PathBuf),
}

#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn load_or_create(source: KeySource) -> Result<MasterKey> {
        match source {
            KeySource::Keyring { service, user } => {
                let entry = keyring::Entry::new(&service, &user)?;
                match entry.get_password() {
                    Ok(b64) => Ok(MasterKey(decode(&b64)?)),
                    Err(keyring::Error::NoEntry) => {
                        let k = fresh();
                        entry.set_password(&base64::engine::general_purpose::STANDARD.encode(k))?;
                        Ok(MasterKey(k))
                    }
                    Err(e) => Err(e.into()),
                }
            }
            KeySource::File(path) => {
                if path.exists() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = std::fs::metadata(&path)?.permissions().mode();
                        if mode & 0o077 != 0 { bail!("{} is readable by others; refusing", path.display()); }
                    }
                    Ok(MasterKey(decode(std::fs::read_to_string(&path)?.trim())?))
                } else {
                    let k = fresh();
                    std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode(k))
                        .with_context(|| format!("write {}", path.display()))?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                    }
                    Ok(MasterKey(k))
                }
            }
        }
    }

    pub fn fingerprint(&self) -> String { vk_contracts::hash_bytes(&self.0)[..23].to_string() }

    /// Wrap a DEK: nonce || ciphertext.
    pub fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>> { seal(&self.0, dek) }
    pub fn unwrap_dek(&self, wrapped: &[u8]) -> Result<[u8; 32]> {
        let v = open(&self.0, wrapped)?;
        v.try_into().map_err(|_| anyhow::anyhow!("bad DEK length"))
    }
}

fn fresh() -> [u8; 32] { let mut k = [0u8; 32]; rand::rngs::OsRng.fill_bytes(&mut k); k }

fn decode(b64: &str) -> Result<[u8; 32]> {
    let v = base64::engine::general_purpose::STANDARD.decode(b64)?;
    v.try_into().map_err(|_| anyhow::anyhow!("master key must be 32 bytes"))
}

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), plaintext).map_err(|_| anyhow::anyhow!("encrypt"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(sealed.len() > 24, "sealed blob too short");
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(XNonce::from_slice(&sealed[..24]), &sealed[24..]).map_err(|_| anyhow::anyhow!("decrypt failed"))
}
```

`blobs.rs`:
```rust
//! Encrypted, content-addressed payload tier (spec §3.9, D7). One DEK per
//! subject key id; shred = delete the wrapped DEK (and remember that we did).
use crate::keys::{open, seal, MasterKey};
use anyhow::{Context, Result};
use rand::RngCore;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use vk_contracts::labels::Label;
use vk_contracts::storage::{BlobEnvelope, ShredEvent, StorageError};

pub struct BlobStore {
    dir: PathBuf,
    master: MasterKey,
    shredded: BTreeSet<String>,
}

impl BlobStore {
    pub fn open(dir: &Path, master: MasterKey) -> Result<BlobStore> {
        std::fs::create_dir_all(dir.join("keys"))?;
        std::fs::create_dir_all(dir.join("shredded"))?;
        let shredded = std::fs::read_dir(dir.join("shredded"))?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        Ok(BlobStore { dir: dir.to_path_buf(), master, shredded })
    }

    fn blob_path(&self, hash: &str) -> PathBuf { self.dir.join(hash.trim_start_matches("sha256:")).with_extension("bin") }
    fn env_path(&self, hash: &str) -> PathBuf { self.dir.join(hash.trim_start_matches("sha256:")).with_extension("json") }
    fn dek_path(&self, key_id: &str) -> PathBuf { self.dir.join("keys").join(format!("{key_id}.dek")) }

    fn dek_for(&self, key_id: &str, create: bool) -> Result<[u8; 32], StorageError> {
        if self.shredded.contains(key_id) { return Err(StorageError::Shredded); }
        let p = self.dek_path(key_id);
        if p.exists() {
            let wrapped = std::fs::read(&p).map_err(|_| StorageError::NotFound)?;
            return self.master.unwrap_dek(&wrapped).map_err(|_| StorageError::NotFound);
        }
        if !create { return Err(StorageError::NotFound); }
        let mut dek = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut dek);
        let wrapped = self.master.wrap(&dek).map_err(|_| StorageError::NotFound)?;
        std::fs::write(&p, wrapped).map_err(|_| StorageError::NotFound)?;
        Ok(dek)
    }

    pub fn put(&self, key_id: &str, label: Label, plaintext: &[u8]) -> Result<BlobEnvelope> {
        let dek = self.dek_for(key_id, true).map_err(|e| anyhow::anyhow!("{e}"))?;
        let hash = vk_contracts::hash_bytes(plaintext);
        let sealed = seal(&dek, plaintext)?;
        let env = BlobEnvelope { hash: hash.clone(), key_id: key_id.into(), alg: "xchacha20poly1305".into(), ciphertext_len: sealed.len() as u64, label };
        std::fs::write(self.blob_path(&hash), &sealed).context("write blob")?;
        std::fs::write(self.env_path(&hash), serde_json::to_vec(&env)?).context("write envelope")?;
        Ok(env)
    }

    pub fn envelope(&self, hash: &str) -> Result<BlobEnvelope, StorageError> {
        let text = std::fs::read(self.env_path(hash)).map_err(|_| StorageError::NotFound)?;
        serde_json::from_slice(&text).map_err(|_| StorageError::NotFound)
    }

    pub fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let env = self.envelope(hash)?;
        let dek = self.dek_for(&env.key_id, false)?;
        let sealed = std::fs::read(self.blob_path(hash)).map_err(|_| StorageError::NotFound)?;
        open(&dek, &sealed).map_err(|_| StorageError::NotFound)
    }

    pub fn shred(&mut self, e: ShredEvent) -> Result<()> {
        let _ = std::fs::remove_file(self.dek_path(&e.key_id));
        std::fs::write(self.dir.join("shredded").join(&e.key_id), serde_json::to_vec(&e)?)?;
        self.shredded.insert(e.key_id);
        Ok(())
    }

    pub fn is_shredded(&self, key_id: &str) -> bool { self.shredded.contains(key_id) }
}
```
`lib.rs`: add `pub mod blobs; pub mod keys;`.

- [ ] **Step 4: Run** — `cargo test -p vk-store` → 7 passed. **Step 5: Commit** — `feat(store): master key, per-subject DEKs, encrypted content-addressed blobs, shred`.

---

### Task 3: Ledger segments on disk

**Files:**
- Create: `crates/vk-store/src/ledger_fs.rs`
- Modify: `crates/vk-store/src/lib.rs` (`pub mod ledger_fs;` and `Store` aggregate)

**Interfaces:**
- Produces: `LedgerFs::open(dir) -> Result<LedgerFs>` (reads all segments, verifies the chain, reports `recovered_partial_line: bool`), `append(kind, retention, wall_ms, quality, hlc, causal_heads, payload_hash) -> Result<LedgerEvent>`, `tail(n) -> Vec<LedgerEvent>`, `verify() -> bool`, `len()`; `Store { db: Db, blobs: BlobStore, ledger: LedgerFs }` with `Store::open(state_dir, key_source)`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vk_contracts::ledger::{ClockQuality, Hlc, RetentionClass};

    fn hlc(n: u64) -> Hlc { Hlc { wall_ms: n, counter: 0, node: "n1".into() } }

    #[test]
    fn appends_persist_and_chain_verifies_after_reopen() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut l = LedgerFs::open(d.path()).unwrap();
            l.append("boot", RetentionClass::Operational90d, 1, ClockQuality::Synced, hlc(1), vec![], "sha256:p".into()).unwrap();
            l.append("task.submitted", RetentionClass::Operational90d, 2, ClockQuality::Synced, hlc(2), vec![], "sha256:q".into()).unwrap();
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
            l.append("boot", RetentionClass::Operational90d, 1, ClockQuality::Synced, hlc(1), vec![], "sha256:p".into()).unwrap();
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
            l.append("boot", RetentionClass::Operational90d, 1, ClockQuality::Synced, hlc(1), vec![], "sha256:p".into()).unwrap();
        }
        let seg = d.path().join("seg-000000.jsonl");
        let text = std::fs::read_to_string(&seg).unwrap().replace("sha256:p", "sha256:evil");
        std::fs::write(&seg, text).unwrap();
        assert!(!LedgerFs::open(d.path()).unwrap().verify());
    }
}
```

- [ ] **Step 2: Run to verify failure** — compile errors.

- [ ] **Step 3: Implement**

```rust
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
                if line.trim().is_empty() { continue; }
                match serde_json::from_str::<LedgerEvent>(line) {
                    Ok(e) => chain.push_verified(e),
                    Err(_) => { recovered_partial_line = true; }
                }
            }
        }
        Ok(LedgerFs { dir: dir.to_path_buf(), chain, recovered_partial_line })
    }

    fn segment_path(&self, seq: u64) -> PathBuf { self.dir.join(format!("seg-{:06}.jsonl", seq / SEGMENT_EVENTS)) }

    #[allow(clippy::too_many_arguments)]
    pub fn append(&mut self, kind: &str, retention: RetentionClass, wall_ms: u64, quality: ClockQuality, hlc: Hlc, causal_heads: Vec<String>, payload_hash: String) -> Result<LedgerEvent> {
        let e = self.chain.append(kind, retention, wall_ms, quality, hlc, causal_heads, payload_hash).clone();
        let path = self.segment_path(e.seq);
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).with_context(|| format!("open {}", path.display()))?;
        f.write_all(serde_json::to_string(&e)?.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_data()?;
        Ok(e)
    }

    pub fn tail(&self, n: usize) -> Vec<LedgerEvent> {
        let ev = self.chain.events();
        ev[ev.len().saturating_sub(n)..].to_vec()
    }
    pub fn verify(&self) -> bool { self.chain.verify_chain() }
    pub fn len(&self) -> usize { self.chain.events().len() }
    pub fn is_empty(&self) -> bool { self.chain.events().is_empty() }
    pub fn events(&self) -> &[LedgerEvent] { self.chain.events() }
}
```
This needs one addition to SP0's `vk_contracts::ledger::Ledger`:
```rust
    /// Re-load a persisted event without recomputing it (used by on-disk segments).
    pub fn push_verified(&mut self, e: LedgerEvent) { self.events.push(e); }
```
(`verify_chain` recomputes hashes, so a tampered loaded event still fails verification.)

`Store` in `lib.rs`:
```rust
pub mod blobs; pub mod db; pub mod keys; pub mod ledger_fs; pub mod paths;

pub struct Store { pub db: db::Db, pub blobs: blobs::BlobStore, pub ledger: ledger_fs::LedgerFs, pub state_dir: std::path::PathBuf }

impl Store {
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
```

- [ ] **Step 4: Run** — `cargo test --workspace` → all green (vk-store 10, SP0 45). **Step 5: Commit** — `feat(store): hash-chained ledger segments on disk; Store aggregate`.

---

### Task 4: `RealKernel` — the stub's semantics over the store, interceptors shared

**Files:**
- Create: `crates/vk-contracts/src/interceptors.rs` (moved from `vk-stub/src/interceptors.rs`), `crates/vk-kernel/src/lib.rs`, `crates/vk-kernel/src/arch.rs`
- Modify: `crates/vk-contracts/src/lib.rs`, `crates/vk-stub/src/lib.rs` (use `vk_contracts::interceptors`), delete `crates/vk-stub/src/interceptors.rs`

**Interfaces:**
- Produces: `RealKernel::open(state_dir, key_source, node_id) -> Result<RealKernel>` implementing `Kernel` and `KernelTestHooks`; `arch::ArchAdapter` trait:

```rust
pub trait ArchAdapter: Send + Sync {
    fn manifest(&self) -> &ArchManifest;
    /// Real context budget in tokens (I4'); adapters must report what is actually loaded.
    fn context_budget(&self) -> u32;
    fn count_tokens(&self, text: &str) -> u32;
    fn complete(&self, prompt: &str, max_tokens: u32) -> anyhow::Result<String>;
}
pub struct MockAdapter { manifest: ArchManifest, budget: u32 }   // echoes "PLAN:" / "DRAFT:" + first 200 chars
pub fn lower(reg: &Register, role: &str) -> String              // IR → prompt
pub fn raise(reg: &mut Register, role: &str, output: &str)      // prompt output → IR (decision or evidence)
```

- [ ] **Step 1: Move interceptors** — `git mv crates/vk-stub/src/interceptors.rs crates/vk-contracts/src/interceptors.rs`; change its imports from `vk_contracts::…` to `crate::…`; add `pub mod interceptors;` to vk-contracts; in vk-stub replace `pub mod interceptors;` with `use vk_contracts::interceptors;`. Run `cargo test --workspace` → still green.

- [ ] **Step 2: Failing tests** (`crates/vk-kernel/src/lib.rs` bottom) — the same four scenarios as the stub's unit tests, plus persistence:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vk_contracts::arch::*;
    use vk_contracts::labels::*;
    use vk_contracts::principal::*;
    use vk_contracts::syscalls::*;
    use vk_contracts::testing::KernelTestHooks;
    use vk_store::keys::KeySource;

    fn open(dir: &std::path::Path) -> RealKernel {
        RealKernel::open(dir, KeySource::File(dir.join("master.key")), "n1").unwrap()
    }
    fn local(clearance: Clearance) -> ArchManifest {
        ArchManifest { name: "mock".into(), capabilities: [Capability::Generate, Capability::Plan].into(), locality: Locality::Local, jurisdiction: "FR".into(),
            retention_days: None, cost_per_1k_tokens_eur: 0.0, latency_ms_p50: 1, context_ceiling: 100, determinism: Determinism::SeededDeterministic,
            identity: ArchIdentity { weights_sha256: "sha256:mock".into(), engine: "mock".into(), engine_version: "1".into(), backend: "cpu".into(), quant: "-".into(),
                kv_cache: "-".into(), threads: 1, batch: 1, sampling: Default::default(), seed: Some(1) }, clearance, governed: true }
    }
    fn machine(now: u64) -> Ctx { Ctx { principal: Principal::Machine { node_id: "n1".into(), lease_id: "cli".into() }, clearance: Clearance { max_scope: Scope::Personal, third_party_allowed: true }, partition: "p1".into(), now_ms: now } }
    fn human(now: u64) -> Ctx { Ctx { principal: Principal::Human { device_id: "phone-1".into() }, ..machine(now) } }

    #[test]
    fn state_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let (arch, reg, stop_id) = {
            let mut k = open(d.path());
            let arch = k.register_arch(local(Clearance { max_scope: Scope::Personal, third_party_allowed: true }));
            let reg = k.submit_task(&machine(1), "draft a proposal", Label::bottom()).unwrap();
            k.infer(&machine(2), &arch, Capability::Plan, &reg).unwrap();
            let s = k.stop(&human(3), "business:acme").unwrap();
            (arch, reg, s)
        };
        let mut k = open(d.path());
        let r = k.read_register(&machine(4), &reg).unwrap();
        assert!(!r.decisions.is_empty(), "the plan raised into the IR must persist");
        assert!(k.stops().stopped("business:acme"));
        assert!(k.ledger().verify_chain());
        assert!(k.ledger().events().iter().any(|e| e.kind == "infer"));
        k.resume(&human(5), &stop_id).unwrap();
        assert!(!k.stops().stopped("business:acme"));
        let _ = arch;
    }

    #[test]
    fn i2_and_i4_prime_hold_on_the_real_kernel() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let cloud = k.register_arch(ArchManifest { locality: Locality::Cloud, clearance: Clearance { max_scope: Scope::Business, third_party_allowed: false }, ..local(Clearance { max_scope: Scope::Public, third_party_allowed: false }) });
        let r = k.submit_task(&machine(1), "x", Label { scope: Scope::Personal, data_class: DataClass::Own, origins: Default::default() }).unwrap();
        assert!(matches!(k.infer(&machine(1), &cloud, Capability::Generate, &r), Err(KernelError::I2(_))));
        let small = k.register_arch(local(Clearance { max_scope: Scope::Personal, third_party_allowed: true }));
        k.set_context_budget(&small, 5);
        let r2 = k.submit_task(&machine(1), &"g".repeat(400), Label::bottom()).unwrap();
        assert!(k.infer(&machine(1), &small, Capability::Generate, &r2).unwrap().projected);
        assert!(k.ledger().events().iter().any(|e| e.kind == "infer.projected"));
    }

    #[test]
    fn artefacts_are_stored_as_encrypted_blobs_under_the_task_subject() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let r = k.submit_task(&machine(1), "x", Label::bottom()).unwrap();
        let env = k.attach_artefact(&machine(2), &r, "proposal.md", b"# Proposal").unwrap();
        assert_eq!(k.read_artefact(&machine(3), &env.hash).unwrap(), b"# Proposal".to_vec());
        let reg = k.read_register(&machine(4), &r).unwrap();
        assert_eq!(reg.artefacts[0].hash, env.hash);
    }
}
```

- [ ] **Step 3: Run to verify failure** — compile errors.

- [ ] **Step 4: Implement**

`arch.rs`:
```rust
//! Arch adapters (spec §3.7) and IR lowering/raising (spec §3.2).
use vk_contracts::arch::ArchManifest;
use vk_contracts::register::Register;

pub trait ArchAdapter: Send + Sync {
    fn manifest(&self) -> &ArchManifest;
    fn context_budget(&self) -> u32;
    fn count_tokens(&self, text: &str) -> u32;
    fn complete(&self, prompt: &str, max_tokens: u32) -> anyhow::Result<String>;
}

pub struct MockAdapter { pub manifest: ArchManifest, pub budget: u32 }

impl ArchAdapter for MockAdapter {
    fn manifest(&self) -> &ArchManifest { &self.manifest }
    fn context_budget(&self) -> u32 { self.budget }
    fn count_tokens(&self, text: &str) -> u32 { (text.len() / 4) as u32 + 1 }
    fn complete(&self, prompt: &str, _max_tokens: u32) -> anyhow::Result<String> {
        let role = prompt.lines().next().unwrap_or("").trim_start_matches("ROLE: ").to_uppercase();
        let body: String = prompt.chars().take(200).collect();
        Ok(format!("{role}: {body}"))
    }
}

/// Lower a register into a prompt for `role` (plan | draft | judge). The role line
/// comes first so adapters and tests can recognise it.
pub fn lower(reg: &Register, role: &str) -> String {
    let mut s = format!("ROLE: {role}\nGOAL: {}\n", reg.goal);
    if !reg.constraints.is_empty() { s.push_str(&format!("CONSTRAINTS:\n- {}\n", reg.constraints.join("\n- "))); }
    for e in &reg.evidence { s.push_str(&format!("EVIDENCE ({:?}): {}\n", e.origin, e.content)); }
    for d in &reg.decisions { s.push_str(&format!("DECISION: {d}\n")); }
    for q in &reg.open_questions { s.push_str(&format!("OPEN: {q}\n")); }
    s
}

/// Structural projection when the prompt exceeds the budget (I4'): keep the role,
/// goal and decisions; truncate evidence, never silently.
pub fn project(prompt: &str, budget_tokens: u32) -> String {
    let max_chars = (budget_tokens as usize).saturating_mul(4);
    if prompt.len() <= max_chars { return prompt.to_string(); }
    let head: String = prompt.chars().take(max_chars.saturating_sub(40)).collect();
    format!("{head}\n[PROJECTED: {} chars dropped]\n", prompt.len() - head.len())
}

pub fn raise(reg: &mut Register, role: &str, output: &str) {
    match role {
        "plan" => reg.decisions.push(format!("plan: {}", output.trim())),
        "judge" => reg.open_questions.push(format!("judge: {}", output.trim())),
        _ => reg.decisions.push(format!("{role}: {}", output.trim())),
    }
}
```

`lib.rs` (RealKernel):
```rust
//! The real single-node kernel (spec §3): the stub's semantics over vk-store.
pub mod arch;

use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use vk_contracts::arch::{ArchManifest, Capability};
use vk_contracts::hash_canonical;
use vk_contracts::interceptors;
use vk_contracts::labels::{Label, Scope};
use vk_contracts::ledger::{ClockQuality, HlcClock, Ledger, RetentionClass};
use vk_contracts::locks::{Lease, LockHome, LockTable};
use vk_contracts::module::{GateKind, GateVerdict, ModuleManifest};
use vk_contracts::principal::{Approval, ApprovalKind, DeviceRegistry};
use vk_contracts::register::{ArtefactRef, Register, RegisterId};
use vk_contracts::stop::{LivenessLease, ResumeEvent, StopEvent, StopSet};
use vk_contracts::storage::BlobEnvelope;
use vk_contracts::syscalls::{Ctx, InferOutcome, Kernel, KernelError};
use vk_contracts::testing::KernelTestHooks;
use vk_store::keys::KeySource;
use vk_store::Store;

#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceRow { vk_hex: String, trust_class: String }

pub struct RealKernel {
    pub node_id: String,
    store: Store,
    clock: HlcClock,
    adapters: BTreeMap<String, Arc<dyn arch::ArchAdapter>>,
    budgets: BTreeMap<String, u32>,
    locks: LockTable,
    home: LockHome,
    devices: DeviceRegistry,
    stops: StopSet,
    infer_log: Vec<(String, Label)>,
    counter: u64,
}

impl RealKernel {
    pub fn open(state_dir: &Path, key_source: KeySource, node_id: &str) -> Result<RealKernel> {
        let store = Store::open(state_dir, key_source)?;
        let mut k = RealKernel { node_id: node_id.into(), store, clock: HlcClock::new(node_id), adapters: BTreeMap::new(), budgets: BTreeMap::new(),
            locks: LockTable::default(), home: LockHome::default(), devices: DeviceRegistry::default(), stops: StopSet::default(), infer_log: vec![], counter: 0 };
        k.load()?;
        Ok(k)
    }

    fn load(&mut self) -> Result<()> {
        for (_, s) in self.store.db.list_json::<StopEvent>("stops")? { let _ = self.stops.try_add_stop(s); }
        for (_, r) in self.store.db.list_json::<ResumeEvent>("resumes")? { let _ = self.stops.add_resume(r); }
        for (id, d) in self.store.db.list_json::<DeviceRow>("devices")? {
            if let Ok(bytes) = hex::decode(&d.vk_hex) { if let Ok(arr) = <[u8; 32]>::try_from(bytes) { self.devices.register(id, arr); } }
        }
        for (id, m) in self.store.db.list_json::<ArchManifest>("arches")? {
            let budget = m.context_ceiling;
            self.adapters.insert(id.clone(), Arc::new(arch::MockAdapter { manifest: m, budget }));
            self.budgets.insert(id, budget);
        }
        self.counter = self.store.db.kv_get("counter")?.and_then(|v| v.parse().ok()).unwrap_or(0);
        Ok(())
    }

    /// Mount a real adapter (replaces the mock loaded from the manifest table).
    pub fn mount(&mut self, adapter: Arc<dyn arch::ArchAdapter>) -> Result<String> {
        let m = adapter.manifest().clone();
        m.validate()?;
        let id = m.arch_id();
        self.store.db.put_json("arches", &id, &m)?;
        self.budgets.insert(id.clone(), adapter.context_budget());
        self.adapters.insert(id.clone(), adapter);
        self.log("arch.mounted", now_ms(), &id);
        Ok(id)
    }
    pub fn unmount(&mut self, arch_id: &str) -> Result<()> {
        self.adapters.remove(arch_id); self.budgets.remove(arch_id);
        self.store.db.delete("arches", arch_id)?;
        self.log("arch.unmounted", now_ms(), &arch_id);
        Ok(())
    }
    pub fn arches(&self) -> Vec<(String, ArchManifest)> { self.adapters.iter().map(|(k, a)| (k.clone(), a.manifest().clone())).collect() }
    pub fn store(&self) -> &Store { &self.store }

    pub fn attach_artefact(&mut self, ctx: &Ctx, reg_id: &RegisterId, kind: &str, bytes: &[u8]) -> Result<BlobEnvelope, KernelError> {
        let mut reg = self.read_register(ctx, reg_id)?;
        let env = self.store.blobs.put(&format!("task:{}", reg.task_id), reg.label.clone(), bytes).map_err(|e| KernelError::NotFound(e.to_string()))?;
        reg.artefacts.push(ArtefactRef { hash: env.hash.clone(), kind: kind.into() });
        self.write_register(ctx, reg)?;
        Ok(env)
    }
    pub fn read_artefact(&self, ctx: &Ctx, hash: &str) -> Result<Vec<u8>, KernelError> {
        let env = self.store.blobs.envelope(hash).map_err(|e| KernelError::NotFound(e.to_string()))?;
        if !env.label.flows_to(&ctx.clearance) { return Err(KernelError::I2(format!("artefact {hash} exceeds caller clearance"))); }
        self.store.blobs.get(hash).map_err(|e| KernelError::NotFound(e.to_string()))
    }

    fn log(&mut self, kind: &str, wall_ms: u64, payload: &impl serde::Serialize) {
        let hlc = self.clock.now(wall_ms);
        let _ = self.store.ledger.append(kind, RetentionClass::Operational90d, wall_ms, ClockQuality::Synced, hlc, vec![], hash_canonical(payload));
    }
    fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        let _ = self.store.db.kv_set("counter", &self.counter.to_string());
        format!("{prefix}-{}-{}", self.node_id, self.counter)
    }
    fn liveness(&self, business: &str) -> Option<LivenessLease> { self.store.db.get_json("liveness", business).ok().flatten() }
}

pub fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }

impl Kernel for RealKernel {
    fn submit_task(&mut self, ctx: &Ctx, goal: &str, label: Label) -> Result<RegisterId, KernelError> {
        let id = RegisterId(self.next_id("reg"));
        let task_id = self.next_id("task");
        let reg = Register { id: id.clone(), task_id, label, goal: goal.into(), constraints: vec![], evidence: vec![], decisions: vec![], open_questions: vec![], artefacts: vec![] };
        self.store.db.put_json("registers", &id.0, &reg).map_err(|e| KernelError::NotFound(e.to_string()))?;
        self.log("task.submitted", ctx.now_ms, &id);
        Ok(id)
    }
    fn read_register(&mut self, ctx: &Ctx, id: &RegisterId) -> Result<Register, KernelError> {
        let reg: Register = self.store.db.get_json("registers", &id.0).ok().flatten().ok_or_else(|| KernelError::NotFound(id.0.clone()))?;
        if !reg.label.flows_to(&ctx.clearance) { return Err(KernelError::I2(format!("register {} exceeds caller clearance", id.0))); }
        Ok(reg)
    }
    fn write_register(&mut self, ctx: &Ctx, reg: Register) -> Result<(), KernelError> {
        self.store.db.put_json("registers", &reg.id.0, &reg).map_err(|e| KernelError::NotFound(e.to_string()))?;
        self.log("register.written", ctx.now_ms, &reg.id);
        Ok(())
    }
    fn infer(&mut self, ctx: &Ctx, arch_id: &str, capability: Capability, reg_id: &RegisterId) -> Result<InferOutcome, KernelError> {
        let adapter = self.adapters.get(arch_id).cloned().ok_or_else(|| KernelError::NotFound(arch_id.into()))?;
        let mut reg = self.read_register(ctx, reg_id)?;
        interceptors::i2_flow(&reg.label, adapter.manifest())?;
        let role = match capability { Capability::Plan => "plan", Capability::Judge => "judge", _ => "draft" };
        let prompt = arch::lower(&reg, role);
        let tokens = adapter.count_tokens(&prompt);
        let budget = *self.budgets.get(arch_id).unwrap_or(&adapter.context_budget());
        let projected = tokens > budget;
        let prompt = if projected { self.log("infer.projected", ctx.now_ms, &(arch_id, tokens, budget)); arch::project(&prompt, budget) } else { prompt };
        let output = adapter.complete(&prompt, budget.min(1024)).map_err(|e| KernelError::NotFound(format!("arch error: {e}")))?;
        arch::raise(&mut reg, role, &output);
        self.write_register(ctx, reg.clone())?;
        self.log("infer", ctx.now_ms, &(arch_id, reg_id));
        self.infer_log.push((arch_id.into(), reg.label));
        Ok(InferOutcome { arch_id: arch_id.into(), projected, tokens_in: tokens.min(budget) })
    }
    fn lease(&mut self, ctx: &Ctx, resource: &str, ttl_ms: u64) -> Result<Lease, KernelError> {
        let l = self.locks.acquire(resource, ctx.principal.clone(), ctx.now_ms, ttl_ms, &ctx.partition, &mut self.home)?;
        let _ = self.store.db.put_json("leases", &l.id, &l);
        self.log("lease.granted", ctx.now_ms, &l.id);
        Ok(l)
    }
    fn approve(&mut self, ctx: &Ctx, approval: Approval) -> Result<(), KernelError> {
        interceptors::i1_approval(&ctx.principal, &approval, &self.devices, ctx.now_ms)?;
        let key = format!("{}:{}", approval.subject_hash, hash_canonical(&approval));
        let _ = self.store.db.put_json("approvals", &key, &approval);
        self.log("approval.recorded", ctx.now_ms, &approval);
        Ok(())
    }
    fn stop(&mut self, ctx: &Ctx, scope: &str) -> Result<String, KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        let id = self.next_id("stop");
        let e = StopEvent { id: id.clone(), scope: scope.into(), issuer: ctx.principal.clone(), hlc_ms: ctx.now_ms, causal_heads: vec![] };
        self.stops.try_add_stop(e.clone())?;
        let _ = self.store.db.put_json("stops", &id, &e);
        self.log("stop", ctx.now_ms, &id);
        Ok(id)
    }
    fn resume(&mut self, ctx: &Ctx, stop_id: &str) -> Result<(), KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        let id = self.next_id("resume");
        let e = ResumeEvent { id: id.clone(), cites: stop_id.into(), issuer: ctx.principal.clone(), hlc_ms: ctx.now_ms };
        self.stops.add_resume(e.clone())?;
        let _ = self.store.db.put_json("resumes", &id, &e);
        self.log("resume", ctx.now_ms, &stop_id);
        Ok(())
    }
    fn run_automation(&mut self, ctx: &Ctx, business: &str, module: &str) -> Result<(), KernelError> {
        if ctx.principal.is_human() { return Ok(()); }
        let lease = self.liveness(business);
        interceptors::i4_liveness(business, lease.as_ref(), &self.stops, ctx.now_ms)?;
        self.log("automation.ran", ctx.now_ms, &(business, module));
        Ok(())
    }
    fn promote(&mut self, ctx: &Ctx, module: &ModuleManifest, verdicts: &[GateVerdict]) -> Result<(), KernelError> {
        module.validate()?;
        let subject = module.provenance.content_hash.clone();
        if !verdicts.iter().any(|v| v.gate == GateKind::AnnexIii && v.subject_hash == subject && v.pass) { return Err(KernelError::Gate("annex_iii verdict required for promotion".into())); }
        let needs_human = module.autonomy_profile.as_ref().map(|p| !p.auto_approve_allowed).unwrap_or(true);
        let has_human = self.approvals_for(&subject).iter().any(|a| a.kind == ApprovalKind::Human);
        if needs_human && !has_human { return Err(KernelError::I1(format!("promotion of {} requires a human approval", module.name))); }
        let _ = self.store.db.put_json("hot", &subject, module);
        self.log("module.promoted", ctx.now_ms, &subject);
        Ok(())
    }
    fn export(&mut self, ctx: &Ctx, module_hash: &str, to_scope: Scope, verdicts: &[GateVerdict]) -> Result<(), KernelError> {
        if to_scope <= Scope::Vertical && !verdicts.iter().any(|v| v.gate == GateKind::Declassification && v.subject_hash == module_hash && v.pass) { return Err(KernelError::Gate("declassification verdict required to leave the business".into())); }
        self.log("module.exported", ctx.now_ms, &(module_hash, to_scope));
        Ok(())
    }
    fn ledger(&self) -> &Ledger { self.store.ledger.chain() }
}

impl KernelTestHooks for RealKernel {
    fn register_arch(&mut self, m: ArchManifest) -> String { let budget = m.context_ceiling; self.mount(Arc::new(arch::MockAdapter { manifest: m, budget })).expect("mount") }
    fn enroll_device(&mut self, device_id: &str, vk: [u8; 32]) {
        self.devices.register(device_id.into(), vk);
        let _ = self.store.db.put_json("devices", device_id, &DeviceRow { vk_hex: hex::encode(vk), trust_class: "full".into() });
        self.log("device.enrolled", now_ms(), &device_id);
    }
    fn renew_liveness(&mut self, business: &str, device_id: &str, expires_at_ms: u64) {
        let _ = self.store.db.put_json("liveness", business, &LivenessLease { business: business.into(), renewed_by_device: device_id.into(), expires_at_ms });
    }
    fn set_context_budget(&mut self, arch_id: &str, tokens: u32) { self.budgets.insert(arch_id.into(), tokens); }
    fn approvals_for(&self, subject_hash: &str) -> Vec<Approval> {
        self.store.db.list_json::<Approval>("approvals").unwrap_or_default().into_iter().filter(|(k, _)| k.starts_with(&format!("{subject_hash}:"))).map(|(_, a)| a).collect()
    }
    fn hot_modules(&self) -> Vec<String> { self.store.db.list_json::<ModuleManifest>("hot").unwrap_or_default().into_iter().map(|(k, _)| k).collect() }
    fn infer_log(&self) -> Vec<(String, Label)> { self.infer_log.clone() }
    fn stops(&self) -> StopSet { self.stops.clone() }
}
```
`LedgerFs` needs `pub fn chain(&self) -> &Ledger { &self.chain }` (add in vk-store). Note `enroll_device` and `renew_liveness` are also exposed as real (non-test) operations by the IPC server in Task 7 — they are legitimate admin syscalls; the trait just guarantees both kernels have them.

- [ ] **Step 5: Run** — `cargo test --workspace` → vk-kernel 3 new tests pass, everything else green. Clippy clean.

- [ ] **Step 6: Commit** — `feat(kernel): RealKernel over vk-store; interceptors shared via vk-contracts; artefacts as encrypted blobs`.

---

### Task 5: Property tests run against both kernels

**Files:**
- Modify: `crates/vk-props/Cargo.toml` (add `vk-kernel`, `vk-store`, `tempfile` dev-deps), all four `crates/vk-props/tests/*.rs`

**Interfaces:**
- Consumes: `KernelTestHooks`. Each test body becomes `fn check<K: KernelTestHooks>(k: &mut K, …)`; two `proptest!` wrappers call it with `StubKernel::new("n1")` and `RealKernel::open(tempdir, KeySource::File(...), "n1")`.

- [ ] **Step 1: Refactor one file first** — `i4_liveness_and_truncation.rs`:

```rust
use proptest::prelude::*;
use vk_contracts::arch::*;
use vk_contracts::labels::*;
use vk_contracts::principal::Principal;
use vk_contracts::syscalls::*;
use vk_contracts::testing::KernelTestHooks;

fn local() -> ArchManifest { /* unchanged from SP0 */ }
fn machine(now: u64, max_scope: Scope) -> Ctx { /* unchanged */ }

fn liveness_property<K: KernelTestHooks>(k: &mut K, expiry: u64, ticks: &[u64]) -> Result<(), TestCaseError> {
    k.renew_liveness("acme", "phone-1", expiry);
    for &now in ticks {
        let ran = k.run_automation(&machine(now, Scope::Personal), "acme", "m").is_ok();
        prop_assert_eq!(ran, now < expiry, "ran={} at now={} expiry={}", ran, now, expiry);
    }
    Ok(())
}

fn truncation_property<K: KernelTestHooks>(k: &mut K, goal_len: usize, budget: u32) -> Result<(), TestCaseError> {
    let id = k.register_arch(local());
    k.set_context_budget(&id, budget);
    let ctx = machine(1, Scope::Holdout);
    let r = k.submit_task(&ctx, &"g".repeat(goal_len), Label::bottom()).unwrap();
    let out = k.infer(&ctx, &id, Capability::Generate, &r).unwrap();
    let logged = k.ledger().events().iter().any(|e| e.kind == "infer.projected");
    prop_assert_eq!(out.projected, logged);
    prop_assert!(out.tokens_in <= budget);
    Ok(())
}

fn real(dir: &std::path::Path) -> vk_kernel::RealKernel {
    vk_kernel::RealKernel::open(dir, vk_store::keys::KeySource::File(dir.join("master.key")), "n1").unwrap()
}

proptest! {
    #[test]
    fn stub_liveness(expiry in 1u64..1000, ticks in prop::collection::vec(1u64..2000, 1..30)) { liveness_property(&mut vk_stub::StubKernel::new("n1"), expiry, &ticks)?; }
    #[test]
    fn real_liveness(expiry in 1u64..1000, ticks in prop::collection::vec(1u64..2000, 1..30)) { let d = tempfile::tempdir().unwrap(); liveness_property(&mut real(d.path()), expiry, &ticks)?; }
    #[test]
    fn stub_truncation(goal_len in 0usize..2000, budget in 1u32..64) { truncation_property(&mut vk_stub::StubKernel::new("n1"), goal_len, budget)?; }
    #[test]
    fn real_truncation(goal_len in 0usize..2000, budget in 1u32..64) { let d = tempfile::tempdir().unwrap(); truncation_property(&mut real(d.path()), goal_len, budget)?; }
}
```
Apply the same shape to `i1_human_path.rs`, `i2_clearance.rs` (I3 is store-level and stays as is). For the real kernel set `ProptestConfig { cases: 24, ..Default::default() }` on the `proptest!` block to keep SQLite setup time reasonable.

- [ ] **Step 2: Run** — `cargo test -p vk-props` → 8 property tests (4 stub, 3 real + I3) pass. If a real-kernel property fails, that is a kernel bug: fix `vk-kernel`, never the property.

- [ ] **Step 3: Commit** — `test(props): invariant properties run against stub and real kernels`.

---

### Task 6: Tasks, steps, the sequential scheduler, `ps`/`top` views, namespace

**Files:**
- Create: `crates/vk-kernel/src/tasks.rs`, `crates/vk-kernel/src/ns.rs`
- Modify: `crates/vk-kernel/src/lib.rs` (`pub mod tasks; pub mod ns;`, table `tasks`)

**Interfaces:**
- Produces:

```rust
pub enum StepKind { Plan { arch_id: String }, Draft { arch_id: String }, Judge { arch_id: String }, Harness { name: String }, Approve, Release { to_dir: String } }
pub enum StepStatus { Pending, Running, WaitingHuman, Done, Failed(String) }
pub struct Step { pub kind: StepKind, pub status: StepStatus, pub started_ms: Option<u64>, pub ended_ms: Option<u64>, pub tokens: u32 }
pub struct Task { pub id: String, pub register: RegisterId, pub goal: String, pub artefact_type: String, pub steps: Vec<Step>, pub status: TaskStatus, pub created_ms: u64 }
pub enum TaskStatus { Queued, Running, WaitingHuman, Done, Failed, Stopped }
impl RealKernel {
    pub fn create_task(&mut self, ctx: &Ctx, goal: &str, artefact_type: &str, label: Label, steps: Vec<StepKind>) -> Result<Task, KernelError>;
    pub fn run_task_step(&mut self, ctx: &Ctx, task_id: &str) -> Result<Task, KernelError>;   // runs the next pending step; Harness steps return WaitingHuman until SP1b
    pub fn tasks(&self) -> Vec<Task>;
    pub fn top(&self) -> TopView;     // per arch: calls, tokens, projected; leases held; liveness; stopped scopes
}
pub mod ns { pub enum Entry { Dir(Vec<String>), Arch(ArchManifest), Task(Task), Artefact(BlobEnvelope), Device(String), LedgerTail(Vec<LedgerEvent>) } pub fn resolve(k: &RealKernel, path: &str) -> Result<Entry, KernelError>; }
```

- [ ] **Step 1: Failing tests** (`tasks.rs` bottom)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealKernel;
    use vk_contracts::labels::*;
    use vk_contracts::principal::Principal;
    use vk_contracts::syscalls::Ctx;
    use vk_contracts::testing::KernelTestHooks;

    fn machine(now: u64) -> Ctx { Ctx { principal: Principal::Machine { node_id: "n1".into(), lease_id: "cli".into() }, clearance: Clearance { max_scope: Scope::Personal, third_party_allowed: true }, partition: "p1".into(), now_ms: now } }

    #[test]
    fn plan_then_draft_then_approve_waits_for_a_human() {
        let d = tempfile::tempdir().unwrap();
        let mut k = RealKernel::open(d.path(), vk_store::keys::KeySource::File(d.path().join("m.key")), "n1").unwrap();
        let arch = k.register_arch(crate::tests::local(Clearance { max_scope: Scope::Personal, third_party_allowed: true }));
        let t = k.create_task(&machine(1), "Draft a proposal for Acme", "proposal", Label::bottom(),
            vec![StepKind::Plan { arch_id: arch.clone() }, StepKind::Draft { arch_id: arch.clone() }, StepKind::Approve, StepKind::Release { to_dir: d.path().join("out").to_string_lossy().into() }]).unwrap();
        let t = k.run_task_step(&machine(2), &t.id).unwrap();
        assert!(matches!(t.steps[0].status, StepStatus::Done));
        let t = k.run_task_step(&machine(3), &t.id).unwrap();
        assert!(matches!(t.steps[1].status, StepStatus::Done));
        let t = k.run_task_step(&machine(4), &t.id).unwrap();
        assert!(matches!(t.status, TaskStatus::WaitingHuman));
        let reg = k.read_register(&machine(5), &t.register).unwrap();
        assert!(reg.decisions.iter().any(|d| d.starts_with("plan:")));
        assert!(reg.decisions.iter().any(|d| d.starts_with("draft:")));
        assert_eq!(k.top().arches[&arch].calls, 2);
    }

    #[test]
    fn stopped_scope_halts_the_scheduler() {
        let d = tempfile::tempdir().unwrap();
        let mut k = RealKernel::open(d.path(), vk_store::keys::KeySource::File(d.path().join("m.key")), "n1").unwrap();
        let arch = k.register_arch(crate::tests::local(Clearance { max_scope: Scope::Personal, third_party_allowed: true }));
        let t = k.create_task(&machine(1), "x", "note", Label::bottom(), vec![StepKind::Plan { arch_id: arch }]).unwrap();
        let human = Ctx { principal: Principal::Human { device_id: "phone-1".into() }, ..machine(2) };
        k.stop(&human, "node").unwrap();
        assert!(matches!(k.run_task_step(&machine(3), &t.id), Err(vk_contracts::syscalls::KernelError::Stopped(_))));
    }

    #[test]
    fn namespace_lists_and_resolves() {
        let d = tempfile::tempdir().unwrap();
        let mut k = RealKernel::open(d.path(), vk_store::keys::KeySource::File(d.path().join("m.key")), "n1").unwrap();
        let arch = k.register_arch(crate::tests::local(Clearance { max_scope: Scope::Personal, third_party_allowed: true }));
        assert!(matches!(crate::ns::resolve(&k, "/").unwrap(), crate::ns::Entry::Dir(_)));
        assert!(matches!(crate::ns::resolve(&k, &format!("/arches/{arch}")).unwrap(), crate::ns::Entry::Arch(_)));
        assert!(crate::ns::resolve(&k, "/nope").is_err());
    }
}
```
(Make the `local(...)` helper in `lib.rs` tests `pub(crate)`.)

- [ ] **Step 2: Run to verify failure** — compile errors.

- [ ] **Step 3: Implement `tasks.rs`**

```rust
//! Tasks and the sequential scheduler (spec §3.3). Steps run one at a time;
//! STOP on scope "node" or the task's business halts everything; Approve waits
//! for a human approval whose subject is the latest artefact hash; Harness steps
//! are completed by SP1b.
use crate::{now_ms, RealKernel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vk_contracts::arch::Capability;
use vk_contracts::labels::Label;
use vk_contracts::principal::ApprovalKind;
use vk_contracts::register::RegisterId;
use vk_contracts::syscalls::{Ctx, Kernel, KernelError};
use vk_contracts::testing::KernelTestHooks;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum StepKind { Plan { arch_id: String }, Draft { arch_id: String }, Judge { arch_id: String }, Harness { name: String }, Approve, Release { to_dir: String } }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus { Pending, Running, WaitingHuman, Done, Failed(String) }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Step { pub kind: StepKind, pub status: StepStatus, pub started_ms: Option<u64>, pub ended_ms: Option<u64>, pub tokens: u32 }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus { Queued, Running, WaitingHuman, Done, Failed, Stopped }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task { pub id: String, pub register: RegisterId, pub goal: String, pub artefact_type: String, pub steps: Vec<Step>, pub status: TaskStatus, pub created_ms: u64 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchStats { pub calls: u32, pub tokens_in: u64, pub projected: u32 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TopView { pub arches: BTreeMap<String, ArchStats>, pub tasks: BTreeMap<String, TaskStatus>, pub stopped_scopes: Vec<String>, pub liveness: BTreeMap<String, u64> }

impl RealKernel {
    pub fn create_task(&mut self, ctx: &Ctx, goal: &str, artefact_type: &str, label: Label, steps: Vec<StepKind>) -> Result<Task, KernelError> {
        let register = self.submit_task(ctx, goal, label)?;
        let id = self.next_id("task");
        let task = Task { id: id.clone(), register, goal: goal.into(), artefact_type: artefact_type.into(),
            steps: steps.into_iter().map(|kind| Step { kind, status: StepStatus::Pending, started_ms: None, ended_ms: None, tokens: 0 }).collect(),
            status: TaskStatus::Queued, created_ms: ctx.now_ms };
        self.save_task(&task)?;
        Ok(task)
    }

    fn save_task(&mut self, t: &Task) -> Result<(), KernelError> { self.store.db.put_json("tasks", &t.id, t).map_err(|e| KernelError::NotFound(e.to_string())) }
    pub fn task(&self, id: &str) -> Option<Task> { self.store.db.get_json("tasks", id).ok().flatten() }
    pub fn tasks(&self) -> Vec<Task> { self.store.db.list_json::<Task>("tasks").unwrap_or_default().into_iter().map(|(_, t)| t).collect() }

    pub fn run_task_step(&mut self, ctx: &Ctx, task_id: &str) -> Result<Task, KernelError> {
        let mut t = self.task(task_id).ok_or_else(|| KernelError::NotFound(task_id.into()))?;
        if self.stops.stopped("node") { t.status = TaskStatus::Stopped; self.save_task(&t)?; return Err(KernelError::Stopped("node".into())); }
        let Some(i) = t.steps.iter().position(|s| !matches!(s.status, StepStatus::Done)) else { t.status = TaskStatus::Done; self.save_task(&t)?; return Ok(t); };
        t.steps[i].status = StepStatus::Running; t.steps[i].started_ms = Some(ctx.now_ms); t.status = TaskStatus::Running;
        let kind = t.steps[i].kind.clone();
        let outcome: Result<StepStatus, KernelError> = match &kind {
            StepKind::Plan { arch_id } => self.infer(ctx, arch_id, Capability::Plan, &t.register).map(|o| { t.steps[i].tokens = o.tokens_in; StepStatus::Done }),
            StepKind::Draft { arch_id } => self.infer(ctx, arch_id, Capability::Generate, &t.register).map(|o| { t.steps[i].tokens = o.tokens_in; StepStatus::Done }),
            StepKind::Judge { arch_id } => self.infer(ctx, arch_id, Capability::Judge, &t.register).map(|o| { t.steps[i].tokens = o.tokens_in; StepStatus::Done }),
            StepKind::Harness { .. } => Ok(StepStatus::WaitingHuman), // SP1b replaces this with a confined launch
            StepKind::Approve => {
                let reg = self.read_register(ctx, &t.register)?;
                let subject = reg.artefacts.last().map(|a| a.hash.clone()).unwrap_or_else(|| vk_contracts::hash_canonical(&reg));
                if self.approvals_for(&subject).iter().any(|a| a.kind == ApprovalKind::Human) { Ok(StepStatus::Done) } else { Ok(StepStatus::WaitingHuman) }
            }
            StepKind::Release { to_dir } => {
                let reg = self.read_register(ctx, &t.register)?;
                std::fs::create_dir_all(to_dir).map_err(|e| KernelError::NotFound(e.to_string()))?;
                for a in &reg.artefacts {
                    let bytes = self.read_artefact(ctx, &a.hash)?;
                    std::fs::write(std::path::Path::new(to_dir).join(format!("{}.{}", a.hash.trim_start_matches("sha256:").get(..12).unwrap_or("artefact"), a.kind)), bytes).map_err(|e| KernelError::NotFound(e.to_string()))?;
                }
                Ok(StepStatus::Done)
            }
        };
        match outcome {
            Ok(StepStatus::WaitingHuman) => { t.steps[i].status = StepStatus::WaitingHuman; t.status = TaskStatus::WaitingHuman; }
            Ok(s) => { t.steps[i].status = s; t.steps[i].ended_ms = Some(now_ms()); if t.steps.iter().all(|s| matches!(s.status, StepStatus::Done)) { t.status = TaskStatus::Done; } }
            Err(e) => { t.steps[i].status = StepStatus::Failed(e.to_string()); t.status = TaskStatus::Failed; self.save_task(&t)?; return Err(e); }
        }
        self.log("task.step", ctx.now_ms, &(task_id, i));
        self.save_task(&t)?;
        Ok(t)
    }

    pub fn top(&self) -> TopView {
        let mut v = TopView::default();
        for e in self.ledger().events() {
            if e.kind == "infer" || e.kind == "infer.projected" {
                // payload hashes are opaque; per-arch stats come from the in-memory infer log plus projected counter
            }
        }
        for (arch, _) in self.infer_log() { v.arches.entry(arch).or_default().calls += 1; }
        for t in self.tasks() { v.tasks.insert(t.id, t.status); }
        for scope in ["node"] { if self.stops.stopped(scope) { v.stopped_scopes.push(scope.into()); } }
        for (b, l) in self.store.db.list_json::<vk_contracts::stop::LivenessLease>("liveness").unwrap_or_default() { v.liveness.insert(b, l.expires_at_ms); }
        v
    }
}
```
(Persist per-arch token counters in `kv` under `stats:<arch_id>` inside `infer` so `top` survives restarts — add `self.store.db.kv_set(&format!("stats:{arch_id}"), …)` in Task 4's `infer` and read it in `top`; the test only checks `calls`.)

`ns.rs`:
```rust
//! The namespace (SP1 design §7): everything the kernel manages has a path.
use crate::tasks::Task;
use crate::RealKernel;
use vk_contracts::arch::ArchManifest;
use vk_contracts::ledger::LedgerEvent;
use vk_contracts::storage::BlobEnvelope;
use vk_contracts::syscalls::KernelError;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Entry { Dir { entries: Vec<String> }, Arch(ArchManifest), Task(Task), Artefact(BlobEnvelope), Device { id: String }, LedgerTail { events: Vec<LedgerEvent> } }

pub fn resolve(k: &RealKernel, path: &str) -> Result<Entry, KernelError> {
    let parts: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    match parts.as_slice() {
        [] => Ok(Entry::Dir { entries: vec!["arches".into(), "tasks".into(), "artefacts".into(), "devices".into(), "ledger".into()] }),
        ["arches"] => Ok(Entry::Dir { entries: k.arches().into_iter().map(|(id, m)| format!("{id}  {}", m.name)).collect() }),
        ["arches", id] => k.arches().into_iter().find(|(i, _)| i == id).map(|(_, m)| Entry::Arch(m)).ok_or_else(|| KernelError::NotFound(path.into())),
        ["tasks"] => Ok(Entry::Dir { entries: k.tasks().into_iter().map(|t| t.id).collect() }),
        ["tasks", id] => k.task(id).map(Entry::Task).ok_or_else(|| KernelError::NotFound(path.into())),
        ["artefacts", hash] => k.store().blobs.envelope(&format!("sha256:{}", hash.trim_start_matches("sha256:"))).map(Entry::Artefact).map_err(|_| KernelError::NotFound(path.into())),
        ["devices"] => Ok(Entry::Dir { entries: k.store().db.list_json::<serde_json::Value>("devices").unwrap_or_default().into_iter().map(|(id, _)| id).collect() }),
        ["ledger"] => Ok(Entry::LedgerTail { events: k.store().ledger.tail(50) }),
        _ => Err(KernelError::NotFound(path.into())),
    }
}
```

- [ ] **Step 4: Run** — `cargo test -p vk-kernel` → 6 passed. **Step 5: Commit** — `feat(kernel): tasks, sequential scheduler with STOP/approval gates, top view, namespace`.

---

### Task 7: IPC — JSON-RPC over pipe/socket, principal derivation, presence ceremony

**Files:**
- Create: `crates/vk-ipc/src/lib.rs`, `crates/vk-ipc/src/transport.rs`, `crates/vk-ipc/src/server.rs`, `crates/vk-ipc/src/client.rs`, `crates/vk-kernel/src/presence.rs`

**Interfaces:**
- Produces: request/response types, method names (`ns.ls`, `arch.ls`, `arch.mount_mock`, `arch.unmount`, `task.create`, `task.step`, `task.show`, `task.ls`, `top`, `stop`, `resume`, `approve`, `presence.challenge`, `device.enroll_node`, `ledger.tail`, `ledger.verify`, `boot.info`), `Server::serve(kernel: Arc<Mutex<RealKernel>>, endpoint) `, `Client::connect(endpoint)?.call(method, params) -> Result<Value>`; `presence::NodeDevice` — the node's own software key (SP0 `SoftwareHumanKey`, private key stored in the keyring under `vk/node-device`), enrolled at first boot as device `node:<node_id>` with trust class `full`.

**Principal derivation rule (the whole point of this task):** a connection on the local endpoint is a `Principal::Machine { node_id, lease_id: "cli" }`. A request may be *upgraded* to `Principal::Human { device_id }` **only** by presenting a presence proof: the client first calls `presence.challenge` (server returns `{nonce, expires_at_ms}`), signs `sha256("presence|" + nonce)` with an enrolled device key, and sends `presence: {device_id, nonce, signature_hex}` inside the next request; the server verifies against `DeviceRegistry` and builds a human `Ctx` for that one request. `approve` additionally requires a full SP0 `Approval` with challenge + signature (I1). Passkeys (SP1b) become a second way to produce the same proofs.

- [ ] **Step 1: Failing tests** (`crates/vk-ipc/tests/roundtrip.rs`)

```rust
use serde_json::json;
use std::sync::{Arc, Mutex};
use vk_contracts::principal::HumanKey;

fn kernel(dir: &std::path::Path) -> Arc<Mutex<vk_kernel::RealKernel>> {
    Arc::new(Mutex::new(vk_kernel::RealKernel::open(dir, vk_store::keys::KeySource::File(dir.join("m.key")), "n1").unwrap()))
}

#[tokio::test]
async fn cli_principal_cannot_stop_but_presence_proof_can() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let device = vk_contracts::principal::SoftwareHumanKey::generate("laptop");
    { use vk_contracts::testing::KernelTestHooks; k.lock().unwrap().enroll_device("laptop", device.verifying_key_bytes()); }
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c = vk_ipc::client::Client::connect(&endpoint).await.unwrap();
    let err = c.call("stop", json!({"scope": "node"}), None).await.unwrap_err();
    assert!(err.to_string().contains("I1"), "machine principal must not STOP: {err}");
    let ch = c.call("presence.challenge", json!({}), None).await.unwrap();
    let nonce = ch["nonce"].as_str().unwrap().to_string();
    let proof = vk_ipc::PresenceProof::sign(&device, &nonce);
    let ok = c.call("stop", json!({"scope": "node"}), Some(proof)).await.unwrap();
    assert!(ok["stop_id"].as_str().unwrap().starts_with("stop-"));
    assert!(k.lock().unwrap().stops().stopped("node"));
    server.abort();
}

#[tokio::test]
async fn ns_and_task_flow_over_ipc() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c = vk_ipc::client::Client::connect(&endpoint).await.unwrap();
    let arch = c.call("arch.mount_mock", json!({"name": "mock", "context_ceiling": 200}), None).await.unwrap()["arch_id"].as_str().unwrap().to_string();
    let t = c.call("task.create", json!({"goal": "Draft a proposal", "artefact_type": "proposal", "steps": [{"kind":"plan","arch_id":arch},{"kind":"draft","arch_id":arch},{"kind":"approve"}]}), None).await.unwrap();
    let id = t["id"].as_str().unwrap().to_string();
    c.call("task.step", json!({"task_id": id}), None).await.unwrap();
    c.call("task.step", json!({"task_id": id}), None).await.unwrap();
    let waiting = c.call("task.step", json!({"task_id": id}), None).await.unwrap();
    assert_eq!(waiting["status"], "waiting_human");
    let ls = c.call("ns.ls", json!({"path": "/tasks"}), None).await.unwrap();
    assert!(ls["entries"].as_array().unwrap().iter().any(|e| e == &json!(id)));
    assert_eq!(c.call("ledger.verify", json!({}), None).await.unwrap()["ok"], true);
    server.abort();
}
```
Add to `vk-ipc/Cargo.toml` dev-deps: `tempfile = "3"`, `vk-store = { path = "../vk-store" }`; `tokio` already has `macros`.

- [ ] **Step 2: Run to verify failure** — compile errors.

- [ ] **Step 3: Implement**

`transport.rs`:
```rust
//! Local endpoint: named pipe on Windows, Unix socket elsewhere. The OS ACL on
//! the endpoint is the first authentication factor (same user account only).
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone, Debug)]
pub struct Endpoint(pub String);

pub fn default_endpoint() -> Endpoint {
    #[cfg(windows)] { Endpoint(format!(r"\\.\pipe\vk-{}", whoami())) }
    #[cfg(not(windows))] { Endpoint(std::env::var("XDG_RUNTIME_DIR").map(|d| format!("{d}/vk.sock")).unwrap_or_else(|_| format!("/tmp/vk-{}.sock", whoami()))) }
}
pub fn test_endpoint() -> Endpoint {
    let id = uuid::Uuid::new_v4().simple().to_string();
    #[cfg(windows)] { Endpoint(format!(r"\\.\pipe\vk-test-{id}")) }
    #[cfg(not(windows))] { Endpoint(format!("{}/vk-test-{id}.sock", std::env::temp_dir().display())) }
}
fn whoami() -> String { std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "user".into()) }

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[cfg(windows)]
pub mod os {
    use super::*;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    pub struct Listener { name: String, next: Option<NamedPipeServer> }
    pub async fn bind(ep: &Endpoint) -> Result<Listener> {
        let first = ServerOptions::new().first_pipe_instance(true).create(&ep.0)?;
        Ok(Listener { name: ep.0.clone(), next: Some(first) })
    }
    impl Listener {
        pub async fn accept(&mut self) -> Result<Box<dyn Stream>> {
            let server = self.next.take().unwrap();
            server.connect().await?;
            self.next = Some(ServerOptions::new().create(&self.name)?);
            Ok(Box::new(server))
        }
    }
    pub async fn connect(ep: &Endpoint) -> Result<Box<dyn Stream>> {
        for _ in 0..50 {
            match ClientOptions::new().open(&ep.0) {
                Ok(c) => return Ok(Box::new(c)),
                Err(e) if e.raw_os_error() == Some(231) => tokio::time::sleep(std::time::Duration::from_millis(20)).await, // ERROR_PIPE_BUSY
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("pipe busy")
    }
}

#[cfg(not(windows))]
pub mod os {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};
    pub struct Listener(UnixListener);
    pub async fn bind(ep: &Endpoint) -> Result<Listener> {
        let _ = std::fs::remove_file(&ep.0);
        let l = UnixListener::bind(&ep.0)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ep.0, std::fs::Permissions::from_mode(0o600))?;
        Ok(Listener(l))
    }
    impl Listener { pub async fn accept(&mut self) -> Result<Box<dyn Stream>> { let (s, _) = self.0.accept().await?; Ok(Box::new(s)) } }
    pub async fn connect(ep: &Endpoint) -> Result<Box<dyn Stream>> { Ok(Box::new(UnixStream::connect(&ep.0).await?)) }
}
```
Add `uuid.workspace = true` to vk-ipc deps.

`lib.rs`:
```rust
//! Syscall transport (spec §3.11): newline-delimited JSON-RPC 2.0 on a local endpoint.
pub mod client;
pub mod server;
pub mod transport;

use serde::{Deserialize, Serialize};
use vk_contracts::principal::HumanKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceProof { pub device_id: String, pub nonce: String, pub signature_hex: String }

impl PresenceProof {
    pub fn message(nonce: &str) -> Vec<u8> { vk_contracts::hash_bytes(format!("presence|{nonce}").as_bytes()).into_bytes() }
    pub fn sign(key: &impl HumanKey, nonce: &str) -> PresenceProof {
        PresenceProof { device_id: key.device_id(), nonce: nonce.into(), signature_hex: hex::encode(key.sign(&Self::message(nonce))) }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Request { pub jsonrpc: String, pub id: u64, pub method: String, pub params: serde_json::Value, #[serde(default)] pub presence: Option<PresenceProof> }

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError { pub code: i32, pub message: String }

#[derive(Debug, Serialize, Deserialize)]
pub struct Response { pub jsonrpc: String, pub id: u64, #[serde(skip_serializing_if = "Option::is_none")] pub result: Option<serde_json::Value>, #[serde(skip_serializing_if = "Option::is_none")] pub error: Option<RpcError> }

pub const E_INVARIANT: i32 = -32001;
pub const E_NOT_FOUND: i32 = -32004;
pub const E_BAD_PARAMS: i32 = -32602;
```

`server.rs` (dispatch core; each handler is a small function):
```rust
use crate::{transport::{self, Endpoint}, PresenceProof, Request, Response, RpcError, E_BAD_PARAMS, E_INVARIANT, E_NOT_FOUND};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use vk_contracts::labels::{Clearance, Label, Scope};
use vk_contracts::principal::{Approval, Principal};
use vk_contracts::syscalls::{Ctx, Kernel, KernelError};
use vk_contracts::testing::KernelTestHooks;
use vk_kernel::tasks::StepKind;
use vk_kernel::{now_ms, RealKernel};

type Shared = Arc<Mutex<RealKernel>>;
struct Challenges(Mutex<BTreeMap<String, u64>>); // nonce -> expires_at_ms

pub async fn serve(kernel: Shared, endpoint: Endpoint) -> Result<()> {
    let mut listener = transport::os::bind(&endpoint).await?;
    let challenges = Arc::new(Challenges(Mutex::new(BTreeMap::new())));
    loop {
        let stream = listener.accept().await?;
        let (k, ch) = (kernel.clone(), challenges.clone());
        tokio::spawn(async move { let _ = handle_connection(stream, k, ch).await; });
    }
}

async fn handle_connection(stream: Box<dyn transport::Stream>, kernel: Shared, challenges: Arc<Challenges>) -> Result<()> {
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();
    while let Some(line) = lines.next_line().await? {
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => { let id = req.id; match dispatch(&kernel, &challenges, req) { Ok(v) => Response { jsonrpc: "2.0".into(), id, result: Some(v), error: None }, Err(e) => Response { jsonrpc: "2.0".into(), id, result: None, error: Some(e) } } }
            Err(e) => Response { jsonrpc: "2.0".into(), id: 0, result: None, error: Some(RpcError { code: E_BAD_PARAMS, message: e.to_string() }) },
        };
        w.write_all(serde_json::to_string(&resp)?.as_bytes()).await?;
        w.write_all(b"\n").await?;
    }
    Ok(())
}

fn kerr(e: KernelError) -> RpcError {
    let code = match e { KernelError::NotFound(_) => E_NOT_FOUND, _ => E_INVARIANT };
    RpcError { code, message: e.to_string() }
}
fn bad(msg: &str) -> RpcError { RpcError { code: E_BAD_PARAMS, message: msg.into() } }

/// The only place a Ctx is built. Machine by default; human only with a valid presence proof.
fn ctx_for(k: &RealKernel, challenges: &Challenges, presence: Option<PresenceProof>) -> Result<Ctx, RpcError> {
    let now = now_ms();
    let principal = match presence {
        None => Principal::Machine { node_id: k.node_id.clone(), lease_id: "cli".into() },
        Some(p) => {
            let mut map = challenges.0.lock().unwrap();
            let exp = map.remove(&p.nonce).ok_or_else(|| RpcError { code: E_INVARIANT, message: "I1: unknown or reused presence nonce".into() })?;
            if now >= exp { return Err(RpcError { code: E_INVARIANT, message: "I1: presence challenge expired".into() }); }
            let sig: [u8; 64] = hex::decode(&p.signature_hex).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| RpcError { code: E_INVARIANT, message: "I1: bad signature".into() })?;
            k.devices().verify(&p.device_id, &PresenceProof::message(&p.nonce), &sig).map_err(|e| RpcError { code: E_INVARIANT, message: format!("I1: {e}") })?;
            Principal::Human { device_id: p.device_id }
        }
    };
    Ok(Ctx { principal, clearance: Clearance { max_scope: Scope::Personal, third_party_allowed: true }, partition: "local".into(), now_ms: now })
}

fn dispatch(kernel: &Shared, challenges: &Challenges, req: Request) -> Result<Value, RpcError> {
    let mut k = kernel.lock().unwrap();
    let p = req.params;
    match req.method.as_str() {
        "presence.challenge" => { let nonce = uuid::Uuid::new_v4().simple().to_string(); let exp = now_ms() + 60_000; challenges.0.lock().unwrap().insert(nonce.clone(), exp); Ok(json!({"nonce": nonce, "expires_at_ms": exp})) }
        "boot.info" => Ok(json!({"node_id": k.node_id, "arches": k.arches().len(), "ledger_len": k.ledger().events().len(), "ledger_ok": k.ledger().verify_chain(), "state_dir": k.store().state_dir})),
        "ns.ls" => { let path = p["path"].as_str().unwrap_or("/"); vk_kernel::ns::resolve(&k, path).map(|e| serde_json::to_value(e).unwrap()).map_err(kerr) }
        "arch.ls" => Ok(json!(k.arches().into_iter().map(|(id, m)| json!({"arch_id": id, "manifest": m})).collect::<Vec<_>>())),
        "arch.mount_mock" => { let m = mock_manifest(p["name"].as_str().unwrap_or("mock"), p["context_ceiling"].as_u64().unwrap_or(4096) as u32); Ok(json!({"arch_id": k.register_arch(m)})) }
        "arch.unmount" => { k.unmount(p["arch_id"].as_str().ok_or_else(|| bad("arch_id"))?).map_err(|e| bad(&e.to_string()))?; Ok(json!({"ok": true})) }
        "task.create" => {
            let ctx = ctx_for(&k, challenges, req.presence)?;
            let steps: Vec<StepKind> = serde_json::from_value(p["steps"].clone()).map_err(|e| bad(&e.to_string()))?;
            let t = k.create_task(&ctx, p["goal"].as_str().ok_or_else(|| bad("goal"))?, p["artefact_type"].as_str().unwrap_or("note"), Label::bottom(), steps).map_err(kerr)?;
            Ok(serde_json::to_value(t).unwrap())
        }
        "task.step" => { let ctx = ctx_for(&k, challenges, req.presence)?; k.run_task_step(&ctx, p["task_id"].as_str().ok_or_else(|| bad("task_id"))?).map(|t| serde_json::to_value(t).unwrap()).map_err(kerr) }
        "task.show" => k.task(p["task_id"].as_str().unwrap_or("")).map(|t| serde_json::to_value(t).unwrap()).ok_or_else(|| RpcError { code: E_NOT_FOUND, message: "task".into() }),
        "task.ls" => Ok(serde_json::to_value(k.tasks()).unwrap()),
        "top" => Ok(serde_json::to_value(k.top()).unwrap()),
        "stop" => { let ctx = ctx_for(&k, challenges, req.presence)?; k.stop(&ctx, p["scope"].as_str().unwrap_or("node")).map(|id| json!({"stop_id": id})).map_err(kerr) }
        "resume" => { let ctx = ctx_for(&k, challenges, req.presence)?; k.resume(&ctx, p["stop_id"].as_str().ok_or_else(|| bad("stop_id"))?).map(|_| json!({"ok": true})).map_err(kerr) }
        "approve" => { let ctx = ctx_for(&k, challenges, req.presence)?; let a: Approval = serde_json::from_value(p["approval"].clone()).map_err(|e| bad(&e.to_string()))?; k.approve(&ctx, a).map(|_| json!({"ok": true})).map_err(kerr) }
        "device.enroll_node" => { let vk_hex = p["vk_hex"].as_str().ok_or_else(|| bad("vk_hex"))?; let id = p["device_id"].as_str().ok_or_else(|| bad("device_id"))?; let bytes: [u8; 32] = hex::decode(vk_hex).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| bad("vk_hex"))?; k.enroll_device(id, bytes); Ok(json!({"ok": true})) }
        "ledger.tail" => Ok(serde_json::to_value(k.store().ledger.tail(p["n"].as_u64().unwrap_or(50) as usize)).unwrap()),
        "ledger.verify" => Ok(json!({"ok": k.ledger().verify_chain(), "len": k.ledger().events().len()})),
        m => Err(RpcError { code: -32601, message: format!("unknown method {m}") }),
    }
}

fn mock_manifest(name: &str, ctx: u32) -> vk_contracts::arch::ArchManifest {
    use vk_contracts::arch::*;
    ArchManifest { name: name.into(), capabilities: [Capability::Generate, Capability::Plan, Capability::Judge].into(), locality: Locality::Local, jurisdiction: "FR".into(), retention_days: None,
        cost_per_1k_tokens_eur: 0.0, latency_ms_p50: 1, context_ceiling: ctx, determinism: Determinism::SeededDeterministic,
        identity: ArchIdentity { weights_sha256: format!("sha256:mock-{name}"), engine: "mock".into(), engine_version: "1".into(), backend: "cpu".into(), quant: "-".into(), kv_cache: "-".into(), threads: 1, batch: 1, sampling: Default::default(), seed: Some(1) },
        clearance: Clearance { max_scope: Scope::Holdout, third_party_allowed: true }, governed: true }
}
```
`RealKernel` needs `pub fn devices(&self) -> &DeviceRegistry`. **Note on `enroll_node`:** SP1a lets the local machine principal enroll the node's own device once at first boot (Task 9's `vk boot` does it and refuses if a node device already exists); enrolment of *other* devices is an admin ceremony (SP1b/SP4).

`client.rs`:
```rust
use crate::{transport::{self, Endpoint}, PresenceProof, Request, Response};
use anyhow::{anyhow, Result};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

pub struct Client { inner: Mutex<(tokio::io::Lines<BufReader<tokio::io::ReadHalf<Box<dyn transport::Stream>>>>, tokio::io::WriteHalf<Box<dyn transport::Stream>>)>, next_id: std::sync::atomic::AtomicU64 }

impl Client {
    pub async fn connect(ep: &Endpoint) -> Result<Client> {
        let stream = transport::os::connect(ep).await?;
        let (r, w) = tokio::io::split(stream);
        Ok(Client { inner: Mutex::new((BufReader::new(r).lines(), w)), next_id: 1.into() })
    }
    pub async fn call(&self, method: &str, params: Value, presence: Option<PresenceProof>) -> Result<Value> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let req = Request { jsonrpc: "2.0".into(), id, method: method.into(), params, presence };
        let mut g = self.inner.lock().await;
        g.1.write_all(serde_json::to_string(&req)?.as_bytes()).await?;
        g.1.write_all(b"\n").await?;
        let line = g.0.next_line().await?.ok_or_else(|| anyhow!("connection closed"))?;
        let resp: Response = serde_json::from_str(&line)?;
        match (resp.result, resp.error) { (Some(v), _) => Ok(v), (_, Some(e)) => Err(anyhow!("{} ({})", e.message, e.code)), _ => Err(anyhow!("empty response")) }
    }
}
```

`vk-kernel/src/presence.rs` — the node's own device key persisted in the keyring (private key bytes base64 under `vk/node-device`; file fallback `VK_NODE_KEY_FILE` for tests), exposing `NodeDevice::load_or_create(source) -> Result<NodeDevice>` implementing `HumanKey` with `device_id = "node:<node_id>"`. Implementation mirrors `SoftwareHumanKey` but constructs `SigningKey::from_bytes(&[u8;32])` from the stored secret.

- [ ] **Step 4: Run** — `cargo test -p vk-ipc` → 2 passed; `cargo test --workspace` green; clippy clean. On Windows, if `first_pipe_instance` errors on re-bind in tests, use unique test pipe names (already) and drop the listener before the next test.

- [ ] **Step 5: Commit** — `feat(ipc): JSON-RPC over named pipe/unix socket; principal derived from connection; presence ceremony for human calls`.

---

### Task 8: The `vk` shell (CLI) — usable milestone

**Files:**
- Create: `crates/vk-cli/src/main.rs`, `crates/vk-cli/src/render.rs`, `crates/vkd/src/main.rs`

**Interfaces:**
- Produces the `vk` binary:

```
vk boot [--state-dir DIR] [--foreground]      start vkd (Task 9 adds the full boot sequence)
vk status                                     boot.info
vk ls [PATH]                                  namespace listing
vk ps                                         tasks and their step status
vk top                                        per-arch calls/tokens, stopped scopes, liveness
vk mount mock NAME [--ctx N] | vk umount ARCH_ID
vk task submit --goal G [--artefact TYPE] --plan ARCH --draft ARCH [--approve] [--release DIR]
vk task step TASK_ID [--all]                  run the next step (or until it waits/finishes)
vk task show TASK_ID
vk stop [SCOPE] | vk resume STOP_ID           human calls: signed presence proof with the node device key
vk approve TASK_ID                            builds an SP0 Approval for the task's latest artefact, signed by the node device key (passkeys in SP1b)
vk dmesg [-n N]                               ledger tail
vk ledger verify
vk man SYSCALL|TYPE                           Task 9
vk --json …                                   machine-readable output for every command
```
and `vkd` (daemon): `vkd --state-dir DIR --node-id ID --endpoint EP` runs `serve`.

- [ ] **Step 1: Failing test** — `crates/vk-cli/tests/smoke.rs` spawns `vkd` with a temp state dir and a test endpoint, then runs `vk` subcommands via `std::process::Command` (env `VK_ENDPOINT`), asserting: `vk status --json` returns `ledger_ok: true`; `vk mount mock m1` then `vk ls /arches` lists it; `vk task submit --goal "Draft a proposal" --plan <arch> --draft <arch> --approve` then `vk task step <id> --all` ends with `waiting_human`; `vk stop` succeeds (node device auto-enrolled by `vkd` at first start in SP1a: `--auto-enroll-node`); `vk task step` now fails with `stopped`; `vk resume`; `vk approve <id>`; `vk task step` reaches `done`; `vk ledger verify` ok. Use `assert_cmd`-free plain `Command`, checking exit codes and JSON.

- [ ] **Step 2: Implement `vkd/src/main.rs`**

```rust
use clap::Parser;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "vkd", about = "VerticalAI kernel daemon")]
struct Args {
    #[arg(long)] state_dir: Option<std::path::PathBuf>,
    #[arg(long, default_value = "node-1")] node_id: String,
    #[arg(long)] endpoint: Option<String>,
    #[arg(long)] master_key_file: Option<std::path::PathBuf>,
    #[arg(long)] node_key_file: Option<std::path::PathBuf>,
    /// SP1a convenience: enroll this node's own device key at first start.
    #[arg(long)] auto_enroll_node: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let a = Args::parse();
    let state_dir = vk_store::paths::state_dir(a.state_dir)?;
    let key_source = match a.master_key_file { Some(p) => vk_store::keys::KeySource::File(p), None => vk_store::keys::KeySource::Keyring { service: "vk".into(), user: "master".into() } };
    let mut kernel = vk_kernel::RealKernel::open(&state_dir, key_source, &a.node_id)?;
    if a.auto_enroll_node {
        let src = match a.node_key_file { Some(p) => vk_kernel::presence::KeySource::File(p), None => vk_kernel::presence::KeySource::Keyring };
        let dev = vk_kernel::presence::NodeDevice::load_or_create(src, &a.node_id)?;
        kernel.enroll_node_device(&dev)?;
    }
    kernel.boot()?;   // Task 9; until then a no-op that logs "boot"
    let endpoint = a.endpoint.map(vk_ipc::transport::Endpoint).unwrap_or_else(vk_ipc::transport::default_endpoint);
    tracing::info!(%endpoint.0, "vkd listening");
    vk_ipc::server::serve(Arc::new(Mutex::new(kernel)), endpoint).await
}
```
`RealKernel::enroll_node_device(&NodeDevice)` enrolls `node:<id>` once (idempotent) and `boot()` appends a `boot` ledger event.

- [ ] **Step 3: Implement `vk-cli/src/main.rs`** (clap derive with the subcommands above; a `run()` that builds a tokio runtime, connects via `Client`, and for `stop`/`resume`/`approve` loads the node device key (`VK_NODE_KEY_FILE` or keyring), requests `presence.challenge`, signs, and sends the proof; `approve` reads the task, takes the latest artefact hash as `subject_hash`, builds `Challenge { resource: format!("task:{id}"), action_digest: subject, nonce, expires_at_ms: now+60000 }`, signs its digest with the node device key and submits `Approval { kind: Human, approver: Human{device_id}, challenge, signature_hex }`). `render.rs` prints fixed-width tables for `ls`, `ps`, `top`, `dmesg`; `--json` prints the raw value.

- [ ] **Step 4: Run** — `cargo test -p vk-cli` (the smoke test) → passes; manual check:

```
vkd --state-dir %TEMP%\vk-demo --auto-enroll-node --master-key-file %TEMP%\vk-demo\master.key --node-key-file %TEMP%\vk-demo\node.key
vk status
vk mount mock gemma-mock --ctx 4096
vk task submit --goal "Draft a proposal for Acme" --artefact proposal --plan <ARCH> --draft <ARCH> --approve --release .\out
vk task step <TASK> --all      # → waiting_human
vk approve <TASK>              # node device key ceremony
vk task step <TASK> --all      # → done; .\out\<hash>.proposal exists
vk dmesg -n 20 ; vk ledger verify
```

- [ ] **Step 5: Commit** — `feat(cli): the vk shell and vkd daemon — status, ls, ps, top, mount, task, stop/resume, approve, dmesg, ledger`.

**Milestone:** from here the CLI drives real flows with the mock arch; other use cases can be scripted as `vk task submit …` sequences while SP1b wires real arches.

---

### Task 9: Boot sequence, `vk man`, docs

**Files:**
- Modify: `crates/vk-kernel/src/lib.rs` (`boot()`), `crates/vk-cli/src/man.rs`, `README.md`

**Interfaces:**
- `RealKernel::boot() -> Result<BootReport { ledger_ok, ledger_len, recovered_partial_line, arches, devices, stopped_scopes }>`: verify the ledger chain (refuse to serve if it fails, unless `--force`), load policies (none yet — placeholder key `policies_version`), enumerate arches and devices, append `boot` with the report hash, log the report at info level.
- `vk man <name>`: renders `contracts/schemas/<name>.schema.json` (embedded at build time with `include_str!` via a generated `man/mod.rs`, or read from the repo path in dev) as a readable synopsis: title, required fields, each property with type/enum/description.

- [ ] **Step 1: Failing test** — in `vk-kernel` tests: a tampered ledger segment makes `boot()` return `Err` containing "ledger"; a healthy store returns `ledger_ok: true` and appends one `boot` event.
- [ ] **Step 2: Implement** per the interface; `vk man` lists available names when called without args.
- [ ] **Step 3: README** — add "Running the kernel (SP1a)" with the manual check block from Task 8 and the OS-surface table (`vk` verbs ↔ OS concepts).
- [ ] **Step 4: Run `cargo test --workspace`, clippy, fmt** — green. **Step 5: Commit** — `feat(kernel): boot sequence with ledger verification; vk man from contracts`.

---

## Self-review

**Spec coverage (SP1 design §1–§3, §7–§8 of the approved chat design; spec §3):** crates → Tasks 0, 4, 7, 8; storage tiers → Tasks 1–3; RealKernel with interceptors and I1–I4′ on the real implementation → Tasks 4, 5; scheduler, `ps`/`top`, namespace → Task 6; transport + principal derivation + presence ceremony → Task 7; the `vk` shell → Task 8; boot and `man` → Task 9. Deferred to SP1b by design: llama-server/anthropic adapters, harness confinement and MCP façade, passkeys, Windows service, signing, the demo.

**Placeholder scan:** none; the two "unchanged from SP0" helper bodies in Task 5 refer to code that exists verbatim in the repository files named there.

**Type consistency:** `KernelTestHooks` method set identical in Tasks 0, 4, 5, 7; `StepKind`/`StepStatus`/`TaskStatus` identical in Tasks 6, 7, 8 (serde `snake_case`, tag `kind`); `PresenceProof::{sign, message}` identical in Task 7's lib/server/client and Task 8; `Ctx` fields as in SP0.
