//! SQLite metadata tier (spec §3.9). Generic JSON tables keep the schema small;
//! typed wrappers live in vk-kernel.
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

/// Every metadata table. Each is `(key TEXT PRIMARY KEY, json TEXT, updated_ms
/// INTEGER)` and the typed wrapper lives in vk-kernel, so a new kind of row
/// costs a name here and a struct there rather than a migration.
///
/// `mounts` is the logical `mounts(arch_id, kind, config_json)` Task 1b calls
/// for: the key is the arch id and the JSON is the `MountSpec` — the `kind`
/// and the `config` — that the next boot re-creates that arch from.
pub const TABLES: &[&str] = &[
    "arches",
    "mounts",
    "registers",
    "tasks",
    "leases",
    "approvals",
    "stops",
    "resumes",
    "liveness",
    "devices",
    "hot",
    // The bytes a passkey assertion signed, beside the approval it made
    // (SP1b Task 5 fix round 1): what lets an `approval.recorded` event of
    // proof `webauthn` be re-verified from the store and the ledger alone.
    "assertions",
    // One row per completed call on an arch (SP1b Task 8, ruling 8): which
    // arch, which task's which step, what it spent and how long it took. The
    // per-arch counters are the sum of these; only the rows can say which
    // task the money went on. The key is `<ts>-<seq>`, so `list_json`'s
    // key order is the order the calls came back in.
    "usage",
    "kv_test",
];

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        // The database file exists, owner-only, before SQLite first opens it:
        // SQLite gives `-wal` and `-shm` the main file's mode, so a file born
        // `0600` keeps its companions private too. An empty file is an empty
        // database. (Made explicit below as well, for a store an older
        // version created with the umask.)
        let mut opts = crate::paths::private_file_options();
        opts.write(true).create(true);
        opts.open(path)
            .with_context(|| format!("create {}", path.display()))?;
        crate::paths::restrict_file(path)?;
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // FULL, not NORMAL: in WAL mode NORMAL syncs at checkpoints only, so a
        // committed STOP, resume or approval row would survive a process crash
        // but not a power cut — while the ledger event that recorded it, synced
        // per append, would. The rows here are the state the ledger describes;
        // they have to be at least as durable as the record.
        conn.pragma_update(None, "synchronous", "FULL")?;
        let db = Db { conn };
        db.migrate()?;
        for companion in ["-wal", "-shm"] {
            let mut side = path.as_os_str().to_owned();
            side.push(companion);
            let side = Path::new(&side);
            if side.exists() {
                crate::paths::restrict_file(side)?;
            }
        }
        Ok(db)
    }

    pub fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )?;
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

    pub fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        table: &str,
        key: &str,
    ) -> Result<Option<T>> {
        Self::check_table(table)?;
        let json: Option<String> = self
            .conn
            .query_row(
                &format!("SELECT json FROM {table} WHERE key = ?1"),
                params![key],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match json {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    pub fn list_json<T: serde::de::DeserializeOwned>(
        &self,
        table: &str,
    ) -> Result<Vec<(String, T)>> {
        Self::check_table(table)?;
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT key, json FROM {table} ORDER BY key"))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (k, j) = row?;
            out.push((k, serde_json::from_str(&j)?));
        }
        Ok(out)
    }

    /// The newest `limit` rows of a table, by key, returned oldest-first.
    ///
    /// `LIMIT` in the query, not a truncation of the answer: the `usage`
    /// table grows for the life of a node, and a screen that shows its last
    /// two hundred calls must not deserialize a hundred thousand rows to do
    /// it (SP1b Task 8 review, Minor 2). The keys of every table that uses
    /// this are ordered — `usage` is `<ts>-<seq>`, both zero-padded — so
    /// "newest by key" is newest.
    pub fn list_json_last<T: serde::de::DeserializeOwned>(
        &self,
        table: &str,
        limit: usize,
    ) -> Result<Vec<(String, T)>> {
        Self::check_table(table)?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT key, json FROM {table} ORDER BY key DESC LIMIT ?1"
        ))?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (k, j) = row?;
            out.push((k, serde_json::from_str(&j)?));
        }
        out.reverse();
        Ok(out)
    }

    pub fn delete(&self, table: &str, key: &str) -> Result<()> {
        Self::check_table(table)?;
        self.conn
            .execute(&format!("DELETE FROM {table} WHERE key = ?1"), params![key])?;
        Ok(())
    }

    /// Run `f` as one transaction: everything it writes lands together or not
    /// at all.
    ///
    /// For the rows that are two halves of one fact — an arch's manifest and
    /// the mount spec the next boot re-creates it from — where a crash between
    /// the two writes would leave a node that lists an arch it cannot make
    /// again. `unchecked_transaction` because every write here goes through
    /// `&self`; there is one connection and one writer, so there is no second
    /// transaction for this one to nest inside.
    pub fn transaction<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let tx = self.conn.unchecked_transaction()?;
        let out = f()?;
        tx.commit()?;
        Ok(out)
    }

    pub fn kv_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Every `kv` entry whose key starts with `prefix`, ordered by key. The
    /// kernel replays whole families of small values on boot (lock fences, for
    /// one) and needs to enumerate them without knowing their names.
    pub fn kv_list_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM kv WHERE key LIKE ?1 ESCAPE '\\' ORDER BY key")?;
        let pattern = format!(
            "{}%",
            prefix
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        let rows = stmt.query_map(params![pattern], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Remove a `kv` entry. The counterpart `kv_set` has always needed:
    /// without it a caller that wants a key gone has to leave an empty
    /// value behind, and "empty" and "absent" then have to mean the same
    /// thing everywhere that reads it.
    pub fn kv_delete(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM kv WHERE key = ?1", params![key])?;
        Ok(())
    }

    pub fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute("INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![key, value])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Thing {
        n: u32,
    }
    #[test]
    fn json_round_trip_and_list() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("vk.sqlite")).unwrap();
        db.put_json("kv_test", "a", &Thing { n: 1 }).unwrap();
        db.put_json("kv_test", "b", &Thing { n: 2 }).unwrap();
        assert_eq!(
            db.get_json::<Thing>("kv_test", "a").unwrap(),
            Some(Thing { n: 1 })
        );
        assert_eq!(db.list_json::<Thing>("kv_test").unwrap().len(), 2);
        db.delete("kv_test", "a").unwrap();
        assert_eq!(db.get_json::<Thing>("kv_test", "a").unwrap(), None);
    }
    /// Durability across a power cut, not only across a process crash: WAL
    /// with `synchronous=FULL` (2) syncs the log on every commit.
    #[test]
    fn commits_are_synced_on_every_transaction() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("vk.sqlite")).unwrap();
        let synchronous: i64 = db
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(synchronous, 2, "PRAGMA synchronous must be FULL");
        let journal: String = db
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(journal, "wal");
    }

    #[test]
    fn migrate_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("vk.sqlite")).unwrap();
        db.migrate().unwrap();
        db.migrate().unwrap();
        assert_eq!(db.kv_get("schema_version").unwrap().as_deref(), Some("1"));
    }

    /// The primitive `persist_mount` and `unmount` rest their atomicity on
    /// (Task 1b review, Minor 3): everything a transaction writes lands
    /// together, and a closure that fails leaves the store exactly as it was.
    #[test]
    fn a_transaction_commits_both_writes_or_neither() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("vk.sqlite")).unwrap();
        db.put_json("kv_test", "keep", &Thing { n: 1 }).unwrap();

        // Committed: both rows are there afterwards.
        let out = db
            .transaction(|| {
                db.put_json("kv_test", "a", &Thing { n: 1 })?;
                db.put_json("arches", "b", &Thing { n: 2 })?;
                Ok(7)
            })
            .unwrap();
        assert_eq!(out, 7, "the closure's value comes back");
        assert_eq!(
            db.get_json::<Thing>("kv_test", "a").unwrap(),
            Some(Thing { n: 1 })
        );
        assert_eq!(
            db.get_json::<Thing>("arches", "b").unwrap(),
            Some(Thing { n: 2 })
        );

        // Rolled back: the first write is undone by the second's failure, and
        // a row written before the transaction is untouched.
        let err = db
            .transaction(|| -> Result<()> {
                db.put_json("kv_test", "c", &Thing { n: 3 })?;
                db.delete("kv_test", "keep")?;
                anyhow::bail!("the second half did not land")
            })
            .unwrap_err();
        assert!(err.to_string().contains("did not land"), "{err}");
        assert_eq!(
            db.get_json::<Thing>("kv_test", "c").unwrap(),
            None,
            "a write inside a transaction that failed must not survive it"
        );
        assert_eq!(
            db.get_json::<Thing>("kv_test", "keep").unwrap(),
            Some(Thing { n: 1 }),
            "and a delete inside it must not either"
        );
    }
}
