//! SQLite metadata tier (spec §3.9). Generic JSON tables keep the schema small;
//! typed wrappers live in vk-kernel.
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub const TABLES: &[&str] = &[
    "arches",
    "registers",
    "tasks",
    "leases",
    "approvals",
    "stops",
    "resumes",
    "liveness",
    "devices",
    "hot",
    "kv_test",
];

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

    pub fn delete(&self, table: &str, key: &str) -> Result<()> {
        Self::check_table(table)?;
        self.conn
            .execute(&format!("DELETE FROM {table} WHERE key = ?1"), params![key])?;
        Ok(())
    }

    pub fn kv_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
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
    #[test]
    fn migrate_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("vk.sqlite")).unwrap();
        db.migrate().unwrap();
        db.migrate().unwrap();
        assert_eq!(db.kv_get("schema_version").unwrap().as_deref(), Some("1"));
    }
}
