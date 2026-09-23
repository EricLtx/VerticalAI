//! The namespace (SP1 design §7): everything the kernel manages has a path, so
//! a shell, the CLI and a future `vk cat` all name the same objects the same
//! way. Resolution is read-only and never mutates the kernel.
use crate::tasks::Task;
use crate::RealKernel;
use vk_contracts::arch::ArchManifest;
use vk_contracts::ledger::LedgerEvent;
use vk_contracts::storage::BlobEnvelope;
use vk_contracts::syscalls::{Ctx, KernelError};

/// The ledger tail a bare `/ledger` returns: enough to see what just happened,
/// short enough to print.
const LEDGER_TAIL: usize = 50;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Entry {
    Dir { entries: Vec<String> },
    Arch(ArchManifest),
    Task(Task),
    Artefact(BlobEnvelope),
    Device { id: String },
    LedgerTail { events: Vec<LedgerEvent> },
}

/// Resolve `path` as `ctx` may see it. The namespace is a read surface like
/// any other: `/tasks` lists, and `/tasks/<id>` shows, only the tasks whose
/// register flows to the caller's clearance (I2); the rest are not there.
pub fn resolve(k: &RealKernel, ctx: &Ctx, path: &str) -> Result<Entry, KernelError> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match parts.as_slice() {
        [] => Ok(Entry::Dir {
            entries: vec![
                "arches".into(),
                "tasks".into(),
                "artefacts".into(),
                "devices".into(),
                "ledger".into(),
            ],
        }),
        ["arches"] => Ok(Entry::Dir {
            entries: k
                .arches()
                .into_iter()
                .map(|(id, m)| format!("{id}  {}", m.name))
                .collect(),
        }),
        ["arches", id] => k
            .arches()
            .into_iter()
            .find(|(i, _)| i == id)
            .map(|(_, m)| Entry::Arch(m))
            .ok_or_else(|| KernelError::NotFound(path.into())),
        ["tasks"] => Ok(Entry::Dir {
            entries: k.tasks(ctx).into_iter().map(|t| t.id).collect(),
        }),
        ["tasks", id] => k
            .task(ctx, id)
            .map(Entry::Task)
            .ok_or_else(|| KernelError::NotFound(path.into())),
        // The envelope, never the plaintext: reading the bytes is `read_artefact`,
        // which is the call that checks the label against a caller's clearance.
        ["artefacts", hash] => k
            .store()
            .blobs
            .envelope(&format!("sha256:{}", hash.trim_start_matches("sha256:")))
            .map(Entry::Artefact)
            .map_err(|_| KernelError::NotFound(path.into())),
        ["devices"] => Ok(Entry::Dir {
            entries: k
                .store()
                .db
                .list_json::<serde_json::Value>("devices")
                .unwrap_or_default()
                .into_iter()
                .map(|(id, _)| id)
                .collect(),
        }),
        // The id alone: a device row holds the verifying key that authenticates
        // its owner's approvals, and the namespace is a read surface, not a
        // place to hand that out.
        ["devices", id] => k
            .store()
            .db
            .get_json::<serde_json::Value>("devices", id)
            .ok()
            .flatten()
            .map(|_| Entry::Device { id: (*id).into() })
            .ok_or_else(|| KernelError::NotFound(path.into())),
        ["ledger"] => Ok(Entry::LedgerTail {
            events: k.store().ledger.tail(LEDGER_TAIL),
        }),
        _ => Err(KernelError::NotFound(path.into())),
    }
}
