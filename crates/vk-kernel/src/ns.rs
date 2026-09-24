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

/// One arch in the `/arches` listing: enough to choose one, and the state that
/// says whether choosing it would work (SP1b ruling 14).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchRow {
    pub arch_id: String,
    pub name: String,
    /// `ready` or `unavailable`.
    pub state: &'static str,
    /// Why it is not usable; absent for one that is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Entry {
    Dir {
        entries: Vec<String>,
    },
    /// `/arches`: a listing of its own rather than a directory of strings,
    /// because an arch has a state and a line of text cannot be a column.
    Arches {
        arches: Vec<ArchRow>,
    },
    /// One arch: the manifest, flattened so the object still reads as the
    /// manifest it always was, plus the state.
    Arch {
        #[serde(flatten)]
        manifest: Box<ArchManifest>,
        state: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Task(Task),
    Artefact(BlobEnvelope),
    Device {
        id: String,
    },
    LedgerTail {
        events: Vec<LedgerEvent>,
    },
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
        ["arches"] => Ok(Entry::Arches {
            arches: k
                .arch_states()
                .into_iter()
                .map(|(arch_id, m, state)| ArchRow {
                    arch_id,
                    name: m.name,
                    state: state.name(),
                    reason: state.reason().map(str::to_string),
                })
                .collect(),
        }),
        ["arches", id] => k
            .arch_states()
            .into_iter()
            .find(|(i, _, _)| i == id)
            .map(|(_, m, state)| Entry::Arch {
                manifest: Box::new(m),
                state: state.name(),
                reason: state.reason().map(str::to_string),
            })
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
