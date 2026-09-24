//! The label-projected workspace (spec §4.2, invariant I2).
//!
//! A harness sees a directory, not the store. [`Workspace::materialise`] builds
//! `<state_dir>/harness/<task_id>/` and writes into it only what the harness
//! clearance may see: `TASK.md` (the goal), `PLAN.md` (the register's
//! decisions), and under `BRIEF/` each evidence artefact whose label *flows to*
//! that clearance. An artefact above the clearance is refused — never written —
//! and every artefact admitted is logged as a projection, so the record says
//! exactly what was placed within the harness's reach and what was withheld.
//!
//! The kernel is reached through the [`Host`] trait, whose every type is a
//! contract: this crate must not depend on `vk-kernel`, because the kernel
//! depends on it. `RealKernel` implements `Host`; a test implements a fake one.
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use vk_contracts::labels::{Clearance, Label, Scope};
use vk_contracts::register::RegisterId;
use vk_contracts::syscalls::{Ctx, KernelError};

/// The clearance a `locality: cloud` harness runs at, by default: up to
/// Business, no third-party data (spec §3.7; the same clearance the Claude Code
/// arch carries). The workspace is projected to this, and the `harness.*`
/// syscalls the harness makes are answered at it.
pub fn harness_clearance() -> Clearance {
    Clearance {
        max_scope: Scope::Business,
        third_party_allowed: false,
    }
}

/// One projection the workspace made: an artefact placed within the harness's
/// reach. The kernel writes this to the ledger (under `infer.projected`, the
/// existing "an object was projected" kind — no new event kind); a refusal is
/// not a projection and is logged only in the daemon's log.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectionRecord {
    pub task_id: String,
    pub artefact_hash: String,
    pub kind: String,
    /// The scope of the artefact's label, named so an auditor can see what
    /// class of data was admitted to the harness.
    pub scope: String,
}

/// What the workspace projection needs of the kernel. Every type here is a
/// contract, so `vk-harness` need not depend on `vk-kernel`.
pub trait Host {
    /// Read the task's register at the harness clearance (I2 applies: a register
    /// above the clearance is refused, and then there is nothing to materialise).
    fn read_register(
        &mut self,
        ctx: &Ctx,
        reg: &RegisterId,
    ) -> std::result::Result<vk_contracts::register::Register, KernelError>;
    /// The bytes of one artefact, or [`KernelError::I2`] when it is above the
    /// clearance — which is how the projection learns to refuse it.
    fn read_artefact(&self, ctx: &Ctx, hash: &str) -> std::result::Result<Vec<u8>, KernelError>;
    /// The label an artefact carries, for the projection record; `None` when the
    /// artefact is not there.
    fn artefact_label(&self, hash: &str) -> Option<Label>;
    /// Record one projection on the ledger.
    fn log_projection(
        &mut self,
        now_ms: u64,
        rec: &ProjectionRecord,
    ) -> std::result::Result<(), KernelError>;
}

/// The label-projected workspace.
pub struct Workspace;

impl Workspace {
    /// Build the workspace at `dir` and return its path.
    ///
    /// Reads the register at the harness clearance, writes `TASK.md` and
    /// `PLAN.md`, and for each artefact on the register attempts to read it: one
    /// that flows to the clearance is written under `BRIEF/` and logged as a
    /// projection; one that does not is refused (skipped, logged to the daemon
    /// log). `OUT/` is created empty for the harness's own output.
    pub fn materialise(
        host: &mut dyn Host,
        ctx: &Ctx,
        reg_id: &RegisterId,
        dir: &Path,
        now_ms: u64,
    ) -> Result<PathBuf> {
        // The register at the harness clearance: if it does not flow, there is
        // nothing this harness may be handed, and the projection refuses rather
        // than building an empty-but-misleading workspace.
        let reg = host
            .read_register(ctx, reg_id)
            .map_err(|e| anyhow::anyhow!("register does not flow to the harness clearance: {e}"))?;

        // A fresh workspace: an old one from a previous run of this task would
        // leave stale brief or output for the new one to trip over.
        if dir.exists() {
            std::fs::remove_dir_all(dir)
                .with_context(|| format!("clear stale workspace {}", dir.display()))?;
        }
        private_dir(dir)?;
        private_dir(&dir.join("BRIEF"))?;
        private_dir(&dir.join("OUT"))?;

        // TASK.md — the goal and constraints, so the harness knows what it is for.
        let mut task_md = format!("# Task {}\n\n## Goal\n{}\n", reg.task_id, reg.goal);
        if !reg.constraints.is_empty() {
            task_md.push_str("\n## Constraints\n");
            for c in &reg.constraints {
                task_md.push_str(&format!("- {c}\n"));
            }
        }
        std::fs::write(dir.join("TASK.md"), task_md)
            .with_context(|| format!("write {}", dir.join("TASK.md").display()))?;

        // PLAN.md — the register's decisions so far (the plan step's output).
        let plan_md = if reg.decisions.is_empty() {
            "# Plan\n\n(no plan recorded yet)\n".to_string()
        } else {
            format!("# Plan\n\n{}\n", reg.decisions.join("\n\n"))
        };
        std::fs::write(dir.join("PLAN.md"), plan_md)
            .with_context(|| format!("write {}", dir.join("PLAN.md").display()))?;

        // BRIEF/ — each artefact that flows to the clearance, and only those.
        // `read_artefact` is the I2 gate: an artefact above the clearance comes
        // back as [`KernelError::I2`], which is a refusal to log, not an error to
        // propagate. Any other error is a real failure.
        for (i, art) in reg.artefacts.iter().enumerate() {
            let scope = host
                .artefact_label(&art.hash)
                .map(|l| scope_name(l.scope))
                .unwrap_or_else(|| "unknown".into());
            match host.read_artefact(ctx, &art.hash) {
                Ok(bytes) => {
                    let name = brief_name(i, art);
                    std::fs::write(dir.join("BRIEF").join(&name), &bytes)
                        .with_context(|| format!("write BRIEF/{name}"))?;
                    host.log_projection(
                        now_ms,
                        &ProjectionRecord {
                            task_id: reg.task_id.clone(),
                            artefact_hash: art.hash.clone(),
                            kind: art.kind.clone(),
                            scope,
                        },
                    )
                    .map_err(|e| anyhow::anyhow!("log projection: {e}"))?;
                    tracing::info!(task = %reg.task_id, artefact = %art.hash, "materialised into the harness workspace");
                }
                Err(KernelError::I2(why)) => {
                    // Refused: not written, not logged as a projection (nothing
                    // was projected), but said in the daemon log so an operator
                    // can see the workspace was narrowed.
                    tracing::warn!(task = %reg.task_id, artefact = %art.hash, scope = %scope, reason = %why, "artefact refused: above the harness clearance, withheld from the workspace");
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("read artefact {}: {e}", art.hash));
                }
            }
        }

        Ok(dir.to_path_buf())
    }
}

/// The scope of a label as the ledger spells it (`business`, `personal`, …),
/// matching the wire form the rest of the contracts use.
fn scope_name(s: Scope) -> String {
    match s {
        Scope::Public => "public",
        Scope::Vertical => "vertical",
        Scope::Business => "business",
        Scope::Personal => "personal",
        Scope::Holdout => "holdout",
    }
    .to_string()
}

/// The file name one artefact takes under `BRIEF/`: its position and its kind.
/// The kind is validated where the artefact was attached (a short plain token,
/// no separator, no `..`), so it cannot traverse out of `BRIEF/`.
fn brief_name(i: usize, art: &vk_contracts::register::ArtefactRef) -> String {
    format!("{i:02}-{}", art.kind)
}

/// Create `dir` and, on Unix, make it reachable by its owner alone (`0700`):
/// the workspace holds projected data and the child's output, and on a shared
/// machine no other account may read it. Windows leaves it to the parent ACL.
fn private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    Ok(())
}
