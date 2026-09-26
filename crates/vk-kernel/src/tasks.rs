//! Tasks and the sequential scheduler (spec §3.3). Steps run one at a time, one
//! per `run_task_step` call; a STOP on scope `node` halts everything; `Approve`
//! waits for a human approval whose subject is the latest artefact hash; and
//! `Harness` steps are completed by SP1b.
use crate::{store_failed, ArchStats, RealKernel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use vk_contracts::arch::Capability;
use vk_contracts::labels::Label;
use vk_contracts::locks::Lease;
use vk_contracts::principal::{ApprovalKind, Principal};
use vk_contracts::register::{Register, RegisterId};
use vk_contracts::syscalls::{Ctx, Kernel, KernelError};
use vk_contracts::testing::KernelTestHooks;

/// The instruction the drafting harness is launched with (plan Global
/// Constraints). Fixed text, not data — the material the harness may read is in
/// its workspace, projected under the harness clearance.
pub const HARNESS_PROMPT: &str = "You are the drafting harness. Read TASK.md, PLAN.md and BRIEF/. \
Write the proposal to OUT/proposal.md, then call vk_attach_artefact with kind=proposal and \
path=OUT/proposal.md, then call vk_request_approval.";

/// How much longer than the run's timeout a harness lease lives: the settle
/// after a run that used its whole budget must still find the lease live. The
/// lease TTL is the run timeout plus this (SP1b Task 4 review, M5).
pub const HARNESS_SETTLE_SLACK_MS: u64 = 5 * 60 * 1000;

/// The largest file a harness may attach, explicitly or as its declared output
/// (Ruling 21.6).
pub const HARNESS_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// The most a harness run may attach in total (Ruling 21.6).
pub const HARNESS_MAX_RUN_BYTES: u64 = 16 * 1024 * 1024;

/// The egress sample interval recorded in `harness.connections`; matches
/// `vk_harness::launch::SAMPLE_EVERY`.
const HARNESS_SAMPLE_EVERY_MS: u64 = 500;

/// One unit of work the scheduler knows how to run. `Plan`/`Draft`/`Judge` are
/// the three inference roles; the rest are the non-inference steps a task needs
/// before its output may leave the kernel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum StepKind {
    Plan { arch_id: String },
    Draft { arch_id: String },
    Judge { arch_id: String },
    Harness { name: String },
    Approve,
    Release { to_dir: String },
}

impl StepKind {
    /// Does running this step push a decision onto the register? The other side
    /// of `arch::raise`: `plan` and `draft` do, `judge` raises an open question
    /// instead, and the three non-inference kinds raise nothing. A harness may
    /// write one of its own through `harness.write_decision`, but that is the
    /// agent's act inside the step, not the step's own, so it does not count
    /// here — `task_decisions` stops rather than misattribute one.
    fn raises_decision(&self) -> bool {
        matches!(self, StepKind::Plan { .. } | StepKind::Draft { .. })
    }
}

/// How the register's `decisions` stood once one step had finished: how many
/// there were, and the length and hash of the newest. **Metadata only, never a
/// decision's text** (Ruling 28) — the text is the register's, under the
/// register's label, and `task.show` is a task read surface, not a register
/// one. A non-zero `count` with a non-zero `last_len_bytes` is what "the plan
/// left a decision the drafter read" means when it is asserted rather than
/// inferred.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionsAfterStep {
    /// The index into `Task::steps` of the step this state was reached by.
    pub after_step: usize,
    pub count: usize,
    pub last_len_bytes: usize,
    pub last_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Running,
    WaitingHuman,
    Done,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    pub kind: StepKind,
    pub status: StepStatus,
    pub started_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    pub tokens: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Running,
    WaitingHuman,
    Done,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Task {
    pub id: String,
    pub register: RegisterId,
    pub goal: String,
    pub artefact_type: String,
    pub steps: Vec<Step>,
    pub status: TaskStatus,
    pub created_ms: u64,
}

/// What a step left `Running` by a process that died becomes at the next boot
/// (SP1b review, M11). A reason, not a status of its own: to everything that
/// reads a task this is a failed step, and the only special thing about it is
/// that the failure was a restart.
pub const INTERRUPTED: &str = "interrupted by restart";

/// The `task.step` payload for one of those. The same event kind as a step
/// that ran, because that is what this is — the end of a step — with the
/// reason named, so an auditor can tell a step this node ended from one it
/// finished.
#[derive(Debug, Serialize)]
struct InterruptedRecord<'a> {
    task_id: &'a str,
    step: usize,
    status: &'a str,
    reason: &'a str,
}

/// What a `Release` step put on the filesystem, as the `artefact.released`
/// ledger event records it. Decrypted bytes leaving the kernel is the one thing
/// an auditor must be able to reconstruct from the ledger alone, so the event
/// names the artefacts and where they went — not an opaque step index.
#[derive(Debug, Serialize)]
struct ReleaseRecord<'a> {
    task_id: &'a str,
    hashes: Vec<String>,
    destination: String,
}

/// What phase one of a harness step produced (SP1b Task 4), for the daemon to
/// run outside the kernel lock. The launch is driven with the lock **released**:
/// the harness calls back over MCP (`harness.read_register`,
/// `harness.attach_artefact`, …) while it runs, and a lock held across the wait
/// would deadlock the harness against its own syscalls. The kernel leases and
/// materialises here (phase one), the daemon runs [`vk_harness::launch`], then
/// the kernel settles (phase two).
pub struct HarnessLaunch {
    pub workspace: PathBuf,
    /// Where the run's `mcp.json` and `settings.json` go: outside the
    /// workspace, removed at settle.
    pub config_dir: PathBuf,
    pub lease_id: String,
    /// The run's secret (Ruling 21.2): goes into the run's `mcp.json` and
    /// nowhere else — never a payload, a log line or a `--dry-run` answer.
    pub token: String,
    pub prompt: String,
    pub name: String,
    pub step_index: usize,
    /// How many artefacts the register held before the run, so settle can tell
    /// what the harness attached explicitly over MCP (Ruling 21.6).
    pub artefacts_before: usize,
}

/// By hand, not derived: a derived `Debug` would print the token into any
/// panic message, assertion or log line that formats a launch. The token is the
/// one field that never appears anywhere but the run's `mcp.json`.
impl std::fmt::Debug for HarnessLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HarnessLaunch")
            .field("workspace", &self.workspace)
            .field("config_dir", &self.config_dir)
            .field("lease_id", &self.lease_id)
            .field("token", &"<redacted>")
            .field("prompt", &self.prompt)
            .field("name", &self.name)
            .field("step_index", &self.step_index)
            .field("artefacts_before", &self.artefacts_before)
            .finish()
    }
}

/// The `harness.connections` event payload (founder decision 2026-09-24): one
/// per harness run, appended after the child exits and before the step's own
/// `task.step` event. Public and owned so [`RealKernel::record_harness_connection`]
/// and its test can build one; it is a ledger payload, not a contract type.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HarnessConnectionsRecord {
    pub task_id: String,
    pub step_index: usize,
    pub lease_id: String,
    pub harness: String,
    /// Remote `ip:port` the harness reached, deduplicated and sorted; empty when
    /// it opened none (or a run too short to sample).
    pub connections: Vec<String>,
    pub samples: usize,
    pub sample_every_ms: u64,
    pub governed: bool,
    /// `code N`, `killed by governor`, `timeout`, `signal`, `not contained`
    /// or `not started` (`vk_harness::launch::ExitReason::label`).
    pub exit: String,
    pub duration_ms: u64,
}

/// The `task.step` payload of a harness step: the run's governance, exit and
/// duration only — the endpoints ride the `harness.connections` event, never
/// this one (founder decision 2026-09-24).
#[derive(serde::Serialize)]
struct HarnessStepRecord<'a> {
    task_id: &'a str,
    step: usize,
    status: &'a str,
    governed: bool,
    exit: &'a str,
    duration_ms: u64,
}

/// The one file a harness run's `OUT/` is collected for: the declared output,
/// `OUT/<artefact_type>.*` (or exactly `OUT/<artefact_type>`), the first such
/// name in order. Nothing else under `OUT/` is collected (Ruling 21.6): a
/// scratch file is not the task's artefact, and the approval subject must be
/// what the harness produced for the task.
fn declared_output(dir: &Path, artefact_type: &str) -> Option<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == artefact_type || n.starts_with(&format!("{artefact_type}.")))
        })
        .collect();
    files.sort();
    files.into_iter().next()
}

/// Remove a directory tree the harness left behind, best effort: a tree that
/// is already gone is fine, anything else is logged and the settle goes on —
/// a directory that could not be removed is never a reason to leave a token
/// resolving or a step `Running`.
fn remove_tree(dir: &Path, what: &str) {
    if let Err(e) = std::fs::remove_dir_all(dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(dir = %dir.display(), error = %e, "could not remove the {what}");
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A locality as the wire spells it (`on_prem`, not `OnPrem`), so the screen
/// and `--json` name it the same way the manifest does.
pub(crate) fn locality_name(l: vk_contracts::arch::Locality) -> String {
    serde_json::to_value(l)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{l:?}"))
}

/// A status as the wire spells it (`waiting_human`, not `WaitingHuman`), so a
/// refusal a person reads names the same state `vk ps` just showed them.
fn status_name(s: TaskStatus) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{s:?}"))
}

/// What `top` shows: what each arch has cost so far, what every task is doing,
/// which scopes are stopped, and until when each business may act unattended.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TopView {
    pub arches: BTreeMap<String, ArchStats>,
    /// Which of the arches mounted right now are ones this kernel contains —
    /// the process it started, under the caps it set (spec §3.3). Beside the
    /// counters rather than in them: `ArchStats` is what an arch has spent and
    /// is read back from disk, while this is what an arch *is* and is true
    /// only of the arches mounted in this process. An arch with counters but
    /// no entry here is one that has been unmounted since.
    #[serde(default)]
    pub governed: BTreeMap<String, bool>,
    /// `ready` or `unavailable` per mounted arch (SP1b ruling 14). Beside the
    /// counters for the same reason `governed` is: counters are what an arch
    /// has spent and outlive it, this is whether it can be called at all. An
    /// arch with counters and no entry here is one that has been unmounted.
    #[serde(default)]
    pub states: BTreeMap<String, String>,
    /// Why each unavailable arch is unavailable. Only those: a ready arch has
    /// nothing to explain.
    #[serde(default)]
    pub unavailable: BTreeMap<String, String>,
    /// What a thousand prompt tokens cost on each mounted arch, in euros, as
    /// its manifest states it — `None` inside the `Some` for an arch whose
    /// price this node does not know (SP1b Task 2b fix round 1). Beside the
    /// counters for the same reason `governed` is: a price is what an arch
    /// *is*, and an arch with counters and no entry here has been unmounted.
    #[serde(default)]
    pub price_eur_per_1k: BTreeMap<String, Option<f64>>,
    /// Where each mounted arch runs — `local`, `on_prem`, `peer`, `cloud` —
    /// as its manifest declares it (SP1b Task 8). An operator reading this
    /// screen is asking two things at once, what is this spending and what
    /// is leaving the machine, and the second one has no other answer here.
    #[serde(default)]
    pub locality: BTreeMap<String, String>,
    /// And under whose law the answer was produced: the manifest's
    /// `jurisdiction`, which is what makes a €0.004 call on `US` a different
    /// fact from the same call on `EU`.
    #[serde(default)]
    pub jurisdiction: BTreeMap<String, String>,
    /// The per-call rows behind the counters, when the caller asked for them
    /// (`vk top --calls`). Empty otherwise, and the newest few when asked
    /// for: `top` is a screen, and a node that has run for a week has more
    /// calls than a screen holds. `usage.ls` is the unbounded surface, for a
    /// script that wants them all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<crate::UsageRow>,
    /// Were there older calls than the ones in `calls`? The screen says so
    /// rather than quietly ending. Not a count: counting them would mean
    /// reading the whole table, which is exactly what the bound exists to
    /// avoid (SP1b Task 8 review, Minor 2).
    #[serde(default, skip_serializing_if = "is_false")]
    pub calls_truncated: bool,
    pub tasks: BTreeMap<String, TaskStatus>,
    pub stopped_scopes: Vec<String>,
    pub liveness: BTreeMap<String, u64>,
}

impl RealKernel {
    pub fn create_task(
        &mut self,
        ctx: &Ctx,
        goal: &str,
        artefact_type: &str,
        label: Label,
        steps: Vec<StepKind>,
    ) -> Result<Task, KernelError> {
        // The artefact type becomes a file name (`<hash>.<kind>` on release,
        // `OUT/<kind>.*` for a harness) and the kind of every attachment, so it
        // is held to the attach rule here, at creation — a task that could never
        // settle is refused before it exists (SP1b Task 4 review, I4).
        crate::validate_artefact_kind(artefact_type)?;
        let register = self.submit_task(ctx, goal, label)?;
        // The task id is the register's, never a second one minted here. The
        // payload tier keys every artefact under `task:{register.task_id}`, so
        // a `Task` carrying a different id would name a subject no blob, and no
        // shred, has ever heard of.
        let id = self.read_register(ctx, &register)?.task_id;
        let task = Task {
            id,
            register,
            goal: goal.into(),
            artefact_type: artefact_type.into(),
            steps: steps
                .into_iter()
                .map(|kind| Step {
                    kind,
                    status: StepStatus::Pending,
                    started_ms: None,
                    ended_ms: None,
                    tokens: 0,
                })
                .collect(),
            status: TaskStatus::Queued,
            created_ms: ctx.now_ms,
        };
        self.save_task(&task)?;
        Ok(task)
    }

    fn save_task(&mut self, t: &Task) -> Result<(), KernelError> {
        self.store
            .db
            .put_json("tasks", &t.id, t)
            .map_err(store_failed)
    }

    /// The row as stored, with no question asked about who is looking. Every
    /// read that leaves the kernel goes through `task`, which asks it.
    fn task_row(&self, id: &str) -> Option<Task> {
        self.store.db.get_json("tasks", id).ok().flatten()
    }

    /// May `ctx` see this task? A `Task` carries its register's goal and the
    /// trail of what was done with it, so it is subject to the register's
    /// label exactly as `read_register` is (I2): the label must flow to the
    /// caller's clearance. A task whose register cannot be read — or cannot
    /// be found — is hidden rather than refused: "not found" says nothing,
    /// where "exceeds your clearance" would say that something is there.
    fn visible_to(&self, ctx: &Ctx, t: &Task) -> bool {
        self.store
            .db
            .get_json::<Register>("registers", &t.register.0)
            .ok()
            .flatten()
            .is_some_and(|r| r.label.flows_to(&ctx.clearance))
    }

    /// One task, as `ctx` may see it: `None` for a task that is not there and
    /// for one whose label the caller is not cleared for, indistinguishably.
    pub fn task(&self, ctx: &Ctx, id: &str) -> Option<Task> {
        self.task_row(id).filter(|t| self.visible_to(ctx, t))
    }

    /// What each of a task's steps left in its register's `decisions` — and
    /// nothing of what any of them says (Ruling 28).
    ///
    /// A task read surface could not answer "did the plan leave the drafter
    /// something to read?" at all before this: `decisions` is a field of
    /// `Register`, and the only verb that reads a register is the lease-gated
    /// `harness.read_register`. So H1's own check had to be inferred from
    /// prompt-token growth. This answers it directly, in metadata only — a
    /// count, a byte length and a hash. The text stays behind the register's
    /// label, because that is what the label is for.
    ///
    /// Read through `read_register`, so the register's label must flow to the
    /// caller's clearance (I2) exactly as for a register read: a count and a
    /// hash are smaller facts about a register, not lesser ones.
    ///
    /// Attribution is `arch::raise`'s rule read back: `plan` pushes one
    /// decision, every other inference role but `judge` pushes one, and
    /// `judge` pushes an open question instead — so the n-th finished step that
    /// raises a decision owns the n-th decision. Steps that raise none get no
    /// entry. A register holding fewer decisions than its finished steps
    /// account for — a harness that wrote its own through
    /// `harness.write_decision`, a register some later verb edits — ends the
    /// walk instead of guessing, so an entry here is never about a decision
    /// some other step made.
    pub fn task_decisions(
        &mut self,
        ctx: &Ctx,
        task: &Task,
    ) -> Result<Vec<DecisionsAfterStep>, KernelError> {
        let reg = <Self as Kernel>::read_register(self, ctx, &task.register)?;
        let mut out = Vec::new();
        let mut count = 0usize;
        for (i, step) in task.steps.iter().enumerate() {
            if step.status != StepStatus::Done || !step.kind.raises_decision() {
                continue;
            }
            count += 1;
            let Some(decision) = reg.decisions.get(count - 1) else {
                break;
            };
            out.push(DecisionsAfterStep {
                after_step: i,
                count,
                last_len_bytes: decision.len(),
                last_hash: vk_contracts::hash_bytes(decision.as_bytes()),
            });
        }
        Ok(out)
    }

    /// What a human approval of this task has to name as its subject: the
    /// latest artefact on the register, or — with none attached — the register
    /// itself.
    ///
    /// The `Approve` step below asks the same question of the same function,
    /// and so does the client that builds the approval (`task.subject` over the
    /// transport). One rule in one place: an approval built against a subject
    /// the scheduler would not recognise is an approval that never completes a
    /// step, and a second copy of this expression is how that happens.
    ///
    /// Answered only while the task is *at* its `Approve` step. The subject is
    /// a property of a moment, not of a task: every earlier step rewrites the
    /// register, so a hash handed out before then names something no step will
    /// ever ask about — and a human would have signed it, had it recorded, and
    /// been told `ok` for an approval that can never complete anything. The
    /// step asks from inside its own run, so it always satisfies this.
    pub fn approval_subject(&mut self, ctx: &Ctx, task_id: &str) -> Result<String, KernelError> {
        let t = self
            .task(ctx, task_id)
            .ok_or_else(|| KernelError::NotFound(task_id.into()))?;
        let current = t
            .steps
            .iter()
            .find(|s| !matches!(s.status, StepStatus::Done))
            .map(|s| &s.kind);
        if !matches!(current, Some(StepKind::Approve)) {
            return Err(KernelError::Gate(format!(
                "task {task_id} is not waiting for an approval; its status is {}",
                status_name(t.status)
            )));
        }
        let reg = self.read_register(ctx, &t.register)?;
        Ok(reg
            .artefacts
            .last()
            .map(|a| a.hash.clone())
            .unwrap_or_else(|| vk_contracts::hash_canonical(&reg)))
    }

    /// The one directory a `Release` step may write to. Every release
    /// destination is resolved under it, so "where did my artefact go?" has a
    /// single answer: `export_root().join(to_dir)`.
    pub fn export_root(&self) -> PathBuf {
        self.store.state_dir.join("exports")
    }

    /// Resolve a caller-supplied release destination under the export root.
    ///
    /// A machine principal chooses `to_dir`, so it is confined rather than
    /// trusted: an absolute path, a drive prefix, a leading `/` or a single
    /// `..` would otherwise let a task land decrypted bytes anywhere the
    /// daemon can write. Only ordinary path components are accepted, which
    /// makes escaping the root unrepresentable rather than merely checked for.
    fn release_dest(&self, to_dir: &str) -> Result<PathBuf, KernelError> {
        let rel = Path::new(to_dir);
        let ok = !to_dir.is_empty()
            && rel
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if !ok {
            return Err(KernelError::Gate(
                "release destination must be a relative subpath of the export root".into(),
            ));
        }
        Ok(self.export_root().join(rel))
    }

    /// The file name one artefact is released under, `<hash12>.<kind>`.
    ///
    /// `kind` is validated when the artefact is attached, but a register is a
    /// durable document that some other path may have written, and a name is
    /// joined onto the destination exactly like a directory is: a `kind` of
    /// `../../x.md` would traverse out through the file name and undo the
    /// confinement `release_dest` just established. So the composed name is
    /// held to the same rule — it must be exactly one ordinary path component —
    /// and the kernel refuses rather than trusting what it read back.
    fn release_file_name(hash: &str, kind: &str) -> Result<String, KernelError> {
        let name = format!(
            "{}.{}",
            hash.trim_start_matches("sha256:")
                .get(..12)
                .unwrap_or("artefact"),
            kind
        );
        let mut parts = Path::new(&name).components();
        if !matches!(
            (parts.next(), parts.next()),
            (Some(Component::Normal(_)), None)
        ) {
            return Err(KernelError::Gate(format!(
                "artefact kind {kind:?} is not a plain file name"
            )));
        }
        Ok(name)
    }

    /// Every task `ctx` may see (I2, as for `task`): the listing is a read
    /// surface too, and an id in it is a fact about a register.
    pub fn tasks(&self, ctx: &Ctx) -> Vec<Task> {
        self.store
            .db
            .list_json::<Task>("tasks")
            .unwrap_or_default()
            .into_iter()
            .map(|(_, t)| t)
            .filter(|t| self.visible_to(ctx, t))
            .collect()
    }

    /// End every step a dead process left `Running`, and say so in the record
    /// (SP1b review, M11).
    ///
    /// A `Running` step on disk at boot is a step whose process is gone: the
    /// scheduler runs one step at a time in the call that asked for it, so
    /// nothing is running when this node starts. It is *not* re-run. How far
    /// it got is unknowable — the inference may already have left this node,
    /// been paid for and been answered — and a scheduler that quietly repeats
    /// it would spend twice and could release twice. So the step fails with
    /// [`INTERRUPTED`], the task fails with it, and re-running is left to a
    /// caller who says so.
    ///
    /// Called by `boot`, after the `boot` event, so the record reads in the
    /// order things happened. Idempotent: a second boot finds nothing.
    pub(crate) fn recover_interrupted_steps(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<String>, KernelError> {
        let rows = self
            .store
            .db
            .list_json::<Task>("tasks")
            .map_err(store_failed)?;
        let mut recovered = Vec::new();
        for (_, mut t) in rows {
            let interrupted: Vec<usize> = t
                .steps
                .iter()
                .enumerate()
                .filter(|(_, s)| matches!(s.status, StepStatus::Running))
                .map(|(i, _)| i)
                .collect();
            if interrupted.is_empty() {
                continue;
            }
            for i in &interrupted {
                t.steps[*i].status = StepStatus::Failed(INTERRUPTED.into());
                t.steps[*i].ended_ms = Some(now_ms);
                // Ledger before the row, as everywhere else in this kernel.
                self.log(
                    "task.step",
                    now_ms,
                    &InterruptedRecord {
                        task_id: &t.id,
                        step: *i,
                        status: "failed",
                        reason: INTERRUPTED,
                    },
                )?;
            }
            t.status = TaskStatus::Failed;
            self.save_task(&t)?;
            tracing::warn!(
                task = %t.id,
                steps = ?interrupted,
                "a step was still running when this node last stopped; failed, not re-run"
            );
            recovered.push(t.id.clone());
        }
        Ok(recovered)
    }

    /// Run the next step that is not yet `Done`, and only that one: the
    /// scheduler is sequential by construction, so nothing can overtake a step
    /// that is waiting for a human.
    ///
    /// Every state the task passes through is written down before the next one
    /// is attempted. A step that fails leaves the reason on the step and the
    /// task `Failed`, durably, *and* returns the error: a caller that never
    /// comes back must not be the only record of what went wrong.
    ///
    /// `Done` and `Failed` are terminal. Calling this again on either is a
    /// no-op that returns the task unchanged — a failed step is not silently
    /// retried (and so cannot flip a `Failed` task back to `Running`), and a
    /// finished task is not restated as `Stopped` just because the node has
    /// been stopped since it finished. Re-running a failed task is a decision
    /// for a caller who says so, not a side effect of asking after it.
    pub fn run_task_step(&mut self, ctx: &Ctx, task_id: &str) -> Result<Task, KernelError> {
        // As the caller may see it: a task above the caller's clearance is
        // not found, and its row is not touched — no step of it could have
        // run anyway, since every step reads the register.
        let mut t = self
            .task(ctx, task_id)
            .ok_or_else(|| KernelError::NotFound(task_id.into()))?;
        if matches!(t.status, TaskStatus::Done | TaskStatus::Failed) {
            return Ok(t);
        }
        if self.stops.stopped("node") {
            t.status = TaskStatus::Stopped;
            self.save_task(&t)?;
            return Err(KernelError::Stopped("node".into()));
        }
        let Some(i) = t
            .steps
            .iter()
            .position(|s| !matches!(s.status, StepStatus::Done))
        else {
            t.status = TaskStatus::Done;
            self.save_task(&t)?;
            return Ok(t);
        };
        // A harness step is not run by the generic scheduler: it leases,
        // materialises a workspace, launches a confined process and settles it,
        // all outside the kernel lock (SP1b Task 4). Refused here *before* the
        // row is touched — so `vk task step` on a harness step neither fails the
        // task nor claims work — with the verb that does run it.
        if matches!(t.steps[i].kind, StepKind::Harness { .. }) {
            return Err(KernelError::Gate(format!(
                "step {i} of task {task_id} is a harness step; run it with `vk harness run {task_id}`"
            )));
        }
        // Polling a step that is already waiting for a human is not a start.
        // Marking it `Running` again would write the row and, below, append a
        // `task.step` event on every poll: a task waiting a week would grow the
        // ledger without anything having happened.
        let was_waiting = matches!(t.steps[i].status, StepStatus::WaitingHuman);
        if !was_waiting {
            t.steps[i].status = StepStatus::Running;
            t.steps[i].started_ms = Some(ctx.now_ms);
            t.status = TaskStatus::Running;
            self.save_task(&t)?;
        }
        let kind = t.steps[i].kind.clone();
        // Which step is about to spend, for the usage row `infer` writes
        // (SP1b Task 8). Set around this one call and cleared again below,
        // whatever the step did: a stale value would attribute the next
        // inference outside a task to the last step that ran.
        self.usage_step = Some((task_id.to_string(), i));
        let ran = self.run_step(ctx, task_id, &kind, &t.register, &t.artefact_type);
        self.usage_step = None;
        match ran {
            Ok((StepStatus::WaitingHuman, _)) => {
                if was_waiting {
                    // Still waiting on the same human: nothing transitioned, so
                    // nothing is written and nothing is logged.
                    return Ok(t);
                }
                t.steps[i].status = StepStatus::WaitingHuman;
                t.status = TaskStatus::WaitingHuman;
            }
            Ok((s, tokens)) => {
                t.steps[i].status = s;
                t.steps[i].tokens = tokens;
                t.steps[i].ended_ms = Some(ctx.now_ms);
                // Set from the steps, not left over from the pre-save: a step
                // that was waiting and has now finished skipped that pre-save,
                // and the task must not stay `WaitingHuman` because of it.
                t.status = if t.steps.iter().all(|s| matches!(s.status, StepStatus::Done)) {
                    TaskStatus::Done
                } else {
                    TaskStatus::Running
                };
            }
            // Retryable: the arch this step names is still being built. Nothing
            // failed, so nothing is recorded as having failed — the step goes
            // back to `Pending` and the task to `Queued`, and the next
            // `vk task step` runs it (Task 1b review, Important 1). Marking it
            // `Failed` would make a task need a human to re-submit it because
            // a container took four seconds to start.
            Err(e @ KernelError::ArchStarting(_)) => {
                t.steps[i].status = StepStatus::Pending;
                t.steps[i].started_ms = None;
                t.status = TaskStatus::Queued;
                self.save_task(&t)?;
                return Err(e);
            }
            Err(e) => {
                t.steps[i].status = StepStatus::Failed(e.to_string());
                t.steps[i].ended_ms = Some(ctx.now_ms);
                t.status = TaskStatus::Failed;
                self.save_task(&t)?;
                return Err(e);
            }
        }
        // Ledger before the row, as everywhere else in this kernel: the step's
        // own effects are already durable, so a failed save leaves a task that
        // still says `Running` over a ledger that says the step ran — never a
        // step recorded as `Done` with no trace of it having happened.
        self.log("task.step", ctx.now_ms, &(task_id, i))?;
        self.save_task(&t)?;
        Ok(t)
    }

    /// Do the work of one step and report what it became, plus the tokens it
    /// spent. Every failure leaves by the `Err` return so that the caller — the
    /// only place that owns the task row — can record it: a `?` inside
    /// `run_task_step`'s own match arms would return from `run_task_step`
    /// instead, leaving a task that failed still marked `Running` on disk.
    fn run_step(
        &mut self,
        ctx: &Ctx,
        task_id: &str,
        kind: &StepKind,
        register: &RegisterId,
        artefact_type: &str,
    ) -> Result<(StepStatus, u32), KernelError> {
        match kind {
            StepKind::Plan { arch_id } => {
                let o = self.infer(ctx, arch_id, Capability::Plan, register)?;
                Ok((StepStatus::Done, o.tokens_in))
            }
            // The draft is what the task is *for*, so it is the step that
            // produces the artefact: approval names it, release writes it, and
            // `artefact_type` is the kind the caller asked for. `infer` returns
            // no text — it raises the completion into the register — so the
            // attachment reads it back from there rather than the arch being
            // called twice.
            StepKind::Draft { arch_id } => {
                let o = self.infer(ctx, arch_id, Capability::Generate, register)?;
                let reg = self.read_register(ctx, register)?;
                let drafted = reg.decisions.last().cloned().ok_or_else(|| {
                    KernelError::Gate(format!(
                        "arch {arch_id} returned nothing to attach as the task's {artefact_type}"
                    ))
                })?;
                self.attach_artefact(ctx, register, artefact_type, drafted.as_bytes())?;
                Ok((StepStatus::Done, o.tokens_in))
            }
            StepKind::Judge { arch_id } => {
                let o = self.infer(ctx, arch_id, Capability::Judge, register)?;
                Ok((StepStatus::Done, o.tokens_in))
            }
            // Never reached through `run_task_step`, which refuses a harness step
            // before this (above): a harness runs via `harness_launch` /
            // `harness_settle`, outside the kernel lock. Kept as a guard so a new
            // caller of `run_step` cannot silently run one under the lock.
            StepKind::Harness { .. } => Err(KernelError::Gate(
                "harness steps are run by `vk harness run`, not the generic scheduler".into(),
            )),
            StepKind::Approve => {
                // The approval has to name *what* was approved, and the rule
                // for that lives in `approval_subject` — the same call the
                // client makes to learn what to sign. A later artefact leaves
                // an earlier approval behind rather than inheriting it.
                let subject = self.approval_subject(ctx, task_id)?;
                let approved = self
                    .approvals_for(&subject)
                    .iter()
                    .any(|a| a.kind == ApprovalKind::Human);
                Ok(if approved {
                    (StepStatus::Done, 0)
                } else {
                    (StepStatus::WaitingHuman, 0)
                })
            }
            StepKind::Release { to_dir } => {
                let reg = self.read_register(ctx, register)?;
                // Refuse before anything exists on disk: a destination the
                // kernel will not write to must not leave a directory behind.
                let dest = self.release_dest(to_dir)?;
                // Every name is composed and checked before anything is logged
                // or created, so a release this kernel will refuse leaves no
                // directory, no half-written export and no ledger event
                // claiming one.
                let files = reg
                    .artefacts
                    .iter()
                    .map(|a| Ok((a.hash.clone(), Self::release_file_name(&a.hash, &a.kind)?)))
                    .collect::<Result<Vec<_>, KernelError>>()?;
                // Ledger before the bytes. This is the moment plaintext leaves
                // the kernel, and an unaudited release is the failure that
                // cannot be repaired afterwards; a write that fails half way
                // leaves an over-broad record, which an auditor can reconcile.
                self.log(
                    "artefact.released",
                    ctx.now_ms,
                    &ReleaseRecord {
                        task_id,
                        hashes: reg.artefacts.iter().map(|a| a.hash.clone()).collect(),
                        destination: dest.display().to_string(),
                    },
                )?;
                // The export root and the destination under it are the
                // owner's alone (Unix `0700`), and so is each released file
                // (`0600`): this is plaintext, outside the encrypted tier.
                vk_store::paths::private_dir(&self.export_root()).map_err(store_failed)?;
                vk_store::paths::private_dir(&dest).map_err(store_failed)?;
                for (hash, name) in files {
                    // `read_artefact` re-checks the label against the caller's
                    // clearance: leaving the kernel is exactly where I2 matters.
                    let bytes = self.read_artefact(ctx, &hash)?;
                    let path = dest.join(name);
                    let mut opts = vk_store::paths::private_file_options();
                    opts.write(true).create(true).truncate(true);
                    let mut f = opts.open(&path).map_err(store_failed)?;
                    std::io::Write::write_all(&mut f, &bytes).map_err(store_failed)?;
                    vk_store::paths::restrict_file(&path).map_err(store_failed)?;
                }
                Ok((StepStatus::Done, 0))
            }
        }
    }

    /// Acquire the lease a harness run holds (SP1b Task 4).
    ///
    /// The resource is `harness:<task_id>`; the holder is a principal minted
    /// for this run alone, so two runs of one task can never be the same holder
    /// — the lock table refuses the second rather than renewing the first
    /// (Ruling 21.3). The lease id is what the ledger and every principal carry;
    /// the token `vk-mcp` holds is minted separately and mapped to it.
    pub fn harness_lease(
        &mut self,
        ctx: &Ctx,
        task_id: &str,
        ttl_ms: u64,
    ) -> Result<Lease, KernelError> {
        let run_ctx = Ctx {
            principal: Principal::Machine {
                node_id: self.node_id.clone(),
                lease_id: format!("harness-run:{}", uuid::Uuid::new_v4().simple()),
            },
            ..ctx.clone()
        };
        self.lease(&run_ctx, &format!("harness:{task_id}"), ttl_ms)
    }

    /// Phase one of a harness step, under the kernel lock: validate, STOP-check,
    /// refuse a second run of a task whose run is live, lease (TTL = the run's
    /// timeout plus settle slack), mint the token, materialise the
    /// label-projected workspace, mark the step running. The daemon runs
    /// [`vk_harness::launch::launch_claude_code`] with the lock released, then
    /// calls [`RealKernel::harness_settle`].
    ///
    /// `name` is the harness the caller asked for; it must be the one the step
    /// names. `timeout_ms` is the daemon's run budget.
    pub fn harness_launch(
        &mut self,
        ctx: &Ctx,
        task_id: &str,
        name: &str,
        timeout_ms: u64,
    ) -> Result<HarnessLaunch, KernelError> {
        // The task id becomes a directory name: hold it to a plain token.
        if task_id.is_empty()
            || !task_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        {
            return Err(KernelError::Gate(format!(
                "task id {task_id:?} is not a plain name"
            )));
        }
        let mut t = self
            .task(ctx, task_id)
            .ok_or_else(|| KernelError::NotFound(task_id.into()))?;
        if matches!(t.status, TaskStatus::Done | TaskStatus::Failed) {
            return Err(KernelError::Gate(format!(
                "task {task_id} is already {}",
                status_name(t.status)
            )));
        }
        // A STOP halts the harness exactly as it halts the scheduler.
        if self.stops.stopped("node") {
            t.status = TaskStatus::Stopped;
            self.save_task(&t)?;
            return Err(KernelError::Stopped("node".into()));
        }
        let Some(i) = t
            .steps
            .iter()
            .position(|s| !matches!(s.status, StepStatus::Done))
        else {
            return Err(KernelError::Gate(format!(
                "task {task_id} has no steps left to run"
            )));
        };
        let step_name = match &t.steps[i].kind {
            StepKind::Harness { name } => name.clone(),
            other => {
                return Err(KernelError::Gate(format!(
                    "the next step of task {task_id} is not a harness step: {other:?}"
                )))
            }
        };
        if step_name != name {
            return Err(KernelError::Gate(format!(
                "task {task_id}'s harness step is named {step_name:?}, not {name:?}"
            )));
        }
        // One run per task at a time (Ruling 21.3): a step already `Running`,
        // or a live token for this task, is a run in progress — a second one
        // would delete the first's lease and empty its workspace under it.
        if matches!(t.steps[i].status, StepStatus::Running) || self.harness_running(task_id) {
            return Err(KernelError::Gate(format!(
                "harness already running for task {task_id}"
            )));
        }
        // Lease, then token, then the workspace at the harness clearance. If the
        // workspace cannot be materialised nothing ran: the lease is released and
        // the token forgotten before returning.
        let lease = self.harness_lease(ctx, task_id, timeout_ms + HARNESS_SETTLE_SLACK_MS)?;
        let token = self.mint_harness_token(&lease.id, task_id);
        let hctx = Ctx {
            principal: Principal::Machine {
                node_id: self.node_id.clone(),
                lease_id: lease.id.clone(),
            },
            clearance: vk_harness::harness_clearance(),
            partition: ctx.partition.clone(),
            now_ms: ctx.now_ms,
        };
        let dir = self.harness_workspace_dir(task_id);
        let reg_id = t.register.clone();
        let artefacts_before = self.read_register(ctx, &reg_id)?.artefacts.len();
        let workspace =
            match vk_harness::Workspace::materialise(self, &hctx, &reg_id, &dir, ctx.now_ms) {
                Ok(ws) => ws,
                Err(e) => {
                    self.revoke_harness_run(&lease.id, &token);
                    return Err(KernelError::Gate(format!(
                        "materialise harness workspace: {e:#}"
                    )));
                }
            };
        t.steps[i].status = StepStatus::Running;
        t.steps[i].started_ms = Some(ctx.now_ms);
        t.status = TaskStatus::Running;
        if let Err(e) = self.save_task(&t) {
            self.revoke_harness_run(&lease.id, &token);
            return Err(e);
        }
        Ok(HarnessLaunch {
            workspace,
            config_dir: self.harness_config_dir(task_id),
            lease_id: lease.id,
            token,
            prompt: HARNESS_PROMPT.into(),
            name: step_name,
            step_index: i,
            artefacts_before,
        })
    }

    /// Phase two of a harness step, under the kernel lock: record the run's
    /// egress, collect what it produced, end the step, revoke the token and the
    /// lease, and remove the run's configuration and (unless `keep`) its
    /// workspace.
    ///
    /// **Every exit path settles** (Ruling 21.4): whatever the run did and
    /// whatever fails in here, the `harness.connections` event is appended
    /// first, the token stops resolving, the lease is released, the row is
    /// written with `Done` or `Failed(reason)`, and the configuration directory
    /// holding the token is removed. A bookkeeping error is returned after the
    /// cleanup, never instead of it.
    ///
    /// The order is the founder's (2026-09-24): one `harness.connections` event,
    /// then the step's own `task.step`, then the release. A run that did not
    /// finish cleanly (`killed by governor`, `timeout`, `not contained`, a
    /// non-zero exit) collects nothing and fails the step — its egress is
    /// recorded all the same, because what a killed harness reached is exactly
    /// what an auditor most needs. A clean exit that attached nothing, over MCP
    /// or as `OUT/<artefact_type>.*`, fails too: a harness step is for an
    /// artefact.
    pub fn harness_settle(
        &mut self,
        ctx: &Ctx,
        task_id: &str,
        launch: &HarnessLaunch,
        run: &vk_harness::launch::HarnessRun,
        keep: bool,
    ) -> Result<Task, KernelError> {
        let i = launch.step_index;
        let exit = run.exit_reason.label();

        // 1. The egress record, first and unconditionally.
        let recorded = self.record_harness_connection(
            ctx.now_ms,
            &HarnessConnectionsRecord {
                task_id: task_id.into(),
                step_index: i,
                lease_id: launch.lease_id.clone(),
                harness: launch.name.clone(),
                connections: run.connections.clone(),
                samples: run.samples,
                sample_every_ms: HARNESS_SAMPLE_EVERY_MS,
                governed: run.governed,
                exit: exit.clone(),
                duration_ms: run.duration_ms,
            },
        );

        // 2. The verdict: what the run produced, if it finished at all.
        let verdict: Result<(), String> = if !run.exit_reason.is_success() {
            Err(format!("harness run ended: {exit}"))
        } else {
            self.collect_harness_output(ctx, task_id, launch)
        };
        let status = if verdict.is_ok() { "done" } else { "failed" };

        // 3. The step's own task.step (the founder's three fields).
        let logged = self.log(
            "task.step",
            ctx.now_ms,
            &HarnessStepRecord {
                task_id,
                step: i,
                status,
                governed: run.governed,
                exit: &exit,
                duration_ms: run.duration_ms,
            },
        );

        // 4. The token stops resolving and the lease is released — before the
        // row, before the directories, whatever happened above.
        self.revoke_harness_run(&launch.lease_id, &launch.token);

        // 5. The row: the step ended, one way or the other.
        let saved = match self.task_row(task_id) {
            Some(mut t) => {
                t.steps[i].status = match &verdict {
                    Ok(()) => StepStatus::Done,
                    Err(why) => StepStatus::Failed(why.clone()),
                };
                t.steps[i].ended_ms = Some(ctx.now_ms);
                t.status = if verdict.is_err() {
                    TaskStatus::Failed
                } else if t.steps.iter().all(|s| matches!(s.status, StepStatus::Done)) {
                    TaskStatus::Done
                } else {
                    TaskStatus::Running
                };
                self.save_task(&t).map(|()| t)
            }
            None => Err(KernelError::NotFound(task_id.into())),
        };

        // 6. The directories: the configuration (it held the token) always; the
        // workspace unless asked to keep it — it held projected data, and a kept
        // one is swept at the next boot.
        remove_tree(&launch.config_dir, "harness configuration");
        if !keep {
            remove_tree(&self.harness_workspace_dir(task_id), "harness workspace");
        }

        recorded?;
        logged?;
        saved
    }

    /// What a clean run produced (Ruling 21.6): the artefacts the harness
    /// attached explicitly over MCP, or — when it attached none — its declared
    /// output `OUT/<artefact_type>.*`, collected once, capped, and deduplicated
    /// by the subject-scoped address the register holds. The approval subject
    /// is therefore what the harness attached (the register's last artefact),
    /// never a scratch file.
    fn collect_harness_output(
        &mut self,
        ctx: &Ctx,
        task_id: &str,
        launch: &HarnessLaunch,
    ) -> Result<(), String> {
        // A file the run tried to attach past a cap fails the step by name.
        if let Some(file) = self
            .harness_tokens
            .get(&RealKernel::harness_token_key(&launch.token))
            .and_then(|s| s.oversize.clone())
        {
            return Err(format!(
                "harness attached more than the limit allows: {file}"
            ));
        }
        let t = self
            .task_row(task_id)
            .ok_or_else(|| format!("task {task_id} is gone"))?;
        let reg = self
            .read_register(ctx, &t.register)
            .map_err(|e| e.to_string())?;
        // The harness chose its artefact over MCP: that is the subject, and the
        // declared file is not collected over it.
        if reg.artefacts.len() > launch.artefacts_before {
            return Ok(());
        }
        let out_dir = self.harness_workspace_dir(task_id).join("OUT");
        let Some(path) = declared_output(&out_dir, &t.artefact_type) else {
            return Err("harness produced no artefact".into());
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len > HARNESS_MAX_FILE_BYTES {
            return Err(format!(
                "OUT/{name} is {len} bytes, above the {HARNESS_MAX_FILE_BYTES}-byte limit for one file"
            ));
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("read OUT/{name}: {e}"))?;
        let address = self
            .store
            .blobs
            .address_of(&format!("task:{}", reg.task_id), &bytes);
        if reg.artefacts.iter().any(|a| a.hash == address) {
            return Ok(());
        }
        self.attach_artefact(ctx, &t.register, &t.artefact_type, &bytes)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Attach a workspace file on the harness's behalf (`harness.attach_artefact`):
    /// resolve the token, hold the file to the per-file and per-run caps
    /// (Ruling 21.6) — a breach is refused *and* remembered, so settle fails the
    /// step naming the file — read it, attach it at the harness clearance.
    pub fn harness_attach_file(
        &mut self,
        token: &str,
        now_ms: u64,
        kind: &str,
        rel: &str,
    ) -> Result<vk_contracts::storage::BlobEnvelope, KernelError> {
        let session = self.harness_session(token, now_ms)?;
        let key = RealKernel::harness_token_key(token);
        let path = self.harness_file_path(&session.task_id, rel)?;
        let len = std::fs::metadata(&path)
            .map(|m| m.len())
            .map_err(|e| KernelError::NotFound(format!("{rel}: {e}")))?;
        let attached = self
            .harness_tokens
            .get(&key)
            .map(|s| s.bytes_attached)
            .unwrap_or(0);
        let breach = if len > HARNESS_MAX_FILE_BYTES {
            Some(format!(
                "{rel} is {len} bytes, above the {HARNESS_MAX_FILE_BYTES}-byte limit for one file"
            ))
        } else if attached + len > HARNESS_MAX_RUN_BYTES {
            Some(format!(
                "{rel} ({len} bytes) would take the run past the {HARNESS_MAX_RUN_BYTES}-byte limit"
            ))
        } else {
            None
        };
        if let Some(why) = breach {
            if let Some(s) = self.harness_tokens.get_mut(&key) {
                s.oversize.get_or_insert(rel.to_string());
            }
            return Err(KernelError::Gate(why));
        }
        let bytes =
            std::fs::read(&path).map_err(|e| KernelError::NotFound(format!("{rel}: {e}")))?;
        let env = self.attach_artefact(&session.ctx, &session.register, kind, &bytes)?;
        if let Some(s) = self.harness_tokens.get_mut(&key) {
            s.bytes_attached += len;
        }
        Ok(env)
    }

    /// Resolve a harness-supplied path inside a task's workspace, confined to it.
    ///
    /// The `rel` path is the harness's own (from `vk_attach_artefact`), so it is
    /// held to ordinary components: an absolute path, a drive prefix or a `..`
    /// would read outside the workspace, and the confinement is the whole point.
    fn harness_file_path(&self, task_id: &str, rel: &str) -> Result<PathBuf, KernelError> {
        let relp = Path::new(rel);
        let ok = !rel.is_empty()
            && relp
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if !ok {
            return Err(KernelError::Gate(format!(
                "workspace path {rel:?} must be a relative subpath of the workspace"
            )));
        }
        Ok(self.harness_workspace_dir(task_id).join(relp))
    }

    /// Read a file from a task's harness workspace, confined to it and held to
    /// the per-file cap.
    pub fn read_harness_file(&self, task_id: &str, rel: &str) -> Result<Vec<u8>, KernelError> {
        let path = self.harness_file_path(task_id, rel)?;
        let len = std::fs::metadata(&path)
            .map(|m| m.len())
            .map_err(|e| KernelError::NotFound(format!("{}: {e}", path.display())))?;
        if len > HARNESS_MAX_FILE_BYTES {
            return Err(KernelError::Gate(format!(
                "{rel} is {len} bytes, above the {HARNESS_MAX_FILE_BYTES}-byte limit for one file"
            )));
        }
        std::fs::read(&path).map_err(|e| KernelError::NotFound(format!("{}: {e}", path.display())))
    }

    /// Append the one `harness.connections` event for a run (SP1b Task 4). Public
    /// so the harness step drives it and a test can assert it — including that a
    /// run with no samples still logs the event with an empty connection list.
    pub fn record_harness_connection(
        &mut self,
        now_ms: u64,
        rec: &HarnessConnectionsRecord,
    ) -> Result<(), KernelError> {
        self.log("harness.connections", now_ms, rec)
    }

    /// End a run's authority: forget its token and release its lease (drop it
    /// from the table, delete its row). Best effort and never a reason to skip
    /// the rest of a settle — a row that could not be deleted is logged, and
    /// the token is gone from memory regardless. The fence row persists, as it
    /// does for every lease.
    fn revoke_harness_run(&mut self, lease_id: &str, token: &str) {
        self.revoke_harness_token(token);
        self.locks.release(lease_id);
        if let Err(e) = self.store.db.delete("leases", lease_id) {
            tracing::warn!(lease = %lease_id, error = %e, "could not delete a harness lease row");
        }
    }

    /// Sweep every harness lease and workspace left on disk (Ruling 21.4, boot).
    /// No harness survives a restart, so a `harness:*` lease row is a leftover
    /// whose token no longer exists, and `<state_dir>/harness/` holds projected
    /// plaintext and configuration that no run will read again.
    pub(crate) fn sweep_harness_state(&mut self) -> Result<(), KernelError> {
        let rows = self
            .store
            .db
            .list_json::<Lease>("leases")
            .map_err(store_failed)?;
        for (key, lease) in rows {
            if lease.resource.starts_with("harness:") {
                self.locks.release(&key);
                self.store.db.delete("leases", &key).map_err(store_failed)?;
                tracing::info!(lease = %key, resource = %lease.resource, "swept a harness lease left by a previous run");
            }
        }
        self.harness_tokens.clear();
        remove_tree(&self.store.state_dir.join("harness"), "harness directory");
        Ok(())
    }

    /// The operator's one screen. Everything here is read back from disk, so it
    /// says the same thing after a restart as it did before one. The tasks on
    /// it are the ones `ctx` may see (I2); arches, STOPs and liveness carry no
    /// label.
    pub fn top(&self, ctx: &Ctx) -> TopView {
        let mut v = TopView::default();
        for (key, value) in self.store.db.kv_list_prefix("stats:").unwrap_or_default() {
            if let (Some(arch), Ok(stats)) = (
                key.strip_prefix("stats:"),
                serde_json::from_str::<ArchStats>(&value),
            ) {
                v.arches.insert(arch.into(), stats);
            }
        }
        // Every arch mounted right now, whether or not it has ever been
        // called: an operator asking which arches this node has, and which of
        // them it contains, must not have to run one first to find out
        // (Ruling 9d). A row of zeros is an answer — and an arch with counters
        // but no governance is one that has been unmounted since.
        for (id, m, state) in self.arch_states() {
            v.arches.entry(id.clone()).or_default();
            v.governed.insert(id.clone(), m.governed);
            v.price_eur_per_1k
                .insert(id.clone(), m.cost_per_1k_tokens_eur);
            v.locality.insert(id.clone(), locality_name(m.locality));
            v.jurisdiction.insert(id.clone(), m.jurisdiction.clone());
            v.states.insert(id.clone(), state.name().into());
            if let Some(why) = state.reason() {
                v.unavailable.insert(id, why.into());
            }
        }
        for t in self.tasks(ctx) {
            v.tasks.insert(t.id, t.status);
        }
        // Every scope a live STOP holds, from the STOP set itself rather than
        // from a list of scopes worth asking about: a scope this screen did
        // not think to ask about is exactly the one whose STOP an operator
        // would never find. `vk status` reads the same set.
        v.stopped_scopes = self.stopped_scopes();
        for (business, l) in self
            .store
            .db
            .list_json::<vk_contracts::stop::LivenessLease>("liveness")
            .unwrap_or_default()
        {
            v.liveness.insert(business, l.expires_at_ms);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealKernel;
    use vk_contracts::labels::*;
    use vk_contracts::principal::Principal;
    use vk_contracts::testing::KernelTestHooks;

    fn open(dir: &std::path::Path) -> RealKernel {
        RealKernel::open(
            dir,
            vk_store::keys::KeySource::File(dir.join("m.key")),
            "n1",
        )
        .unwrap()
    }

    fn personal() -> Clearance {
        Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        }
    }

    fn machine(now: u64) -> Ctx {
        Ctx {
            principal: Principal::Machine {
                node_id: "n1".into(),
                lease_id: "cli".into(),
            },
            clearance: personal(),
            partition: "p1".into(),
            now_ms: now,
        }
    }

    fn human(now: u64) -> Ctx {
        Ctx {
            principal: Principal::Human {
                device_id: "phone-1".into(),
            },
            ..machine(now)
        }
    }

    fn released(k: &RealKernel) -> usize {
        k.ledger()
            .events()
            .iter()
            .filter(|e| e.kind == "artefact.released")
            .count()
    }

    #[test]
    fn plan_then_draft_then_approve_waits_for_a_human() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(crate::tests::local(personal()));
        let t = k
            .create_task(
                &machine(1),
                "Draft a proposal for Acme",
                "proposal",
                Label::bottom(),
                vec![
                    StepKind::Plan {
                        arch_id: arch.clone(),
                    },
                    StepKind::Draft {
                        arch_id: arch.clone(),
                    },
                    StepKind::Approve,
                    StepKind::Release {
                        to_dir: "out".into(),
                    },
                ],
            )
            .unwrap();
        let t = k.run_task_step(&machine(2), &t.id).unwrap();
        assert!(matches!(t.steps[0].status, StepStatus::Done));
        let t = k.run_task_step(&machine(3), &t.id).unwrap();
        assert!(matches!(t.steps[1].status, StepStatus::Done));
        let t = k.run_task_step(&machine(4), &t.id).unwrap();
        assert!(matches!(t.status, TaskStatus::WaitingHuman));
        let reg = k.read_register(&machine(5), &t.register).unwrap();
        assert!(reg.decisions.iter().any(|d| d.starts_with("plan:")));
        assert!(reg.decisions.iter().any(|d| d.starts_with("draft:")));
        assert_eq!(k.top(&machine(0)).arches[&arch].calls, 2);
        // One task, one id: the payload tier keys artefacts under the
        // register's task id, and the `Task` must name the same subject.
        assert_eq!(t.id, reg.task_id);

        // Polling a step that is still waiting is not a transition: it must
        // leave the row alone and add nothing to the ledger.
        let before = k.ledger().events().len();
        let again = k.run_task_step(&machine(6), &t.id).unwrap();
        assert!(matches!(again.status, TaskStatus::WaitingHuman));
        assert_eq!(again, t);
        assert_eq!(
            k.ledger().events().len(),
            before,
            "re-polling a waiting step must not grow the ledger"
        );
    }

    #[test]
    fn the_draft_step_attaches_its_output_as_the_tasks_artefact() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(crate::tests::local(personal()));
        let t = k
            .create_task(
                &machine(1),
                "Draft a proposal for Acme",
                "proposal",
                Label::bottom(),
                vec![
                    StepKind::Draft { arch_id: arch },
                    StepKind::Release {
                        to_dir: "out".into(),
                    },
                ],
            )
            .unwrap();
        let t = k.run_task_step(&machine(2), &t.id).unwrap();
        assert!(matches!(t.steps[0].status, StepStatus::Done));

        // One artefact, of the kind the task was submitted for, holding what
        // the arch actually drafted.
        let reg = k.read_register(&machine(3), &t.register).unwrap();
        assert_eq!(reg.artefacts.len(), 1, "the draft is the task's artefact");
        assert_eq!(reg.artefacts[0].kind, "proposal");
        let bytes = k
            .read_artefact(&machine(3), &reg.artefacts[0].hash)
            .unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            *reg.decisions.last().unwrap()
        );

        // It is what a release writes out.
        let t = k.run_task_step(&machine(5), &t.id).unwrap();
        assert!(matches!(t.status, TaskStatus::Done));
        let name = format!(
            "{}.proposal",
            &reg.artefacts[0].hash.trim_start_matches("sha256:")[..12]
        );
        let path = k.export_root().join("out").join(&name);
        assert!(path.exists(), "{}", path.display());
    }

    /// Ruling 28: `task_decisions` is the task read surface that answers H1's
    /// own question — did this step leave the next one something to read? — in
    /// metadata only.
    ///
    /// The shape the SP1 demo submits, `[Plan(A), Draft(B), Judge(B)]`: the
    /// plan's decision is there after step 0, the draft's after step 1, and the
    /// judge raises an *open question*, not a decision, so it gets no entry. A
    /// step that has not run gets none either — a count is a fact about work
    /// that happened.
    #[test]
    fn task_decisions_reports_a_count_a_length_and_a_hash_per_step_and_never_the_text() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(crate::tests::local(personal()));
        let t = k
            .create_task(
                &machine(1),
                "Draft a proposal for Acme",
                "proposal",
                Label::bottom(),
                vec![
                    StepKind::Plan {
                        arch_id: arch.clone(),
                    },
                    StepKind::Draft {
                        arch_id: arch.clone(),
                    },
                    StepKind::Judge { arch_id: arch },
                ],
            )
            .unwrap();

        // Nothing has run: nothing to report, and no error either.
        assert!(k.task_decisions(&machine(2), &t).unwrap().is_empty());

        // The plan.
        let t = k.run_task_step(&machine(3), &t.id).unwrap();
        let after_plan = k.task_decisions(&machine(4), &t).unwrap();
        assert_eq!(after_plan.len(), 1, "{after_plan:?}");
        assert_eq!(after_plan[0].after_step, 0);
        assert_eq!(after_plan[0].count, 1);
        assert!(after_plan[0].last_len_bytes > 0, "{after_plan:?}");
        assert!(
            after_plan[0].last_hash.starts_with("sha256:"),
            "{after_plan:?}"
        );

        // The draft, then the judge. Two decisions, growing; the judge's
        // verdict is an open question and adds no entry.
        let t = k.run_task_step(&machine(5), &t.id).unwrap();
        let t = k.run_task_step(&machine(6), &t.id).unwrap();
        assert!(matches!(t.steps[2].status, StepStatus::Done));
        let all = k.task_decisions(&machine(7), &t).unwrap();
        assert_eq!(
            all.iter().map(|d| d.after_step).collect::<Vec<_>>(),
            vec![0, 1],
            "the judge raises an open question, not a decision: {all:?}"
        );
        assert_eq!(all[1].count, 2, "{all:?}");
        assert_ne!(all[0].last_hash, all[1].last_hash, "{all:?}");

        // The hashes and lengths are of the real decisions, and the summary
        // carries neither their text nor anything derived from it but a digest.
        let reg = k.read_register(&machine(8), &t.register).unwrap();
        assert_eq!(reg.decisions.len(), 2);
        assert_eq!(all[0].last_len_bytes, reg.decisions[0].len());
        assert_eq!(all[1].last_len_bytes, reg.decisions[1].len());
        assert_eq!(
            all[1].last_hash,
            vk_contracts::hash_bytes(reg.decisions[1].as_bytes())
        );
        let json = serde_json::to_string(&all).unwrap();
        for decision in &reg.decisions {
            assert!(
                !json.contains(decision.trim()),
                "a decision's text reached the summary: {json}"
            );
        }
    }

    /// I2 on the summary, as on every other register read: a count and a hash
    /// are smaller facts about a register, not lesser ones, so a caller who
    /// cannot read the register learns neither.
    #[test]
    fn task_decisions_refuses_a_register_above_the_callers_clearance() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(crate::tests::local(personal()));
        let t = k
            .create_task(
                &machine(1),
                "the confidential goal",
                "note",
                Label {
                    scope: Scope::Business,
                    data_class: DataClass::Own,
                    origins: Default::default(),
                },
                vec![StepKind::Plan { arch_id: arch }],
            )
            .unwrap();
        let t = k.run_task_step(&machine(2), &t.id).unwrap();
        assert_eq!(k.task_decisions(&machine(3), &t).unwrap().len(), 1);

        let low = Ctx {
            clearance: Clearance {
                max_scope: Scope::Public,
                third_party_allowed: true,
            },
            ..machine(4)
        };
        assert!(matches!(
            k.task_decisions(&low, &t),
            Err(KernelError::I2(_))
        ));
    }

    /// A subject answered before the task is at its `Approve` step would name a
    /// register that the very next step rewrites: the human would sign it, the
    /// approval would be recorded, and the step would still be waiting.
    #[test]
    fn the_approval_subject_is_answered_only_while_the_task_waits_at_its_approve_step() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(crate::tests::local(personal()));
        let t = k
            .create_task(
                &machine(1),
                "Draft a proposal for Acme",
                "proposal",
                Label::bottom(),
                vec![StepKind::Draft { arch_id: arch }, StepKind::Approve],
            )
            .unwrap();

        // Queued: the draft has not run, so there is nothing to approve yet.
        let err = k.approval_subject(&machine(2), &t.id).unwrap_err();
        assert!(matches!(err, KernelError::Gate(_)), "{err}");
        assert!(
            err.to_string().contains("not waiting for an approval")
                && err.to_string().contains("queued"),
            "the refusal must name the status a person just saw: {err}"
        );

        // At the Approve step: the drafted artefact, and the step agrees.
        let t = k.run_task_step(&machine(3), &t.id).unwrap();
        let subject = k.approval_subject(&machine(4), &t.id).unwrap();
        let reg = k.read_register(&machine(4), &t.register).unwrap();
        assert_eq!(subject, reg.artefacts[0].hash);
        let t = k.run_task_step(&machine(5), &t.id).unwrap();
        assert!(matches!(t.status, TaskStatus::WaitingHuman));
        assert_eq!(k.approval_subject(&machine(6), &t.id).unwrap(), subject);
    }

    #[test]
    fn stopped_scope_halts_the_scheduler() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(crate::tests::local(personal()));
        let t = k
            .create_task(
                &machine(1),
                "x",
                "note",
                Label::bottom(),
                vec![StepKind::Plan { arch_id: arch }],
            )
            .unwrap();
        k.stop(&human(2), "node").unwrap();
        assert!(matches!(
            k.run_task_step(&machine(3), &t.id),
            Err(vk_contracts::syscalls::KernelError::Stopped(_))
        ));
    }

    #[test]
    fn terminal_tasks_are_not_restarted() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(crate::tests::local(personal()));
        let done = k
            .create_task(
                &machine(1),
                "draft a proposal",
                "note",
                Label::bottom(),
                vec![StepKind::Plan { arch_id: arch }],
            )
            .unwrap();
        let done = k.run_task_step(&machine(2), &done.id).unwrap();
        assert!(matches!(done.status, TaskStatus::Done));

        let failed = k
            .create_task(
                &machine(3),
                "x",
                "note",
                Label::bottom(),
                vec![StepKind::Plan {
                    arch_id: "arch-nope".into(),
                }],
            )
            .unwrap();
        assert!(k.run_task_step(&machine(4), &failed.id).is_err());
        // A failed step is not silently retried, so the task cannot flip back
        // to Running and go on to report a success it never had.
        let again = k.run_task_step(&machine(5), &failed.id).unwrap();
        assert!(matches!(again.status, TaskStatus::Failed));
        assert!(matches!(again.steps[0].status, StepStatus::Failed(_)));

        // And a task that finished before the STOP stays finished: a STOP
        // halts what is running, it does not rewrite history.
        k.stop(&human(6), "node").unwrap();
        let after = k.run_task_step(&machine(7), &done.id).unwrap();
        assert!(matches!(after.status, TaskStatus::Done));
        assert!(matches!(
            k.task(&machine(0), &done.id).unwrap().status,
            TaskStatus::Done
        ));
    }

    #[test]
    fn release_writes_artefacts_under_the_export_root() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let t = k
            .create_task(
                &machine(1),
                "x",
                "proposal",
                Label::bottom(),
                vec![StepKind::Release {
                    to_dir: "out".into(),
                }],
            )
            .unwrap();
        let env = k
            .attach_artefact(&machine(2), &t.register, "proposal.md", b"# Proposal")
            .unwrap();
        let t = k.run_task_step(&machine(3), &t.id).unwrap();
        assert!(matches!(t.status, TaskStatus::Done));
        let name = format!(
            "{}.proposal.md",
            &env.hash.trim_start_matches("sha256:")[..12]
        );
        let path = k.export_root().join("out").join(&name);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"# Proposal".to_vec(),
            "{}",
            path.display()
        );
        assert_eq!(released(&k), 1, "the release must be on the ledger");

        // A destination that is not a relative subpath of the export root is
        // refused before anything is written, and leaves nothing behind.
        let escapes = [
            "../escape".to_string(),
            d.path().join("abs").to_string_lossy().into_owned(),
        ];
        for bad in escapes {
            let t = k
                .create_task(
                    &machine(4),
                    "x",
                    "proposal",
                    Label::bottom(),
                    vec![StepKind::Release {
                        to_dir: bad.clone(),
                    }],
                )
                .unwrap();
            k.attach_artefact(&machine(5), &t.register, "proposal.md", b"# Proposal")
                .unwrap();
            assert!(
                matches!(
                    k.run_task_step(&machine(6), &t.id),
                    Err(KernelError::Gate(_))
                ),
                "{bad} must be refused"
            );
            let row = k.task(&machine(0), &t.id).unwrap();
            assert!(matches!(row.status, TaskStatus::Failed));
            assert!(matches!(row.steps[0].status, StepStatus::Failed(_)));
        }
        assert!(!d.path().join("escape").exists());
        assert!(!d.path().join("abs").exists());
        assert_eq!(released(&k), 1, "a refused release must not be logged");
    }

    #[test]
    fn a_traversing_artefact_kind_cannot_escape_the_export_root() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let t = k
            .create_task(
                &machine(1),
                "x",
                "proposal",
                Label::bottom(),
                vec![StepKind::Release {
                    to_dir: "out".into(),
                }],
            )
            .unwrap();
        k.attach_artefact(&machine(2), &t.register, "proposal.md", b"# Proposal")
            .unwrap();
        // `attach_artefact` refuses a kind like this, but a register is durable
        // and some other path may have written one: the release must refuse
        // what it reads back rather than trust it. Confining the *directory* is
        // only half the job while the file name can traverse out of it.
        let mut reg = k.read_register(&machine(3), &t.register).unwrap();
        reg.artefacts[0].kind = "../../../../vk-escape-marker.md".into();
        k.write_register(&machine(3), reg).unwrap();

        assert!(matches!(
            k.run_task_step(&machine(4), &t.id),
            Err(KernelError::Gate(_))
        ));
        let row = k.task(&machine(0), &t.id).unwrap();
        assert!(matches!(row.status, TaskStatus::Failed));
        assert!(matches!(row.steps[0].status, StepStatus::Failed(_)));
        assert!(
            !d.path()
                .parent()
                .unwrap()
                .join("vk-escape-marker.md")
                .exists(),
            "nothing may be written above the state directory"
        );
        assert!(!k.export_root().join("out").exists());
        assert_eq!(released(&k), 0, "a refused release must not be logged");
    }

    #[test]
    fn stopped_and_failed_rows_are_persisted() {
        let d = tempfile::tempdir().unwrap();
        let (failed_id, stopped_id) = {
            let mut k = open(d.path());
            let failed = k
                .create_task(
                    &machine(1),
                    "x",
                    "note",
                    Label::bottom(),
                    vec![StepKind::Plan {
                        arch_id: "arch-nope".into(),
                    }],
                )
                .unwrap();
            assert!(matches!(
                k.run_task_step(&machine(2), &failed.id),
                Err(KernelError::NotFound(_))
            ));
            let row = k.task(&machine(0), &failed.id).unwrap();
            assert!(matches!(row.status, TaskStatus::Failed));
            match &row.steps[0].status {
                StepStatus::Failed(reason) => assert!(reason.contains("arch-nope"), "{reason}"),
                other => panic!("expected a failed step, got {other:?}"),
            }

            let arch = k.register_arch(crate::tests::local(personal()));
            let stopped = k
                .create_task(
                    &machine(3),
                    "x",
                    "note",
                    Label::bottom(),
                    vec![StepKind::Plan { arch_id: arch }],
                )
                .unwrap();
            k.stop(&human(4), "node").unwrap();
            assert!(matches!(
                k.run_task_step(&machine(5), &stopped.id),
                Err(KernelError::Stopped(_))
            ));
            assert!(matches!(
                k.task(&machine(0), &stopped.id).unwrap().status,
                TaskStatus::Stopped
            ));
            (failed.id, stopped.id)
        };
        // A caller that never comes back must not be the only record of either.
        let k = open(d.path());
        assert!(matches!(
            k.task(&machine(0), &failed_id).unwrap().status,
            TaskStatus::Failed
        ));
        assert!(matches!(
            k.task(&machine(0), &stopped_id).unwrap().status,
            TaskStatus::Stopped
        ));
        assert_eq!(k.top(&machine(0)).stopped_scopes, vec!["node".to_string()]);
    }

    /// `top` and `boot`/`vk status` read one set. A scope this screen had to
    /// know about in advance to report — a business with no liveness lease, a
    /// vertical, anything a later release names — would be a STOP an operator
    /// holds and cannot see.
    #[test]
    fn top_names_every_stopped_scope_not_only_the_ones_it_knows_to_ask_about() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let s = k.stop(&human(1), "business:acme").unwrap();
        assert_eq!(
            k.top(&machine(0)).stopped_scopes,
            vec!["business:acme".to_string()]
        );
        k.resume(&human(2), &s).unwrap();
        assert!(k.top(&machine(0)).stopped_scopes.is_empty());
    }

    #[test]
    fn top_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let (arch, id) = {
            let mut k = open(d.path());
            let arch = k.register_arch(crate::tests::local(personal()));
            let t = k
                .create_task(
                    &machine(1),
                    "draft a proposal",
                    "note",
                    Label::bottom(),
                    vec![StepKind::Plan {
                        arch_id: arch.clone(),
                    }],
                )
                .unwrap();
            let t = k.run_task_step(&machine(2), &t.id).unwrap();
            assert!(matches!(t.status, TaskStatus::Done));
            assert_eq!(k.top(&machine(0)).arches[&arch].calls, 1);
            (arch, t.id)
        };
        let k = open(d.path());
        let v = k.top(&machine(0));
        assert_eq!(
            v.arches[&arch].calls, 1,
            "per-arch counters come from disk, not from this process's memory"
        );
        assert!(matches!(v.tasks[&id], TaskStatus::Done));
        assert!(v.stopped_scopes.is_empty());
    }

    /// Where the call went and under whose law it was answered, beside what it
    /// cost (SP1b Task 8). An operator reading `vk top` is asking two
    /// questions at once — what is this spending, and is any of it leaving the
    /// Union — and a screen that answers only the first sends them to
    /// `vk arch show` for every row.
    #[test]
    fn top_says_where_each_arch_is_and_under_whose_law() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let mut cloud = crate::tests::local_named("cloud", personal());
        cloud.locality = vk_contracts::arch::Locality::Cloud;
        cloud.jurisdiction = "US".into();
        cloud.governed = false;
        let cloud_id = k.register_arch(cloud);
        let local_id = k.register_arch(crate::tests::local_named("here", personal()));

        let v = k.top(&machine(0));
        assert_eq!(v.locality[&cloud_id], "cloud");
        assert_eq!(v.jurisdiction[&cloud_id], "US");
        assert!(!v.governed[&cloud_id], "a cloud arch is not governed");
        assert_eq!(v.locality[&local_id], "local");
        assert_eq!(v.jurisdiction[&local_id], "FR");
        // Never called, and still on the screen with a row of zeros: an
        // operator must not have to run an arch to find out it is there.
        assert_eq!(v.arches[&cloud_id].calls, 0);
        assert_eq!(v.arches[&local_id].calls, 0);
        // Nothing has been called, so there is nothing per-call to show.
        assert!(v.calls.is_empty(), "{:?}", v.calls);
    }

    #[test]
    fn namespace_lists_and_resolves() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(crate::tests::local(personal()));
        k.enroll_device("phone-1", [7u8; 32]);
        assert!(matches!(
            crate::ns::resolve(&k, &machine(0), "/").unwrap(),
            crate::ns::Entry::Dir { .. }
        ));
        assert!(matches!(
            crate::ns::resolve(&k, &machine(0), &format!("/arches/{arch}")).unwrap(),
            crate::ns::Entry::Arch { .. }
        ));
        match crate::ns::resolve(&k, &machine(0), "/devices/phone-1").unwrap() {
            crate::ns::Entry::Device { id } => assert_eq!(id, "phone-1"),
            other => panic!("expected a device, got {other:?}"),
        }
        assert!(crate::ns::resolve(&k, &machine(0), "/devices/ghost").is_err());
        assert!(crate::ns::resolve(&k, &machine(0), "/nope").is_err());
    }

    /// I2 on the task views. A task carries its register's goal, so a task
    /// whose register does not flow to the caller is not merely refused, it
    /// is not there: absent from `tasks`, `top` and `/tasks`, not found by
    /// `task`, `/tasks/<id>` and `run_task_step` — and the row untouched by
    /// the attempt. A caller cleared for the label sees it everywhere, and a
    /// task at the bottom label is visible to both.
    #[test]
    fn a_task_above_the_callers_clearance_is_absent_from_every_task_view() {
        use crate::ns::{resolve, Entry};
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(crate::tests::local(personal()));
        let above = Label {
            scope: Scope::Business,
            data_class: DataClass::Own,
            origins: Default::default(),
        };
        let cleared = machine(1);
        let secret = k
            .create_task(
                &cleared,
                "the confidential goal",
                "note",
                above,
                vec![StepKind::Plan {
                    arch_id: arch.clone(),
                }],
            )
            .unwrap();
        let plain = k
            .create_task(
                &cleared,
                "a public goal",
                "note",
                Label::bottom(),
                vec![StepKind::Plan { arch_id: arch }],
            )
            .unwrap();
        let low = Ctx {
            clearance: Clearance {
                max_scope: Scope::Public,
                third_party_allowed: true,
            },
            ..machine(2)
        };
        fn listed(k: &RealKernel, ctx: &Ctx) -> Vec<String> {
            match resolve(k, ctx, "/tasks").unwrap() {
                Entry::Dir { entries } => entries,
                other => panic!("expected a listing, got {other:?}"),
            }
        }

        // Not there, for the caller who is not cleared for it.
        assert!(k.task(&low, &secret.id).is_none());
        assert_eq!(
            k.tasks(&low)
                .iter()
                .map(|t| t.id.clone())
                .collect::<Vec<_>>(),
            vec![plain.id.clone()]
        );
        assert_eq!(
            k.top(&low).tasks.keys().cloned().collect::<Vec<_>>(),
            vec![plain.id.clone()]
        );
        assert_eq!(listed(&k, &low), vec![plain.id.clone()]);
        assert!(matches!(
            resolve(&k, &low, &format!("/tasks/{}", secret.id)),
            Err(KernelError::NotFound(_))
        ));
        assert!(matches!(
            k.run_task_step(&low, &secret.id),
            Err(KernelError::NotFound(_))
        ));
        assert!(matches!(
            k.approval_subject(&low, &secret.id),
            Err(KernelError::NotFound(_))
        ));

        // There, unchanged, for the caller who is.
        let seen = k
            .task(&cleared, &secret.id)
            .expect("visible to a cleared caller");
        assert_eq!(
            seen, secret,
            "the refused step must not have touched the row"
        );
        assert_eq!(k.tasks(&cleared).len(), 2);
        assert!(k.top(&cleared).tasks.contains_key(&secret.id));
        assert_eq!(listed(&k, &cleared).len(), 2);
        assert!(matches!(
            resolve(&k, &cleared, &format!("/tasks/{}", secret.id)),
            Ok(Entry::Task(_))
        ));
    }

    /// Unix only: what a release writes is plaintext outside the encrypted
    /// tier, so the export root, the destination and each released file are
    /// the owner's alone — including a root that already existed open to
    /// others, as a careless `mkdir` would have left it.
    #[cfg(unix)]
    #[test]
    fn on_unix_a_release_leaves_only_owner_readable_directories_and_files() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let t = k
            .create_task(
                &machine(1),
                "x",
                "proposal",
                Label::bottom(),
                vec![StepKind::Release {
                    to_dir: "out/deep".into(),
                }],
            )
            .unwrap();
        let env = k
            .attach_artefact(&machine(2), &t.register, "proposal.md", b"# Proposal")
            .unwrap();
        std::fs::create_dir_all(k.export_root()).unwrap();
        std::fs::set_permissions(k.export_root(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let t = k.run_task_step(&machine(3), &t.id).unwrap();
        assert!(matches!(t.status, TaskStatus::Done));

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let out = k.export_root().join("out");
        assert_eq!(mode(&k.export_root()), 0o700, "export root");
        assert_eq!(mode(&out), 0o700, "out");
        assert_eq!(mode(&out.join("deep")), 0o700, "out/deep");
        let name = format!(
            "{}.proposal.md",
            &env.hash.trim_start_matches("sha256:")[..12]
        );
        assert_eq!(mode(&out.join("deep").join(name)), 0o600, "released file");
    }
    /// Review M11: a step that was `Running` when the process died is not a
    /// step to re-run. Nobody knows how far it got — an inference may already
    /// have left this node and been paid for — so boot ends it, says so in the
    /// record, and the scheduler never picks it up again. Re-running it is a
    /// decision for a caller who says so, exactly as for any other failed step.
    #[test]
    fn a_step_left_running_by_a_crash_is_failed_at_boot_and_never_re_run() {
        let d = tempfile::tempdir().unwrap();
        let (arch, id);
        {
            let mut k = open(d.path());
            arch = k.register_arch(crate::tests::local(personal()));
            let t = k
                .create_task(
                    &machine(1),
                    "Draft a proposal for Acme",
                    "proposal",
                    Label::bottom(),
                    vec![
                        StepKind::Plan {
                            arch_id: arch.clone(),
                        },
                        StepKind::Draft {
                            arch_id: arch.clone(),
                        },
                    ],
                )
                .unwrap();
            id = t.id.clone();
            // What a crash mid-step leaves on disk: the row says the step
            // started, and nothing anywhere says how it ended.
            let mut crashed = t;
            crashed.steps[0].status = StepStatus::Running;
            crashed.steps[0].started_ms = Some(1);
            crashed.status = TaskStatus::Running;
            k.save_task(&crashed).unwrap();
        }

        let mut k = open(d.path());
        let before = k.ledger().events().len();
        k.boot().unwrap();
        let t = k.task(&machine(2), &id).expect("the task is still there");
        assert_eq!(
            t.steps[0].status,
            StepStatus::Failed(INTERRUPTED.into()),
            "the interrupted step says what happened to it"
        );
        assert!(matches!(t.status, TaskStatus::Failed));
        assert!(
            matches!(t.steps[1].status, StepStatus::Pending),
            "only the step that was running is touched"
        );
        let kinds: Vec<&str> = k.ledger().events()[before..]
            .iter()
            .map(|e| e.kind.as_str())
            .collect();
        assert!(
            kinds.contains(&"task.step"),
            "the recovery belongs in the record: {kinds:?}"
        );

        // Never re-run: the arch is not called again, and the row does not move.
        let calls = |k: &RealKernel| k.top(&machine(9)).arches.get(&arch).map_or(0, |s| s.calls);
        let spent = calls(&k);
        let again = k.run_task_step(&machine(3), &id).unwrap();
        assert_eq!(again.steps[0].status, t.steps[0].status);
        assert!(matches!(again.status, TaskStatus::Failed));
        assert_eq!(calls(&k), spent, "a failed step is not retried by asking");

        // And booting again changes nothing: there is no `Running` step left
        // to recover, so the second boot appends no second recovery.
        let before = k.ledger().events().len();
        k.boot().unwrap();
        let kinds: Vec<&str> = k.ledger().events()[before..]
            .iter()
            .map(|e| e.kind.as_str())
            .collect();
        assert_eq!(kinds, ["boot"], "a clean boot recovers nothing: {kinds:?}");
    }
}
