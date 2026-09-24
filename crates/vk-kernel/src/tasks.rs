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
use vk_contracts::principal::ApprovalKind;
use vk_contracts::register::{Register, RegisterId};
use vk_contracts::syscalls::{Ctx, Kernel, KernelError};
use vk_contracts::testing::KernelTestHooks;

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
        match self.run_step(ctx, task_id, &kind, &t.register, &t.artefact_type) {
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
            // SP1b replaces this with a confined launch; until then the step is
            // honest about needing a human rather than claiming work it did not do.
            StepKind::Harness { .. } => Ok((StepStatus::WaitingHuman, 0)),
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
        // Governance comes off the mounted adapters, not off the counters: it
        // is a fact about the arch, not about what it has spent.
        for (id, m) in self.arches() {
            v.governed.insert(id, m.governed);
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
            crate::ns::Entry::Arch(_)
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
