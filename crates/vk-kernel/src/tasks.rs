//! Tasks and the sequential scheduler (spec §3.3). Steps run one at a time, one
//! per `run_task_step` call; a STOP on scope `node` halts everything; `Approve`
//! waits for a human approval whose subject is the latest artefact hash; and
//! `Harness` steps are completed by SP1b.
use crate::{store_failed, ArchStats, RealKernel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vk_contracts::arch::Capability;
use vk_contracts::labels::Label;
use vk_contracts::principal::ApprovalKind;
use vk_contracts::register::RegisterId;
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

/// What `top` shows: what each arch has cost so far, what every task is doing,
/// which scopes are stopped, and until when each business may act unattended.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TopView {
    pub arches: BTreeMap<String, ArchStats>,
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
        let id = self.next_id("task")?;
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

    pub fn task(&self, id: &str) -> Option<Task> {
        self.store.db.get_json("tasks", id).ok().flatten()
    }

    pub fn tasks(&self) -> Vec<Task> {
        self.store
            .db
            .list_json::<Task>("tasks")
            .unwrap_or_default()
            .into_iter()
            .map(|(_, t)| t)
            .collect()
    }

    /// Run the next step that is not yet `Done`, and only that one: the
    /// scheduler is sequential by construction, so nothing can overtake a step
    /// that is waiting for a human.
    ///
    /// Every state the task passes through is written down before the next one
    /// is attempted. A step that fails leaves the reason on the step and the
    /// task `Failed`, durably, *and* returns the error: a caller that never
    /// comes back must not be the only record of what went wrong.
    pub fn run_task_step(&mut self, ctx: &Ctx, task_id: &str) -> Result<Task, KernelError> {
        let mut t = self
            .task(task_id)
            .ok_or_else(|| KernelError::NotFound(task_id.into()))?;
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
        t.steps[i].status = StepStatus::Running;
        t.steps[i].started_ms = Some(ctx.now_ms);
        t.status = TaskStatus::Running;
        self.save_task(&t)?;
        let kind = t.steps[i].kind.clone();
        let outcome: Result<StepStatus, KernelError> = match &kind {
            StepKind::Plan { arch_id } => self
                .infer(ctx, arch_id, Capability::Plan, &t.register)
                .map(|o| {
                    t.steps[i].tokens = o.tokens_in;
                    StepStatus::Done
                }),
            StepKind::Draft { arch_id } => self
                .infer(ctx, arch_id, Capability::Generate, &t.register)
                .map(|o| {
                    t.steps[i].tokens = o.tokens_in;
                    StepStatus::Done
                }),
            StepKind::Judge { arch_id } => self
                .infer(ctx, arch_id, Capability::Judge, &t.register)
                .map(|o| {
                    t.steps[i].tokens = o.tokens_in;
                    StepStatus::Done
                }),
            // SP1b replaces this with a confined launch; until then the step is
            // honest about needing a human rather than claiming work it did not do.
            StepKind::Harness { .. } => Ok(StepStatus::WaitingHuman),
            StepKind::Approve => {
                let reg = self.read_register(ctx, &t.register)?;
                // The approval has to name *what* was approved. The latest
                // artefact is that thing; with none attached yet, the register
                // itself is, and either way a later artefact leaves the
                // approval behind rather than inheriting it.
                let subject = reg
                    .artefacts
                    .last()
                    .map(|a| a.hash.clone())
                    .unwrap_or_else(|| vk_contracts::hash_canonical(&reg));
                if self
                    .approvals_for(&subject)
                    .iter()
                    .any(|a| a.kind == ApprovalKind::Human)
                {
                    Ok(StepStatus::Done)
                } else {
                    Ok(StepStatus::WaitingHuman)
                }
            }
            StepKind::Release { to_dir } => {
                let reg = self.read_register(ctx, &t.register)?;
                std::fs::create_dir_all(to_dir).map_err(store_failed)?;
                for a in &reg.artefacts {
                    // `read_artefact` re-checks the label against the caller's
                    // clearance: leaving the kernel is exactly where I2 matters.
                    let bytes = self.read_artefact(ctx, &a.hash)?;
                    let name = format!(
                        "{}.{}",
                        a.hash
                            .trim_start_matches("sha256:")
                            .get(..12)
                            .unwrap_or("artefact"),
                        a.kind
                    );
                    std::fs::write(std::path::Path::new(to_dir).join(name), bytes)
                        .map_err(store_failed)?;
                }
                Ok(StepStatus::Done)
            }
        };
        match outcome {
            Ok(StepStatus::WaitingHuman) => {
                t.steps[i].status = StepStatus::WaitingHuman;
                t.status = TaskStatus::WaitingHuman;
            }
            Ok(s) => {
                t.steps[i].status = s;
                t.steps[i].ended_ms = Some(ctx.now_ms);
                if t.steps.iter().all(|s| matches!(s.status, StepStatus::Done)) {
                    t.status = TaskStatus::Done;
                }
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

    /// The operator's one screen. Everything here is read back from disk, so it
    /// says the same thing after a restart as it did before one.
    pub fn top(&self) -> TopView {
        let mut v = TopView::default();
        for (key, value) in self.store.db.kv_list_prefix("stats:").unwrap_or_default() {
            if let (Some(arch), Ok(stats)) = (
                key.strip_prefix("stats:"),
                serde_json::from_str::<ArchStats>(&value),
            ) {
                v.arches.insert(arch.into(), stats);
            }
        }
        for t in self.tasks() {
            v.tasks.insert(t.id, t.status);
        }
        if self.stops.stopped("node") {
            v.stopped_scopes.push("node".into());
        }
        for (business, l) in self
            .store
            .db
            .list_json::<vk_contracts::stop::LivenessLease>("liveness")
            .unwrap_or_default()
        {
            let scope = format!("business:{business}");
            if self.stops.stopped(&scope) {
                v.stopped_scopes.push(scope);
            }
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
    use vk_contracts::syscalls::{Ctx, Kernel};
    use vk_contracts::testing::KernelTestHooks;

    fn machine(now: u64) -> Ctx {
        Ctx {
            principal: Principal::Machine {
                node_id: "n1".into(),
                lease_id: "cli".into(),
            },
            clearance: Clearance {
                max_scope: Scope::Personal,
                third_party_allowed: true,
            },
            partition: "p1".into(),
            now_ms: now,
        }
    }

    #[test]
    fn plan_then_draft_then_approve_waits_for_a_human() {
        let d = tempfile::tempdir().unwrap();
        let mut k = RealKernel::open(
            d.path(),
            vk_store::keys::KeySource::File(d.path().join("m.key")),
            "n1",
        )
        .unwrap();
        let arch = k.register_arch(crate::tests::local(Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        }));
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
                        to_dir: d.path().join("out").to_string_lossy().into(),
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
        assert_eq!(k.top().arches[&arch].calls, 2);
    }

    #[test]
    fn stopped_scope_halts_the_scheduler() {
        let d = tempfile::tempdir().unwrap();
        let mut k = RealKernel::open(
            d.path(),
            vk_store::keys::KeySource::File(d.path().join("m.key")),
            "n1",
        )
        .unwrap();
        let arch = k.register_arch(crate::tests::local(Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        }));
        let t = k
            .create_task(
                &machine(1),
                "x",
                "note",
                Label::bottom(),
                vec![StepKind::Plan { arch_id: arch }],
            )
            .unwrap();
        let human = Ctx {
            principal: Principal::Human {
                device_id: "phone-1".into(),
            },
            ..machine(2)
        };
        k.stop(&human, "node").unwrap();
        assert!(matches!(
            k.run_task_step(&machine(3), &t.id),
            Err(vk_contracts::syscalls::KernelError::Stopped(_))
        ));
    }

    #[test]
    fn namespace_lists_and_resolves() {
        let d = tempfile::tempdir().unwrap();
        let mut k = RealKernel::open(
            d.path(),
            vk_store::keys::KeySource::File(d.path().join("m.key")),
            "n1",
        )
        .unwrap();
        let arch = k.register_arch(crate::tests::local(Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        }));
        assert!(matches!(
            crate::ns::resolve(&k, "/").unwrap(),
            crate::ns::Entry::Dir { .. }
        ));
        assert!(matches!(
            crate::ns::resolve(&k, &format!("/arches/{arch}")).unwrap(),
            crate::ns::Entry::Arch(_)
        ));
        assert!(crate::ns::resolve(&k, "/nope").is_err());
    }
}
