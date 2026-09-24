//! The workspace projection is an I2 gate (spec §4.2): only what the harness
//! clearance may see is written into its workspace. A register with one
//! Business/own artefact and one Personal artefact materialises the first alone
//! for a Business clearance, and logs exactly that one projection.
//!
//! The kernel is faked here — the projection needs only the `Host` trait, whose
//! every type is a contract — so this test never links `vk-kernel`.
use std::collections::BTreeMap;
use vk_contracts::labels::{DataClass, Label, Origin, Scope};
use vk_contracts::principal::Principal;
use vk_contracts::register::{ArtefactRef, Register, RegisterId};
use vk_contracts::syscalls::{Ctx, KernelError};
use vk_harness::workspace::{harness_clearance, Host, ProjectionRecord, Workspace};

/// A register, its artefacts' labels and bytes, and the projections logged
/// against it — everything `materialise` touches, in memory.
struct FakeHost {
    reg: Register,
    blobs: BTreeMap<String, (Label, Vec<u8>)>,
    projections: Vec<ProjectionRecord>,
}

impl Host for FakeHost {
    fn read_register(&mut self, ctx: &Ctx, reg: &RegisterId) -> Result<Register, KernelError> {
        assert_eq!(reg, &self.reg.id);
        if !self.reg.label.flows_to(&ctx.clearance) {
            return Err(KernelError::I2("register exceeds harness clearance".into()));
        }
        Ok(self.reg.clone())
    }
    fn read_artefact(&self, ctx: &Ctx, hash: &str) -> Result<Vec<u8>, KernelError> {
        let (label, bytes) = self
            .blobs
            .get(hash)
            .ok_or_else(|| KernelError::NotFound(hash.into()))?;
        if !label.flows_to(&ctx.clearance) {
            return Err(KernelError::I2(format!(
                "artefact {hash} exceeds clearance"
            )));
        }
        Ok(bytes.clone())
    }
    fn artefact_label(&self, hash: &str) -> Option<Label> {
        self.blobs.get(hash).map(|(l, _)| l.clone())
    }
    fn log_projection(&mut self, _now_ms: u64, rec: &ProjectionRecord) -> Result<(), KernelError> {
        self.projections.push(rec.clone());
        Ok(())
    }
}

fn label(scope: Scope) -> Label {
    Label {
        scope,
        data_class: DataClass::Own,
        origins: [Origin::OwnerAuthored].into(),
    }
}

fn harness_ctx() -> Ctx {
    Ctx {
        principal: Principal::Machine {
            node_id: "n1".into(),
            lease_id: "lease-1".into(),
        },
        clearance: harness_clearance(),
        partition: "local".into(),
        now_ms: 1,
    }
}

#[test]
fn materialises_only_the_evidence_that_flows_to_the_harness_clearance() {
    // A register at the bottom label (so the harness may read it), holding a
    // decision for the plan and two evidence artefacts: one Business/own that a
    // Business clearance may see, one Personal that it may not.
    let reg = Register {
        id: RegisterId("reg-1".into()),
        task_id: "task-1".into(),
        label: Label::bottom(),
        goal: "Draft a quote for Acme".into(),
        constraints: vec!["be brief".into()],
        evidence: vec![],
        decisions: vec!["plan: gather the figures, then draft".into()],
        open_questions: vec![],
        artefacts: vec![
            ArtefactRef {
                hash: "sha256:business".into(),
                kind: "figures".into(),
            },
            ArtefactRef {
                hash: "sha256:personal".into(),
                kind: "medical".into(),
            },
        ],
    };
    let mut blobs = BTreeMap::new();
    blobs.insert(
        "sha256:business".to_string(),
        (label(Scope::Business), b"Q3 revenue: 1.2M".to_vec()),
    );
    blobs.insert(
        "sha256:personal".to_string(),
        (label(Scope::Personal), b"a private note".to_vec()),
    );
    let mut host = FakeHost {
        reg,
        blobs,
        projections: vec![],
    };

    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().join("harness").join("task-1");
    let out = Workspace::materialise(
        &mut host,
        &harness_ctx(),
        &RegisterId("reg-1".into()),
        &ws,
        7,
    )
    .expect("materialise");
    assert_eq!(out, ws);

    // The goal and the plan are there.
    let task_md = std::fs::read_to_string(ws.join("TASK.md")).expect("TASK.md");
    assert!(task_md.contains("Draft a quote for Acme"), "{task_md}");
    let plan_md = std::fs::read_to_string(ws.join("PLAN.md")).expect("PLAN.md");
    assert!(plan_md.contains("gather the figures"), "{plan_md}");

    // OUT/ is there for the harness to write into.
    assert!(ws.join("OUT").is_dir(), "OUT/ must exist");

    // BRIEF/ holds exactly the Business artefact — the Personal one was refused.
    let brief: Vec<_> = std::fs::read_dir(ws.join("BRIEF"))
        .expect("BRIEF/")
        .map(|e| e.unwrap())
        .collect();
    assert_eq!(
        brief.len(),
        1,
        "only the artefact that flows is materialised"
    );
    let contents = std::fs::read(brief[0].path()).unwrap();
    assert_eq!(
        contents, b"Q3 revenue: 1.2M",
        "the Business artefact, verbatim"
    );

    // Nothing anywhere in the workspace holds the Personal artefact's bytes.
    for entry in walk(&ws) {
        let bytes = std::fs::read(&entry).unwrap_or_default();
        assert!(
            !bytes
                .windows(b"a private note".len())
                .any(|w| w == b"a private note"),
            "the refused artefact leaked into {}",
            entry.display()
        );
    }

    // And exactly one projection was logged: the one that was admitted.
    assert_eq!(host.projections.len(), 1, "one projection logged");
    assert_eq!(host.projections[0].artefact_hash, "sha256:business");
    assert_eq!(host.projections[0].scope, "business");
}

/// Every file under `root`, recursively.
fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = vec![];
    let Ok(entries) = std::fs::read_dir(root) else {
        return files;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            files.extend(walk(&p));
        } else {
            files.push(p);
        }
    }
    files
}
