//! The `StepKind::Harness` scheduler, end to end against a stand-in `claude`
//! (SP1b Task 4): lease and materialise (phase one), launch a confined process
//! that writes `OUT/proposal.md` (phase two), attach it, record the egress and
//! settle (phase three). No daemon and no MCP round-trip — the stand-in just
//! writes its output and exits — so this pins the kernel side alone.
use std::path::{Path, PathBuf};
use std::time::Duration;
use vk_contracts::labels::{Clearance, Label, Scope};
use vk_contracts::principal::Principal;
use vk_contracts::syscalls::{Ctx, Kernel};
use vk_harness::confine::for_this_platform;
use vk_harness::launch::{launch_claude_code, HarnessConfig};
use vk_kernel::tasks::{HarnessConnectionsRecord, StepKind, TaskStatus};
use vk_kernel::RealKernel;

fn open(dir: &Path) -> RealKernel {
    RealKernel::open(
        dir,
        vk_store::keys::KeySource::File(dir.join("m.key")),
        "n1",
    )
    .unwrap()
}

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
        partition: "local".into(),
        now_ms: now,
    }
}

/// A stand-in `claude`: it ignores its arguments, writes a proposal into the
/// workspace's `OUT/` (its working directory is the workspace), prints a minimal
/// result object and exits 0. Enough to drive the whole harness step without a
/// subscription, a network or MCP.
fn write_standin(dir: &Path) -> PathBuf {
    let bin = dir.join(if cfg!(windows) {
        "stand-in-claude.cmd"
    } else {
        "stand-in-claude.sh"
    });
    let script = if cfg!(windows) {
        "@echo off\r\n\
         >OUT\\proposal.md echo # Proposal from the harness\r\n\
         echo {\"type\":\"result\",\"is_error\":false,\"result\":\"wrote OUT/proposal.md\"}\r\n\
         exit /b 0\r\n"
    } else {
        "#!/bin/sh\n\
         printf '# Proposal from the harness\\n' > OUT/proposal.md\n\
         printf '{\"type\":\"result\",\"is_error\":false,\"result\":\"wrote OUT/proposal.md\"}\\n'\n\
         exit 0\n"
    };
    std::fs::write(&bin, script).expect("write stand-in");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).expect("chmod +x");
    }
    bin
}

fn harness_connections_events(k: &RealKernel) -> usize {
    k.ledger()
        .events()
        .iter()
        .filter(|e| e.kind == "harness.connections")
        .count()
}

#[test]
fn a_harness_step_leases_materialises_launches_attaches_and_settles() {
    let d = tempfile::tempdir().unwrap();
    let mut k = open(d.path());
    let bin = write_standin(d.path());

    // A task whose one step is a harness step.
    let t = k
        .create_task(
            &machine(1),
            "Draft a proposal for Acme",
            "proposal",
            Label::bottom(),
            vec![StepKind::Harness {
                name: "claude-code".into(),
            }],
        )
        .unwrap();

    // The generic scheduler refuses a harness step, non-destructively — it is
    // run by the harness path, not `task step`.
    let refused = k.run_task_step(&machine(2), &t.id).unwrap_err();
    assert!(
        refused.to_string().contains("harness run"),
        "a harness step points the operator at `vk harness run`: {refused}"
    );
    assert!(
        matches!(
            k.task(&machine(0), &t.id).unwrap().status,
            TaskStatus::Queued
        ),
        "the refusal must not have failed the task"
    );

    // Phase one: lease and materialise.
    let launch = k.harness_launch(&machine(3), &t.id).unwrap();
    assert!(launch.workspace.join("TASK.md").exists(), "TASK.md written");
    assert!(launch.workspace.join("OUT").is_dir(), "OUT/ created");
    assert!(
        !launch.workspace.join(".mcp.json").exists(),
        "the .mcp.json is written by the launch, not the materialise"
    );

    // Phase two: launch the stand-in under the governor.
    let cfg = HarnessConfig {
        binary: bin,
        workspace: launch.workspace.clone(),
        lease_token: launch.lease_id.clone(),
        endpoint: "unused-in-this-test".into(),
        mcp_server: PathBuf::from("vk-mcp"),
        prompt: launch.prompt.clone(),
        model: None,
        timeout: Duration::from_secs(30),
    };
    let governor = for_this_platform(2 * 1024 * 1024 * 1024, None).unwrap();
    let run = launch_claude_code(&cfg, governor, &|| false).expect("launch");
    assert!(
        run.exit_reason.is_success(),
        "the stand-in exits cleanly: {:?}",
        run.exit_reason
    );
    assert_eq!(
        run.governed,
        cfg!(windows),
        "contained on Windows, ungoverned elsewhere (Ruling 18)"
    );
    // The launch wrote the .mcp.json carrying the lease token.
    let mcp = std::fs::read_to_string(launch.workspace.join(".mcp.json")).unwrap();
    assert!(
        mcp.contains(&launch.lease_id),
        "the token rides the .mcp.json"
    );
    assert!(mcp.contains("vk-mcp"), "the vk server is the mcp command");
    // The connection list is deduplicated and sorted by construction.
    let mut sorted = run.connections.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        run.connections, sorted,
        "connections are deduped and sorted"
    );

    // Phase three: settle.
    let before = harness_connections_events(&k);
    let settled = k
        .harness_settle(&machine(4), &t.id, &launch, &run, false)
        .unwrap();
    assert!(matches!(settled.status, TaskStatus::Done), "{settled:?}");

    // Exactly one harness.connections event for the run.
    assert_eq!(
        harness_connections_events(&k) - before,
        1,
        "one harness.connections event per run"
    );

    // The register gained the proposal, of the task's artefact type, holding what
    // the stand-in wrote.
    let reg = k.read_register(&machine(5), &settled.register).unwrap();
    assert_eq!(reg.artefacts.len(), 1, "the harness output is attached");
    assert_eq!(reg.artefacts[0].kind, "proposal");
    let bytes = k
        .read_artefact(&machine(5), &reg.artefacts[0].hash)
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&bytes).trim(),
        "# Proposal from the harness"
    );

    // The workspace was removed after collection (no --keep).
    assert!(
        !launch.workspace.exists(),
        "the workspace is cleaned up unless --keep"
    );

    // The lease token no longer resolves: the run is over.
    assert!(
        k.harness_session(&launch.lease_id, 6).is_err(),
        "the token is spent once the run settles"
    );
    assert!(k.ledger().verify_chain(), "the record still verifies");
}

/// A run that opened no connection — or was too short to sample — still logs its
/// `harness.connections` event, with an empty list (founder decision 2026-09-24).
#[test]
fn a_run_with_no_samples_still_logs_an_empty_connections_event() {
    let d = tempfile::tempdir().unwrap();
    let mut k = open(d.path());
    let before = harness_connections_events(&k);
    k.record_harness_connection(
        1,
        &HarnessConnectionsRecord {
            task_id: "task-x".into(),
            step_index: 0,
            lease_id: "lease-x".into(),
            harness: "claude-code".into(),
            connections: vec![],
            samples: 0,
            sample_every_ms: 500,
            governed: true,
            exit: "code 0".into(),
            duration_ms: 3,
        },
    )
    .unwrap();
    assert_eq!(
        harness_connections_events(&k) - before,
        1,
        "the event is logged even with no samples and an empty list"
    );
    assert!(k.ledger().verify_chain());
}
