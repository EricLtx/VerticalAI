//! The `StepKind::Harness` scheduler, end to end against a stand-in `claude`
//! (SP1b Task 4): lease and materialise (phase one), launch a confined process
//! that writes `OUT/proposal.md` (phase two), collect it, record the egress and
//! settle (phase three) — and the rules the review made load-bearing: the token
//! is a secret that is never the lease id and stops resolving the moment a run
//! settles, however it settled; one run per task at a time; nothing attached
//! twice; only the declared output collected, capped; a clean run with no
//! artefact fails; a bad artefact type is refused at creation; a restart sweeps
//! every harness lease and workspace.
use std::path::{Path, PathBuf};
use std::time::Duration;
use vk_contracts::labels::{Clearance, Label, Scope};
use vk_contracts::locks::Lease;
use vk_contracts::principal::Principal;
use vk_contracts::syscalls::{Ctx, Kernel, KernelError};
use vk_harness::confine::for_this_platform;
use vk_harness::launch::{launch_claude_code, ExitReason, HarnessConfig, HarnessRun};
use vk_kernel::tasks::{HarnessConnectionsRecord, HarnessLaunch, StepKind, StepStatus, TaskStatus};
use vk_kernel::RealKernel;

/// A kernel over `dir`, retrying the store's single-writer lock for a moment.
///
/// The retry is about *this test binary*, not about the lock. On Unix the
/// lock is an `flock` on an open file description, and a description is
/// inherited by every `fork` — including the one `Command::spawn` makes,
/// which holds a copy of every open descriptor until the child `exec`s. One
/// test here launches a stand-in process; the tests run on threads of one
/// process; so a store this test closed can stay locked for as long as some
/// other test's child sits between `fork` and `exec`. Under load on WSL that
/// is milliseconds, and it was enough to fail this file about one run in
/// three (present since before SP1b Task 8; reproduced at 8d0b358).
///
/// Nothing about the daemon's own rule is relaxed: `StoreLock::acquire` still
/// refuses at once, and `a_second_vkd_over_a_served_state_dir_is_refused_and_
/// writes_nothing` still proves it. This is the test waiting out a race the
/// test suite creates for itself.
fn open(dir: &Path) -> RealKernel {
    let source = || vk_store::keys::KeySource::File(dir.join("m.key"));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match RealKernel::open(dir, source(), "n1") {
            Ok(k) => return k,
            Err(e) if std::time::Instant::now() < deadline => {
                assert!(
                    e.to_string().contains("already open"),
                    "opening {}: {e:#}",
                    dir.display()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("opening {}: {e:#}", dir.display()),
        }
    }
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
         echo {\"type\":\"result\",\"is_error\":false,\"num_turns\":2,\"total_cost_usd\":0.01,\"result\":\"wrote OUT/proposal.md\",\"permission_denials\":[]}\r\n\
         exit /b 0\r\n"
    } else {
        "#!/bin/sh\n\
         printf '# Proposal from the harness\\n' > OUT/proposal.md\n\
         printf '{\"type\":\"result\",\"is_error\":false,\"num_turns\":2,\"total_cost_usd\":0.01,\"result\":\"wrote OUT/proposal.md\",\"permission_denials\":[]}\\n'\n\
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

/// A task with one harness step (and, if asked, an approval after it).
fn harness_task(k: &mut RealKernel, with_approve: bool) -> vk_kernel::tasks::Task {
    let mut steps = vec![StepKind::Harness {
        name: "claude-code".into(),
    }];
    if with_approve {
        steps.push(StepKind::Approve);
    }
    k.create_task(
        &machine(1),
        "Draft a proposal for Acme",
        "proposal",
        Label::bottom(),
        steps,
    )
    .unwrap()
}

/// A run record as if the process had exited cleanly (or not) without the
/// stand-in: what a settle is handed.
fn run_ending(reason: ExitReason) -> HarnessRun {
    HarnessRun {
        exit_code: match &reason {
            ExitReason::Exited(c) => Some(*c),
            _ => None,
        },
        exit_reason: reason,
        stdout_json: String::new(),
        outcome: None,
        connections: vec![],
        samples: 0,
        duration_ms: 1,
        governed: false,
    }
}

fn config_for(d: &Path, bin: PathBuf, launch: &HarnessLaunch) -> HarnessConfig {
    HarnessConfig {
        binary: bin,
        workspace: launch.workspace.clone(),
        config_dir: launch.config_dir.clone(),
        state_dir: d.to_path_buf(),
        lease_token: launch.token.clone(),
        endpoint: "unused-in-this-test".into(),
        mcp_server: PathBuf::from("vk-mcp"),
        prompt: launch.prompt.clone(),
        model: None,
        timeout: Duration::from_secs(30),
        system_suffix: None,
    }
}

#[test]
fn a_harness_step_leases_materialises_launches_collects_and_settles() {
    let d = tempfile::tempdir().unwrap();
    let mut k = open(d.path());
    let bin = write_standin(d.path());
    let t = harness_task(&mut k, false);

    // The generic scheduler refuses a harness step, non-destructively — it is
    // run by the harness path, not `task step`.
    let refused = k.run_task_step(&machine(2), &t.id).unwrap_err();
    assert!(
        refused.to_string().contains("harness run"),
        "a harness step points the operator at `vk harness run`: {refused}"
    );
    assert!(matches!(
        k.task(&machine(0), &t.id).unwrap().status,
        TaskStatus::Queued
    ));

    // Phase one: lease, token, workspace.
    let launch = k
        .harness_launch(&machine(3), &t.id, "claude-code", 30_000)
        .unwrap();
    assert!(launch.workspace.join("TASK.md").exists(), "TASK.md written");
    assert!(launch.workspace.join("OUT").is_dir(), "OUT/ created");
    assert!(
        !launch.workspace.join(".mcp.json").exists(),
        "no MCP config in the workspace: it lives outside it"
    );
    assert!(
        launch.config_dir.starts_with(d.path().join("harness")),
        "the config dir is beside the workspace, not in it: {}",
        launch.config_dir.display()
    );
    assert!(!launch.config_dir.starts_with(&launch.workspace));
    // The token is a secret of its own: random, base64url, never the lease id.
    assert_ne!(launch.token, launch.lease_id);
    assert_eq!(launch.token.len(), 43, "32 bytes base64url without padding");
    assert!(launch.lease_id.starts_with("lease-"));
    assert!(launch
        .token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    // It resolves to the harness principal, carrying the lease id and the
    // harness clearance.
    let session = k.harness_session(&launch.token, 4).unwrap();
    assert_eq!(
        session.ctx.principal,
        Principal::Machine {
            node_id: "n1".into(),
            lease_id: launch.lease_id.clone(),
        }
    );
    assert_eq!(session.ctx.clearance.max_scope, Scope::Business);
    assert!(!session.ctx.clearance.third_party_allowed);
    assert!(
        k.harness_session(&launch.lease_id, 4).is_err(),
        "the lease id is not a token"
    );
    assert!(k.harness_running(&t.id));

    // Phase two: launch the stand-in under the governor.
    let cfg = config_for(d.path(), bin, &launch);
    let governor = for_this_platform(2 * 1024 * 1024 * 1024, None).unwrap();
    let run = launch_claude_code(&cfg, governor, &|| false).expect("launch");
    assert!(run.exit_reason.is_success(), "{:?}", run.exit_reason);
    assert_eq!(
        run.governed,
        cfg!(windows),
        "contained on Windows (Ruling 18)"
    );
    let outcome = run
        .outcome
        .as_ref()
        .expect("the stand-in printed a result object");
    assert_eq!(outcome.num_turns, 2);
    assert!(outcome.permission_denials.is_empty());
    // The launch wrote the token into mcp.json in the config dir, and the fence
    // into settings.json beside it — nothing into the workspace.
    let mcp = std::fs::read_to_string(launch.config_dir.join("mcp.json")).unwrap();
    assert!(mcp.contains(&launch.token));
    let fence = std::fs::read_to_string(launch.config_dir.join("settings.json")).unwrap();
    assert!(
        fence.contains("Read(./**)") && fence.contains("\"Bash\""),
        "{fence}"
    );
    assert!(!launch.workspace.join("settings.json").exists());
    // The launch line never carries the token.
    assert!(!vk_harness::launch::launch_line(&cfg)
        .iter()
        .any(|a| a.contains(&launch.token)));
    let mut sorted = run.connections.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(run.connections, sorted, "deduped and sorted");

    // Phase three: settle.
    let before = harness_connections_events(&k);
    let settled = k
        .harness_settle(&machine(5), &t.id, &launch, &run, false)
        .unwrap();
    assert!(matches!(settled.status, TaskStatus::Done), "{settled:?}");
    assert_eq!(
        harness_connections_events(&k) - before,
        1,
        "one event per run"
    );

    // The declared output was collected once, as the task's artefact type.
    let reg = k.read_register(&machine(6), &settled.register).unwrap();
    assert_eq!(reg.artefacts.len(), 1);
    assert_eq!(reg.artefacts[0].kind, "proposal");
    let bytes = k
        .read_artefact(&machine(6), &reg.artefacts[0].hash)
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&bytes).trim(),
        "# Proposal from the harness"
    );

    // Everything the run held is gone: the token, the lease, the config dir
    // (it held the token), the workspace (no --keep).
    assert!(
        k.harness_session(&launch.token, 7).is_err(),
        "the token is spent"
    );
    assert!(!k.harness_running(&t.id));
    assert!(
        k.store()
            .db
            .get_json::<Lease>("leases", &launch.lease_id)
            .unwrap()
            .is_none(),
        "the lease row is deleted"
    );
    assert!(!launch.config_dir.exists(), "the config dir is removed");
    assert!(!launch.workspace.exists(), "the workspace is removed");
    // Nothing on the ledger names the token.
    assert!(k.ledger().verify_chain());
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
    assert_eq!(harness_connections_events(&k) - before, 1);
    assert!(k.ledger().verify_chain());
}

/// One run per task at a time (Ruling 21.3): while a run is live a second
/// launch is refused, and a failed settle (Ruling 21.4) still revokes the token,
/// releases the lease and fails the step with the reason.
#[test]
fn a_second_launch_is_refused_while_a_run_is_live_and_a_failed_run_still_revokes() {
    let d = tempfile::tempdir().unwrap();
    let mut k = open(d.path());
    let t = harness_task(&mut k, false);
    let launch = k
        .harness_launch(&machine(2), &t.id, "claude-code", 30_000)
        .unwrap();

    let again = k
        .harness_launch(&machine(3), &t.id, "claude-code", 30_000)
        .unwrap_err();
    assert!(matches!(again, KernelError::Gate(_)), "{again}");
    assert!(
        again.to_string().contains("harness already running"),
        "{again}"
    );
    // The refusal touched nothing: the first run's workspace and token stand.
    assert!(launch.workspace.join("TASK.md").exists());
    assert!(k.harness_session(&launch.token, 3).is_ok());

    // The run times out. Every exit path settles: failed step, token gone,
    // lease gone, config dir gone.
    let before = harness_connections_events(&k);
    let settled = k
        .harness_settle(
            &machine(4),
            &t.id,
            &launch,
            &run_ending(ExitReason::Timeout),
            false,
        )
        .unwrap();
    assert!(matches!(settled.status, TaskStatus::Failed));
    match &settled.steps[0].status {
        StepStatus::Failed(why) => assert!(why.contains("timeout"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        harness_connections_events(&k) - before,
        1,
        "egress is recorded for a killed run too"
    );
    assert!(
        k.harness_session(&launch.token, 5).is_err(),
        "token revoked"
    );
    assert!(k
        .store()
        .db
        .get_json::<Lease>("leases", &launch.lease_id)
        .unwrap()
        .is_none());
    assert!(!launch.config_dir.exists());
    assert!(!k.harness_running(&t.id));
}

/// Ruling 21.5: what the harness attached explicitly over MCP is not attached
/// again by the collection, and it is the approval subject. The mid-run attach
/// is driven through the same kernel path `harness.attach_artefact` uses.
#[test]
fn an_artefact_the_harness_attached_over_mcp_is_not_attached_twice() {
    let d = tempfile::tempdir().unwrap();
    let mut k = open(d.path());
    let t = harness_task(&mut k, true);
    let launch = k
        .harness_launch(&machine(2), &t.id, "claude-code", 30_000)
        .unwrap();

    // The harness writes its proposal and attaches it itself, mid-run.
    std::fs::write(
        launch.workspace.join("OUT").join("proposal.md"),
        b"# The one proposal",
    )
    .unwrap();
    let env = k
        .harness_attach_file(&launch.token, 3, "proposal", "OUT/proposal.md")
        .unwrap();
    // A traversal through the same path is still refused.
    assert!(k
        .harness_attach_file(&launch.token, 3, "proposal", "../m.key")
        .is_err());

    // The run exits cleanly; the same file is still in OUT/. Settle collects
    // nothing on top of it.
    let settled = k
        .harness_settle(
            &machine(4),
            &t.id,
            &launch,
            &run_ending(ExitReason::Exited(0)),
            false,
        )
        .unwrap();
    assert!(matches!(settled.steps[0].status, StepStatus::Done));
    assert!(
        matches!(settled.status, TaskStatus::Running),
        "the approve step is next"
    );
    let reg = k.read_register(&machine(5), &settled.register).unwrap();
    assert_eq!(reg.artefacts.len(), 1, "attached once: {:?}", reg.artefacts);
    assert_eq!(reg.artefacts[0].hash, env.hash);
    // And the approval subject is that artefact.
    let subject = k.approval_subject(&machine(6), &t.id).unwrap();
    assert_eq!(subject, env.hash);
}

/// Ruling 21.6: only `OUT/<artefact_type>.*` is collected — a scratch file is
/// not the task's artefact — and a clean run that left nothing to collect fails.
#[test]
fn only_the_declared_output_is_collected_and_a_run_without_one_fails() {
    let d = tempfile::tempdir().unwrap();
    let mut k = open(d.path());

    // Scratch beside the proposal: one artefact, the proposal.
    let t = harness_task(&mut k, false);
    let launch = k
        .harness_launch(&machine(2), &t.id, "claude-code", 30_000)
        .unwrap();
    let out = launch.workspace.join("OUT");
    std::fs::write(out.join("zz-scratch.txt"), b"scratch").unwrap();
    std::fs::write(out.join("proposal.md"), b"# Proposal").unwrap();
    std::fs::create_dir_all(out.join("sub")).unwrap();
    std::fs::write(out.join("sub").join("proposal.md"), b"nested").unwrap();
    let settled = k
        .harness_settle(
            &machine(3),
            &t.id,
            &launch,
            &run_ending(ExitReason::Exited(0)),
            false,
        )
        .unwrap();
    assert!(matches!(settled.status, TaskStatus::Done));
    let reg = k.read_register(&machine(4), &settled.register).unwrap();
    assert_eq!(reg.artefacts.len(), 1);
    assert_eq!(
        k.read_artefact(&machine(4), &reg.artefacts[0].hash)
            .unwrap(),
        b"# Proposal"
    );

    // Nothing declared: a clean exit is still a failed step.
    let t2 = harness_task(&mut k, false);
    let launch2 = k
        .harness_launch(&machine(5), &t2.id, "claude-code", 30_000)
        .unwrap();
    std::fs::write(launch2.workspace.join("OUT").join("notes.md"), b"not it").unwrap();
    let settled2 = k
        .harness_settle(
            &machine(6),
            &t2.id,
            &launch2,
            &run_ending(ExitReason::Exited(0)),
            false,
        )
        .unwrap();
    assert!(matches!(settled2.status, TaskStatus::Failed));
    match &settled2.steps[0].status {
        StepStatus::Failed(why) => assert!(why.contains("no artefact"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(k.harness_session(&launch2.token, 7).is_err());
}

/// Ruling 21.6: a file past the 2 MiB cap fails the step naming the file,
/// whether the harness tried to attach it mid-run or left it as its output.
#[test]
fn an_oversize_file_fails_the_step_naming_it() {
    let d = tempfile::tempdir().unwrap();
    let mut k = open(d.path());
    let big = vec![b'x'; 2 * 1024 * 1024 + 1];

    // Mid-run: refused at the attach, remembered, and the step fails on it.
    let t = harness_task(&mut k, false);
    let launch = k
        .harness_launch(&machine(2), &t.id, "claude-code", 30_000)
        .unwrap();
    std::fs::write(launch.workspace.join("OUT").join("proposal.md"), &big).unwrap();
    let err = k
        .harness_attach_file(&launch.token, 3, "proposal", "OUT/proposal.md")
        .unwrap_err();
    assert!(err.to_string().contains("OUT/proposal.md"), "{err}");
    let settled = k
        .harness_settle(
            &machine(4),
            &t.id,
            &launch,
            &run_ending(ExitReason::Exited(0)),
            false,
        )
        .unwrap();
    match &settled.steps[0].status {
        StepStatus::Failed(why) => assert!(why.contains("OUT/proposal.md"), "{why}"),
        other => panic!("{other:?}"),
    }

    // As the declared output: not collected, step failed, file named.
    let t2 = harness_task(&mut k, false);
    let launch2 = k
        .harness_launch(&machine(5), &t2.id, "claude-code", 30_000)
        .unwrap();
    std::fs::write(launch2.workspace.join("OUT").join("proposal.md"), &big).unwrap();
    let settled2 = k
        .harness_settle(
            &machine(6),
            &t2.id,
            &launch2,
            &run_ending(ExitReason::Exited(0)),
            false,
        )
        .unwrap();
    match &settled2.steps[0].status {
        StepStatus::Failed(why) => assert!(why.contains("proposal.md"), "{why}"),
        other => panic!("{other:?}"),
    }
    let reg = k.read_register(&machine(7), &settled2.register).unwrap();
    assert!(reg.artefacts.is_empty());
}

/// Ruling 21.4: an artefact type that could never be attached is refused when
/// the task is created, not discovered at settle with a step left `Running`.
#[test]
fn a_task_with_a_bad_artefact_type_is_refused_at_creation() {
    let d = tempfile::tempdir().unwrap();
    let mut k = open(d.path());
    let err = k
        .create_task(
            &machine(1),
            "x",
            "bad kind!",
            Label::bottom(),
            vec![StepKind::Harness {
                name: "claude-code".into(),
            }],
        )
        .unwrap_err();
    assert!(matches!(err, KernelError::Gate(_)), "{err}");
    assert!(k.tasks(&machine(2)).is_empty(), "nothing was created");
}

/// The harness the caller names must be the one the step names.
#[test]
fn a_launch_naming_another_harness_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let mut k = open(d.path());
    let t = harness_task(&mut k, false);
    let err = k
        .harness_launch(&machine(2), &t.id, "other-harness", 30_000)
        .unwrap_err();
    assert!(err.to_string().contains("claude-code"), "{err}");
    assert!(!k.harness_running(&t.id));
}

/// Ruling 21.4 at boot: no harness survives a restart, so every `harness:*`
/// lease row and everything under `<state_dir>/harness/` is swept.
#[test]
fn boot_sweeps_harness_leases_and_workspaces_left_by_a_previous_run() {
    let d = tempfile::tempdir().unwrap();
    let lease_id = {
        let mut k = open(d.path());
        let t = harness_task(&mut k, false);
        let launch = k
            .harness_launch(&machine(2), &t.id, "claude-code", 30_000)
            .unwrap();
        // The daemon dies here: the workspace, the config and the lease row
        // are left on disk exactly as a crash would leave them.
        std::fs::create_dir_all(&launch.config_dir).unwrap();
        std::fs::write(launch.config_dir.join("mcp.json"), b"{}").unwrap();
        assert!(k
            .store()
            .db
            .get_json::<Lease>("leases", &launch.lease_id)
            .unwrap()
            .is_some());
        launch.lease_id
    };
    assert!(d.path().join("harness").exists());

    let mut k = open(d.path());
    k.boot().unwrap();
    assert!(
        k.store()
            .db
            .get_json::<Lease>("leases", &lease_id)
            .unwrap()
            .is_none(),
        "the harness lease is swept"
    );
    assert!(
        !d.path().join("harness").exists(),
        "the harness directory is swept"
    );
    assert!(k.ledger().verify_chain());
}
