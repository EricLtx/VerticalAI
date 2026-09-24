//! The governor against real children: a `cmd /c ping` that outlives its
//! governor by nothing, a PowerShell that cannot allocate past the cap, an
//! assignment refused for a process that is already gone, a `governed()`
//! that answers yes only for a containment the OS read back — and, on every
//! platform, the no-op governor, which contains nothing and says so.
//!
//! Every child is spawned behind [`Reaper`], so a failed assertion kills what
//! it spawned, and no wait on a child is open-ended: [`wait_exit`] gives up at
//! its deadline and the reaper does the rest.
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use vk_harness::confine::{for_this_platform, Governor, NoopGovernor};

/// The longest any test waits on a child. Past it the assertion fails and the
/// reaper kills the child; nothing is left running on the machine.
const DEADLINE: Duration = Duration::from_secs(10);

/// A child that is killed and reaped when the test is done with it, whether
/// the test passed or panicked.
struct Reaper(Child);

impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Polls the child until it exits or `max` has passed.
fn wait_exit(child: &mut Child, max: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        if start.elapsed() >= max {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A child that exits with status 0 straight away, on any platform.
fn quick_child() -> Child {
    let mut cmd = if cfg!(windows) {
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "exit 0"]);
        cmd
    } else {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "exit 0"]);
        cmd
    };
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn a quick child")
}

/// A child that would live about thirty seconds on its own, on any platform.
fn long_lived_child() -> Child {
    let mut cmd = if cfg!(windows) {
        let mut cmd = Command::new("ping");
        cmd.args(["-n", "30", "127.0.0.1"]);
        cmd
    } else {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        cmd
    };
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn a long-lived child")
}

#[test]
fn the_noop_governor_contains_nothing_and_says_so() {
    let governor = NoopGovernor::new();
    let mut child = Reaper(quick_child());
    governor
        .contain(&child.0)
        .expect("the no-op governor refuses nothing");
    assert!(
        !governor.governed(),
        "a governor that enforces nothing must not claim to govern"
    );
    let status = wait_exit(&mut child.0, DEADLINE).expect("the quick child exits");
    assert!(status.success(), "the child ran unhindered: {status}");
}

#[test]
fn the_platform_governor_claims_only_what_it_enforces() {
    let governor = for_this_platform(256 << 20, None).expect("every platform has a governor");
    assert!(
        !governor.governed(),
        "nothing is governed before a containment, on any platform"
    );
    let child = Reaper(long_lived_child());
    governor
        .contain(&child.0)
        .expect("a running child is contained, or the no-op governor refuses nothing");
    assert_eq!(
        governor.governed(),
        cfg!(windows),
        "only the Job Object governs in SP1b, and only once the OS read the containment back"
    );
}

#[cfg(windows)]
mod job_object {
    use super::*;
    use vk_harness::confine::JobGovernor;

    /// A process tree — `cmd` and the `ping` it runs — that would live about
    /// thirty seconds on its own.
    fn ping_tree() -> Child {
        Command::new("cmd")
            .args(["/c", "ping", "-n", "30", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cmd /c ping")
    }

    /// A PowerShell that allocates 256 MiB in one array and exits.
    fn allocate_256_mib() -> Child {
        Command::new("powershell")
            .args(["-NoProfile", "-c", "$a = New-Object byte[] 268435456"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn powershell")
    }

    #[test]
    fn dropping_the_governor_kills_the_child_within_two_seconds() {
        let governor = JobGovernor::new(512 << 20, None).expect("a job object with a 512 MiB cap");
        assert!(
            !governor.governed(),
            "nothing is governed before a containment"
        );
        let mut child = Reaper(ping_tree());
        governor
            .contain(&child.0)
            .expect("a running child is contained");
        assert!(
            governor.governed(),
            "a containment the OS read back is governed"
        );
        assert!(
            child.0.try_wait().expect("try_wait").is_none(),
            "the child lives while its governor does"
        );
        drop(governor);
        assert!(
            wait_exit(&mut child.0, Duration::from_secs(2)).is_some(),
            "the child was still running 2 s after its governor was dropped"
        );
    }

    #[test]
    fn containing_a_child_twice_is_one_containment() {
        let governor = JobGovernor::new(512 << 20, None).expect("a job object");
        let mut child = Reaper(ping_tree());
        governor.contain(&child.0).expect("the first call contains");
        governor
            .contain(&child.0)
            .expect("the second call finds the child contained and refuses nothing");
        drop(governor);
        assert!(
            wait_exit(&mut child.0, Duration::from_secs(2)).is_some(),
            "the child was still running 2 s after its governor was dropped"
        );
    }

    /// Ruling 18: `governed()` is the OS's read-back, remembered — false
    /// before any containment, true after one the OS confirmed, false for a
    /// governor whose containment failed, and false again for a governor
    /// that was refused a process after containing another.
    #[test]
    fn governed_is_true_only_after_a_verified_containment() {
        let governor = JobGovernor::new(512 << 20, None).expect("a job object");
        assert!(
            !governor.governed(),
            "a fresh governor has verified nothing"
        );
        let child = Reaper(ping_tree());
        governor
            .contain(&child.0)
            .expect("a running child is contained");
        assert!(
            governor.governed(),
            "a containment the OS read back is governed"
        );

        let mut gone = quick_child();
        gone.wait().expect("wait");
        let refused = JobGovernor::new(512 << 20, None).expect("a job object");
        refused
            .contain(&gone)
            .expect_err("a process that is gone cannot be contained");
        assert!(
            !refused.governed(),
            "a governor whose containment failed governs nothing"
        );

        governor
            .contain(&gone)
            .expect_err("a process that is gone cannot be contained");
        assert!(
            !governor.governed(),
            "a governor refused one process cannot claim its tree is whole"
        );
    }

    #[test]
    fn a_64_mib_cap_refuses_a_256_mib_allocation() {
        let governor = JobGovernor::new(64 << 20, None).expect("a job object with a 64 MiB cap");
        let mut capped = Reaper(allocate_256_mib());
        governor
            .contain(&capped.0)
            .expect("a running child is contained");
        let status = wait_exit(&mut capped.0, DEADLINE)
            .expect("the capped PowerShell did not exit within the deadline");
        assert!(
            !status.success(),
            "a 256 MiB allocation went through under a 64 MiB cap: {status}"
        );

        let mut free = Reaper(allocate_256_mib());
        let status = wait_exit(&mut free.0, DEADLINE)
            .expect("the uncapped PowerShell did not exit within the deadline");
        assert!(
            status.success(),
            "the same allocation failed without a cap: {status}"
        );
    }

    #[test]
    fn containing_an_exited_child_is_an_error_not_a_panic() {
        let governor = JobGovernor::new(64 << 20, None).expect("a job object");
        let mut child = Command::new("cmd")
            .args(["/c", "exit 3"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cmd /c exit 3");
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(3));
        let err = governor
            .contain(&child)
            .expect_err("a process that is gone cannot be contained");
        let text = format!("{err:#}");
        assert!(
            text.contains("had already exited with code 3"),
            "the error names the exit code it found: {text}"
        );
        assert!(
            text.contains("0x80070005"),
            "the OS refusal, ERROR_ACCESS_DENIED, stays in the chain: {text}"
        );
        assert!(
            !governor.governed(),
            "a refused containment governs nothing"
        );
    }

    #[test]
    fn caps_outside_their_range_are_refused_before_any_job_exists() {
        assert!(
            JobGovernor::new(0, None).is_err(),
            "a cap of 0 bytes is not a cap"
        );
        assert!(
            JobGovernor::new(64 << 20, Some(0)).is_err(),
            "0 % of the CPU is not a rate"
        );
        assert!(
            JobGovernor::new(64 << 20, Some(101)).is_err(),
            "101 % of the CPU is not a rate"
        );
        let governor =
            JobGovernor::new(64 << 20, Some(25)).expect("a hard cap of 25 % is accepted");
        assert_eq!(governor.max_memory_bytes(), 64 << 20);
        assert_eq!(governor.cpu_rate_percent(), Some(25));
    }
}
