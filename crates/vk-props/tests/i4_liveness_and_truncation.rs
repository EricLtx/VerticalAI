use proptest::prelude::*;
use vk_contracts::arch::*;
use vk_contracts::labels::*;
use vk_contracts::principal::Principal;
use vk_contracts::syscalls::*;
use vk_contracts::testing::KernelTestHooks;

fn local() -> ArchManifest {
    ArchManifest {
        name: "local".into(),
        capabilities: [Capability::Generate].into(),
        locality: Locality::Local,
        jurisdiction: "FR".into(),
        retention_days: None,
        cost_per_1k_tokens_eur: 0.0,
        latency_ms_p50: 1,
        context_ceiling: 64,
        determinism: Determinism::SeededDeterministic,
        identity: ArchIdentity {
            weights_sha256: "sha256:l".into(),
            engine: "llama".into(),
            engine_version: "1".into(),
            backend: "cpu".into(),
            quant: "q4".into(),
            kv_cache: "f16".into(),
            threads: 1,
            batch: 1,
            sampling: Default::default(),
            seed: Some(1),
        },
        clearance: Clearance {
            max_scope: Scope::Holdout,
            third_party_allowed: true,
        },
        governed: true,
    }
}

fn machine(now: u64, max_scope: Scope) -> Ctx {
    Ctx {
        principal: Principal::Machine {
            node_id: "n1".into(),
            lease_id: "l".into(),
        },
        clearance: Clearance {
            max_scope,
            third_party_allowed: true,
        },
        partition: "p".into(),
        now_ms: now,
    }
}

fn liveness_property<K: KernelTestHooks>(
    k: &mut K,
    expiry: u64,
    ticks: &[u64],
) -> Result<(), TestCaseError> {
    k.renew_liveness("acme", "phone-1", expiry);
    for &now in ticks {
        let ran = k
            .run_automation(&machine(now, Scope::Personal), "acme", "m")
            .is_ok();
        prop_assert_eq!(
            ran,
            now < expiry,
            "ran={} at now={} expiry={}",
            ran,
            now,
            expiry
        );
    }
    Ok(())
}

/// I4': a projected outcome always has a matching `infer.projected` ledger
/// event and never exceeds the arch's budget. On the real kernel a budget too
/// small to hold even the ROLE/GOAL lines is not a projection at all — `infer`
/// legitimately refuses with `I4Prime` rather than send a mutilated prompt. In
/// that case the property becomes: nothing about the call was logged.
fn truncation_property<K: KernelTestHooks>(
    k: &mut K,
    goal_len: usize,
    budget: u32,
) -> Result<(), TestCaseError> {
    let id = k.register_arch(local());
    k.set_context_budget(&id, budget);
    let ctx = machine(1, Scope::Holdout);
    let r = k
        .submit_task(&ctx, &"g".repeat(goal_len), Label::bottom())
        .unwrap();
    match k.infer(&ctx, &id, Capability::Generate, &r) {
        Err(KernelError::I4Prime(_)) => {
            let logged_infer = k.ledger().events().iter().any(|e| e.kind == "infer");
            let logged_projected = k
                .ledger()
                .events()
                .iter()
                .any(|e| e.kind == "infer.projected");
            prop_assert!(!logged_infer, "I4' refusal must not log an infer event");
            prop_assert!(
                !logged_projected,
                "I4' refusal must not log an infer.projected event"
            );
            prop_assert!(
                k.infer_log().is_empty(),
                "I4' refusal must not append to infer_log"
            );
            Ok(())
        }
        Err(e) => Err(TestCaseError::fail(format!(
            "infer failed with an error other than I4': {e:?}"
        ))),
        Ok(out) => {
            let logged = k
                .ledger()
                .events()
                .iter()
                .any(|e| e.kind == "infer.projected");
            prop_assert_eq!(
                out.projected,
                logged,
                "projection without a ledger entry (or vice versa)"
            );
            prop_assert!(out.tokens_in <= budget);
            Ok(())
        }
    }
}

fn real(dir: &std::path::Path) -> vk_kernel::RealKernel {
    vk_kernel::RealKernel::open(
        dir,
        vk_store::keys::KeySource::File(dir.join("master.key")),
        "n1",
    )
    .unwrap()
}

proptest! {
    #[test]
    fn stub_liveness(expiry in 1u64..1000, ticks in prop::collection::vec(1u64..2000, 1..30)) {
        liveness_property(&mut vk_stub::StubKernel::new("n1"), expiry, &ticks)?;
    }

    #[test]
    fn stub_truncation(goal_len in 0usize..2000, budget in 1u32..64) {
        truncation_property(&mut vk_stub::StubKernel::new("n1"), goal_len, budget)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..Default::default() })]

    #[test]
    fn real_liveness(expiry in 1u64..1000, ticks in prop::collection::vec(1u64..2000, 1..30)) {
        let d = tempfile::tempdir().unwrap();
        liveness_property(&mut real(d.path()), expiry, &ticks)?;
    }

    #[test]
    fn real_truncation(goal_len in 0usize..2000, budget in 1u32..64) {
        let d = tempfile::tempdir().unwrap();
        truncation_property(&mut real(d.path()), goal_len, budget)?;
    }
}
