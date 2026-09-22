use proptest::prelude::*;
use vk_contracts::arch::*;
use vk_contracts::labels::*;
use vk_contracts::principal::Principal;
use vk_contracts::syscalls::*;
use vk_stub::StubKernel;

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

proptest! {
    #[test]
    fn automation_never_runs_after_liveness_expiry(expiry in 1u64..1000, ticks in prop::collection::vec(1u64..2000, 1..30)) {
        let mut k = StubKernel::new("n1");
        k.renew_liveness("acme", "phone-1", expiry);
        for now in ticks {
            let ran = k.run_automation(&machine(now, Scope::Personal), "acme", "m").is_ok();
            prop_assert_eq!(ran, now < expiry, "ran={} at now={} expiry={}", ran, now, expiry);
        }
    }

    #[test]
    fn over_budget_inference_is_always_a_logged_projection(goal_len in 0usize..2000, budget in 1u32..64) {
        let mut k = StubKernel::new("n1");
        let id = k.register_arch(local());
        k.set_context_budget(&id, budget);
        let ctx = machine(1, Scope::Holdout);
        let r = k.submit_task(&ctx, &"g".repeat(goal_len), Label::bottom()).unwrap();
        let out = k.infer(&ctx, &id, Capability::Generate, &r).unwrap();
        let logged = k.ledger().events().iter().any(|e| e.kind == "infer.projected");
        prop_assert_eq!(out.projected, logged, "projection without a ledger entry (or vice versa)");
        prop_assert!(out.tokens_in <= budget);
    }
}
