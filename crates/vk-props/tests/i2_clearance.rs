use proptest::prelude::*;
use vk_contracts::arch::*;
use vk_contracts::labels::*;
use vk_contracts::principal::Principal;
use vk_contracts::syscalls::*;
use vk_contracts::testing::KernelTestHooks;

fn arch(max_scope: Scope, third_party: bool) -> ArchManifest {
    ArchManifest {
        name: format!("a-{max_scope:?}-{third_party}"),
        capabilities: [Capability::Generate].into(),
        locality: Locality::Cloud,
        jurisdiction: "US".into(),
        retention_days: Some(30),
        cost_per_1k_tokens_eur: Some(0.01),
        latency_ms_p50: 1,
        context_ceiling: 10_000,
        determinism: Determinism::NonDeterministic,
        identity: ArchIdentity {
            weights_sha256: format!("sha256:{max_scope:?}{third_party}"),
            engine: "api".into(),
            engine_version: "1".into(),
            backend: "cloud".into(),
            quant: "-".into(),
            kv_cache: "-".into(),
            threads: 0,
            batch: 0,
            sampling: Default::default(),
            seed: None,
        },
        clearance: Clearance {
            max_scope,
            third_party_allowed: third_party,
        },
        governed: false,
    }
}

fn scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        Just(Scope::Public),
        Just(Scope::Vertical),
        Just(Scope::Business),
        Just(Scope::Personal),
        Just(Scope::Holdout)
    ]
}
fn class() -> impl Strategy<Value = DataClass> {
    prop_oneof![
        Just(DataClass::Own),
        Just(DataClass::ThirdPartyMandated),
        Just(DataClass::Unknown)
    ]
}

fn clearance_property<K: KernelTestHooks>(
    k: &mut K,
    labels: Vec<(Scope, DataClass)>,
    max: Scope,
    tp: bool,
) -> Result<(), TestCaseError> {
    let id = k.register_arch(arch(max, tp));
    let ctx = Ctx {
        principal: Principal::Machine {
            node_id: "n1".into(),
            lease_id: "l".into(),
        },
        clearance: Clearance {
            max_scope: Scope::Holdout,
            third_party_allowed: true,
        },
        partition: "p".into(),
        now_ms: 1,
    };
    for (s, c) in labels {
        let r = k
            .submit_task(
                &ctx,
                "g",
                Label {
                    scope: s,
                    data_class: c,
                    origins: Default::default(),
                },
            )
            .unwrap();
        let _ = k.infer(&ctx, &id, Capability::Generate, &r);
    }
    let clearance = Clearance {
        max_scope: max,
        third_party_allowed: tp,
    };
    for (arch_id, label) in k.infer_log().iter() {
        prop_assert_eq!(arch_id, &id);
        prop_assert!(
            label.flows_to(&clearance),
            "leaked {:?} to clearance {:?}",
            label,
            clearance
        );
    }
    Ok(())
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
    fn stub_infer_never_receives_a_label_above_arch_clearance(
        labels in prop::collection::vec((scope(), class()), 1..20),
        max in scope(),
        tp in any::<bool>()
    ) {
        clearance_property(&mut vk_stub::StubKernel::new("n1"), labels, max, tp)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..Default::default() })]

    #[test]
    fn real_infer_never_receives_a_label_above_arch_clearance(
        labels in prop::collection::vec((scope(), class()), 1..20),
        max in scope(),
        tp in any::<bool>()
    ) {
        let d = tempfile::tempdir().unwrap();
        clearance_property(&mut real(d.path()), labels, max, tp)?;
    }
}
