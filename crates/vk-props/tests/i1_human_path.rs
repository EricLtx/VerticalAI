use proptest::prelude::*;
use vk_contracts::labels::*;
use vk_contracts::principal::*;
use vk_contracts::syscalls::*;
use vk_contracts::testing::KernelTestHooks;

#[derive(Debug, Clone)]
enum Op {
    Approve(ApprovalKind),
    Lease(String),
    Stop,
    Automation,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        prop_oneof![
            Just(ApprovalKind::Test),
            Just(ApprovalKind::Audit),
            Just(ApprovalKind::Human)
        ]
        .prop_map(Op::Approve),
        "[a-c]".prop_map(Op::Lease),
        Just(Op::Stop),
        Just(Op::Automation),
    ]
}

fn human_path_property<K: KernelTestHooks>(k: &mut K, ops: &[Op]) -> Result<(), TestCaseError> {
    k.renew_liveness("acme", "phone-1", 1_000_000);
    let m = Ctx {
        principal: Principal::Machine {
            node_id: "n1".into(),
            lease_id: "l".into(),
        },
        clearance: Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        },
        partition: "p".into(),
        now_ms: 1,
    };
    for (i, o) in ops.iter().enumerate() {
        let ctx = Ctx {
            now_ms: 1 + i as u64,
            ..m.clone()
        };
        match o {
            Op::Approve(kind) => {
                let _ = k.approve(
                    &ctx,
                    Approval {
                        subject_hash: "sha256:s".into(),
                        kind: *kind,
                        approver: Principal::Human {
                            device_id: "phone-1".into(),
                        },
                        challenge: None,
                        signature_hex: None,
                    },
                );
            }
            Op::Lease(r) => {
                let _ = k.lease(&ctx, r, 10);
            }
            Op::Stop => {
                let _ = k.stop(&ctx, "business:acme");
            }
            Op::Automation => {
                let _ = k.run_automation(&ctx, "acme", "m");
            }
        }
    }
    prop_assert!(k
        .approvals_for("sha256:s")
        .iter()
        .all(|a| a.kind != ApprovalKind::Human));
    prop_assert!(
        !k.stops().stopped("business:acme"),
        "a machine managed to STOP"
    );
    // The human path is reachable regardless of what machines did:
    let h = Ctx {
        principal: Principal::Human {
            device_id: "phone-1".into(),
        },
        ..m.clone()
    };
    prop_assert!(k.stop(&h, "business:acme").is_ok());
    prop_assert!(k.stops().stopped("business:acme"));
    prop_assert!(matches!(
        k.run_automation(&m, "acme", "m"),
        Err(KernelError::Stopped(_))
    ));
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
    fn stub_human_path(ops in prop::collection::vec(op(), 0..40)) {
        human_path_property(&mut vk_stub::StubKernel::new("n1"), &ops)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..Default::default() })]

    #[test]
    fn real_human_path(ops in prop::collection::vec(op(), 0..40)) {
        let d = tempfile::tempdir().unwrap();
        human_path_property(&mut real(d.path()), &ops)?;
    }
}
