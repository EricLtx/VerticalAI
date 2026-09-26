use proptest::prelude::*;
use vk_contracts::labels::*;
use vk_contracts::principal::*;
use vk_contracts::syscalls::*;
use vk_contracts::testing::KernelTestHooks;

#[derive(Debug, Clone)]
enum Op {
    Approve(ApprovalKind),
    /// A human approval that is valid in every respect but the channel: a
    /// challenge the kernel minted, signed by the enrolled key, presented by
    /// a machine principal (SP1a review M16).
    SignedApprovalOnMachineChannel,
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
        Just(Op::SignedApprovalOnMachineChannel),
        "[a-c]".prop_map(Op::Lease),
        Just(Op::Stop),
        Just(Op::Automation),
    ]
}

/// `key`'s approval of exactly `challenge`, as `vk approve` would build it.
fn signed(key: &SoftwareHumanKey, challenge: Challenge) -> Approval {
    Approval {
        subject_hash: challenge.action_digest.clone(),
        kind: ApprovalKind::Human,
        approver: Principal::Human {
            device_id: key.device_id(),
        },
        signature_hex: Some(hex::encode(key.sign(&challenge.digest()))),
        challenge: Some(challenge),
    }
}

/// I1, both halves: whatever the machine principal tries — unsigned human
/// approvals, a **valid** signed approval on its own channel, STOPs,
/// automations — no human approval is recorded and no STOP lands; and the
/// human's own channel still works, for a STOP and for **one valid approval
/// per run** (SP1a review M16), so the property proves acceptance and not
/// only refusal.
fn human_path_property<K: KernelTestHooks>(k: &mut K, ops: &[Op]) -> Result<(), TestCaseError> {
    let key = SoftwareHumanKey::generate("phone-1");
    k.enroll_device("phone-1", key.verifying_key_bytes());
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
            Op::SignedApprovalOnMachineChannel => {
                let challenge = k.mint_challenge(&ctx, "subject", "sha256:s", 60_000);
                let refused = k.approve(&ctx, signed(&key, challenge));
                prop_assert!(
                    matches!(refused, Err(KernelError::I1(_))),
                    "a valid signature on a machine channel is still not a human: {refused:?}"
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
        now_ms: 1_000,
        ..m.clone()
    };
    prop_assert!(k.stop(&h, "business:acme").is_ok());
    prop_assert!(k.stops().stopped("business:acme"));
    prop_assert!(matches!(
        k.run_automation(&m, "acme", "m"),
        Err(KernelError::Stopped(_))
    ));
    // …and one valid human approval per run is accepted: minted by the
    // kernel, signed by the enrolled key, presented on the human's channel —
    // exactly once, because the challenge is spent by the approval.
    let challenge = k.mint_challenge(&h, "subject", "sha256:h", 60_000);
    let approval = signed(&key, challenge);
    prop_assert!(
        k.approve(&h, approval.clone()).is_ok(),
        "the human path accepts"
    );
    let recorded = k.approvals_for("sha256:h");
    prop_assert_eq!(recorded.len(), 1);
    prop_assert_eq!(recorded[0].kind, ApprovalKind::Human);
    prop_assert!(
        matches!(k.approve(&h, approval), Err(KernelError::I1(_))),
        "a spent challenge is not answered twice"
    );
    Ok(())
}

fn real(dir: &std::path::Path) -> vk_kernel::RealKernel {
    vk_contracts::testing::guard_state_dir(dir);
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
