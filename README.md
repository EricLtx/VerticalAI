# VerticalAI

Self-improving, peer-to-peer, local-first orchestration runtime for businesses.
Design: `docs/superpowers/specs/2026-09-22-verticalai-design.md`.
Plan for this stage: `docs/superpowers/plans/2026-09-22-sp0-contracts-and-kernel-boundary.md`.

## SP0 — contracts and kernel boundary

- `contracts/` — language-neutral JSON Schemas (generated from `crates/vk-contracts`) and protocol documents.
- `crates/vk-contracts` — the contract types; the schemas are generated from them.
- `crates/vk-stub` — in-memory stub kernel with the interceptor chain, used to test invariants.
- `crates/vk-props` — property tests for invariants I1–I4′.

### Contracts index

| Schema | Type | Spec |
|---|---|---|
| `label`, `clearance` | information-flow lattice | §3.2, §4.2 |
| `register` | task-state IR | §3.2 |
| `arch_manifest` | arch descriptor with content-addressed identity | §3.7 |
| `principal`, `challenge`, `approval` | principals, human ceremony, approval records (I1) | §3.6 |
| `lease` | work-in-progress lease with fence | §3.4 |
| `stop_event`, `resume_event`, `liveness_lease` | STOP primitive and autonomy liveness (I4) | §3.5 |
| `ledger_event` | hash-chained ledger event with three stamps | §3.9 |
| `blob_envelope`, `shred_event` | storage tiering and erasure | §3.9 |
| `module_manifest`, `validator_manifest`, `gate_verdict` | userland object formats | §4.1, §4.3 |
| `syscall_ctx` | authenticated call context | §3.11 |
| `tuf_root` | federation root role with threshold signatures | §4.4 |

Protocol documents: `contracts/identity/phone-bootstrap.md`, `contracts/federation/tuf-roles.md`, `contracts/tcb.md`.

## Build

MSRV: Rust 1.98.1 (stable, 2026-09-01), MSVC toolchain on Windows (`rust-toolchain.toml` pins `stable`).

```
cargo test --workspace                          # 46 tests: unit, schema drift, examples, stub, properties
cargo run -p vk-contracts --bin gen-schemas     # regenerate contracts/schemas/ after changing a contract type
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Windows notes:
- Install Visual Studio 2022 Build Tools with the "Desktop development with C++" workload before `rustup`. The GNU host toolchain does not work here: rustup's self-contained `dlltool` cannot build the import libraries that `raw-dylib` crates (`getrandom`, `windows-sys`) need.
- Build outside OneDrive-synced folders: `set CARGO_TARGET_DIR=%USERPROFILE%\.cargo-target\verticalai`.
