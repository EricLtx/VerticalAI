# SP0 — Contracts & Kernel Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define the VerticalAI kernel boundary as executable, language-neutral contracts — the task-state IR, arch manifests, principals, the lock tagged union, STOP/liveness, the ledger, storage tiering, module/validator/gate formats, and the syscall surface — and prove the four kernel invariants (I1, I2, I3, I4/I4′) with property tests against an in-memory stub kernel.

**Architecture:** A Rust workspace with three crates. `vk-contracts` holds the Rust types that *are* the contracts; JSON Schemas are generated from them (`schemars`) and committed under `contracts/schemas/`, with a drift test so the schema on disk is always the schema in code. `vk-stub` is an in-memory kernel implementing the `Kernel` trait with the interceptor chain — no persistence, no network, no real inference — so invariants can be tested before SP1 builds the real thing. `vk-props` holds property tests (`proptest`) that generate syscall sequences and partition schedules and assert the invariants over them.

**Tech Stack:** Rust stable (MSVC toolchain on Windows), `serde`/`serde_json`, `schemars` 1.x (schema generation), `jsonschema` (example validation), `sha2` + `hex` (content addressing), `ed25519-dalek` 2.x + `rand` 0.8 (software stand-in for hardware human keys), `proptest`, `thiserror`. GitHub Actions for CI on windows/ubuntu/macos.

**Spec:** `docs/superpowers/specs/2026-09-22-verticalai-design.md` — this plan implements §3 (kernel) at contract level, §4.1 object formats, §4.4 TUF roles, §5 spec-first + testing, and the SP0 row of §6.

## Global Constraints

- Rust edition 2021, `rust-toolchain.toml` pins `channel = "stable"`; MSRV is whatever stable is at SP0 start (record it in `README.md`).
- Every contract type derives `Serialize, Deserialize, JsonSchema` and uses `#[serde(rename_all = "snake_case")]` on enums; field names in JSON are `snake_case`.
- Content hashes are SHA-256 over canonical JSON (`serde_json::to_vec` of the struct — field order is declaration order and must not change without a schema version bump), rendered as lowercase hex, prefixed `sha256:`.
- No syscall accepts a caller-asserted principal (spec §3.6): the principal lives in `Ctx`, constructed by the channel, never by userland.
- Secrets never appear in any contract type (spec §3.2, §3.9). The word `secret`, `api_key` or `token` in a schema is a defect.
- `01_Architectural_Documentation/` is git-ignored; never `git add -f` it.
- `git config user.name` must be set before the first commit of this plan (currently unset; commits would be authored `unknown`).
- Commit messages: conventional commits (`feat:`, `test:`, `chore:`, `docs:`), ending with the attribution line in force for this session.
- All tests run with `cargo test --workspace`; CI must be green on windows-latest, ubuntu-latest, macos-latest.

---

## File structure

```
Cargo.toml                          workspace: members = ["crates/*"]
rust-toolchain.toml
README.md                           what SP0 is, how to run tests, MSRV
LICENSE                             "All rights reserved" (commercial first, D15)
.github/workflows/ci.yml            fmt + clippy + test matrix + schema drift + signing scaffold
contracts/
  README.md                         how schemas are generated; versioning rule
  schemas/*.schema.json             GENERATED — never hand-edited
  examples/<type>/*.json            hand-written valid/invalid examples
  identity/phone-bootstrap.md       protocol (spec §3.6)
  federation/tuf-roles.md           roles, thresholds, freshness (spec §4.4)
  tcb.md                            trusted computing base statement (spec §5)
crates/vk-contracts/
  Cargo.toml
  src/lib.rs                        re-exports; `hash_canonical()`
  src/labels.rs                     Scope, DataClass, Origin, Label (lattice), Clearance
  src/register.rs                   Register (task-state IR)
  src/arch.rs                       ArchManifest, ArchIdentity, arch_id()
  src/principal.rs                  Principal, Challenge, Approval, HumanKey trait, SoftwareHumanKey
  src/locks.rs                      Lease, Fence, LockHome contract types
  src/stop.rs                       StopEvent, ResumeEvent, StopSet, LivenessLease
  src/ledger.rs                     Hlc, ClockQuality, RetentionClass, LedgerEvent, chain verify, receive guard
  src/storage.rs                    BlobEnvelope, ShredEvent, MetadataDoc (G-set with conflict surfacing)
  src/module.rs                     ModuleManifest, ValidatorManifest, GateVerdict + validation rules
  src/syscalls.rs                   Ctx, Kernel trait, KernelError, InferOutcome
  src/bin/gen-schemas.rs            writes contracts/schemas/*.schema.json
  tests/schema_drift.rs             committed schema == generated schema
  tests/examples_validate.rs        every example validates (or fails) as its folder says
crates/vk-stub/
  Cargo.toml
  src/lib.rs                        StubKernel: in-memory state + interceptors
  src/interceptors.rs               i1(), i2(), i3(), i4(), i4_prime()
crates/vk-props/
  Cargo.toml                        dev-only crate
  tests/i1_human_path.rs
  tests/i2_clearance.rs
  tests/i3_merge_conservation.rs
  tests/i4_liveness_and_truncation.rs
```

---

### Task 0: Toolchain, workspace, CI skeleton

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `README.md`, `LICENSE`, `.github/workflows/ci.yml`, `crates/vk-contracts/Cargo.toml`, `crates/vk-contracts/src/lib.rs`

**Interfaces:**
- Produces: a workspace where `cargo test --workspace` runs; crate name `vk-contracts` (lib `vk_contracts`).

- [ ] **Step 1: Install Rust (Windows)**

Run in PowerShell:
```powershell
winget install --id Rustlang.Rustup -e
```
Then open a new terminal. If `cargo --version` fails with a linker error later, install the MSVC build tools: `winget install --id Microsoft.VisualStudio.2022.BuildTools -e` and select the "Desktop development with C++" workload. Verify:
```powershell
rustup default stable; rustc --version; cargo --version
```
Expected: both print a version (e.g. `rustc 1.9x.0`). Record the version as MSRV in `README.md` (Step 4).

- [ ] **Step 2: Create the workspace**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
edition = "2021"
license = "SEE LICENSE IN LICENSE"
repository = "https://github.com/EricLtx/VerticalAI"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
schemars = "1"
thiserror = "2"
sha2 = "0.10"
hex = "0.4"
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

`crates/vk-contracts/Cargo.toml`:
```toml
[package]
name = "vk-contracts"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "VerticalAI kernel contracts: types that define the kernel boundary"

[dependencies]
serde.workspace = true
serde_json.workspace = true
schemars.workspace = true
thiserror.workspace = true
sha2.workspace = true
hex.workspace = true
```

`crates/vk-contracts/src/lib.rs`:
```rust
//! VerticalAI kernel contracts.
//!
//! Every public type here is a contract: its JSON Schema is generated into
//! `contracts/schemas/` and checked for drift in tests.

use sha2::{Digest, Sha256};

/// SHA-256 over canonical JSON of `value`, rendered as `sha256:<hex>`.
/// Canonical = `serde_json::to_vec`; struct field order is declaration order.
pub fn hash_canonical<T: serde::Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("contract types always serialize");
    hash_bytes(&bytes)
}

/// SHA-256 over raw bytes, rendered as `sha256:<hex>`.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_prefixed() {
        let h = hash_bytes(b"verticalai");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64);
        assert_eq!(h, hash_bytes(b"verticalai"));
    }
}
```

- [ ] **Step 3: Run the first test**

Run: `cargo test --workspace`
Expected: `test tests::hash_is_stable_and_prefixed ... ok`

- [ ] **Step 4: README and LICENSE**

`README.md`:
```markdown
# VerticalAI

Self-improving, peer-to-peer, local-first orchestration runtime for businesses.
Design: `docs/superpowers/specs/2026-09-22-verticalai-design.md`.

## SP0 — contracts and kernel boundary

- `contracts/` — language-neutral JSON Schemas (generated from `crates/vk-contracts`) and protocol documents.
- `crates/vk-contracts` — the contract types.
- `crates/vk-stub` — in-memory stub kernel used to test invariants.
- `crates/vk-props` — property tests for invariants I1–I4′.

## Build

MSRV: <fill from `rustc --version` at SP0 start>. `cargo test --workspace`.
Regenerate schemas: `cargo run -p vk-contracts --bin gen-schemas`.
```

`LICENSE`:
```
Copyright (c) 2026 VerticalAI. All rights reserved.

This software and its documentation are proprietary. No licence is granted
to use, copy, modify or distribute them without written permission.
The kernel is planned for a later open-source release (see design D15).
```

- [ ] **Step 5: CI skeleton**

`.github/workflows/ci.yml`:
```yaml
name: ci
on:
  push: { branches: [master, main] }
  pull_request:
jobs:
  test:
    strategy:
      matrix: { os: [windows-latest, ubuntu-latest, macos-latest] }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt, clippy }
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
  sign:
    # Scaffold only: signs release binaries when a certificate secret exists (SP1 gate).
    if: ${{ github.event_name == 'push' }}
    needs: test
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check signing secret
        shell: pwsh
        run: |
          if (-not $env:SIGNING_CERT_B64) { Write-Host "no SIGNING_CERT_B64 secret; skipping (expected in SP0)"; exit 0 }
          Write-Host "signing pipeline would run here"
        env: { SIGNING_CERT_B64: ${{ secrets.SIGNING_CERT_B64 }} }
```

- [ ] **Step 6: Commit**

```bash
git config user.name "<name from founder>"
git add Cargo.toml rust-toolchain.toml README.md LICENSE .github crates/vk-contracts .gitignore docs
git commit -m "chore: SP0 workspace, CI skeleton, design spec and plan"
```

---

### Task 1: Labels — the information-flow lattice

**Files:**
- Create: `crates/vk-contracts/src/labels.rs`
- Modify: `crates/vk-contracts/src/lib.rs` (add `pub mod labels;`)

**Interfaces:**
- Produces: `Scope`, `DataClass`, `Origin`, `Label { scope, data_class, origins }`, `Label::bottom()`, `Label::join(&self, &Label) -> Label`, `Clearance { max_scope, third_party_allowed }`, `Label::flows_to(&self, &Clearance) -> bool`.

- [ ] **Step 1: Write the failing tests**

Append to `crates/vk-contracts/src/labels.rs` (create the file with only the test module first):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_takes_the_maximum_scope_and_unions_origins() {
        let a = Label { scope: Scope::Business, data_class: DataClass::Own, origins: [Origin::OwnerAuthored].into() };
        let b = Label { scope: Scope::Personal, data_class: DataClass::Unknown, origins: [Origin::Web].into() };
        let j = a.join(&b);
        assert_eq!(j.scope, Scope::Personal);
        assert_eq!(j.data_class, DataClass::Unknown);
        assert_eq!(j.origins.len(), 2);
    }

    #[test]
    fn join_is_idempotent_and_bottom_is_identity() {
        let a = Label { scope: Scope::Vertical, data_class: DataClass::ThirdPartyMandated, origins: [Origin::ThirdPartyInbound].into() };
        assert_eq!(a.join(&a), a);
        assert_eq!(a.join(&Label::bottom()), a);
    }

    #[test]
    fn holdout_never_flows_to_any_clearance() {
        let l = Label { scope: Scope::Holdout, data_class: DataClass::Own, origins: Default::default() };
        let c = Clearance { max_scope: Scope::Personal, third_party_allowed: true };
        assert!(!l.flows_to(&c));
    }

    #[test]
    fn third_party_data_needs_explicit_clearance() {
        let l = Label { scope: Scope::Business, data_class: DataClass::Unknown, origins: Default::default() };
        assert!(!l.flows_to(&Clearance { max_scope: Scope::Business, third_party_allowed: false }));
        assert!(l.flows_to(&Clearance { max_scope: Scope::Business, third_party_allowed: true }));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p vk-contracts labels`
Expected: compile error — `Label` not found.

- [ ] **Step 3: Implement**

Top of `crates/vk-contracts/src/labels.rs`:
```rust
//! Information-flow labels (spec §3.2, §4.2). A `Label` is a join-semilattice
//! element; every object written by a task carries the join of what the task read.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Ordered low → high. `Holdout` is the top: readable only by the rehearsal verifier role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scope { Public, Vertical, Business, Personal, Holdout }

/// Ordered low → high; `Unknown` is treated as third-party and is the most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataClass { Own, ThirdPartyMandated, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Origin { OwnerAuthored, OwnerShipped, ThirdPartyInbound, Web }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Label {
    pub scope: Scope,
    pub data_class: DataClass,
    pub origins: BTreeSet<Origin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Clearance {
    pub max_scope: Scope,
    pub third_party_allowed: bool,
}

impl Label {
    pub fn bottom() -> Label {
        Label { scope: Scope::Public, data_class: DataClass::Own, origins: BTreeSet::new() }
    }

    pub fn join(&self, other: &Label) -> Label {
        Label {
            scope: self.scope.max(other.scope),
            data_class: self.data_class.max(other.data_class),
            origins: self.origins.union(&other.origins).copied().collect(),
        }
    }

    /// I2 predicate: may an object with this label be projected to a principal with `clearance`?
    pub fn flows_to(&self, clearance: &Clearance) -> bool {
        if self.scope == Scope::Holdout { return false; }
        let scope_ok = self.scope <= clearance.max_scope;
        let class_ok = self.data_class == DataClass::Own || clearance.third_party_allowed;
        scope_ok && class_ok
    }
}
```
Add `pub mod labels;` to `lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p vk-contracts labels`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/vk-contracts/src/labels.rs crates/vk-contracts/src/lib.rs
git commit -m "feat(contracts): information-flow label lattice and clearance predicate"
```

---

### Task 2: Schema generation and drift test

**Files:**
- Create: `crates/vk-contracts/src/bin/gen-schemas.rs`, `crates/vk-contracts/tests/schema_drift.rs`, `contracts/README.md`
- Modify: `crates/vk-contracts/Cargo.toml` (add `[[bin]]` and dev-deps)

**Interfaces:**
- Produces: `vk_contracts::schema_registry() -> Vec<(&'static str, schemars::Schema)>` — every later task registers its type here; `contracts/schemas/<name>.schema.json` on disk.

- [ ] **Step 1: Write the failing drift test**

`crates/vk-contracts/tests/schema_drift.rs`:
```rust
use std::path::PathBuf;

fn schemas_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/schemas")
}

#[test]
fn committed_schemas_match_generated() {
    for (name, schema) in vk_contracts::schema_registry() {
        let path = schemas_dir().join(format!("{name}.schema.json"));
        let on_disk = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing {} — run `cargo run -p vk-contracts --bin gen-schemas`", path.display()));
        let generated = serde_json::to_string_pretty(&schema).unwrap() + "\n";
        assert_eq!(on_disk, generated, "schema drift in {name}; regenerate and commit");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p vk-contracts --test schema_drift`
Expected: compile error — `schema_registry` not found.

- [ ] **Step 3: Implement the registry and generator**

Add to `lib.rs`:
```rust
/// Every contract type, by schema file name. Extend this in each task.
pub fn schema_registry() -> Vec<(&'static str, schemars::Schema)> {
    vec![
        ("label", schemars::schema_for!(labels::Label)),
        ("clearance", schemars::schema_for!(labels::Clearance)),
    ]
}
```

`crates/vk-contracts/src/bin/gen-schemas.rs`:
```rust
//! Regenerates contracts/schemas/*.schema.json from the Rust contract types.
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/schemas");
    std::fs::create_dir_all(&dir).expect("create schemas dir");
    for (name, schema) in vk_contracts::schema_registry() {
        let path = dir.join(format!("{name}.schema.json"));
        let text = serde_json::to_string_pretty(&schema).unwrap() + "\n";
        std::fs::write(&path, text).expect("write schema");
        println!("wrote {}", path.display());
    }
}
```

`contracts/README.md`:
```markdown
# VerticalAI contracts

`schemas/*.schema.json` are GENERATED from `crates/vk-contracts` — do not edit by hand.
Regenerate with `cargo run -p vk-contracts --bin gen-schemas`; the test
`schema_drift` fails if the committed files differ from the code.

Versioning rule: any change to a struct's field order, names or types is a
schema change and bumps `vk-contracts`' minor version. Hashes are computed over
canonical JSON, so field order is part of the contract.

`examples/<type>/valid/*.json` must validate; `examples/<type>/invalid/*.json` must not.
```

- [ ] **Step 4: Generate and run**

Run: `cargo run -p vk-contracts --bin gen-schemas && cargo test -p vk-contracts --test schema_drift`
Expected: two files written; test passes.

- [ ] **Step 5: Commit**

```bash
git add contracts crates/vk-contracts
git commit -m "feat(contracts): schema generation from types with drift test"
```

---

### Task 3: Example validation harness

**Files:**
- Create: `crates/vk-contracts/tests/examples_validate.rs`, `contracts/examples/label/valid/business_own.json`, `contracts/examples/label/invalid/bad_scope.json`
- Modify: `crates/vk-contracts/Cargo.toml` (dev-dependency `jsonschema = "0.30"`, `walkdir = "2"`)

**Interfaces:**
- Produces: a test that, for every `contracts/examples/<name>/{valid,invalid}/*.json`, validates against `contracts/schemas/<name>.schema.json`. Later tasks only add example files.

- [ ] **Step 1: Write the examples and the failing test**

`contracts/examples/label/valid/business_own.json`:
```json
{ "scope": "business", "data_class": "own", "origins": ["owner_authored"] }
```
`contracts/examples/label/invalid/bad_scope.json`:
```json
{ "scope": "galactic", "data_class": "own", "origins": [] }
```

`crates/vk-contracts/tests/examples_validate.rs`:
```rust
use std::path::{Path, PathBuf};

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts") }

fn validator_for(name: &str) -> jsonschema::Validator {
    let text = std::fs::read_to_string(root().join(format!("schemas/{name}.schema.json"))).expect("schema exists");
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();
    jsonschema::validator_for(&schema).expect("schema compiles")
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir).into_iter().filter_map(Result::ok)
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .map(|e| e.into_path()).collect()
}

#[test]
fn every_example_validates_as_its_folder_says() {
    let examples = root().join("examples");
    let mut checked = 0;
    for type_dir in std::fs::read_dir(&examples).unwrap().flatten() {
        let name = type_dir.file_name().to_string_lossy().to_string();
        let v = validator_for(&name);
        for f in walk(&type_dir.path().join("valid")) {
            let inst: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
            let errors: Vec<String> = v.iter_errors(&inst).map(|e| e.to_string()).collect();
            assert!(errors.is_empty(), "{} should be valid: {errors:?}", f.display());
            checked += 1;
        }
        for f in walk(&type_dir.path().join("invalid")) {
            let inst: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
            assert!(!v.is_valid(&inst), "{} should be invalid", f.display());
            checked += 1;
        }
    }
    assert!(checked >= 2, "no examples found");
}
```

Add to `crates/vk-contracts/Cargo.toml`:
```toml
[dev-dependencies]
jsonschema = "0.30"
walkdir = "2"
```

- [ ] **Step 2: Run to verify it passes (harness) — then break it to prove it bites**

Run: `cargo test -p vk-contracts --test examples_validate`
Expected: PASS. Then temporarily change `"business"` to `"galactic"` in the valid example, run again — expected FAIL with `should be valid` — and revert.

- [ ] **Step 3: Commit**

```bash
git add contracts/examples crates/vk-contracts
git commit -m "test(contracts): example validation harness against generated schemas"
```

---

### Task 4: Register — the task-state IR

**Files:**
- Create: `crates/vk-contracts/src/register.rs`, `contracts/examples/register/valid/minimal.json`, `contracts/examples/register/invalid/missing_label.json`
- Modify: `lib.rs` (mod + registry entry `("register", schema_for!(register::Register))`)

**Interfaces:**
- Produces: `RegisterId(String)`, `Evidence { content, origin, source_hash }`, `ArtefactRef { hash, kind }`, `Register { id, task_id, label, goal, constraints, evidence, decisions, open_questions, artefacts }`, `Register::with_read(&mut self, &Label)` (label join on read — used by the stub for I2 labelling).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::*;

    fn reg() -> Register {
        Register { id: RegisterId("r1".into()), task_id: "t1".into(), label: Label::bottom(), goal: "draft a quote".into(),
            constraints: vec![], evidence: vec![], decisions: vec![], open_questions: vec![], artefacts: vec![] }
    }

    #[test]
    fn round_trips_through_json() {
        let r = reg();
        let s = serde_json::to_string(&r).unwrap();
        let back: Register = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn reading_a_higher_label_raises_the_register_label() {
        let mut r = reg();
        r.with_read(&Label { scope: Scope::Personal, data_class: DataClass::Own, origins: [Origin::Web].into() });
        assert_eq!(r.label.scope, Scope::Personal);
        assert!(r.label.origins.contains(&Origin::Web));
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p vk-contracts register` → compile error.

- [ ] **Step 3: Implement**

```rust
//! The task-state IR (spec §3.2): the only thing that crosses arch boundaries.
use crate::labels::Label;
use crate::labels::Origin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct RegisterId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence { pub content: String, pub origin: Origin, pub source_hash: String }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtefactRef { pub hash: String, pub kind: String }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Register {
    pub id: RegisterId,
    pub task_id: String,
    pub label: Label,
    pub goal: String,
    pub constraints: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub decisions: Vec<String>,
    pub open_questions: Vec<String>,
    pub artefacts: Vec<ArtefactRef>,
}

impl Register {
    /// Information-flow rule: a task that reads `other` taints everything it writes.
    pub fn with_read(&mut self, other: &Label) { self.label = self.label.join(other); }
}
```
Examples — valid `minimal.json`:
```json
{ "id": "r1", "task_id": "t1", "label": { "scope": "personal", "data_class": "own", "origins": [] },
  "goal": "draft a quote", "constraints": [], "evidence": [], "decisions": [], "open_questions": [], "artefacts": [] }
```
invalid `missing_label.json`: same without the `label` key.

- [ ] **Step 4: Regenerate schemas, run all** — `cargo run -p vk-contracts --bin gen-schemas && cargo test -p vk-contracts` → all pass.

- [ ] **Step 5: Commit** — `git commit -am "feat(contracts): register (task-state IR) with label inheritance"` after `git add contracts crates`.

---

### Task 5: Arch manifest and content-addressed arch id

**Files:**
- Create: `crates/vk-contracts/src/arch.rs`, `contracts/examples/arch_manifest/valid/gemma_local.json`, `contracts/examples/arch_manifest/invalid/no_capabilities.json`
- Modify: `lib.rs` (mod + `("arch_manifest", schema_for!(arch::ArchManifest))`)

**Interfaces:**
- Produces: `Capability`, `Locality`, `Determinism`, `ArchIdentity`, `ArchManifest { name, capabilities, locality, jurisdiction, retention_days, cost_per_1k_tokens_eur, latency_ms_p50, context_ceiling, determinism, identity, clearance, governed }`, `ArchManifest::arch_id(&self) -> String`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::*;

    fn gemma() -> ArchManifest {
        ArchManifest {
            name: "gemma-4-9b".into(), capabilities: [Capability::Generate, Capability::Plan].into(),
            locality: Locality::Local, jurisdiction: "FR".into(), retention_days: None,
            cost_per_1k_tokens_eur: 0.0, latency_ms_p50: 900, context_ceiling: 8192, determinism: Determinism::SeededDeterministic,
            identity: ArchIdentity { weights_sha256: "sha256:abc".into(), engine: "llama-server".into(), engine_version: "b5000".into(),
                backend: "cuda".into(), quant: "Q4_K_M".into(), kv_cache: "f16".into(), threads: 8, batch: 512, sampling: Default::default(), seed: Some(7) },
            clearance: Clearance { max_scope: Scope::Personal, third_party_allowed: true }, governed: true,
        }
    }

    #[test]
    fn arch_id_changes_when_any_identity_field_changes() {
        let a = gemma();
        let mut b = gemma(); b.identity.quant = "Q8_0".into();
        let mut c = gemma(); c.identity.seed = Some(8);
        assert_ne!(a.arch_id(), b.arch_id());
        assert_ne!(a.arch_id(), c.arch_id());
        assert_eq!(a.arch_id(), gemma().arch_id());
    }

    #[test]
    fn arch_id_ignores_non_identity_fields() {
        let a = gemma();
        let mut b = gemma(); b.latency_ms_p50 = 5;
        assert_eq!(a.arch_id(), b.arch_id());
    }

    #[test]
    fn manifest_must_declare_at_least_one_capability() {
        let mut a = gemma(); a.capabilities.clear();
        assert!(a.validate().is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p vk-contracts arch` → compile error.

- [ ] **Step 3: Implement**

```rust
//! Arch manifests (spec §3.7). An arch is any AI system behind an adapter.
use crate::labels::Clearance;
use crate::hash_canonical;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Capability { Generate, Embed, Predict, Perceive, Plan, Judge }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Locality { Local, OnPrem, Peer, Cloud }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Determinism { SeededDeterministic, NonDeterministic }

/// Everything that changes model behaviour. Any change = a new arch id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArchIdentity {
    pub weights_sha256: String,
    pub engine: String,
    pub engine_version: String,
    pub backend: String,
    pub quant: String,
    pub kv_cache: String,
    pub threads: u32,
    pub batch: u32,
    pub sampling: BTreeMap<String, String>,
    pub seed: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArchManifest {
    pub name: String,
    pub capabilities: BTreeSet<Capability>,
    pub locality: Locality,
    /// ISO 3166 country code, or "EU".
    pub jurisdiction: String,
    pub retention_days: Option<u32>,
    pub cost_per_1k_tokens_eur: f64,
    pub latency_ms_p50: u32,
    pub context_ceiling: u32,
    pub determinism: Determinism,
    pub identity: ArchIdentity,
    pub clearance: Clearance,
    /// True only if the kernel launched and contains the inference process (spec §3.3).
    pub governed: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArchError {
    #[error("manifest declares no capabilities")]
    NoCapabilities,
    #[error("context_ceiling must be > 0")]
    ZeroContext,
}

impl ArchManifest {
    pub fn arch_id(&self) -> String { hash_canonical(&self.identity) }

    pub fn validate(&self) -> Result<(), ArchError> {
        if self.capabilities.is_empty() { return Err(ArchError::NoCapabilities); }
        if self.context_ceiling == 0 { return Err(ArchError::ZeroContext); }
        Ok(())
    }
}
```
Valid example `gemma_local.json`: the JSON form of `gemma()` above (`"capabilities": ["generate","plan"]`, `"locality": "local"`, `"determinism": "seeded_deterministic"`, `"clearance": {"max_scope":"personal","third_party_allowed":true}`, `"governed": true`, `"sampling": {}`, `"seed": 7`, `"retention_days": null`). Invalid `no_capabilities.json`: `"capabilities": "generate"` (wrong type — schema-level failure).

- [ ] **Step 4: Regenerate, run** — `cargo run -p vk-contracts --bin gen-schemas && cargo test -p vk-contracts` → pass.

- [ ] **Step 5: Commit** — `git add contracts crates && git commit -m "feat(contracts): arch manifest with content-addressed identity"`.

---

### Task 6: Principals, human challenge ceremony, approvals

**Files:**
- Create: `crates/vk-contracts/src/principal.rs`, `contracts/examples/approval/valid/test_kind.json`, `contracts/examples/approval/invalid/missing_signature.json`
- Modify: `Cargo.toml` (deps `ed25519-dalek = { version = "2", features = ["rand_core"] }`, `rand = "0.8"`), `lib.rs` (mod + `("principal", …)`, `("approval", …)`, `("challenge", …)`)

**Interfaces:**
- Produces: `Principal::{Machine{node_id, lease_id}, Human{device_id}}`, `Challenge { resource, action_digest, nonce, expires_at_ms }`, `Challenge::digest(&self) -> Vec<u8>`, `ApprovalKind::{Test, Audit, Human}`, `Approval { subject_hash, kind, approver, challenge: Option<Challenge>, signature_hex: Option<String> }`, trait `HumanKey { fn device_id(&self) -> String; fn sign(&self, msg:&[u8]) -> [u8;64]; fn verifying_key_bytes(&self) -> [u8;32]; }`, `SoftwareHumanKey::generate()`, `DeviceRegistry { register(device_id, vk_bytes), verify(device_id, msg, sig) -> bool }`, `Approval::verify_human(&self, &DeviceRegistry, now_ms) -> Result<(), PrincipalError>`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(exp: u64) -> Challenge {
        Challenge { resource: "invoice:42".into(), action_digest: "sha256:deadbeef".into(), nonce: "n1".into(), expires_at_ms: exp }
    }

    #[test]
    fn human_approval_verifies_with_enrolled_device_key() {
        let key = SoftwareHumanKey::generate("phone-1");
        let mut reg = DeviceRegistry::default();
        reg.register(key.device_id(), key.verifying_key_bytes());
        let ch = challenge(10_000);
        let sig = key.sign(&ch.digest());
        let ap = Approval { subject_hash: "sha256:deadbeef".into(), kind: ApprovalKind::Human,
            approver: Principal::Human { device_id: "phone-1".into() }, challenge: Some(ch), signature_hex: Some(hex::encode(sig)) };
        assert_eq!(ap.verify_human(&reg, 5_000), Ok(()));
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let key = SoftwareHumanKey::generate("phone-1");
        let mut reg = DeviceRegistry::default();
        reg.register(key.device_id(), key.verifying_key_bytes());
        let ch = challenge(1_000);
        let sig = key.sign(&ch.digest());
        let ap = Approval { subject_hash: "sha256:deadbeef".into(), kind: ApprovalKind::Human,
            approver: Principal::Human { device_id: "phone-1".into() }, challenge: Some(ch), signature_hex: Some(hex::encode(sig)) };
        assert_eq!(ap.verify_human(&reg, 5_000), Err(PrincipalError::Expired));
    }

    #[test]
    fn forged_or_unenrolled_signature_is_rejected() {
        let key = SoftwareHumanKey::generate("phone-1");
        let impostor = SoftwareHumanKey::generate("phone-1");
        let mut reg = DeviceRegistry::default();
        reg.register(key.device_id(), key.verifying_key_bytes());
        let ch = challenge(10_000);
        let sig = impostor.sign(&ch.digest());
        let ap = Approval { subject_hash: "sha256:deadbeef".into(), kind: ApprovalKind::Human,
            approver: Principal::Human { device_id: "phone-1".into() }, challenge: Some(ch), signature_hex: Some(hex::encode(sig)) };
        assert_eq!(ap.verify_human(&reg, 5_000), Err(PrincipalError::BadSignature));
    }

    #[test]
    fn machine_principal_cannot_carry_a_human_approval() {
        let reg = DeviceRegistry::default();
        let ap = Approval { subject_hash: "sha256:x".into(), kind: ApprovalKind::Human,
            approver: Principal::Machine { node_id: "n1".into(), lease_id: "l1".into() }, challenge: None, signature_hex: None };
        assert_eq!(ap.verify_human(&reg, 0), Err(PrincipalError::NotHuman));
    }

    #[test]
    fn approval_subject_must_match_challenge_action() {
        let key = SoftwareHumanKey::generate("phone-1");
        let mut reg = DeviceRegistry::default();
        reg.register(key.device_id(), key.verifying_key_bytes());
        let ch = challenge(10_000);
        let sig = key.sign(&ch.digest());
        let ap = Approval { subject_hash: "sha256:other".into(), kind: ApprovalKind::Human,
            approver: Principal::Human { device_id: "phone-1".into() }, challenge: Some(ch), signature_hex: Some(hex::encode(sig)) };
        assert_eq!(ap.verify_human(&reg, 5_000), Err(PrincipalError::SubjectMismatch));
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p vk-contracts principal` → compile error.

- [ ] **Step 3: Implement**

```rust
//! Principals and the human approval ceremony (spec §3.6, invariant I1).
//! The kernel never accepts a caller-asserted principal; `Principal` values are
//! constructed by the channel layer. `SoftwareHumanKey` is the test stand-in for
//! TPM / Secure Enclave keys; production keys implement `HumanKey`.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Principal {
    Machine { node_id: String, lease_id: String },
    Human { device_id: String },
}

impl Principal {
    pub fn is_human(&self) -> bool { matches!(self, Principal::Human { .. }) }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Challenge {
    pub resource: String,
    pub action_digest: String,
    pub nonce: String,
    pub expires_at_ms: u64,
}

impl Challenge {
    /// H(resource || action_digest || nonce || expiry) — what the hardware key signs.
    pub fn digest(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(self.resource.as_bytes()); h.update(b"|");
        h.update(self.action_digest.as_bytes()); h.update(b"|");
        h.update(self.nonce.as_bytes()); h.update(b"|");
        h.update(self.expires_at_ms.to_be_bytes());
        h.finalize().to_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind { Test, Audit, Human }

/// An immutable, signed, mergeable record. Promotion = a valid approval exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Approval {
    pub subject_hash: String,
    pub kind: ApprovalKind,
    pub approver: Principal,
    pub challenge: Option<Challenge>,
    pub signature_hex: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PrincipalError {
    #[error("approval of kind human requires a human principal")] NotHuman,
    #[error("challenge expired")] Expired,
    #[error("challenge or signature missing")] Incomplete,
    #[error("device not enrolled")] UnknownDevice,
    #[error("signature does not verify")] BadSignature,
    #[error("approval subject does not match challenge action")] SubjectMismatch,
}

pub trait HumanKey {
    fn device_id(&self) -> String;
    fn sign(&self, msg: &[u8]) -> [u8; 64];
    fn verifying_key_bytes(&self) -> [u8; 32];
}

/// Software ed25519 key — tests and development only.
pub struct SoftwareHumanKey { device_id: String, key: SigningKey }

impl SoftwareHumanKey {
    pub fn generate(device_id: &str) -> Self {
        Self { device_id: device_id.to_string(), key: SigningKey::generate(&mut rand::rngs::OsRng) }
    }
}

impl HumanKey for SoftwareHumanKey {
    fn device_id(&self) -> String { self.device_id.clone() }
    fn sign(&self, msg: &[u8]) -> [u8; 64] { self.key.sign(msg).to_bytes() }
    fn verifying_key_bytes(&self) -> [u8; 32] { self.key.verifying_key().to_bytes() }
}

/// Enrolled devices (spec §3.6): populated only by the admin enrolment flow.
#[derive(Default)]
pub struct DeviceRegistry { keys: BTreeMap<String, [u8; 32]> }

impl DeviceRegistry {
    pub fn register(&mut self, device_id: String, vk: [u8; 32]) { self.keys.insert(device_id, vk); }
    pub fn verify(&self, device_id: &str, msg: &[u8], sig: &[u8; 64]) -> Result<(), PrincipalError> {
        let vk_bytes = self.keys.get(device_id).ok_or(PrincipalError::UnknownDevice)?;
        let vk = VerifyingKey::from_bytes(vk_bytes).map_err(|_| PrincipalError::BadSignature)?;
        vk.verify(msg, &Signature::from_bytes(sig)).map_err(|_| PrincipalError::BadSignature)
    }
}

impl Approval {
    /// I1 check for human approvals. Machine approvals (test/audit) are verified elsewhere.
    pub fn verify_human(&self, devices: &DeviceRegistry, now_ms: u64) -> Result<(), PrincipalError> {
        let device_id = match &self.approver {
            Principal::Human { device_id } => device_id,
            _ => return Err(PrincipalError::NotHuman),
        };
        let (ch, sig_hex) = match (&self.challenge, &self.signature_hex) {
            (Some(c), Some(s)) => (c, s),
            _ => return Err(PrincipalError::Incomplete),
        };
        if ch.action_digest != self.subject_hash { return Err(PrincipalError::SubjectMismatch); }
        if now_ms >= ch.expires_at_ms { return Err(PrincipalError::Expired); }
        let sig_vec = hex::decode(sig_hex).map_err(|_| PrincipalError::BadSignature)?;
        let sig: [u8; 64] = sig_vec.try_into().map_err(|_| PrincipalError::BadSignature)?;
        devices.verify(device_id, &ch.digest(), &sig)
    }
}
```
Registry entries: `("principal", schema_for!(principal::Principal))`, `("challenge", …Challenge)`, `("approval", …Approval)`. Valid example `test_kind.json`: `{ "subject_hash": "sha256:abc", "kind": "test", "approver": { "kind": "machine", "node_id": "n1", "lease_id": "l1" }, "challenge": null, "signature_hex": null }`. Invalid `missing_signature.json`: drop the `approver` key.

- [ ] **Step 4: Regenerate, run** — `cargo run -p vk-contracts --bin gen-schemas && cargo test -p vk-contracts` → pass (5 new tests).

- [ ] **Step 5: Commit** — `git add contracts crates Cargo.lock && git commit -m "feat(contracts): principals, human challenge ceremony, approvals (I1)"`.

---

### Task 7: Lock surface — LEASE, fences, lock home

**Files:**
- Create: `crates/vk-contracts/src/locks.rs`, `contracts/examples/lease/valid/wip.json`
- Modify: `lib.rs` (mod + `("lease", …)`)

**Interfaces:**
- Produces: `Lease { id, resource, holder: Principal, granted_at_ms, ttl_ms, fence: u64, partition: String }`, `Lease::expired(&self, now_ms) -> bool`, `LockHome { issue_fence(&mut self, resource) -> u64, is_stale(&self, resource, fence) -> bool }`, `LockTable { acquire(resource, holder, now, ttl, partition, &mut LockHome) -> Result<Lease, LockError>, release(lease_id) }`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::Principal;

    fn m(n: &str) -> Principal { Principal::Machine { node_id: n.into(), lease_id: format!("l-{n}") } }

    #[test]
    fn second_holder_in_same_partition_is_refused_until_expiry() {
        let mut home = LockHome::default();
        let mut t = LockTable::default();
        let a = t.acquire("doc:1", m("a"), 0, 1_000, "p1", &mut home).unwrap();
        assert_eq!(t.acquire("doc:1", m("b"), 500, 1_000, "p1", &mut home), Err(LockError::Held));
        assert!(a.expired(1_001));
        assert!(t.acquire("doc:1", m("b"), 1_001, 1_000, "p1", &mut home).is_ok());
    }

    #[test]
    fn fences_are_monotonic_and_stale_ones_detectable() {
        let mut home = LockHome::default();
        let f1 = home.issue_fence("invoice:42");
        let f2 = home.issue_fence("invoice:42");
        assert!(f2 > f1);
        assert!(home.is_stale("invoice:42", f1));
        assert!(!home.is_stale("invoice:42", f2));
    }

    #[test]
    fn release_frees_the_resource() {
        let mut home = LockHome::default();
        let mut t = LockTable::default();
        let a = t.acquire("doc:1", m("a"), 0, 1_000, "p1", &mut home).unwrap();
        t.release(&a.id);
        assert!(t.acquire("doc:1", m("b"), 1, 1_000, "p1", &mut home).is_ok());
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p vk-contracts locks` → compile error.

- [ ] **Step 3: Implement**

```rust
//! Lock surface (spec §3.4): LEASE for work-in-progress mutual exclusion (AP
//! semantics, exclusive within a partition), fences issued by a lock home for
//! irreversible actions. APPROVAL lives in `principal.rs`.
use crate::principal::Principal;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Lease {
    pub id: String,
    pub resource: String,
    pub holder: Principal,
    pub granted_at_ms: u64,
    pub ttl_ms: u64,
    pub fence: u64,
    /// Diagnostic only (spec §3.4): which connected partition granted it.
    pub partition: String,
}

impl Lease {
    pub fn expired(&self, now_ms: u64) -> bool { now_ms > self.granted_at_ms + self.ttl_ms }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LockError {
    #[error("resource is held by another principal")] Held,
}

/// Per-resource-class fence issuer. Default: the creating node (spec D5).
#[derive(Default)]
pub struct LockHome { next: BTreeMap<String, u64> }

impl LockHome {
    pub fn issue_fence(&mut self, resource: &str) -> u64 {
        let f = self.next.entry(resource.to_string()).or_insert(0);
        *f += 1;
        *f
    }
    pub fn is_stale(&self, resource: &str, fence: u64) -> bool {
        self.next.get(resource).map(|latest| fence < *latest).unwrap_or(true)
    }
}

#[derive(Default)]
pub struct LockTable { leases: BTreeMap<String, Lease>, counter: u64 }

impl LockTable {
    pub fn acquire(&mut self, resource: &str, holder: Principal, now_ms: u64, ttl_ms: u64, partition: &str, home: &mut LockHome)
        -> Result<Lease, LockError> {
        if let Some(existing) = self.leases.values().find(|l| l.resource == resource && l.partition == partition) {
            if !existing.expired(now_ms) && existing.holder != holder { return Err(LockError::Held); }
        }
        self.leases.retain(|_, l| !(l.resource == resource && l.partition == partition));
        self.counter += 1;
        let lease = Lease { id: format!("lease-{}", self.counter), resource: resource.into(), holder, granted_at_ms: now_ms,
            ttl_ms, fence: home.issue_fence(resource), partition: partition.into() };
        self.leases.insert(lease.id.clone(), lease.clone());
        Ok(lease)
    }
    pub fn release(&mut self, lease_id: &str) { self.leases.remove(lease_id); }
    pub fn holder_of(&self, resource: &str, partition: &str, now_ms: u64) -> Option<&Principal> {
        self.leases.values().find(|l| l.resource == resource && l.partition == partition && !l.expired(now_ms)).map(|l| &l.holder)
    }
}
```
Example `wip.json`: `{ "id": "lease-1", "resource": "doc:1", "holder": { "kind": "machine", "node_id": "n1", "lease_id": "l1" }, "granted_at_ms": 0, "ttl_ms": 1000, "fence": 1, "partition": "p1" }`.

- [ ] **Step 4: Regenerate, run** — pass. **Step 5: Commit** — `git commit -m "feat(contracts): lease table, fences and lock home"`.

---

### Task 8: STOP, RESUME and the autonomy liveness lease (I4)

**Files:**
- Create: `crates/vk-contracts/src/stop.rs`, `contracts/examples/stop_event/valid/business_stop.json`
- Modify: `lib.rs` (mod + `("stop_event", …)`, `("resume_event", …)`, `("liveness_lease", …)`)

**Interfaces:**
- Produces: `StopEvent { id, scope, issuer: Principal, hlc_ms, causal_heads }`, `ResumeEvent { id, cites: String, issuer, hlc_ms }`, `StopSet { add_stop, add_resume -> Result<(), StopError>, stopped(scope) -> bool, merge(&other) }`, `LivenessLease { business, renewed_by_device, expires_at_ms }`, `LivenessLease::alive(now) -> bool`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::Principal;

    fn human() -> Principal { Principal::Human { device_id: "phone-1".into() } }
    fn stop(id: &str, scope: &str) -> StopEvent { StopEvent { id: id.into(), scope: scope.into(), issuer: human(), hlc_ms: 1, causal_heads: vec![] } }

    #[test]
    fn stop_is_effective_until_a_resume_cites_it() {
        let mut s = StopSet::default();
        s.add_stop(stop("s1", "business:acme"));
        assert!(s.stopped("business:acme"));
        s.add_resume(ResumeEvent { id: "r1".into(), cites: "s1".into(), issuer: human(), hlc_ms: 2 }).unwrap();
        assert!(!s.stopped("business:acme"));
    }

    #[test]
    fn resume_without_a_known_stop_is_invalid() {
        let mut s = StopSet::default();
        assert_eq!(s.add_resume(ResumeEvent { id: "r1".into(), cites: "ghost".into(), issuer: human(), hlc_ms: 2 }), Err(StopError::UnknownStop));
    }

    #[test]
    fn machine_issued_stop_is_rejected_but_any_human_presence_suffices() {
        let mut s = StopSet::default();
        let m = StopEvent { issuer: Principal::Machine { node_id: "n".into(), lease_id: "l".into() }, ..stop("s1", "x") };
        assert_eq!(s.try_add_stop(m), Err(StopError::NotHuman));
        assert_eq!(s.try_add_stop(stop("s2", "x")), Ok(()));
    }

    #[test]
    fn merge_is_grow_only_so_a_stop_survives_concurrent_resume_of_another_stop() {
        let mut a = StopSet::default(); a.add_stop(stop("s1", "x"));
        let mut b = StopSet::default(); b.add_stop(stop("s2", "x"));
        b.add_resume(ResumeEvent { id: "r2".into(), cites: "s2".into(), issuer: human(), hlc_ms: 3 }).unwrap();
        a.merge(&b);
        assert!(a.stopped("x"), "s1 was never resumed");
    }

    #[test]
    fn liveness_lease_expires() {
        let l = LivenessLease { business: "acme".into(), renewed_by_device: "phone-1".into(), expires_at_ms: 100 };
        assert!(l.alive(99)); assert!(!l.alive(100));
    }
}
```

- [ ] **Step 2: Run to verify failure** — compile error.

- [ ] **Step 3: Implement**

```rust
//! STOP as a kernel primitive and the autonomy liveness lease (spec §3.5, I4).
use crate::principal::Principal;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StopEvent { pub id: String, pub scope: String, pub issuer: Principal, pub hlc_ms: u64, pub causal_heads: Vec<String> }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResumeEvent { pub id: String, pub cites: String, pub issuer: Principal, pub hlc_ms: u64 }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LivenessLease { pub business: String, pub renewed_by_device: String, pub expires_at_ms: u64 }

impl LivenessLease { pub fn alive(&self, now_ms: u64) -> bool { now_ms < self.expires_at_ms } }

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StopError {
    #[error("STOP and RESUME require a human principal")] NotHuman,
    #[error("RESUME cites an unknown STOP")] UnknownStop,
}

/// Grow-only sets; `stopped` is a pure function of causal state (spec §3.5).
#[derive(Default, Debug, Clone)]
pub struct StopSet { stops: BTreeMap<String, StopEvent>, resumes: BTreeMap<String, ResumeEvent> }

impl StopSet {
    pub fn try_add_stop(&mut self, e: StopEvent) -> Result<(), StopError> {
        if !e.issuer.is_human() { return Err(StopError::NotHuman); }
        self.stops.insert(e.id.clone(), e);
        Ok(())
    }
    /// Convenience for tests and channels that already authenticated a human.
    pub fn add_stop(&mut self, e: StopEvent) { self.try_add_stop(e).expect("human-issued stop"); }

    pub fn add_resume(&mut self, e: ResumeEvent) -> Result<(), StopError> {
        if !e.issuer.is_human() { return Err(StopError::NotHuman); }
        if !self.stops.contains_key(&e.cites) { return Err(StopError::UnknownStop); }
        self.resumes.insert(e.id.clone(), e);
        Ok(())
    }

    pub fn stopped(&self, scope: &str) -> bool {
        let resumed: BTreeSet<&String> = self.resumes.values().map(|r| &r.cites).collect();
        self.stops.values().any(|s| s.scope == scope && !resumed.contains(&s.id))
    }

    /// Union of both grow-only sets. Never removes anything (I3-compatible).
    pub fn merge(&mut self, other: &StopSet) {
        for (k, v) in &other.stops { self.stops.entry(k.clone()).or_insert_with(|| v.clone()); }
        for (k, v) in &other.resumes { if self.stops.contains_key(&v.cites) { self.resumes.entry(k.clone()).or_insert_with(|| v.clone()); } }
    }
}
```
Example `business_stop.json`: `{ "id": "s1", "scope": "business:acme", "issuer": { "kind": "human", "device_id": "phone-1" }, "hlc_ms": 1, "causal_heads": [] }`.

- [ ] **Step 4: Regenerate, run** — pass. **Step 5: Commit** — `git commit -m "feat(contracts): STOP/RESUME grow-only sets and liveness lease (I4)"`.

---

### Task 9: Ledger — HLC, three stamps, hash chain, receive guard

**Files:**
- Create: `crates/vk-contracts/src/ledger.rs`, `contracts/examples/ledger_event/valid/first.json`
- Modify: `lib.rs` (mod + `("ledger_event", …)`)

**Interfaces:**
- Produces: `Hlc { wall_ms, counter, node }`, `HlcClock::new(node) / now(&mut self, wall_ms) -> Hlc / receive(&mut self, remote:&Hlc, wall_ms, max_skew_ms) -> Result<Hlc, ClockAnomaly>`, `ClockQuality::{Synced, Unsynced, ManualChangeDetected}`, `RetentionClass::{Ephemeral, Operational90d, Compliance6m, Compliance10y}`, `LedgerEvent { seq, prev_hash, hash, kind, retention, wall_ms, clock_quality, hlc, causal_heads, payload_hash }`, `Ledger { append(kind, retention, wall_ms, quality, hlc, causal_heads, payload_hash) -> &LedgerEvent, verify_chain() -> bool, events() }`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_is_monotonic_even_if_wall_clock_goes_backwards() {
        let mut c = HlcClock::new("n1");
        let a = c.now(1_000);
        let b = c.now(900);
        assert!(b > a);
    }

    #[test]
    fn receive_guard_rejects_far_future_and_flags_anomaly() {
        let mut c = HlcClock::new("n1");
        let remote = Hlc { wall_ms: 10_000_000, counter: 0, node: "evil".into() };
        assert!(matches!(c.receive(&remote, 1_000, 5_000), Err(ClockAnomaly { .. })));
        let ok = Hlc { wall_ms: 1_500, counter: 0, node: "peer".into() };
        assert!(c.receive(&ok, 1_000, 5_000).is_ok());
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let mut l = Ledger::default();
        let mut c = HlcClock::new("n1");
        l.append("task.submitted", RetentionClass::Operational90d, 1, ClockQuality::Synced, c.now(1), vec![], "sha256:p1".into());
        l.append("lease.granted", RetentionClass::Operational90d, 2, ClockQuality::Synced, c.now(2), vec![], "sha256:p2".into());
        assert!(l.verify_chain());
        l.tamper_for_test(0, "sha256:evil");
        assert!(!l.verify_chain());
    }
}
```

- [ ] **Step 2: Run to verify failure** — compile error.

- [ ] **Step 3: Implement**

```rust
//! Per-node hash-chained ledger (spec §3.9): three stamps per event, retention
//! class per event type, receive guard against clock poisoning.
use crate::hash_canonical;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct Hlc { pub wall_ms: u64, pub counter: u32, pub node: String }

pub struct HlcClock { node: String, last: Hlc }

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("clock anomaly from {node}: remote wall {remote_wall_ms} vs local {local_wall_ms}")]
pub struct ClockAnomaly { pub node: String, pub remote_wall_ms: u64, pub local_wall_ms: u64 }

impl HlcClock {
    pub fn new(node: &str) -> Self { Self { node: node.into(), last: Hlc { wall_ms: 0, counter: 0, node: node.into() } } }

    pub fn now(&mut self, wall_ms: u64) -> Hlc {
        if wall_ms > self.last.wall_ms { self.last = Hlc { wall_ms, counter: 0, node: self.node.clone() }; }
        else { self.last.counter += 1; }
        self.last.clone()
    }

    /// Spec §3.9: ignore the physical component of any message beyond `max_skew_ms` ahead.
    pub fn receive(&mut self, remote: &Hlc, wall_ms: u64, max_skew_ms: u64) -> Result<Hlc, ClockAnomaly> {
        if remote.wall_ms > wall_ms + max_skew_ms {
            return Err(ClockAnomaly { node: remote.node.clone(), remote_wall_ms: remote.wall_ms, local_wall_ms: wall_ms });
        }
        let max_wall = wall_ms.max(self.last.wall_ms).max(remote.wall_ms);
        let counter = if max_wall == self.last.wall_ms && max_wall == remote.wall_ms { self.last.counter.max(remote.counter) + 1 }
            else if max_wall == self.last.wall_ms { self.last.counter + 1 }
            else if max_wall == remote.wall_ms { remote.counter + 1 }
            else { 0 };
        self.last = Hlc { wall_ms: max_wall, counter, node: self.node.clone() };
        Ok(self.last.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClockQuality { Synced, Unsynced, ManualChangeDetected }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass { Ephemeral, Operational90d, Compliance6m, Compliance10y }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LedgerEvent {
    pub seq: u64,
    pub prev_hash: String,
    pub hash: String,
    pub kind: String,
    pub retention: RetentionClass,
    pub wall_ms: u64,
    pub clock_quality: ClockQuality,
    pub hlc: Hlc,
    pub causal_heads: Vec<String>,
    /// Commits to ciphertext, never to plaintext (spec §3.9).
    pub payload_hash: String,
}

#[derive(Serialize)]
struct Unhashed<'a> { seq: u64, prev_hash: &'a str, kind: &'a str, retention: RetentionClass, wall_ms: u64, clock_quality: ClockQuality, hlc: &'a Hlc, causal_heads: &'a [String], payload_hash: &'a str }

#[derive(Default)]
pub struct Ledger { events: Vec<LedgerEvent> }

impl Ledger {
    #[allow(clippy::too_many_arguments)]
    pub fn append(&mut self, kind: &str, retention: RetentionClass, wall_ms: u64, clock_quality: ClockQuality, hlc: Hlc, causal_heads: Vec<String>, payload_hash: String) -> &LedgerEvent {
        let seq = self.events.len() as u64;
        let prev_hash = self.events.last().map(|e| e.hash.clone()).unwrap_or_else(|| "sha256:genesis".into());
        let hash = hash_canonical(&Unhashed { seq, prev_hash: &prev_hash, kind, retention, wall_ms, clock_quality, hlc: &hlc, causal_heads: &causal_heads, payload_hash: &payload_hash });
        self.events.push(LedgerEvent { seq, prev_hash, hash, kind: kind.into(), retention, wall_ms, clock_quality, hlc, causal_heads, payload_hash });
        self.events.last().unwrap()
    }

    pub fn verify_chain(&self) -> bool {
        let mut prev = "sha256:genesis".to_string();
        for e in &self.events {
            if e.prev_hash != prev { return false; }
            let recomputed = hash_canonical(&Unhashed { seq: e.seq, prev_hash: &e.prev_hash, kind: &e.kind, retention: e.retention, wall_ms: e.wall_ms, clock_quality: e.clock_quality, hlc: &e.hlc, causal_heads: &e.causal_heads, payload_hash: &e.payload_hash });
            if recomputed != e.hash { return false; }
            prev = e.hash.clone();
        }
        true
    }

    pub fn events(&self) -> &[LedgerEvent] { &self.events }

    #[doc(hidden)]
    pub fn tamper_for_test(&mut self, idx: usize, payload_hash: &str) { self.events[idx].payload_hash = payload_hash.into(); }
}
```
Example `first.json`: one event with `"seq": 0, "prev_hash": "sha256:genesis", "hash": "sha256:0000", "kind": "task.submitted", "retention": "operational90d", "wall_ms": 1, "clock_quality": "synced", "hlc": {"wall_ms":1,"counter":0,"node":"n1"}, "causal_heads": [], "payload_hash": "sha256:p1"`.

- [ ] **Step 4: Regenerate, run** — pass. **Step 5: Commit** — `git commit -m "feat(contracts): hash-chained ledger with HLC and receive guard"`.

---

### Task 10: Storage tiering — blob envelopes, shred, metadata G-set with conflict surfacing (I3)

**Files:**
- Create: `crates/vk-contracts/src/storage.rs`, `contracts/examples/blob_envelope/valid/artefact.json`, `contracts/examples/shred_event/valid/subject.json`
- Modify: `lib.rs` (mod + `("blob_envelope", …)`, `("shred_event", …)`)

**Interfaces:**
- Produces: `BlobEnvelope { hash, key_id, alg, ciphertext_len, label }`, `ShredEvent { key_id, issuer: Principal, hlc_ms }`, `BlobStore { put(envelope, bytes), get(hash) -> Result<Vec<u8>, StorageError>, shred(ShredEvent) }`, `MetadataDoc<T> { writes: BTreeMap<String, T>, conflicts: Vec<Conflict<T>> }`, `MetadataDoc::write(key, value, node)`, `MetadataDoc::merge(&other) -> MergeReport { kept, conflicts_surfaced }`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::Label;
    use crate::principal::Principal;

    fn env(hash: &str, key: &str) -> BlobEnvelope { BlobEnvelope { hash: hash.into(), key_id: key.into(), alg: "xchacha20poly1305".into(), ciphertext_len: 3, label: Label::bottom() } }

    #[test]
    fn shred_makes_every_blob_under_that_key_unreadable() {
        let mut s = BlobStore::default();
        s.put(env("sha256:a", "subject-1"), b"abc".to_vec());
        s.put(env("sha256:b", "subject-2"), b"def".to_vec());
        s.shred(ShredEvent { key_id: "subject-1".into(), issuer: Principal::Human { device_id: "d".into() }, hlc_ms: 1 });
        assert_eq!(s.get("sha256:a"), Err(StorageError::Shredded));
        assert_eq!(s.get("sha256:b"), Ok(b"def".to_vec()));
    }

    #[test]
    fn merge_never_drops_a_write_and_surfaces_conflicts() {
        let mut a = MetadataDoc::<String>::default();
        let mut b = MetadataDoc::<String>::default();
        a.write("k1", "from-a".into(), "node-a");
        b.write("k1", "from-b".into(), "node-b");
        b.write("k2", "only-b".into(), "node-b");
        let report = a.merge(&b);
        assert_eq!(report.conflicts_surfaced, 1);
        assert_eq!(a.conflicts.len(), 1);
        assert!(a.writes.contains_key("k2"));
        let all: Vec<&String> = a.conflicts[0].values.iter().map(|(_, v)| v).collect();
        assert!(all.contains(&&"from-a".to_string()) && all.contains(&&"from-b".to_string()));
    }
}
```

- [ ] **Step 2: Run to verify failure** — compile error.

- [ ] **Step 3: Implement**

```rust
//! Storage tiering (spec §3.9): payloads are encrypted, content-addressed blobs
//! under per-subject keys; erasure = shred the key. Metadata documents merge
//! without silent loss (invariant I3): conflicts are surfaced, never resolved by
//! last-writer-wins.
use crate::labels::Label;
use crate::principal::Principal;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BlobEnvelope { pub hash: String, pub key_id: String, pub alg: String, pub ciphertext_len: u64, pub label: Label }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShredEvent { pub key_id: String, pub issuer: Principal, pub hlc_ms: u64 }

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("blob not found")] NotFound,
    #[error("key shredded; ciphertext unreadable")] Shredded,
}

/// In-memory stand-in: real encryption arrives in SP1; the contract is the key/shred semantics.
#[derive(Default)]
pub struct BlobStore { blobs: BTreeMap<String, (BlobEnvelope, Vec<u8>)>, shredded: BTreeSet<String> }

impl BlobStore {
    pub fn put(&mut self, envelope: BlobEnvelope, bytes: Vec<u8>) { self.blobs.insert(envelope.hash.clone(), (envelope, bytes)); }
    pub fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let (env, bytes) = self.blobs.get(hash).ok_or(StorageError::NotFound)?;
        if self.shredded.contains(&env.key_id) { return Err(StorageError::Shredded); }
        Ok(bytes.clone())
    }
    pub fn shred(&mut self, e: ShredEvent) { self.shredded.insert(e.key_id); }
    pub fn is_shredded(&self, key_id: &str) -> bool { self.shredded.contains(key_id) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict<T> { pub key: String, pub values: Vec<(String, T)> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeReport { pub kept: usize, pub conflicts_surfaced: usize }

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataDoc<T: Clone + PartialEq> { pub writes: BTreeMap<String, T>, pub authors: BTreeMap<String, String>, pub conflicts: Vec<Conflict<T>> }

impl<T: Clone + PartialEq> MetadataDoc<T> {
    pub fn write(&mut self, key: &str, value: T, node: &str) {
        self.writes.insert(key.into(), value);
        self.authors.insert(key.into(), node.into());
    }

    /// I3: every write from `other` is either adopted, already present, or recorded as a conflict.
    pub fn merge(&mut self, other: &MetadataDoc<T>) -> MergeReport {
        let mut kept = 0; let mut conflicts_surfaced = 0;
        for (k, v) in &other.writes {
            match self.writes.get(k) {
                None => { self.writes.insert(k.clone(), v.clone()); self.authors.insert(k.clone(), other.authors[k].clone()); kept += 1; }
                Some(mine) if mine == v => { kept += 1; }
                Some(mine) => {
                    self.conflicts.push(Conflict { key: k.clone(), values: vec![(self.authors[k].clone(), mine.clone()), (other.authors[k].clone(), v.clone())] });
                    conflicts_surfaced += 1;
                }
            }
        }
        for c in &other.conflicts { if !self.conflicts.contains(c) { self.conflicts.push(c.clone()); } }
        MergeReport { kept, conflicts_surfaced }
    }
}
```
Examples: `artefact.json` = `{ "hash": "sha256:a", "key_id": "subject-1", "alg": "xchacha20poly1305", "ciphertext_len": 3, "label": {"scope":"personal","data_class":"own","origins":[]} }`; `subject.json` = `{ "key_id": "subject-1", "issuer": {"kind":"human","device_id":"phone-1"}, "hlc_ms": 1 }`.

- [ ] **Step 4: Regenerate, run** — pass. **Step 5: Commit** — `git commit -m "feat(contracts): blob envelopes, shred semantics, conflict-surfacing metadata merge (I3)"`.

---

### Task 11: Module, validator and gate-verdict formats

**Files:**
- Create: `crates/vk-contracts/src/module.rs`, `contracts/examples/module_manifest/valid/skill.json`, `contracts/examples/module_manifest/invalid/wrong_kind.json`, `contracts/examples/validator_manifest/valid/quote_totals.json`, `contracts/examples/gate_verdict/valid/annex3_pass.json`
- Modify: `lib.rs` (mod + three registry entries)

**Interfaces:**
- Produces: `ModuleKind::{Skill, Process, Automation}`, `AutonomyProfile { human_required_kinds: BTreeSet<String>, auto_approve_allowed: bool }`, `Provenance { content_hash, lineage, signer, arch_compat, origin_taints }`, `ModuleManifest { name, kind, version, machine_evolved, files, provenance, pool_epoch, autonomy_profile, tags }`, `ModuleManifest::validate() -> Result<(), ModuleError>`, `ValidatorManifest { name, artefact_type, anchor_suite, signers, community }`, `ValidatorManifest::validate()`, `GateKind::{AnnexIii, Declassification, OutputMarking}`, `GateVerdict { gate, subject_hash, pass, evidence_hash, signer }`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn skill(files: &[&str], evolved: bool) -> ModuleManifest {
        ModuleManifest { name: "quote-drafter".into(), kind: ModuleKind::Skill, version: "0.1.0".into(), machine_evolved: evolved,
            files: files.iter().map(|s| s.to_string()).collect(),
            provenance: Provenance { content_hash: "sha256:c".into(), lineage: vec![], signer: "founder".into(), arch_compat: vec![], origin_taints: Default::default() },
            pool_epoch: None, autonomy_profile: None, tags: Default::default() }
    }

    #[test]
    fn machine_evolved_modules_may_not_contain_scripts_or_validators() {
        assert!(skill(&["SKILL.md", "references/style.md"], true).validate().is_ok());
        assert_eq!(skill(&["SKILL.md", "scripts/run.py"], true).validate(), Err(ModuleError::ScriptInEvolvedModule("scripts/run.py".into())));
        assert_eq!(skill(&["SKILL.md", "validators/totals.json"], true).validate(), Err(ModuleError::ValidatorInEvolvedModule("validators/totals.json".into())));
        assert!(skill(&["SKILL.md", "scripts/run.py"], false).validate().is_ok(), "human-authored modules may ship scripts");
    }

    #[test]
    fn decision_about_person_modules_cannot_be_auto_approved() {
        let mut m = skill(&["SKILL.md"], false);
        m.tags.insert("decision_about_person".into());
        m.autonomy_profile = Some(AutonomyProfile { human_required_kinds: Default::default(), auto_approve_allowed: true });
        assert_eq!(m.validate(), Err(ModuleError::AutoApproveForbidden));
    }

    #[test]
    fn community_validators_need_two_signers() {
        let v = ValidatorManifest { name: "quote-totals".into(), artefact_type: "quote".into(), anchor_suite: vec![], signers: vec!["a".into()], community: true };
        assert_eq!(v.validate(), Err(ValidatorError::CommunityNeedsTwoSigners));
    }
}
```

- [ ] **Step 2: Run to verify failure** — compile error.

- [ ] **Step 3: Implement**

```rust
//! Module, validator and gate-verdict formats (spec §4.1, §4.3, D11).
use crate::labels::Origin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind { Skill, Process, Automation }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AutonomyProfile { pub human_required_kinds: BTreeSet<String>, pub auto_approve_allowed: bool }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Provenance { pub content_hash: String, pub lineage: Vec<String>, pub signer: String, pub arch_compat: Vec<String>, pub origin_taints: BTreeSet<Origin> }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ModuleManifest {
    pub name: String,
    pub kind: ModuleKind,
    pub version: String,
    pub machine_evolved: bool,
    pub files: Vec<String>,
    pub provenance: Provenance,
    pub pool_epoch: Option<String>,
    pub autonomy_profile: Option<AutonomyProfile>,
    pub tags: BTreeSet<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModuleError {
    #[error("machine-evolved module contains a script: {0}")] ScriptInEvolvedModule(String),
    #[error("machine-evolved module contains a validator: {0}")] ValidatorInEvolvedModule(String),
    #[error("modules tagged decision_about_person cannot allow auto-approval (GDPR Art. 22)")] AutoApproveForbidden,
}

const SCRIPT_EXTENSIONS: &[&str] = &["py", "sh", "ps1", "bat", "cmd", "js", "ts", "exe", "dll", "so", "dylib", "wasm", "rb", "php"];

impl ModuleManifest {
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.machine_evolved {
            for f in &self.files {
                let ext = f.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
                if SCRIPT_EXTENSIONS.contains(&ext.as_str()) { return Err(ModuleError::ScriptInEvolvedModule(f.clone())); }
                if f.starts_with("validators/") { return Err(ModuleError::ValidatorInEvolvedModule(f.clone())); }
            }
        }
        if self.tags.contains("decision_about_person") {
            if let Some(p) = &self.autonomy_profile { if p.auto_approve_allowed { return Err(ModuleError::AutoApproveForbidden); } }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnchorCase { pub input_hash: String, pub expected_pass: bool }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ValidatorManifest { pub name: String, pub artefact_type: String, pub anchor_suite: Vec<AnchorCase>, pub signers: Vec<String>, pub community: bool }

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidatorError {
    #[error("community validators require two signers")] CommunityNeedsTwoSigners,
}

impl ValidatorManifest {
    pub fn validate(&self) -> Result<(), ValidatorError> {
        if self.community && self.signers.len() < 2 { return Err(ValidatorError::CommunityNeedsTwoSigners); }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GateKind { AnnexIii, Declassification, OutputMarking }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GateVerdict { pub gate: GateKind, pub subject_hash: String, pub pass: bool, pub evidence_hash: String, pub signer: String }
```
Examples: `skill.json` = JSON of `skill(&["SKILL.md"], false)`; `wrong_kind.json` = same with `"kind": "plugin"`; `quote_totals.json` = `{ "name": "quote-totals", "artefact_type": "quote", "anchor_suite": [{"input_hash":"sha256:q1","expected_pass":true}], "signers": ["founder"], "community": false }`; `annex3_pass.json` = `{ "gate": "annex_iii", "subject_hash": "sha256:c", "pass": true, "evidence_hash": "sha256:e", "signer": "founder" }`.

- [ ] **Step 4: Regenerate, run** — pass. **Step 5: Commit** — `git commit -m "feat(contracts): module, validator and gate-verdict formats with D11 rules"`.

---

### Task 12: The syscall surface — `Kernel` trait, `Ctx`, errors

**Files:**
- Create: `crates/vk-contracts/src/syscalls.rs`
- Modify: `lib.rs` (mod + `("syscall_ctx", schema_for!(syscalls::Ctx))`)

**Interfaces:**
- Produces (used verbatim by Tasks 13–14):

```rust
pub struct Ctx { pub principal: Principal, pub clearance: Clearance, pub partition: String, pub now_ms: u64 }
pub enum KernelError { I1(String), I2(String), I3(String), I4(String), I4Prime(String), Stopped(String), Lock(LockError), Principal(PrincipalError), Stop(StopError), Module(ModuleError), Gate(String), NotFound(String) }
pub struct InferOutcome { pub arch_id: String, pub projected: bool, pub tokens_in: u32 }
pub trait Kernel {
    fn submit_task(&mut self, ctx: &Ctx, goal: &str, label: Label) -> Result<RegisterId, KernelError>;
    fn read_register(&mut self, ctx: &Ctx, id: &RegisterId) -> Result<Register, KernelError>;
    fn write_register(&mut self, ctx: &Ctx, reg: Register) -> Result<(), KernelError>;
    fn infer(&mut self, ctx: &Ctx, arch_id: &str, capability: Capability, reg: &RegisterId) -> Result<InferOutcome, KernelError>;
    fn lease(&mut self, ctx: &Ctx, resource: &str, ttl_ms: u64) -> Result<Lease, KernelError>;
    fn approve(&mut self, ctx: &Ctx, approval: Approval) -> Result<(), KernelError>;
    fn stop(&mut self, ctx: &Ctx, scope: &str) -> Result<String, KernelError>;
    fn resume(&mut self, ctx: &Ctx, stop_id: &str) -> Result<(), KernelError>;
    fn run_automation(&mut self, ctx: &Ctx, business: &str, module: &str) -> Result<(), KernelError>;
    fn promote(&mut self, ctx: &Ctx, module: &ModuleManifest, verdicts: &[GateVerdict]) -> Result<(), KernelError>;
    fn export(&mut self, ctx: &Ctx, module_hash: &str, to_scope: Scope, verdicts: &[GateVerdict]) -> Result<(), KernelError>;
    fn ledger(&self) -> &Ledger;
}
```

- [ ] **Step 1: Write the file (no test — it is a trait; the stub's tests cover it)**

```rust
//! The syscall surface (spec §3.11). Userland reaches arches, registers and
//! approvals only through this trait; interceptors enforce I1–I4′ on every call.
use crate::arch::Capability;
use crate::labels::{Clearance, Label, Scope};
use crate::ledger::Ledger;
use crate::locks::{Lease, LockError};
use crate::module::{GateVerdict, ModuleError, ModuleManifest};
use crate::principal::{Approval, Principal, PrincipalError};
use crate::register::{Register, RegisterId};
use crate::stop::StopError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Built by the channel layer from an authenticated connection — never by userland.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Ctx { pub principal: Principal, pub clearance: Clearance, pub partition: String, pub now_ms: u64 }

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KernelError {
    #[error("I1 violated: {0}")] I1(String),
    #[error("I2 violated: {0}")] I2(String),
    #[error("I3 violated: {0}")] I3(String),
    #[error("I4 violated: {0}")] I4(String),
    #[error("I4' violated: {0}")] I4Prime(String),
    #[error("scope is stopped: {0}")] Stopped(String),
    #[error(transparent)] Lock(#[from] LockError),
    #[error(transparent)] Principal(#[from] PrincipalError),
    #[error(transparent)] Stop(#[from] StopError),
    #[error(transparent)] Module(#[from] ModuleError),
    #[error("gate verdict missing or failed: {0}")] Gate(String),
    #[error("not found: {0}")] NotFound(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferOutcome { pub arch_id: String, pub projected: bool, pub tokens_in: u32 }

pub trait Kernel {
    fn submit_task(&mut self, ctx: &Ctx, goal: &str, label: Label) -> Result<RegisterId, KernelError>;
    fn read_register(&mut self, ctx: &Ctx, id: &RegisterId) -> Result<Register, KernelError>;
    fn write_register(&mut self, ctx: &Ctx, reg: Register) -> Result<(), KernelError>;
    fn infer(&mut self, ctx: &Ctx, arch_id: &str, capability: Capability, reg: &RegisterId) -> Result<InferOutcome, KernelError>;
    fn lease(&mut self, ctx: &Ctx, resource: &str, ttl_ms: u64) -> Result<Lease, KernelError>;
    fn approve(&mut self, ctx: &Ctx, approval: Approval) -> Result<(), KernelError>;
    fn stop(&mut self, ctx: &Ctx, scope: &str) -> Result<String, KernelError>;
    fn resume(&mut self, ctx: &Ctx, stop_id: &str) -> Result<(), KernelError>;
    /// Non-human-initiated execution of a Hot automation; gated by STOP and the liveness lease (I4).
    fn run_automation(&mut self, ctx: &Ctx, business: &str, module: &str) -> Result<(), KernelError>;
    fn promote(&mut self, ctx: &Ctx, module: &ModuleManifest, verdicts: &[GateVerdict]) -> Result<(), KernelError>;
    fn export(&mut self, ctx: &Ctx, module_hash: &str, to_scope: Scope, verdicts: &[GateVerdict]) -> Result<(), KernelError>;
    fn ledger(&self) -> &Ledger;
}
```

- [ ] **Step 2: Build, regenerate, run** — `cargo build --workspace && cargo run -p vk-contracts --bin gen-schemas && cargo test -p vk-contracts` → pass.

- [ ] **Step 3: Commit** — `git commit -m "feat(contracts): Kernel syscall trait, Ctx and error surface"`.

---

### Task 13: Stub kernel with interceptors

**Files:**
- Create: `crates/vk-stub/Cargo.toml`, `crates/vk-stub/src/lib.rs`, `crates/vk-stub/src/interceptors.rs`

**Interfaces:**
- Consumes: everything from Task 12.
- Produces: `StubKernel::new(node_id)`, `StubKernel::register_arch(ArchManifest) -> String`, `StubKernel::enroll_device(device_id, vk_bytes)`, `StubKernel::renew_liveness(business, device_id, expires_at_ms)`, `StubKernel::set_context_budget(arch_id, tokens)` (test hook), `StubKernel::approvals_for(subject_hash) -> Vec<Approval>`, `StubKernel::hot_modules() -> Vec<String>`, `StubKernel::infer_log() -> &[(String, Label)]` (arch_id, label of what it received — the I2 oracle).

- [ ] **Step 1: Failing unit tests (in `crates/vk-stub/src/lib.rs`)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vk_contracts::arch::*;
    use vk_contracts::labels::*;
    use vk_contracts::principal::*;
    use vk_contracts::syscalls::*;

    fn gemma(clearance: Clearance) -> ArchManifest {
        ArchManifest { name: "gemma".into(), capabilities: [Capability::Generate].into(), locality: Locality::Local, jurisdiction: "FR".into(),
            retention_days: None, cost_per_1k_tokens_eur: 0.0, latency_ms_p50: 1, context_ceiling: 100, determinism: Determinism::SeededDeterministic,
            identity: ArchIdentity { weights_sha256: "sha256:w".into(), engine: "e".into(), engine_version: "1".into(), backend: "cpu".into(), quant: "q4".into(),
                kv_cache: "f16".into(), threads: 1, batch: 1, sampling: Default::default(), seed: None }, clearance, governed: true }
    }
    fn machine_ctx(now: u64) -> Ctx { Ctx { principal: Principal::Machine { node_id: "n1".into(), lease_id: "l1".into() }, clearance: Clearance { max_scope: Scope::Personal, third_party_allowed: true }, partition: "p1".into(), now_ms: now } }
    fn human_ctx(now: u64) -> Ctx { Ctx { principal: Principal::Human { device_id: "phone-1".into() }, ..machine_ctx(now) } }

    #[test]
    fn i2_infer_refuses_register_above_arch_clearance() {
        let mut k = StubKernel::new("n1");
        let cloud = k.register_arch(ArchManifest { locality: Locality::Cloud, clearance: Clearance { max_scope: Scope::Business, third_party_allowed: false }, ..gemma(Clearance { max_scope: Scope::Public, third_party_allowed: false }) });
        let ctx = machine_ctx(1);
        let r = k.submit_task(&ctx, "draft", Label { scope: Scope::Personal, data_class: DataClass::Own, origins: Default::default() }).unwrap();
        assert!(matches!(k.infer(&ctx, &cloud, Capability::Generate, &r), Err(KernelError::I2(_))));
        assert!(k.infer_log().is_empty());
    }

    #[test]
    fn i1_machine_cannot_approve_as_human_but_stop_needs_only_presence() {
        let mut k = StubKernel::new("n1");
        let ap = Approval { subject_hash: "sha256:m".into(), kind: ApprovalKind::Human, approver: Principal::Human { device_id: "phone-1".into() }, challenge: None, signature_hex: None };
        assert!(matches!(k.approve(&machine_ctx(1), ap.clone()), Err(KernelError::I1(_))));
        assert!(matches!(k.stop(&machine_ctx(1), "business:acme"), Err(KernelError::I1(_))));
        assert!(k.stop(&human_ctx(1), "business:acme").is_ok());
    }

    #[test]
    fn i4_automation_needs_liveness_and_no_stop() {
        let mut k = StubKernel::new("n1");
        let m = machine_ctx(10);
        assert!(matches!(k.run_automation(&m, "acme", "mod"), Err(KernelError::I4(_))));
        k.renew_liveness("acme", "phone-1", 100);
        assert!(k.run_automation(&m, "acme", "mod").is_ok());
        let s = k.stop(&human_ctx(11), "business:acme").unwrap();
        assert!(matches!(k.run_automation(&m, "acme", "mod"), Err(KernelError::Stopped(_))));
        k.resume(&human_ctx(12), &s).unwrap();
        assert!(k.run_automation(&m, "acme", "mod").is_ok());
        assert!(matches!(k.run_automation(&machine_ctx(100), "acme", "mod"), Err(KernelError::I4(_))));
    }

    #[test]
    fn i4_prime_over_budget_lowering_is_refused_or_logged_projection() {
        let mut k = StubKernel::new("n1");
        let arch = k.register_arch(gemma(Clearance { max_scope: Scope::Personal, third_party_allowed: true }));
        k.set_context_budget(&arch, 5);
        let ctx = machine_ctx(1);
        let r = k.submit_task(&ctx, &"x".repeat(50), Label::bottom()).unwrap();
        let out = k.infer(&ctx, &arch, Capability::Generate, &r).unwrap();
        assert!(out.projected);
        assert!(k.ledger().events().iter().any(|e| e.kind == "infer.projected"));
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p vk-stub` → compile errors.

- [ ] **Step 3: Implement**

`crates/vk-stub/Cargo.toml`:
```toml
[package]
name = "vk-stub"
version = "0.1.0"
edition.workspace = true
license.workspace = true
description = "In-memory stub kernel for invariant testing"

[dependencies]
vk-contracts = { path = "../vk-contracts" }
serde_json.workspace = true
```

`crates/vk-stub/src/interceptors.rs`:
```rust
//! Interceptors (spec §3.11): decidable invariants only.
use vk_contracts::labels::Label;
use vk_contracts::principal::{Approval, ApprovalKind, DeviceRegistry, Principal};
use vk_contracts::stop::{LivenessLease, StopSet};
use vk_contracts::syscalls::KernelError;
use vk_contracts::arch::ArchManifest;

/// I1: human approvals only from human ceremonies; STOP/RESUME require human presence.
pub fn i1_approval(ctx_principal: &Principal, ap: &Approval, devices: &DeviceRegistry, now_ms: u64) -> Result<(), KernelError> {
    if ap.kind == ApprovalKind::Human {
        if !ctx_principal.is_human() || ap.approver != *ctx_principal {
            return Err(KernelError::I1("human approval requires the human's own authenticated channel".into()));
        }
        ap.verify_human(devices, now_ms)?;
    }
    Ok(())
}

pub fn i1_presence(ctx_principal: &Principal) -> Result<(), KernelError> {
    if ctx_principal.is_human() { Ok(()) } else { Err(KernelError::I1("STOP/RESUME require a human principal".into())) }
}

/// I2: the register's label must flow to the arch's effective clearance.
pub fn i2_flow(label: &Label, arch: &ArchManifest) -> Result<(), KernelError> {
    if label.flows_to(&arch.clearance) { Ok(()) }
    else { Err(KernelError::I2(format!("label {:?} exceeds clearance of arch {}", label.scope, arch.name))) }
}

/// I4: machine-initiated automation needs an unexpired liveness lease and no active STOP.
pub fn i4_liveness(business: &str, lease: Option<&LivenessLease>, stops: &StopSet, now_ms: u64) -> Result<(), KernelError> {
    let scope = format!("business:{business}");
    if stops.stopped(&scope) { return Err(KernelError::Stopped(scope)); }
    match lease {
        Some(l) if l.alive(now_ms) => Ok(()),
        _ => Err(KernelError::I4(format!("no live autonomy lease for {business}"))),
    }
}
```

`crates/vk-stub/src/lib.rs`:
```rust
//! In-memory stub kernel: enough behaviour to test invariants I1–I4′.
pub mod interceptors;

use std::collections::BTreeMap;
use vk_contracts::arch::{ArchManifest, Capability};
use vk_contracts::hash_canonical;
use vk_contracts::labels::{Label, Scope};
use vk_contracts::ledger::{ClockQuality, HlcClock, Ledger, RetentionClass};
use vk_contracts::locks::{Lease, LockHome, LockTable};
use vk_contracts::module::{GateKind, GateVerdict, ModuleManifest};
use vk_contracts::principal::{Approval, ApprovalKind, DeviceRegistry, Principal};
use vk_contracts::register::{Register, RegisterId};
use vk_contracts::stop::{LivenessLease, ResumeEvent, StopEvent, StopSet};
use vk_contracts::syscalls::{Ctx, InferOutcome, Kernel, KernelError};

pub struct StubKernel {
    node_id: String,
    clock: HlcClock,
    ledger: Ledger,
    registers: BTreeMap<RegisterId, Register>,
    arches: BTreeMap<String, ArchManifest>,
    budgets: BTreeMap<String, u32>,
    locks: LockTable,
    home: LockHome,
    devices: DeviceRegistry,
    approvals: Vec<Approval>,
    stops: StopSet,
    liveness: BTreeMap<String, LivenessLease>,
    hot: Vec<String>,
    infer_log: Vec<(String, Label)>,
    counter: u64,
}

impl StubKernel {
    pub fn new(node_id: &str) -> Self {
        Self { node_id: node_id.into(), clock: HlcClock::new(node_id), ledger: Ledger::default(), registers: BTreeMap::new(), arches: BTreeMap::new(),
            budgets: BTreeMap::new(), locks: LockTable::default(), home: LockHome::default(), devices: DeviceRegistry::default(), approvals: vec![],
            stops: StopSet::default(), liveness: BTreeMap::new(), hot: vec![], infer_log: vec![], counter: 0 }
    }
    pub fn register_arch(&mut self, m: ArchManifest) -> String { let id = m.arch_id(); self.budgets.insert(id.clone(), m.context_ceiling); self.arches.insert(id.clone(), m); id }
    pub fn enroll_device(&mut self, device_id: &str, vk: [u8; 32]) { self.devices.register(device_id.into(), vk); }
    pub fn renew_liveness(&mut self, business: &str, device_id: &str, expires_at_ms: u64) {
        self.liveness.insert(business.into(), LivenessLease { business: business.into(), renewed_by_device: device_id.into(), expires_at_ms });
    }
    pub fn set_context_budget(&mut self, arch_id: &str, tokens: u32) { self.budgets.insert(arch_id.into(), tokens); }
    pub fn approvals_for(&self, subject_hash: &str) -> Vec<Approval> { self.approvals.iter().filter(|a| a.subject_hash == subject_hash).cloned().collect() }
    pub fn hot_modules(&self) -> Vec<String> { self.hot.clone() }
    pub fn infer_log(&self) -> &[(String, Label)] { &self.infer_log }
    pub fn stops(&self) -> &StopSet { &self.stops }

    fn log(&mut self, kind: &str, now_ms: u64, payload: &impl serde::Serialize) {
        let hlc = self.clock.now(now_ms);
        let payload_hash = hash_canonical(payload);
        self.ledger.append(kind, RetentionClass::Operational90d, now_ms, ClockQuality::Synced, hlc, vec![], payload_hash);
    }
    fn next_id(&mut self, prefix: &str) -> String { self.counter += 1; format!("{prefix}-{}-{}", self.node_id, self.counter) }
    /// Rough token estimate for the stub: 1 token per 4 bytes of goal + evidence.
    fn estimate_tokens(reg: &Register) -> u32 { ((reg.goal.len() + reg.evidence.iter().map(|e| e.content.len()).sum::<usize>()) / 4) as u32 + 1 }
}

impl Kernel for StubKernel {
    fn submit_task(&mut self, ctx: &Ctx, goal: &str, label: Label) -> Result<RegisterId, KernelError> {
        let id = RegisterId(self.next_id("reg"));
        let reg = Register { id: id.clone(), task_id: self.next_id("task"), label, goal: goal.into(), constraints: vec![], evidence: vec![], decisions: vec![], open_questions: vec![], artefacts: vec![] };
        self.registers.insert(id.clone(), reg);
        self.log("task.submitted", ctx.now_ms, &id);
        Ok(id)
    }

    fn read_register(&mut self, ctx: &Ctx, id: &RegisterId) -> Result<Register, KernelError> {
        let reg = self.registers.get(id).cloned().ok_or_else(|| KernelError::NotFound(id.0.clone()))?;
        if !reg.label.flows_to(&ctx.clearance) { return Err(KernelError::I2(format!("register {} exceeds caller clearance", id.0))); }
        Ok(reg)
    }

    fn write_register(&mut self, ctx: &Ctx, reg: Register) -> Result<(), KernelError> {
        self.log("register.written", ctx.now_ms, &reg.id);
        self.registers.insert(reg.id.clone(), reg);
        Ok(())
    }

    fn infer(&mut self, ctx: &Ctx, arch_id: &str, _capability: Capability, reg_id: &RegisterId) -> Result<InferOutcome, KernelError> {
        let arch = self.arches.get(arch_id).cloned().ok_or_else(|| KernelError::NotFound(arch_id.into()))?;
        let reg = self.registers.get(reg_id).cloned().ok_or_else(|| KernelError::NotFound(reg_id.0.clone()))?;
        interceptors::i2_flow(&reg.label, &arch)?;
        let tokens = Self::estimate_tokens(&reg);
        let budget = *self.budgets.get(arch_id).unwrap_or(&arch.context_ceiling);
        let projected = tokens > budget;
        if projected { self.log("infer.projected", ctx.now_ms, &(arch_id, tokens, budget)); }
        self.log("infer", ctx.now_ms, &(arch_id, reg_id));
        self.infer_log.push((arch_id.into(), reg.label.clone()));
        Ok(InferOutcome { arch_id: arch_id.into(), projected, tokens_in: tokens.min(budget) })
    }

    fn lease(&mut self, ctx: &Ctx, resource: &str, ttl_ms: u64) -> Result<Lease, KernelError> {
        let l = self.locks.acquire(resource, ctx.principal.clone(), ctx.now_ms, ttl_ms, &ctx.partition, &mut self.home)?;
        self.log("lease.granted", ctx.now_ms, &l.id);
        Ok(l)
    }

    fn approve(&mut self, ctx: &Ctx, approval: Approval) -> Result<(), KernelError> {
        interceptors::i1_approval(&ctx.principal, &approval, &self.devices, ctx.now_ms)?;
        self.log("approval.recorded", ctx.now_ms, &approval);
        self.approvals.push(approval);
        Ok(())
    }

    fn stop(&mut self, ctx: &Ctx, scope: &str) -> Result<String, KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        let id = self.next_id("stop");
        self.stops.try_add_stop(StopEvent { id: id.clone(), scope: scope.into(), issuer: ctx.principal.clone(), hlc_ms: ctx.now_ms, causal_heads: vec![] })?;
        self.log("stop", ctx.now_ms, &id);
        Ok(id)
    }

    fn resume(&mut self, ctx: &Ctx, stop_id: &str) -> Result<(), KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        let id = self.next_id("resume");
        self.stops.add_resume(ResumeEvent { id, cites: stop_id.into(), issuer: ctx.principal.clone(), hlc_ms: ctx.now_ms })?;
        self.log("resume", ctx.now_ms, &stop_id);
        Ok(())
    }

    fn run_automation(&mut self, ctx: &Ctx, business: &str, module: &str) -> Result<(), KernelError> {
        if ctx.principal.is_human() { return Ok(()); } // human-initiated runs are not automations
        interceptors::i4_liveness(business, self.liveness.get(business), &self.stops, ctx.now_ms)?;
        self.log("automation.ran", ctx.now_ms, &(business, module));
        Ok(())
    }

    fn promote(&mut self, ctx: &Ctx, module: &ModuleManifest, verdicts: &[GateVerdict]) -> Result<(), KernelError> {
        module.validate()?;
        let subject = module.provenance.content_hash.clone();
        if !verdicts.iter().any(|v| v.gate == GateKind::AnnexIii && v.subject_hash == subject && v.pass) {
            return Err(KernelError::Gate("annex_iii verdict required for promotion".into()));
        }
        let needs_human = module.autonomy_profile.as_ref().map(|p| !p.auto_approve_allowed).unwrap_or(true);
        let has_human = self.approvals.iter().any(|a| a.subject_hash == subject && a.kind == ApprovalKind::Human);
        if needs_human && !has_human { return Err(KernelError::I1(format!("promotion of {} requires a human approval", module.name))); }
        self.hot.push(subject.clone());
        self.log("module.promoted", ctx.now_ms, &subject);
        Ok(())
    }

    fn export(&mut self, ctx: &Ctx, module_hash: &str, to_scope: Scope, verdicts: &[GateVerdict]) -> Result<(), KernelError> {
        if to_scope <= Scope::Vertical && !verdicts.iter().any(|v| v.gate == GateKind::Declassification && v.subject_hash == module_hash && v.pass) {
            return Err(KernelError::Gate("declassification verdict required to leave the business".into()));
        }
        self.log("module.exported", ctx.now_ms, &(module_hash, to_scope));
        Ok(())
    }

    fn ledger(&self) -> &Ledger { &self.ledger }
}
```
Note: `Scope` derives `PartialOrd`, so `to_scope <= Scope::Vertical` compiles. `Principal` derives `PartialEq` for `ap.approver != *ctx_principal`.

- [ ] **Step 4: Run** — `cargo test -p vk-stub` → 4 passed. Also `cargo clippy --workspace --all-targets -- -D warnings` clean (fix any warning it reports; the plan's code has none known).

- [ ] **Step 5: Commit** — `git add crates/vk-stub Cargo.lock && git commit -m "feat(stub): in-memory kernel with I1/I2/I4/I4' interceptors"`.

---

### Task 14: Property tests for the invariants

**Files:**
- Create: `crates/vk-props/Cargo.toml`, `crates/vk-props/src/lib.rs` (empty), `crates/vk-props/tests/i1_human_path.rs`, `crates/vk-props/tests/i2_clearance.rs`, `crates/vk-props/tests/i3_merge_conservation.rs`, `crates/vk-props/tests/i4_liveness_and_truncation.rs`

**Interfaces:**
- Consumes: `StubKernel` (Task 13), `MetadataDoc`/`StopSet` (Tasks 8, 10).

- [ ] **Step 1: Crate**

`crates/vk-props/Cargo.toml`:
```toml
[package]
name = "vk-props"
version = "0.1.0"
edition.workspace = true
license.workspace = true
description = "Property tests for kernel invariants"

[dependencies]
vk-contracts = { path = "../vk-contracts" }
vk-stub = { path = "../vk-stub" }

[dev-dependencies]
proptest = "1"
hex = "0.4"
```
`crates/vk-props/src/lib.rs`: `//! Property tests live in tests/.`

- [ ] **Step 2: I2 — generated registers never reach an arch above clearance**

`crates/vk-props/tests/i2_clearance.rs`:
```rust
use proptest::prelude::*;
use vk_contracts::arch::*;
use vk_contracts::labels::*;
use vk_contracts::principal::Principal;
use vk_contracts::syscalls::*;
use vk_stub::StubKernel;

fn arch(max_scope: Scope, third_party: bool) -> ArchManifest {
    ArchManifest { name: format!("a-{max_scope:?}-{third_party}"), capabilities: [Capability::Generate].into(), locality: Locality::Cloud, jurisdiction: "US".into(),
        retention_days: Some(30), cost_per_1k_tokens_eur: 0.01, latency_ms_p50: 1, context_ceiling: 10_000, determinism: Determinism::NonDeterministic,
        identity: ArchIdentity { weights_sha256: format!("sha256:{max_scope:?}{third_party}"), engine: "api".into(), engine_version: "1".into(), backend: "cloud".into(),
            quant: "-".into(), kv_cache: "-".into(), threads: 0, batch: 0, sampling: Default::default(), seed: None },
        clearance: Clearance { max_scope, third_party_allowed: third_party }, governed: false }
}

fn scope() -> impl Strategy<Value = Scope> { prop_oneof![Just(Scope::Public), Just(Scope::Vertical), Just(Scope::Business), Just(Scope::Personal), Just(Scope::Holdout)] }
fn class() -> impl Strategy<Value = DataClass> { prop_oneof![Just(DataClass::Own), Just(DataClass::ThirdPartyMandated), Just(DataClass::Unknown)] }

proptest! {
    #[test]
    fn infer_never_receives_a_label_above_arch_clearance(labels in prop::collection::vec((scope(), class()), 1..20), max in scope(), tp in any::<bool>()) {
        let mut k = StubKernel::new("n1");
        let id = k.register_arch(arch(max, tp));
        let ctx = Ctx { principal: Principal::Machine { node_id: "n1".into(), lease_id: "l".into() }, clearance: Clearance { max_scope: Scope::Holdout, third_party_allowed: true }, partition: "p".into(), now_ms: 1 };
        for (s, c) in labels {
            let r = k.submit_task(&ctx, "g", Label { scope: s, data_class: c, origins: Default::default() }).unwrap();
            let _ = k.infer(&ctx, &id, Capability::Generate, &r);
        }
        let clearance = Clearance { max_scope: max, third_party_allowed: tp };
        for (arch_id, label) in k.infer_log() {
            prop_assert_eq!(arch_id, &id);
            prop_assert!(label.flows_to(&clearance), "leaked {:?} to clearance {:?}", label, clearance);
        }
    }
}
```

- [ ] **Step 3: I1 — no sequence of machine calls produces a human approval; STOP is always reachable**

`crates/vk-props/tests/i1_human_path.rs`:
```rust
use proptest::prelude::*;
use vk_contracts::labels::*;
use vk_contracts::principal::*;
use vk_contracts::syscalls::*;
use vk_stub::StubKernel;

#[derive(Debug, Clone)]
enum Op { Approve(ApprovalKind), Lease(String), Stop, Automation }

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        prop_oneof![Just(ApprovalKind::Test), Just(ApprovalKind::Audit), Just(ApprovalKind::Human)].prop_map(Op::Approve),
        "[a-c]".prop_map(Op::Lease),
        Just(Op::Stop),
        Just(Op::Automation),
    ]
}

proptest! {
    #[test]
    fn machine_sequences_never_yield_human_approvals_and_human_stop_always_works(ops in prop::collection::vec(op(), 0..40)) {
        let mut k = StubKernel::new("n1");
        k.renew_liveness("acme", "phone-1", 1_000_000);
        let m = Ctx { principal: Principal::Machine { node_id: "n1".into(), lease_id: "l".into() }, clearance: Clearance { max_scope: Scope::Personal, third_party_allowed: true }, partition: "p".into(), now_ms: 1 };
        for (i, o) in ops.iter().enumerate() {
            let ctx = Ctx { now_ms: 1 + i as u64, ..m.clone() };
            match o {
                Op::Approve(kind) => { let _ = k.approve(&ctx, Approval { subject_hash: "sha256:s".into(), kind: *kind, approver: Principal::Human { device_id: "phone-1".into() }, challenge: None, signature_hex: None }); }
                Op::Lease(r) => { let _ = k.lease(&ctx, r, 10); }
                Op::Stop => { let _ = k.stop(&ctx, "business:acme"); }
                Op::Automation => { let _ = k.run_automation(&ctx, "acme", "m"); }
            }
        }
        prop_assert!(k.approvals_for("sha256:s").iter().all(|a| a.kind != ApprovalKind::Human));
        prop_assert!(!k.stops().stopped("business:acme"), "a machine managed to STOP");
        // The human path is reachable regardless of what machines did:
        let h = Ctx { principal: Principal::Human { device_id: "phone-1".into() }, ..m.clone() };
        prop_assert!(k.stop(&h, "business:acme").is_ok());
        prop_assert!(k.stops().stopped("business:acme"));
        prop_assert!(matches!(k.run_automation(&m, "acme", "m"), Err(KernelError::Stopped(_))));
    }
}
```

- [ ] **Step 4: I3 — merge conservation across partition schedules**

`crates/vk-props/tests/i3_merge_conservation.rs`:
```rust
use proptest::prelude::*;
use std::collections::BTreeSet;
use vk_contracts::storage::MetadataDoc;

#[derive(Debug, Clone)]
struct Write { node: u8, key: String, value: u32 }

fn write() -> impl Strategy<Value = Write> { (0u8..3, "[k-m]", 0u32..5).prop_map(|(node, key, value)| Write { node, key, value }) }

proptest! {
    #[test]
    fn every_write_survives_any_merge_order(writes in prop::collection::vec(write(), 0..30), order in prop::collection::vec(0usize..3, 0..6)) {
        let mut docs: Vec<MetadataDoc<u32>> = (0..3).map(|_| MetadataDoc::default()).collect();
        for w in &writes { docs[w.node as usize].write(&w.key, w.value, &format!("node-{}", w.node)); }
        // Merge in an arbitrary schedule, then everything into doc 0.
        for &i in &order { let other = docs[(i + 1) % 3].clone(); docs[i].merge(&other); }
        let d1 = docs[1].clone(); docs[0].merge(&d1);
        let d2 = docs[2].clone(); docs[0].merge(&d2);
        let merged = &docs[0];
        // Every (key, value) ever written is present as the kept value or inside a surfaced conflict.
        let mut present: BTreeSet<(String, u32)> = merged.writes.iter().map(|(k, v)| (k.clone(), *v)).collect();
        for c in &merged.conflicts { for (_, v) in &c.values { present.insert((c.key.clone(), *v)); } }
        // Last write per (node, key) is what that node holds; earlier same-node overwrites are legitimately replaced.
        let mut last: std::collections::BTreeMap<(u8, String), u32> = Default::default();
        for w in &writes { last.insert((w.node, w.key.clone()), w.value); }
        for ((_, key), value) in last { prop_assert!(present.contains(&(key.clone(), value)), "lost write {key}={value}"); }
    }
}
```

- [ ] **Step 5: I4 / I4′ — liveness and truncation**

`crates/vk-props/tests/i4_liveness_and_truncation.rs`:
```rust
use proptest::prelude::*;
use vk_contracts::arch::*;
use vk_contracts::labels::*;
use vk_contracts::principal::Principal;
use vk_contracts::syscalls::*;
use vk_stub::StubKernel;

fn local() -> ArchManifest {
    ArchManifest { name: "local".into(), capabilities: [Capability::Generate].into(), locality: Locality::Local, jurisdiction: "FR".into(), retention_days: None,
        cost_per_1k_tokens_eur: 0.0, latency_ms_p50: 1, context_ceiling: 64, determinism: Determinism::SeededDeterministic,
        identity: ArchIdentity { weights_sha256: "sha256:l".into(), engine: "llama".into(), engine_version: "1".into(), backend: "cpu".into(), quant: "q4".into(), kv_cache: "f16".into(), threads: 1, batch: 1, sampling: Default::default(), seed: Some(1) },
        clearance: Clearance { max_scope: Scope::Holdout, third_party_allowed: true }, governed: true }
}

proptest! {
    #[test]
    fn automation_never_runs_after_liveness_expiry(expiry in 1u64..1000, ticks in prop::collection::vec(1u64..2000, 1..30)) {
        let mut k = StubKernel::new("n1");
        k.renew_liveness("acme", "phone-1", expiry);
        for now in ticks {
            let ctx = Ctx { principal: Principal::Machine { node_id: "n1".into(), lease_id: "l".into() }, clearance: Clearance { max_scope: Scope::Personal, third_party_allowed: true }, partition: "p".into(), now_ms: now };
            let ran = k.run_automation(&ctx, "acme", "m").is_ok();
            prop_assert_eq!(ran, now < expiry, "ran={ran} at now={now} expiry={expiry}");
        }
    }

    #[test]
    fn over_budget_inference_is_always_a_logged_projection(goal_len in 0usize..2000, budget in 1u32..64) {
        let mut k = StubKernel::new("n1");
        let id = k.register_arch(local());
        k.set_context_budget(&id, budget);
        let ctx = Ctx { principal: Principal::Machine { node_id: "n1".into(), lease_id: "l".into() }, clearance: Clearance { max_scope: Scope::Holdout, third_party_allowed: true }, partition: "p".into(), now_ms: 1 };
        let r = k.submit_task(&ctx, &"g".repeat(goal_len), Label::bottom()).unwrap();
        let out = k.infer(&ctx, &id, Capability::Generate, &r).unwrap();
        let logged = k.ledger().events().iter().any(|e| e.kind == "infer.projected");
        prop_assert_eq!(out.projected, logged, "projection without a ledger entry (or vice versa)");
        prop_assert!(out.tokens_in <= budget);
    }
}
```

- [ ] **Step 6: Run everything**

Run: `cargo test --workspace`
Expected: all unit tests, both `vk-contracts` integration tests, 4 `vk-stub` tests and 5 property tests pass. If a property test finds a counter-example, it prints the minimal failing input — fix the stub or the contract, never weaken the property.

- [ ] **Step 7: Commit** — `git add crates/vk-props Cargo.lock && git commit -m "test(props): property tests for invariants I1, I2, I3, I4 and I4'"`.

---

### Task 15: Protocol documents — phone bootstrap, TUF roles, TCB statement

**Files:**
- Create: `contracts/identity/phone-bootstrap.md`, `contracts/federation/tuf-roles.md`, `contracts/tcb.md`
- Create: `crates/vk-contracts/src/federation.rs` (role metadata types + threshold verify), `contracts/examples/tuf_root/valid/two_of_three.json`
- Modify: `lib.rs` (mod + `("tuf_root", …)`)

**Interfaces:**
- Produces: `RootRole { keys: BTreeMap<String, String /*vk hex*/>, threshold: u8, expires_at_ms }`, `SignedRoot { root: RootRole, signatures: BTreeMap<String, String> }`, `SignedRoot::verify(now_ms) -> Result<(), FederationError>`.

- [ ] **Step 1: Failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::{HumanKey, SoftwareHumanKey};

    fn signed(n_sign: usize, now: u64) -> SignedRoot {
        let keys: Vec<SoftwareHumanKey> = (0..3).map(|i| SoftwareHumanKey::generate(&format!("k{i}"))).collect();
        let root = RootRole { keys: keys.iter().map(|k| (k.device_id(), hex::encode(k.verifying_key_bytes()))).collect(), threshold: 2, expires_at_ms: now + 1 };
        let msg = root.digest();
        let signatures = keys.iter().take(n_sign).map(|k| (k.device_id(), hex::encode(k.sign(&msg)))).collect();
        SignedRoot { root, signatures }
    }

    #[test]
    fn two_of_three_verifies_one_does_not() {
        assert_eq!(signed(2, 100).verify(100), Ok(()));
        assert_eq!(signed(1, 100).verify(100), Err(FederationError::ThresholdNotMet { have: 1, need: 2 }));
    }

    #[test]
    fn expired_root_fails_closed() {
        assert_eq!(signed(3, 100).verify(101), Err(FederationError::Expired));
    }
}
```

- [ ] **Step 2: Run to verify failure** — compile error.

- [ ] **Step 3: Implement `federation.rs`**

```rust
//! Federation trust roles (spec §4.4, D10): TUF-style root with threshold signatures.
use crate::hash_canonical;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RootRole { pub keys: BTreeMap<String, String>, pub threshold: u8, pub expires_at_ms: u64 }

impl RootRole { pub fn digest(&self) -> Vec<u8> { hash_canonical(self).into_bytes() } }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SignedRoot { pub root: RootRole, pub signatures: BTreeMap<String, String> }

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FederationError {
    #[error("root expired; failing closed")] Expired,
    #[error("threshold not met: {have} of {need}")] ThresholdNotMet { have: usize, need: usize },
}

impl SignedRoot {
    pub fn verify(&self, now_ms: u64) -> Result<(), FederationError> {
        if now_ms >= self.root.expires_at_ms { return Err(FederationError::Expired); }
        let msg = self.root.digest();
        let mut valid = 0usize;
        for (key_id, sig_hex) in &self.signatures {
            let Some(vk_hex) = self.root.keys.get(key_id) else { continue };
            let (Ok(vk_bytes), Ok(sig_bytes)) = (hex::decode(vk_hex), hex::decode(sig_hex)) else { continue };
            let (Ok(vk_arr), Ok(sig_arr)) = (<[u8; 32]>::try_from(vk_bytes), <[u8; 64]>::try_from(sig_bytes)) else { continue };
            let Ok(vk) = VerifyingKey::from_bytes(&vk_arr) else { continue };
            if vk.verify(&msg, &Signature::from_bytes(&sig_arr)).is_ok() { valid += 1; }
        }
        let need = self.root.threshold as usize;
        if valid < need { return Err(FederationError::ThresholdNotMet { have: valid, need }); }
        Ok(())
    }
}
```
Example `two_of_three.json`: any `SignedRoot` JSON with three hex keys, `"threshold": 2`, two signature entries (schema validation only; signatures need not verify in the example).

- [ ] **Step 4: Write the three documents**

`contracts/identity/phone-bootstrap.md`:
```markdown
# Phone thin-node bootstrap (spec §3.6, D6)

Goal: enrol a phone as an approval channel with a hardware-backed key, without the phone ever holding registers or secrets.

1. On a full node, the business admin (human ceremony) issues an **invitation ticket**: `{business_id, ticket_nonce, expires_at_ms}` signed by the admin key, plus a 6-digit out-of-band code shown on the full node's screen.
2. The phone generates a key pair in Secure Enclave / StrongBox (non-exportable, user-verification required). It sends `{ticket, device_public_key, device_attestation}` to the full node over the LAN or the business relay (ciphertext only).
3. The full node checks the ticket signature and expiry, and the admin types the 6-digit code on the phone (proves physical co-presence). The admin approves enrolment with a human ceremony.
4. The full node writes `device.enrolled {device_id, public_key, trust_class: "thin", attestation_hash}` — a ledger event and a metadata write that replicates to the business.
5. From then on the phone can: issue STOP (presence only), sign approval challenges (`Challenge::digest`), renew the autonomy liveness lease, and act as a channel into `submit_task`. It cannot: hold a lock home, read registers above `Scope::Public`, or store any secret.
6. Revocation: `device.revoked {device_id}` signed by the admin key; propagates and wins merges; all approvals signed after the revocation HLC are invalid.
```

`contracts/federation/tuf-roles.md`:
```markdown
# Federation trust roles (spec §4.4, D10)

| Role | Key location | Threshold | Signs |
|---|---|---|---|
| root | offline; founder + independent custodian + sealed recovery share | 2 of 3 | the set of role keys and their expiry |
| targets | online, per signer; short-lived delegations from root | 1 | module manifests admitted to a vertical scope |
| timestamp | online; automated | 1 | freshness of the current targets set; nodes fail closed after `max_age` |
| revocation | any root or targets key | 1 | revocation events; propagate and win merges |

Signer admission: a one-time legal-entity check by the root holders, recorded as a `targets.delegated` event. Usage evidence is never a basis for signing rights (Sybil-attackable). Progressive delegation to businesses is a targets delegation under the same roles.
```

`contracts/tcb.md`:
```markdown
# Trusted computing base statement (spec §5)

In scope of the invariants: the kernel daemon, its service account, the OS keyring, the interceptor chain, kernel-launched (governed) inference processes, enrolled device keys.

Outside the TCB, per platform, and surfaced in the inventory as **unmediated channels**:
- any harness that the platform cannot confine (no Job Object/AppContainer, landlock or sandbox-exec available) — it may read the store directly;
- SaaS assistants embedded inside third-party applications;
- ungoverned inference engines not launched by the kernel.

Any object reachable by an unmediated channel is treated as projected to that channel's clearance for I2 purposes; the UI says so.
```

- [ ] **Step 5: Regenerate, run, commit**

`cargo run -p vk-contracts --bin gen-schemas && cargo test --workspace` → pass.
```bash
git add contracts crates
git commit -m "feat(contracts): TUF root threshold verification; phone bootstrap, TUF roles and TCB documents"
```

---

### Task 16: SP0 exit — CI green, README complete, tag

**Files:**
- Modify: `README.md` (MSRV filled, test counts, how to read contracts)

- [ ] **Step 1: Push and watch CI**

```bash
git push -u origin master
```
Open the Actions tab; all three OS jobs must pass `fmt`, `clippy`, `test`; the `sign` job prints "no SIGNING_CERT_B64 secret; skipping".

- [ ] **Step 2: Fill README**

Replace `<fill from rustc --version at SP0 start>` with the real version; add a "Contracts index" listing each schema file and the spec section it implements (`label` §3.2/§4.2, `register` §3.2, `arch_manifest` §3.7, `principal`/`challenge`/`approval` §3.6, `lease` §3.4, `stop_event`/`resume_event`/`liveness_lease` §3.5, `ledger_event` §3.9, `blob_envelope`/`shred_event` §3.9, `module_manifest`/`validator_manifest`/`gate_verdict` §4.1, `syscall_ctx` §3.11, `tuf_root` §4.4).

- [ ] **Step 3: Tag**

```bash
git add README.md
git commit -m "docs: SP0 contracts index and MSRV"
git tag -a sp0-contracts -m "SP0: contracts and kernel boundary; invariants I1-I4' property-tested on the stub"
git push --tags
```

---

## Self-review

**Spec coverage (spec §6, SP0 row):** syscall/IR/manifest/ledger/module/validator/gate-verdict schemas → Tasks 4, 5, 9, 11, 12 (+ registry in Task 2); lock tagged-union → Tasks 6, 7 (LEASE, APPROVAL, lock home/fences); STOP semantics → Task 8; information-flow labelling → Tasks 1, 4; hardware-key ceremony and phone bootstrap → Tasks 6, 15; storage tiering and retention classes → Tasks 9, 10; TUF role definitions → Task 15; TCB statement → Task 15; jurisdiction/retention manifest fields → Task 5; repo scaffold, `.gitignore`, CI, code-signing pipeline → Task 0 (signing job is a scaffold that skips without a certificate — the real certificate is an SP1 gate item, stated in the spec); property-test harness against a stub → Tasks 13, 14. Exit criterion "schemas reviewed" is Task 16 + the founder's review.

**Gaps deliberately left to SP1 (stated):** real encryption for blobs (Task 10 is semantics only), Automerge integration, process confinement, real HSM/TPM keys (the `HumanKey` trait is the seam), MCP transport for the syscall surface.

**Placeholder scan:** none of "TBD/TODO/handle edge cases/similar to Task N"; the README placeholder `<fill…>` is filled in Task 16 with a concrete instruction.

**Type consistency:** `Ctx{principal, clearance, partition, now_ms}` identical in Tasks 12–14; `Approval` fields identical in Tasks 6, 13, 14; `StopSet::try_add_stop/add_resume/stopped/merge` names identical in Tasks 8, 13, 14; `MetadataDoc::{write, merge, writes, conflicts}` identical in Tasks 10, 14; `StubKernel` helper names (`register_arch`, `renew_liveness`, `set_context_budget`, `approvals_for`, `infer_log`, `stops`) identical in Tasks 13, 14; `Scope` ordering used by `export` and `flows_to` is the one declared in Task 1.
