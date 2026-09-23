# SP1b — Real Arches, Confined Harness, Passkeys, Windows Service and the Demo — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Prerequisite:** SP1a complete (`vk` shell working against the mock arch).

**Goal:** Replace the mock with governed real arches (llama-server first, Anthropic first-party and EU-hosted via Bedrock), run Claude Code as a confined harness through an MCP façade, make the human ceremony a WebAuthn passkey (Windows Hello now, iPhone later), install the kernel as a Windows service, sign the binaries, and pass the SP1 demo: a client proposal drafted from a brief by Gemma 4 and Claude Code co-working through the IR, approved with a passkey, with the roles swapped in a second run (H1).

**Architecture:** Adapters implement SP1a's `ArchAdapter`; llama-server is launched by the kernel inside a Job Object (governed) and reports its real `n_ctx` (I4′). `vk-mcp` is a stdio MCP server the harness talks to; every tool call becomes a syscall under the harness's lease. `vk-harness` materialises a label-projected workspace, launches Claude Code under a Job Object, records its outbound connections, and attaches the produced artefact. `vk-web` runs inside `vkd` and serves `http://127.0.0.1:<port>` (a secure context for WebAuthn) for passkey enrolment and approval; verification happens in-process with `webauthn-rs`, so no client can assert a human principal. `vk-service` wraps `vkd` as a Windows service under a virtual account with a pipe DACL that admits the interactive user.

**Tech Stack:** SP1a stack plus reqwest (rustls), sha2 streaming hash, `windows` crate (Job Objects, security descriptors), `windows-service`, `webauthn-rs` 0.5, axum, `aws-sdk-bedrockruntime` + `aws-config`, signtool / Azure Trusted Signing in CI.

**Spec:** design spec §3.3 (governor), §3.6 (ceremony), §3.7 (arches, manifests, learning modes), §3.8 (nodes, Windows packaging), §3.11, §5; SP1 design approved 2026-09-23 (§4 arches, §5 harness confinement with its stated caveat, §6 ceremony, §8 demo, §9 out of scope). Companion: `2026-09-23-sp1a-kernel-core-store-ipc-cli.md`.

## Execution tiering

| Tier | Model / effort | Tasks |
|---|---|---|
| Hard — process confinement, security descriptors, WebAuthn binding, governor | Fable 5.1 / xhigh | 3, 4, 5, 6 |
| Standard — adapters, MCP façade, service wrapper, demo orchestration | Opus 5 / high | 1, 2, 7, 8 |
| Mechanical — CI signing job, docs, checklist | Sonnet 5 / medium | 9 |
| Spikes (time-boxed, throwaway code allowed, findings recorded in the plan) | Fable 5.1 / xhigh | 3a, 4a, 6a |

## Global Constraints

- Everything in SP1a's Global Constraints.
- **Anthropic calls use raw HTTPS** (no official Rust SDK): `POST https://api.anthropic.com/v1/messages`, header `anthropic-version: 2023-06-01`, default model `claude-opus-5`, `thinking: {"type":"adaptive"}`, streaming not required for the demo's sizes (`max_tokens` ≤ 4096). API key read from the OS keyring entry `vk/anthropic` — never from a file in the repo, never in a manifest.
- **EU-hosted arch** = Anthropic on Amazon Bedrock in `eu-central-1` or `eu-west-1` via `aws-sdk-bedrockruntime` `converse`; manifest `jurisdiction: "EU"`, `locality: cloud`. Runs only when AWS credentials are present; unit-tested against a mock.
- **Claude Code is launched non-interactively**: `claude -p "<prompt>" --mcp-config <path> --allowedTools "mcp__vk__*,Read,Write,Edit,Glob,Grep" --permission-mode acceptEdits --output-format json`, cwd = the materialised workspace. Its own API traffic goes to Anthropic directly (see TCB note in Task 4).
- **The passkey page is a secure context only on loopback** (`http://localhost:<port>` / `127.0.0.1`); it binds to loopback exclusively in SP1b. TLS + LAN comes with SP4.
- **No demo counts as passed on the developer machine alone.** Task 9's gate runs on the VirtualBox stock-Windows image.

---

## File structure

```
crates/vk-arch-llama/       src/lib.rs (LlamaServerAdapter), src/gguf.rs (hash + metadata), src/governor.rs (Job Object), tests/args.rs
crates/vk-arch-anthropic/   src/lib.rs (first-party), src/bedrock.rs (EU-hosted), tests/mock.rs
crates/vk-mcp/              src/main.rs (stdio MCP server binary `vk-mcp`), src/protocol.rs, src/tools.rs
crates/vk-harness/          src/lib.rs (workspace materialisation, launch, collect), src/confine.rs (Job Object + restricted token), src/netwatch.rs
crates/vk-web/              src/lib.rs (axum router inside vkd), src/passkey.rs (webauthn-rs), static/approve.html, static/enroll.html
crates/vk-service/          src/main.rs (`vkd-service` install/uninstall/run), src/pipe_acl.rs
crates/vk-kernel/src/lib.rs modified: mount adapters by kind; record_verified_human_approval; harness step execution
crates/vk-cli/src/main.rs   modified: `vk mount llama|anthropic|bedrock …`, `vk passkey enroll`, `vk approve --passkey`, `vk harness …`
.github/workflows/ci.yml    modified: sign job (Trusted Signing or signtool with OV cert), artifacts
scripts/demo-sp1.ps1        the demo, end to end, both role orders
docs/sp1-gate-checklist.md  the VM gate
```

---

### Task 1: llama-server adapter (governed local arch)

**Files:**
- Create: `crates/vk-arch-llama/Cargo.toml`, `src/lib.rs`, `src/gguf.rs`, `tests/args.rs`
- Modify: workspace `Cargo.toml` (`reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json", "blocking"] }`), `crates/vk-kernel/src/lib.rs` (`mount` already generic), `crates/vk-cli/src/main.rs` (`vk mount llama --model PATH --bin PATH [--ctx N] [--threads N] [--gpu-layers N]`)

**Interfaces:**
- Produces:

```rust
pub struct LlamaConfig { pub binary: PathBuf, pub model: PathBuf, pub ctx: u32, pub threads: u32, pub gpu_layers: u32, pub port: u16, pub seed: u64 }
pub struct LlamaServerAdapter { … }
impl LlamaServerAdapter {
    pub fn launch(cfg: LlamaConfig, governor: Option<Box<dyn Governor>>) -> anyhow::Result<LlamaServerAdapter>;  // spawns, waits for /health, reads /props
    pub fn manifest_for(cfg: &LlamaConfig, weights_sha256: &str, version: &str, n_ctx: u32) -> ArchManifest;
    pub fn args(cfg: &LlamaConfig) -> Vec<String>;
}
impl ArchAdapter for LlamaServerAdapter { … }   // context_budget = n_ctx from /props; count_tokens via POST /tokenize; complete via POST /completion
pub trait Governor: Send + Sync { fn contain(&self, child: &std::process::Child) -> anyhow::Result<()>; }
pub mod gguf { pub fn sha256_streaming(path: &Path) -> anyhow::Result<String>; }
```

- [ ] **Step 1: Failing tests** (`tests/args.rs`)

```rust
use vk_arch_llama::{LlamaConfig, LlamaServerAdapter};
use std::path::PathBuf;

fn cfg() -> LlamaConfig { LlamaConfig { binary: PathBuf::from("llama-server"), model: PathBuf::from("gemma-4-4b-Q4_K_M.gguf"), ctx: 8192, threads: 6, gpu_layers: 99, port: 8087, seed: 7 } }

#[test]
fn args_pin_everything_that_changes_behaviour() {
    let a = LlamaServerAdapter::args(&cfg()).join(" ");
    for needle in ["-m gemma-4-4b-Q4_K_M.gguf", "--port 8087", "-c 8192", "-t 6", "-ngl 99", "--host 127.0.0.1", "--seed 7", "--no-webui"] {
        assert!(a.contains(needle), "missing {needle} in {a}");
    }
}

#[test]
fn manifest_identity_changes_with_quant_or_threads() {
    let m1 = LlamaServerAdapter::manifest_for(&cfg(), "sha256:w", "b5000", 8192);
    let mut c2 = cfg(); c2.threads = 4;
    let m2 = LlamaServerAdapter::manifest_for(&c2, "sha256:w", "b5000", 8192);
    assert_ne!(m1.arch_id(), m2.arch_id());
    assert_eq!(m1.context_ceiling, 8192);
    assert!(m1.governed);
    assert_eq!(m1.identity.quant, "Q4_K_M");
}

#[test]
fn gguf_hash_is_streamed_and_stable() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("m.gguf");
    std::fs::write(&p, vec![7u8; 5 * 1024 * 1024]).unwrap();
    let h = vk_arch_llama::gguf::sha256_streaming(&p).unwrap();
    assert!(h.starts_with("sha256:"));
    assert_eq!(h, vk_arch_llama::gguf::sha256_streaming(&p).unwrap());
}
```

- [ ] **Step 2: Run to verify failure** — compile errors.

- [ ] **Step 3: Implement**

`gguf.rs`:
```rust
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
pub fn sha256_streaming(path: &Path) -> anyhow::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop { let n = f.read(&mut buf)?; if n == 0 { break; } h.update(&buf[..n]); }
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}
/// Quantisation tag from the file name (Q4_K_M, Q8_0, F16, …) — llama-server does not report it over HTTP.
pub fn quant_from_name(path: &Path) -> String {
    let name = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    name.rsplit('-').next().unwrap_or("unknown").to_string()
}
```

`lib.rs`:
```rust
//! llama-server adapter (spec §3.7): kernel-launched, governed, honest manifest.
pub mod gguf;
#[cfg(windows)] pub mod governor;

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use vk_contracts::arch::*;
use vk_contracts::labels::{Clearance, Scope};
use vk_kernel::arch::ArchAdapter;

pub trait Governor: Send + Sync { fn contain(&self, child: &Child) -> Result<()>; }

pub struct LlamaConfig { pub binary: PathBuf, pub model: PathBuf, pub ctx: u32, pub threads: u32, pub gpu_layers: u32, pub port: u16, pub seed: u64 }

pub struct LlamaServerAdapter { manifest: ArchManifest, n_ctx: u32, base: String, child: Option<Child>, http: reqwest::blocking::Client }

impl LlamaServerAdapter {
    pub fn args(cfg: &LlamaConfig) -> Vec<String> {
        vec!["-m".into(), cfg.model.to_string_lossy().into(), "--host".into(), "127.0.0.1".into(), "--port".into(), cfg.port.to_string(),
             "-c".into(), cfg.ctx.to_string(), "-t".into(), cfg.threads.to_string(), "-ngl".into(), cfg.gpu_layers.to_string(),
             "--seed".into(), cfg.seed.to_string(), "--no-webui".into(), "--metrics".into()]
    }

    pub fn manifest_for(cfg: &LlamaConfig, weights_sha256: &str, version: &str, n_ctx: u32) -> ArchManifest {
        let mut sampling = std::collections::BTreeMap::new();
        sampling.insert("temperature".into(), "0.2".into());
        ArchManifest {
            name: format!("llama-server:{}", cfg.model.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()),
            capabilities: [Capability::Generate, Capability::Plan, Capability::Judge].into(),
            locality: Locality::Local, jurisdiction: "FR".into(), retention_days: None, cost_per_1k_tokens_eur: 0.0, latency_ms_p50: 0,
            context_ceiling: n_ctx, determinism: Determinism::SeededDeterministic,
            identity: ArchIdentity { weights_sha256: weights_sha256.into(), engine: "llama-server".into(), engine_version: version.into(),
                backend: if cfg.gpu_layers > 0 { "vulkan".into() } else { "cpu".into() }, quant: gguf::quant_from_name(&cfg.model), kv_cache: "f16".into(),
                threads: cfg.threads, batch: 512, sampling, seed: Some(cfg.seed) },
            clearance: Clearance { max_scope: Scope::Holdout, third_party_allowed: true }, governed: true,
        }
    }

    pub fn launch(cfg: LlamaConfig, governor: Option<Box<dyn Governor>>) -> Result<LlamaServerAdapter> {
        let version = String::from_utf8_lossy(&Command::new(&cfg.binary).arg("--version").output().context("llama-server --version")?.stderr).lines().next().unwrap_or("unknown").to_string();
        let weights = gguf::sha256_streaming(&cfg.model)?;
        let child = Command::new(&cfg.binary).args(Self::args(&cfg)).stdout(Stdio::null()).stderr(Stdio::null()).spawn().context("spawn llama-server")?;
        if let Some(g) = &governor { g.contain(&child)?; }
        let base = format!("http://127.0.0.1:{}", cfg.port);
        let http = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(600)).build()?;
        for _ in 0..600 { // up to 60 s for model load
            if http.get(format!("{base}/health")).send().map(|r| r.status().is_success()).unwrap_or(false) { break; }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let props: serde_json::Value = http.get(format!("{base}/props")).send()?.json()?;
        let n_ctx = props["default_generation_settings"]["n_ctx"].as_u64().or_else(|| props["n_ctx"].as_u64()).map(|v| v as u32).unwrap_or(cfg.ctx);
        if n_ctx == 0 { bail!("llama-server reported n_ctx = 0"); }
        Ok(LlamaServerAdapter { manifest: Self::manifest_for(&cfg, &weights, &version, n_ctx), n_ctx, base, child: Some(child), http })
    }
}

impl ArchAdapter for LlamaServerAdapter {
    fn manifest(&self) -> &ArchManifest { &self.manifest }
    fn context_budget(&self) -> u32 { self.n_ctx }
    fn count_tokens(&self, text: &str) -> u32 {
        self.http.post(format!("{}/tokenize", self.base)).json(&serde_json::json!({"content": text})).send().ok()
            .and_then(|r| r.json::<serde_json::Value>().ok()).and_then(|v| v["tokens"].as_array().map(|a| a.len() as u32)).unwrap_or((text.len() / 4) as u32 + 1)
    }
    fn complete(&self, prompt: &str, max_tokens: u32) -> Result<String> {
        let v: serde_json::Value = self.http.post(format!("{}/completion", self.base))
            .json(&serde_json::json!({"prompt": prompt, "n_predict": max_tokens, "temperature": 0.2, "seed": self.manifest.identity.seed})).send()?.json()?;
        v["content"].as_str().map(|s| s.to_string()).ok_or_else(|| anyhow::anyhow!("no content in llama-server response"))
    }
}

impl Drop for LlamaServerAdapter { fn drop(&mut self) { if let Some(mut c) = self.child.take() { let _ = c.kill(); } } }
```
Real-model integration test (`tests/live.rs`, `#[ignore]` unless `VK_LLAMA_BIN` and `VK_MODEL` are set): launch, `count_tokens("hello world") > 0`, `complete("ROLE: plan\nGOAL: say hi", 16)` returns non-empty, manifest `context_ceiling == /props n_ctx`.

- [ ] **Step 4: Run** — `cargo test -p vk-arch-llama` → 3 passed (+ live test when env set). **Step 5: Commit** — `feat(arch): llama-server adapter with streamed GGUF hash, honest n_ctx and pinned launch args`.

---

### Task 2: Anthropic adapters — first-party (US) and EU-hosted (Bedrock)

**Files:**
- Create: `crates/vk-arch-anthropic/Cargo.toml`, `src/lib.rs`, `src/bedrock.rs`, `tests/mock.rs`
- Modify: `crates/vk-cli/src/main.rs` (`vk mount anthropic [--model M]`, `vk mount bedrock --region eu-central-1 [--model M]`), `crates/vkd/src/main.rs` (keyring lookup `vk/anthropic`)

**Interfaces:**
- `AnthropicAdapter::new(api_key: SecretString, model: &str, base_url: &str) -> Self` with manifest `locality: Cloud, jurisdiction: "US", retention_days: Some(30), clearance: Business / third_party_allowed: false` by default (policy may raise it); `complete` posts `/v1/messages` with `{"model", "max_tokens", "thinking": {"type":"adaptive"}, "messages":[{"role":"user","content": prompt}]}` and concatenates `text` blocks; `count_tokens` posts `/v1/messages/count_tokens`.
- `BedrockAdapter::new(region, model_id) -> Result<Self>` (async client wrapped with a small runtime handle); manifest `jurisdiction: "EU"`, `retention_days: None` (Bedrock does not retain prompts), clearance as above.

- [ ] **Step 1: Failing tests** (`tests/mock.rs`) — spin a tiny axum server on loopback returning a canned `/v1/messages` JSON; assert `complete` returns the concatenated text, sends `anthropic-version` and `x-api-key` headers, and that `manifest().jurisdiction == "US"`. For Bedrock, unit-test only the manifest and the request shape builder (`bedrock::converse_input(prompt, max_tokens)`).
- [ ] **Step 2: Implement** per interface; keys via `keyring::Entry::new("vk", "anthropic")` in `vkd` when mounting; `vk mount anthropic` fails with a clear message if the entry is missing and prints the one-liner to set it (`vk secret set anthropic` → prompts on the terminal, stores in keyring; never echoes).
- [ ] **Step 3: Run, commit** — `feat(arch): Anthropic first-party (US) and Bedrock EU adapters with jurisdiction-tagged manifests`.

---

### Task 3: Governor — Job Object containment on Windows (with spike 3a)

**Files:**
- Create: `crates/vk-arch-llama/src/governor.rs` (Windows), `crates/vk-harness/src/confine.rs` (shared later)
- Modify: `crates/vk-arch-llama/Cargo.toml` (`[target.'cfg(windows)'.dependencies] windows = { version = "0.61", features = ["Win32_Foundation", "Win32_System_JobObjects", "Win32_System_Threading", "Win32_Security"] }`)

**Spike 3a (time-box 2 h):** confirm on this machine that a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS` kills llama-server when `vkd` exits and enforces the memory cap; record the exact `windows` crate version and any API-name corrections in this task before implementing.

**Interfaces:**
- `JobGovernor::new(max_memory_bytes: u64, cpu_rate_percent: Option<u32>) -> Result<JobGovernor>` implementing `Governor::contain(&Child)`; `Drop` closes the handle (which kills the job).

- [ ] **Step 1: Failing test** (Windows-only, `#[cfg(windows)]`): spawn `cmd /c ping -n 30 127.0.0.1` under a `JobGovernor`, drop the governor, assert the child exits within 2 s (`child.try_wait()` loop). Second test: a 64 MiB cap makes `powershell -c "$a = New-Object byte[] 268435456"` fail (non-zero exit) while the same command without the cap succeeds.

- [ ] **Step 2: Implement**

```rust
//! Job Object governor (spec §3.3): kernel-launched processes die with the kernel and stay under caps.
use anyhow::Result;
use std::process::Child;
use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::*;

pub struct JobGovernor { job: HANDLE }
unsafe impl Send for JobGovernor {} unsafe impl Sync for JobGovernor {}

impl JobGovernor {
    pub fn new(max_memory_bytes: u64, cpu_rate_percent: Option<u32>) -> Result<JobGovernor> {
        unsafe {
            let job = CreateJobObjectW(None, None)?;
            let mut ext = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            ext.ProcessMemoryLimit = max_memory_bytes as usize;
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &ext as *const _ as *const _, std::mem::size_of_val(&ext) as u32)?;
            if let Some(pct) = cpu_rate_percent {
                let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::default();
                cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
                cpu.Anonymous.CpuRate = pct * 100; // in 1/100 of a percent
                SetInformationJobObject(job, JobObjectCpuRateControlInformation, &cpu as *const _ as *const _, std::mem::size_of_val(&cpu) as u32)?;
            }
            Ok(JobGovernor { job })
        }
    }
}
impl super::Governor for JobGovernor {
    fn contain(&self, child: &Child) -> Result<()> { unsafe { AssignProcessToJobObject(self.job, HANDLE(child.as_raw_handle() as _))?; } Ok(()) }
}
impl Drop for JobGovernor { fn drop(&mut self) { unsafe { let _ = CloseHandle(self.job); } } }
```
(Field/constant names are from `windows` 0.5x–0.6x; expect a short compile-fix loop — that is what spike 3a is for. On Linux/macOS, `Governor` is implemented in SP4 with cgroups/`sandbox-exec`; until then `NoopGovernor` logs "ungoverned" and the manifest sets `governed: false`.)

- [ ] **Step 3: Wire** — `vk mount llama` uses `JobGovernor::new(cfg.memory_cap, cfg.cpu_cap)` on Windows; the manifest's `governed` reflects whether containment succeeded. `vk top` shows `governed` per arch.

- [ ] **Step 4: Run, commit** — `feat(governor): Job Object containment for kernel-launched arches (Windows)`.

---

### Task 4: MCP façade and confined Claude Code harness (with spike 4a)

**Files:**
- Create: `crates/vk-mcp/…` (binary `vk-mcp`), `crates/vk-harness/…`
- Modify: `crates/vk-kernel/src/tasks.rs` (`StepKind::Harness` executes), `crates/vk-kernel/src/lib.rs` (`harness_lease`, `record_harness_connection`), `crates/vk-cli/src/main.rs` (`vk harness run TASK --name claude-code`, `--dry-run` prints the launch line)

**Spike 4a (time-box 3 h):** (i) verify the Claude Code CLI flags on the installed version (`claude --help`): `-p`, `--mcp-config`, `--allowedTools`, `--permission-mode`, `--output-format json`; (ii) verify Claude Code connects to a stdio MCP server declared in a JSON config and lists `mcp__vk__*` tools; (iii) try `CreateRestrictedToken` + `CreateProcessAsUser` for the harness — if it cannot be made to work within the box, SP1b ships **Job Object + workspace ACL + netwatch** and records restricted-token launch as the open TCB item (spec §5), stated in the gate checklist.

**Interfaces:**
- `vk-mcp` binary: reads env `VK_ENDPOINT`, `VK_LEASE_TOKEN`; speaks MCP over stdio (`initialize` → `{protocolVersion, capabilities:{tools:{}}, serverInfo:{name:"vk"}}`, `tools/list`, `tools/call`). Tools: `vk_read_register {}`, `vk_write_decision {text}`, `vk_attach_artefact {kind, path}` (reads the file from the workspace and attaches it), `vk_request_approval {}`, `vk_log {message}`. Every call → IPC method `harness.*` with the lease token; the server maps the token to `Principal::Machine { node_id, lease_id: <token> }` and a clearance derived from the harness manifest (`locality: cloud` → `Clearance { max_scope: Business, third_party_allowed: false }` by default).
- `vk-harness`: `Workspace::materialise(kernel, ctx, task) -> PathBuf` (writes `BRIEF/*` files whose labels flow to the harness clearance, `PLAN.md` from register decisions, `TASK.md` with the goal; refuses files above clearance and logs each projection); `launch_claude_code(workspace, lease_token, endpoint, prompt, governor) -> Result<HarnessRun { exit_code, stdout_json, connections: Vec<String> }>`; `netwatch::sample(pid) -> Vec<String>` (remote `ip:port` of the PID's established TCP connections via `GetExtendedTcpTable`, sampled every 500 ms into `connections`; appended to the ledger as `harness.connections`).
- `StepKind::Harness { name }` in the scheduler: lease → materialise → launch → wait → attach `proposal.md` (or any new/changed file under `OUT/`) as artefact → release lease → `Done`; failures set `Failed(reason)`.

- [ ] **Step 1: Failing tests** — `vk-mcp/tests/protocol.rs`: pipe a scripted `initialize` + `tools/list` + `tools/call vk_log` through the binary with a fake IPC server (reuse `vk-ipc` test server) and assert the JSON-RPC responses; `vk-harness/tests/workspace.rs`: a task whose register has one `Business/own` evidence file and one `Personal` file materialises only the first for a `Business` clearance and logs one projection.
- [ ] **Step 2: Implement** per interfaces. Launch line (Windows): `claude.cmd -p <PROMPT> --mcp-config <ws>\.mcp.json --allowedTools "mcp__vk__*,Read,Write,Edit,Glob,Grep" --permission-mode acceptEdits --output-format json` with `.mcp.json` = `{"mcpServers":{"vk":{"command":"<path>\\vk-mcp.exe","env":{"VK_ENDPOINT":"…","VK_LEASE_TOKEN":"…"}}}}`. Prompt: "You are the drafting harness. Read TASK.md, PLAN.md and BRIEF/. Write the proposal to OUT/proposal.md, then call vk_attach_artefact with kind=proposal and path=OUT/proposal.md, then call vk_request_approval." Governor: `JobGovernor::new(2 GiB, None)`.
- [ ] **Step 3: TCB note** — add to `contracts/tcb.md`: "SP1b harness: filesystem and process isolation via workspace ACL + Job Object; network egress of the harness is observed (netwatch) not blocked; restricted-token launch: <result of spike 4a>."
- [ ] **Step 4: Run** — unit tests green; manual: `vk harness run <TASK> --name claude-code` produces `OUT/proposal.md`, the register gains the artefact, `vk dmesg` shows `harness.connections` with only `api.anthropic.com:443`-class endpoints.
- [ ] **Step 5: Commit** — `feat(harness): MCP façade and confined Claude Code launch with workspace projection and egress telemetry`.

---

### Task 5: Passkeys — WebAuthn enrolment and approval inside vkd

**Files:**
- Create: `crates/vk-web/Cargo.toml` (`axum`, `webauthn-rs = "0.5"`, `tokio`, `serde`), `src/lib.rs`, `src/passkey.rs`, `static/enroll.html`, `static/approve.html`
- Modify: `crates/vk-kernel/src/lib.rs` (`record_verified_human_approval`, `pending_approvals()`), `crates/vkd/src/main.rs` (serve `vk-web` on `127.0.0.1:<port>` alongside IPC), `crates/vk-cli/src/main.rs` (`vk passkey enroll` opens the browser; `vk approve TASK --passkey` opens the approval page and waits)

**Interfaces:**
- `passkey::Registry` persisted in the `devices` table with `trust_class: "passkey"` and the serialised `Passkey`; `Webauthn` built with `rp_id = "localhost"`, `rp_origin = http://localhost:<port>`.
- Routes: `GET /enroll` → page; `POST /enroll/start` → `CreationChallengeResponse` (state kept server-side keyed by session id); `POST /enroll/finish` → stores the passkey as device `passkey:<credential_id_b64>` and appends `device.enrolled`. `GET /approve/<task_id>` → page showing goal + artefact hash + "Approve with Windows Hello"; `POST /approve/<task_id>/start` → `RequestChallengeResponse`, state stored **together with the action digest** (`subject_hash`); `POST /approve/<task_id>/finish` → `finish_passkey_authentication`; on success the kernel records `Approval { subject_hash, kind: Human, approver: Human { device_id }, challenge: Some(Challenge{resource: task path, action_digest: subject_hash, nonce: webauthn challenge b64, expires_at_ms}), signature_hex: Some(hex(assertion signature)) }` via `record_verified_human_approval` — an in-process method not reachable over IPC — and logs `approval.recorded` with `proof: "webauthn"`.
- I1 argument, written in the code comment: the only path to a human approval without an ed25519 device key is this in-process handler, whose verification is done by `webauthn-rs` against a passkey enrolled through the admin flow; the client never supplies a principal.

- [ ] **Step 1: Failing tests** — `vk-web/tests/flow.rs` with `webauthn-rs`'s software authenticator (`webauthn-authenticator-rs` `SoftPasskey`): enrol, then approve a task; assert the kernel now holds one human approval for the task's artefact hash and the scheduler's `Approve` step completes. Negative: an assertion for a different challenge/state is rejected and no approval is recorded.
- [ ] **Step 2: Implement** — pages are minimal HTML + the standard `navigator.credentials.create/get` JS with base64url helpers; `vk approve --passkey` prints the URL and opens it (`start` on Windows).
- [ ] **Step 3: Run, commit** — `feat(web): passkey enrolment and approval (WebAuthn, loopback secure context) inside vkd`.

---

### Task 6: Windows service, virtual account, pipe DACL (with spike 6a)

**Files:**
- Create: `crates/vk-service/Cargo.toml` (`windows-service`, `windows` with `Win32_Security_Authorization`), `src/main.rs`, `src/pipe_acl.rs`
- Modify: `crates/vk-ipc/src/transport.rs` (accept an optional security descriptor for the pipe), `crates/vkd/src/main.rs` (`--as-service`)

**Spike 6a (time-box 2 h):** install `vkd` as a service running as `NT SERVICE\vkd` (virtual account) with `sc.exe` semantics through `windows-service`; confirm the keyring (Credential Manager) works under that account; build a pipe security descriptor (SDDL) that grants `GA` to the service SID and the interactive user's SID only; confirm `vk status` from the user's shell connects and a second local user is refused. Record the SDDL string in this task.

**Interfaces:**
- `vkd-service install [--user-sid S]` / `uninstall` / `start` / `stop`; state dir under `C:\ProgramData\VerticalAI\vk` for the service account (still refuses sync folders); pipe created with the SDDL `D:(A;;GA;;;<service SID>)(A;;GA;;;<user SID>)`.

- [ ] **Step 1: Test** (manual, recorded in the gate checklist): install, start, `vk status` works, `vk ls /arches` works, service restart survives (ledger verified at boot), uninstall clean.
- [ ] **Step 2: Implement**; **Step 3: Commit** — `feat(service): vkd as a Windows service under a virtual account; pipe DACL admits the interactive user only`.

---

### Task 7: The demo, both role orders (H1), scripted

**Files:**
- Create: `scripts/demo-sp1.ps1`, `docs/demo/brief/acme-brief.md` (a realistic two-page client brief for a freelance designer), `docs/demo/README.md`

**Interfaces:**
- `demo-sp1.ps1 -Model <gguf> -LlamaBin <exe> [-Roles gemma-plans|claude-plans]`: starts `vkd` (or uses the service), mounts llama-server and Anthropic, creates the task with steps `[Plan(A), Harness(claude-code) or Draft(B), Judge(B), Approve, Release ./out]`, drives `vk task step --all`, opens the passkey page, waits, verifies `./out/*.proposal` exists, prints `vk dmesg -n 40` and `vk ledger verify`; then runs the swapped order and asserts the register's decisions from run 1 are absent in run 2's register (fresh task) but that run 2's plan (by Claude) and draft (by Gemma) both raised into the same IR fields — the H1 check is that `vk task show` for run 2 lists both arch ids on consecutive steps with a non-empty `decisions` after each.
- [ ] **Step 1: Write the brief and the script**; **Step 2: Run both orders on this machine**, save the two `vk dmesg` outputs under `docs/demo/runs/<date>/`; **Step 3: Commit** — `docs(demo): SP1 demo script, brief and recorded runs`.

---

### Task 8: `vk` shell additions and `top` with governed/ungoverned, cost and locality

- `vk mount llama|anthropic|bedrock|mock …`, `vk umount`, `vk arch show ID` (manifest incl. identity tuple and clearance), `vk top` columns: arch, locality, jurisdiction, governed, calls, tokens, projected, cost (from `cost_per_1k_tokens_eur`), `vk task submit --harness claude-code`, `vk passkey enroll|ls`, `vk secret set NAME`, `vk approve --passkey`.
- Tests: smoke test extended for `mount mock` + `arch show`; `top` renders cost for a cloud arch.
- Commit — `feat(cli): arch management, harness steps, passkeys and secrets in the vk shell`.

---

### Task 9: Signing, packaging scaffold, the VM gate checklist

**Files:**
- Modify: `.github/workflows/ci.yml` (`sign` job: `azure/trusted-signing-action` when `AZURE_*` secrets exist, else `signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f cert.pfx` when `SIGNING_CERT_B64` exists; uploads `vk.exe`, `vkd.exe`, `vk-mcp.exe`, `vkd-service.exe` as artifacts), `README.md`
- Create: `docs/sp1-gate-checklist.md`, `scripts/install-windows.ps1` (copies signed binaries to `%LOCALAPPDATA%\Programs\VerticalAI`, adds to user PATH, runs `vkd-service install`)

**Gate checklist (all must be ticked on the VirtualBox stock Windows 11 image with Smart App Control on):**
1. Signed binaries install without SmartScreen/SAC prompts.
2. `vkd` runs as a service under `NT SERVICE\vkd`; `vk status` from the user account works; another local user is refused.
3. `vk ledger verify` ok after a service restart.
4. Harness run: Claude Code cannot read a file outside its workspace (attempt logged, fails); `harness.connections` shows only Anthropic endpoints.
5. Passkey approval with Windows Hello completes; a replayed assertion is rejected.
6. Property tests green on the real kernel; `cargo test --workspace` green in CI on three OSes.
7. Demo script passes in both role orders; recorded runs committed.
8. TCB statement updated with spike outcomes (restricted token, network egress).

- Commit — `ci: signing job (Trusted Signing or OV cert), Windows install script, SP1 gate checklist`.

---

## Self-review

**Spec coverage (SP1 design §4–§9, spec §3.3/§3.6/§3.7/§3.8):** llama-server governed adapter with honest `n_ctx` → Tasks 1, 3; Anthropic US + EU-hosted → Task 2; MCP façade + confined harness + egress telemetry + TCB gap stated → Task 4; passkey ceremony in-process with I1 argument → Task 5; service account, DACL, state dir → Task 6; demo with role swap (H1) → Task 7; shell additions → Task 8; signing, install, gate → Task 9. Out of scope items match SP1 design §9.

**Placeholder scan:** spikes 3a, 4a, 6a are explicit, time-boxed, and each names the artefact it must produce (constant names, flag verification, SDDL); no other open steps.

**Type consistency:** `ArchAdapter` methods as defined in SP1a Task 4; `Governor::contain(&Child)` identical in Tasks 1 and 3; `StepKind::Harness { name }` as in SP1a Task 6; `Approval` fields as in SP0; `record_verified_human_approval` named identically in Tasks 5 and the file structure.
