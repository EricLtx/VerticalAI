# SP1b — Real Arches (Ollama container + Claude via subscription), Confined Harness, Passkeys, Windows Service and the Demo — Implementation Plan (rev. 2, 2026-09-24)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Prerequisite:** SP1a complete (tag `sp1a`, master `6057c53`): the `vk` shell works against the mock arch, the whole-branch review is clean, CI is green on Windows/Ubuntu/macOS.

**Revision note (2026-09-24).** The founder decided on 2026-09-24: (1) the local arch is a Gemma-class model served by **Ollama in a Docker container**, llama-server stays optional as the Vulkan iGPU path; (2) Claude joins through **the founder's Claude subscription**, i.e. a Claude Code adapter, while the Anthropic API adapters remain for customers and the EU-hosted case when keys exist; (3) a **`boot.forced` ledger event** is added (event-set change approved); (4) `policies_version` keeps being written as `"0"` on first boot; (5) no free cloud node for now. The SP1a final review's backlog (docs/superpowers/reviews/2026-09-24-sp1a-final-review.md: M1–M11, M13, M14, M16, N1–N4 and recommendations 1–8) is folded into Tasks 0, 1, 5, 8 and the new Task 10. Tasks 3–6 and 9 are unchanged from rev. 1 except where noted.

**Goal:** Replace the mock with governed real arches (Gemma in an Ollama container; Claude via the subscription; API arches when keys exist), run Claude Code as a confined harness through an MCP façade, make the human ceremony a WebAuthn passkey (Windows Hello now, iPhone later), install the kernel as a Windows service, sign the binaries, harden what the SP1a review flagged, and pass the SP1 demo: a client proposal drafted from a brief by Gemma and Claude co-working through the IR, approved with a passkey, with the roles swapped in a second run (H1).

**Architecture:** Adapters implement SP1a's `ArchAdapter`. The Ollama arch is a container the kernel starts through the `docker` CLI with memory and CPU caps (that is its governor) and whose model identity is content-addressed (the Ollama model digest); it reports an honest context ceiling and refuses prompts it would truncate (I4′). The Claude Code arch is a pure completion: `claude -p` in JSON mode, no tools, the founder's login, the prompt on stdin. `vk-mcp` is a stdio MCP server the harness talks to; every tool call becomes a syscall under the harness's lease. `vk-harness` materialises a label-projected workspace, launches Claude Code under a Job Object, records its outbound connections, and attaches the produced artefact. `vk-web` runs inside `vkd` and serves `http://127.0.0.1:<port>` for passkey enrolment and approval; verification happens in-process with `webauthn-rs`; approval challenges are minted by the kernel. `vk-service` wraps `vkd` as a Windows service under a virtual account with a pipe DACL that admits the interactive user.

**Tech Stack:** SP1a stack plus `reqwest` (rustls, blocking, json), `sha2`, the `docker` CLI (no Docker crate), `windows` crate (Job Objects, security descriptors), `windows-service`, `webauthn-rs` 0.5, `axum`, `zeroize`; `aws-sdk-bedrockruntime` + `aws-config` only in Task 2b; signtool / Azure Trusted Signing in CI.

**Spec:** design spec §3.3 (governor), §3.6 (ceremony), §3.7 (arches, manifests, learning modes), §3.8 (nodes, Windows packaging), §3.11, §5; SP1 design approved 2026-09-23 (§4 arches, §5 harness confinement with its stated caveat, §6 ceremony, §8 demo, §9 out of scope). Companion: `2026-09-23-sp1a-kernel-core-store-ipc-cli.md`; review: `docs/superpowers/reviews/2026-09-24-sp1a-final-review.md`.

## Execution tiering

| Tier | Model / effort | Tasks |
|---|---|---|
| Hard — process confinement, security descriptors, WebAuthn binding, governor, crypto hardening | Fable 5.1 / xhigh | 3, 4, 5, 6, 10 |
| Standard — adapters, adapter re-mount, MCP façade, service wrapper, demo orchestration, shell | Opus 5 / high | 1, 1b, 2, 2b, 7, 8 |
| Mechanical — `boot.forced` event, CI signing job, docs, checklist | Sonnet 5 / medium | 0, 9 |
| Spikes (time-boxed, throwaway code allowed, findings recorded in the plan) | Fable 5.1 / xhigh | 1a, 2a, 3a, 4a, 6a |

**Founder checkpoints (rule of 2026-09-23):** any spike outcome that changes the TCB, any new ledger event kind beyond Task 0, any change to a contract type, any CLI verb not listed here, and the choice in Task 1a between the 4B and the 1B model for the demo go to the founder before the task continues.

## Global Constraints

- Everything in SP1a's Global Constraints, plus the founder rule above.
- **Ollama runs in a Docker container managed through the `docker` CLI.** Image `ollama/ollama` pinned by tag in the manifest and recorded by digest (`docker image inspect --format '{{index .RepoDigests 0}}'`); container name `vk-ollama`; port published on loopback only (`-p 127.0.0.1:11434:11434`); weights in the named volume `vk-ollama`; caps `--memory` and `--cpus` from the mount command. `governed: true` only when both caps were applied. `--external URL` mounts an Ollama the kernel does not manage as `governed: false`.
- **Model identity is content-addressed:** the model digest from `GET /api/tags` (`models[].digest`) plus `POST /api/show` details (`details.family`, `details.parameter_size`, `details.quantization_level`, `model_info["<family>.context_length"]`). Two tags: `VK_DEMO_MODEL` (4B-class Gemma, latest generation in the Ollama library) and `VK_TEST_MODEL` (1B-class Gemma). Spike 1a pins both tags in Task 1's "Pinned values" block; until then no code hard-codes a tag.
- **I4′ against Ollama (measured by spike 1a on Ollama 0.33.3):** Ollama silently truncates an oversize prompt to `num_ctx / 2 + 3` tokens — HTTP 200, `done_reason: "stop"`, only a WARN in its own log — so the honest ceiling is **half** of the context. The adapter always sends `options.num_ctx`; the manifest's `context_ceiling` is `min(num_ctx, context_length) / 2`; there is no `/api/tokenize` on this version (404), so the pre-check uses the estimate `bytes/3 + 64` (measured 1.25× the real count) and refuses above 90 % of the ceiling with the existing I4′ error; after the call it fails the step when `prompt_eval_count >= num_ctx / 2`. Gemma 4 thinks by default (`message.thinking` consumes `eval_count`), so every chat request sends top-level `"think": false`. No silent truncation, ever.
- **Claude Code as an arch (Task 2) is a pure completion on the founder's subscription:** the launch line pinned by spike 2a (Task 2, "Pinned values"), prompt on stdin, cwd = one fixed empty directory `<state_dir>/claude-code-cwd` (Ruling 4: `--no-session-persistence` still creates a `memory/` directory per cwd), never an API key. Manifest `locality: cloud`, `jurisdiction: "US"`, `retention_days: Some(30)`, `clearance: Business / third_party_allowed: false`. Customer nodes must use Task 2b's API arches (consumer terms); the README says so.
- **Anthropic API calls (Task 2b) use raw HTTPS**: `POST https://api.anthropic.com/v1/messages`, header `anthropic-version: 2023-06-01`, default model `claude-opus-5`, `thinking: {"type":"adaptive"}`, `max_tokens` ≤ 4096; API key from the OS keyring entry `vk/anthropic`, never a file, never a manifest. **EU-hosted** = Bedrock `eu-central-1`/`eu-west-1` via `converse`; runs only when AWS credentials are present.
- **Claude Code as the harness (Task 4)** is launched non-interactively: `claude -p "<prompt>" --mcp-config <path> --allowedTools "mcp__vk__*,Read,Write,Edit,Glob,Grep" --permission-mode acceptEdits --output-format json`, cwd = the materialised workspace.
- **The passkey page is a secure context only on loopback**; it binds to loopback exclusively in SP1b. TLS + LAN comes with SP4.
- **Nothing new in `contracts/` except Task 0** (`boot.forced`), regenerated with `cargo run -p vk-contracts --bin gen-schemas`; the `schema_drift` test stays green after every task.
- **No demo counts as passed on the developer machine alone.** Task 9's gate runs on the VirtualBox stock-Windows image, with Docker Desktop installed by the install script's checklist.

---

## File structure

```
crates/vk-arch-ollama/        src/lib.rs (OllamaAdapter), src/api.rs (request/response types), src/container.rs (docker CLI), tests/api.rs (fake Ollama), tests/container.rs (#[ignore] unless VK_OLLAMA=1)
crates/vk-arch-claude-code/   src/lib.rs (ClaudeCodeAdapter), src/output.rs (JSON parsing), tests/output.rs, tests/fake_claude.rs (scripted binary), tests/live.rs (#[ignore] unless VK_CLAUDE=1)
crates/vk-arch-anthropic/     src/lib.rs (first-party), src/bedrock.rs (EU-hosted), tests/mock.rs            (Task 2b)
crates/vk-arch-llama/         optional, rev. 1 text kept in git history; only if the Vulkan iGPU path is wanted
crates/vk-mcp/                src/main.rs (stdio MCP server binary `vk-mcp`), src/protocol.rs, src/tools.rs
crates/vk-harness/            src/lib.rs (workspace materialisation, launch, collect), src/confine.rs (Job Object + restricted token), src/netwatch.rs
crates/vk-web/                src/lib.rs (axum router inside vkd), src/passkey.rs (webauthn-rs), static/approve.html, static/enroll.html
crates/vk-service/            src/main.rs (`vkd-service` install/uninstall/run), src/pipe_acl.rs
crates/vk-contracts/src/ledger.rs   modified: `boot.forced` in the allowed kinds (Task 0)
crates/vk-kernel/src/lib.rs   modified: forced-boot record; mount adapters by kind; record_verified_human_approval; mint_approval_challenge; harness step execution; interrupted-step recovery; zeroize
crates/vk-store/src/*         modified (Task 10): DEK AAD, payload-tier modes, HLC re-seed, ownership check
crates/vk-cli/src/main.rs     modified: `vk mount ollama|claude-code|anthropic|bedrock|mock …`, `vk arch show`, `vk fsck`, `vk passkey enroll`, `vk approve --passkey`, `vk harness …`, `vk secret set`
.github/workflows/ci.yml      modified: `arch-ollama` job (ubuntu, docker, test model), sign job, artifacts
scripts/demo-sp1.ps1          the demo, end to end, both role orders (Ollama Gemma ↔ Claude)
docs/demo/                    brief, README, recorded runs
docs/sp1-gate-checklist.md    the VM gate
```

---

### Task 0: `boot.forced` ledger event (founder decision 2026-09-24)

**Files:**
- Modify: `crates/vk-contracts/src/ledger.rs` (allowed kinds gain `boot.forced`), `contracts/schemas/*` (regenerated), `crates/vk-kernel/src/lib.rs` (`record_forced_boot`), `crates/vkd/src/main.rs` (call it when serving under `--force`), `crates/vk-cli/src/render.rs` (`vk status` prints `forced boot` when the last boot-class event is `boot.forced`), `README.md` (one sentence)

**Interfaces:**
- `RealKernel::record_forced_boot(&mut self, report: &BootReport) -> Result<(), KernelError>`: appends `boot.forced` with payload `{ "ledger_ok": bool, "head_ok": bool, "ledger_len": usize, "report_hash": "sha256:…" }`, ledger-before-mutation discipline as for `boot`. Called by `vkd` only after it decided to serve under `--force`; never when the chain is fine.

- [ ] **Step 1: Failing tests** — contracts: `boot.forced` accepted by the allowed-kinds check and present in the regenerated schema (the `schema_drift` test fails until regenerated); kernel: tamper the ledger on disk, reopen, call `record_forced_boot` → last event kind `boot.forced` with `ledger_ok:false`; e2e (`vk-cli/tests/smoke.rs`): `vk boot --force` on a cut store → `vk dmesg -n 3 --json` contains `boot.forced`, and a healthy `vk boot` never emits it.
- [ ] **Step 2: Implement**, regenerate schemas, run `cargo test --workspace` on Windows and in WSL, clippy, fmt.
- [ ] **Step 3: Commit** — `feat(ledger): boot.forced event when the daemon serves a broken record under --force`.

---

### Task 1: Ollama adapter — Gemma in a governed container (with spike 1a)

**Files:**
- Create: `crates/vk-arch-ollama/Cargo.toml`, `src/lib.rs`, `src/api.rs`, `src/container.rs`, `tests/api.rs`, `tests/container.rs`
- Modify: workspace `Cargo.toml` (`reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json", "blocking"] }`), `crates/vk-kernel/src/lib.rs` (`infer` intent logged before the send; interrupted-step recovery), `crates/vk-kernel/src/tasks.rs` (steps left `Running` at boot → `Failed("interrupted by restart")`), `crates/vk-cli/src/main.rs` (`vk mount ollama --model TAG [--container | --external URL] [--ctx N] [--memory 12g] [--cpus 6] [--image ollama/ollama:TAG] [--seed N]`), `.github/workflows/ci.yml` (`arch-ollama` job)

**Spike 1a (time-box 1 h, Fable, on this machine with Docker Desktop):**
1. `docker run -d --name vk-ollama -p 127.0.0.1:11434:11434 -v vk-ollama:/root/.ollama --memory 12g --cpus 6 ollama/ollama`, then `GET /api/version`.
2. Pull the candidate 4B-class and 1B-class Gemma tags with `POST /api/pull {"name": TAG, "stream": false}`; list `GET /api/tags` and `POST /api/show {"model": TAG}`; record the exact tags, the digest strings, and the exact JSON paths for family, parameter size, quantization and context length.
3. Check whether `POST /api/tokenize {"model": TAG, "prompt": "…"}` exists on this Ollama version; record the version.
4. Time one 400-token completion of the 4B on CPU (`eval_count / eval_duration`) and the container's memory (`docker stats --no-stream`).
5. **Founder checkpoint:** if the 4B runs below ~4 tokens/s, ask whether the demo uses the 1B-class model or the optional llama-server Vulkan path; otherwise proceed with the 4B for the demo and the 1B for tests.

**Pinned values (filled by spike 1a on 2026-09-24, then verbatim in the code; full log in `.superpowers/sdd/2026-09-23-sp1b-arches-harness-passkeys-service-demo/spike-1a-report.md`):**
- `VK_DEMO_MODEL = "gemma4:e4b"` — digest `c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb`; `details.family` `"gemma4"`, `details.parameter_size` `"8.0B"` (Gemma 4 E4B, effective 4B — the raw count includes per-layer embeddings), `details.quantization_level` `"Q4_K_M"`; 9.6 GB (alias of `gemma4:e4b-it-q4_K_M` and `gemma4:latest`).
- `VK_TEST_MODEL = "gemma3:1b"` — digest `8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc`; `"gemma3"`, `"999.89M"`, `"Q4_K_M"`; 815 MB (Gemma 4 has no 1B-class tag; its smallest, `gemma4:e2b`, is 7.2 GB).
- Image `ollama/ollama:0.33.3`, digest `sha256:32931b46719f673c05fdbaa81ccb26da18ea4a1c57590a754874ab28ba269eb2` (`GET /api/version` → `"0.33.3"`; Hub `latest` had already moved to `0.34.3`, unmeasured).
- `tokenize_available = false` — `POST /api/tokenize` → 404 `404 page not found` on 0.33.3; the estimate `bytes/3 + 64` measured 1.25× the real count on 36 kB of prose and 1.9× on a 1.3 kB prompt (real counts include the chat template).
- Context-length JSON path: `model_info["<details.family>.context_length"]` from `POST /api/show` (`gemma4.context_length` = 131072, `gemma3.context_length` = 32768). A `capabilities` array exists on `/api/show` (e4b: `completion, vision, audio, tools, thinking`) and on `/api/tags` (e4b: `completion, tools, thinking`).
- Measured on CPU, `num_ctx 8192`, seed 7, temperature 0.2: `gemma4:e4b` **10.1 tokens/s** generation (34 tokens/s prompt eval, 25 s cold load, container at 9.66 GiB of the 12 GiB cap, `OOMKilled=false`); `gemma3:1b` **22.5 tokens/s** (158 tokens/s prompt eval, 9 s load, ~1.9 GiB). Founder checkpoint not triggered.
- Truncation observed: a 9,605-token prompt at `num_ctx 2048` returns HTTP 200, `done_reason "stop"`, no error field, `prompt_eval_count 1027`; Ollama cuts the prompt to **`num_ctx/2 + 3` tokens** (515 at 1024, 1027 at 2048, 2051 at 4096, independent of `num_predict`) and only logs `WARN "truncating input prompt"`. So the I4′ pre-check ceiling is `min(num_ctx, context_length) / 2` and the post-check is `prompt_eval_count < num_ctx/2` (the plan's `num_ctx − 8` never fires). The demo model also needs top-level `"think": false` on `/api/chat` (verified honoured) or the tokens go to `message.thinking`.

**Interfaces:**

```rust
pub struct ContainerSpec { pub image: String, pub name: String, pub memory: String, pub cpus: String, pub volume: String }
impl Default for ContainerSpec { /* "ollama/ollama:<pinned>", "vk-ollama", "12g", "6", "vk-ollama" */ }
pub struct OllamaConfig { pub base_url: String, pub model: String, pub num_ctx: u32, pub seed: u64, pub temperature: f32, pub container: Option<ContainerSpec> }
pub struct ModelIdentity { pub digest: String, pub family: String, pub parameter_size: String, pub quantization: String, pub context_length: u32 }
pub struct OllamaAdapter { /* cfg, client, identity, ollama_version, tokenize_available, governed */ }
impl OllamaAdapter {
    pub fn mount(cfg: OllamaConfig) -> anyhow::Result<OllamaAdapter>;   // container::ensure when cfg.container is Some; wait GET /api/version ≤ 60 s; pull the model if absent (POST /api/pull, stream:false); read identity; probe /api/tokenize once
    pub fn manifest_for(cfg: &OllamaConfig, id: &ModelIdentity, ollama_version: &str, governed: bool) -> ArchManifest;
    // context_ceiling = min(cfg.num_ctx, id.context_length) / 2 (spike 1a: Ollama truncates at half); locality Local; jurisdiction "local"; identity tuple = (family, parameter_size, quantization, digest, ollama_version, num_ctx, seed); governed as given
    pub fn estimate_tokens(text: &str) -> u32;   // text.len() / 3 + 64
    pub fn chat_request(cfg: &OllamaConfig, prompt: &str) -> api::ChatRequest;   // {model, messages:[{role:"user", content}], stream:false, think:false, options:{num_ctx, seed, temperature}}
}
impl ArchAdapter for OllamaAdapter { … }
// complete: ceiling = min(num_ctx, context_length) / 2; pre-check estimate_tokens(prompt) > 0.9 * ceiling → I4′ error; POST /api/chat with "think": false; post-check prompt_eval_count >= num_ctx / 2 → I4′ error (Ollama truncated); returns message.content and usage {tokens_in: prompt_eval_count, tokens_out: eval_count}
// count_tokens: POST /api/tokenize when available, else estimate_tokens
pub mod container {
    pub enum State { Started, AlreadyRunning }
    pub fn ensure(spec: &ContainerSpec) -> anyhow::Result<State>;   // `docker container inspect` → start if exited, run if absent (the exact `docker run` line from the constraints), error if docker is missing (message names Docker Desktop)
    pub fn image_digest(spec: &ContainerSpec) -> anyhow::Result<String>;
    pub fn caps_applied(spec: &ContainerSpec) -> anyhow::Result<bool>;   // inspect HostConfig.Memory > 0 && NanoCpus > 0
    pub fn stop(spec: &ContainerSpec) -> anyhow::Result<()>;
}
```

- [ ] **Step 1: Failing tests** (`tests/api.rs`, against a loopback fake Ollama built with `axum` in the test: canned `/api/version`, `/api/tags`, `/api/show`, `/api/tokenize`, `/api/chat`):

```rust
#[test] fn chat_request_pins_num_ctx_seed_no_streaming_and_no_thinking()   // serialised JSON contains "stream":false, "think":false, "num_ctx":8192, "seed":7
#[test] fn manifest_identity_changes_with_digest_num_ctx_or_seed()   // three manifests, three arch ids; context_ceiling == min(num_ctx, context_length) / 2; governed as given
#[test] fn refuses_a_prompt_the_model_would_truncate()   // a prompt whose estimate is 0.95 * ceiling → complete() is the I4′ error, and the fake /api/chat was never hit
#[test] fn fails_when_the_server_reports_a_truncated_prompt()   // fake /api/chat returns prompt_eval_count == num_ctx / 2 + 3 → I4′ error
#[test] fn estimate_is_conservative()   // for 20 English sentences estimate_tokens ≥ 1.2 × the fake tokenizer's count
#[test] fn usage_is_measured_not_guessed()   // tokens_in == prompt_eval_count from the fake
```
`tests/container.rs` (`#[ignore]`, run with `VK_OLLAMA=1`): real Docker, `ensure` twice → `Started` then `AlreadyRunning`; pull `VK_TEST_MODEL`; `complete("Reply with the single word ok")` → non-empty; manifest digest equals `/api/tags` digest; `caps_applied` true.

- [ ] **Step 2: Run to verify failure** — compile errors.
- [ ] **Step 3: Implement** per interfaces. Kernel side: `infer` is logged with `phase: "requested"` (same event kind, an extra payload field) before `adapter.complete` and `phase: "completed"` after, so a crash mid-send leaves a trace (review M2); at boot, any step still `Running` is set to `Failed("interrupted by restart")` and logged, never re-run (review M11).
- [ ] **Step 4: Wire** — `vk mount ollama …` builds the config (defaults: `--ctx 8192`, `--memory 12g`, `--cpus 6`, container mode), mounts, prints the arch id and `governed`. `vk top` shows `governed` per arch.
- [ ] **Step 5: CI** — job `arch-ollama` on `ubuntu-latest` (Docker preinstalled): `VK_OLLAMA=1 cargo test -p vk-arch-ollama -- --ignored` with `VK_TEST_MODEL`, on push to master and `workflow_dispatch` (the 1B pull per run is accepted; add `actions/cache` for the volume only if it stays under 2 GB).
- [ ] **Step 6: Commit** — `feat(arch): Ollama adapter — containerised Gemma with content-addressed identity, caps as governor, and honest context (I4′)`.

---

### Task 1b: Adapter re-mount at boot (Ruling 6, 2026-09-24)

Found during Task 2: `RealKernel::load` rebuilds a `MockAdapter` for every persisted manifest, so a real arch silently degrades to the mock after a `vkd` restart. Restarts are the normal case once Task 6 installs the service, so this lands before Task 3.

**Files:**
- Modify: `crates/vk-store/src/db.rs` (table `mounts(arch_id TEXT PRIMARY KEY, kind TEXT, config_json TEXT)`), `crates/vk-kernel/src/lib.rs` (`AdapterFactory`, `RealKernel::open_with_factory`, `load` no longer fabricates mocks, `ArchState::{Ready, Unavailable(String)}` on the arch table), `crates/vk-kernel/src/arch.rs` (`MountSpec { kind, config }` stored alongside the manifest; secrets are never part of `config`), `crates/vk-ipc/src/server.rs` (`arch.mount` persists the spec; `arch.ls` and `ns.ls /arches/<id>` show `state`), `crates/vkd/src/main.rs` (builds the factory from the compiled-in kinds: `mock`, `claude-code`, `ollama` once Task 1 exists), `crates/vk-cli/src/render.rs` (`state` column in `vk ls /arches` and `vk top`)

**Interfaces:**
- `pub type AdapterFactory = Box<dyn Fn(&MountSpec) -> anyhow::Result<Box<dyn ArchAdapter>> + Send + Sync>;`
- `RealKernel::open_with_factory(state_dir, key_source, node_id, factory: AdapterFactory)`; `RealKernel::open` keeps its signature and uses a factory that knows only `mock` (tests).
- On load, every persisted manifest is re-created through the factory: `Ok(adapter)` → `Ready`; `Err(e)` → `Unavailable(e.to_string())`, logged at warn, listed by `arch.ls` with its state, refused by the scheduler with a clear step failure (never a mock). `arch.mount` on an `Unavailable` id with the same manifest re-attaches (the SP1a "identical re-mount swaps the adapter" rule).

- [ ] **Step 1: Failing tests** — kernel: mount a stand-in adapter whose factory succeeds, drop and reopen the kernel with the same factory → the arch is `Ready` and `infer` reaches the stand-in (not a mock); reopen with a factory that fails for that kind → `Unavailable`, `run_task_step` on a step naming it → `Failed("arch unavailable: …")`, no `infer` event. IPC: `arch.ls` shows `state`. Smoke: `vk mount claude-code --bin <stand-in>`, `vk boot` again on the same store → `vk ls /arches --json` shows `ready` and `vk task step` runs through the stand-in.
- [ ] **Step 2: Implement**; **Step 3: Run** both OSes, clippy, fmt; **Step 4: Commit** — `fix(kernel): re-create real adapters at boot from a persisted mount spec; unavailable arches are listed, never mocked`.

---

### Task 2: Claude Code adapter — Claude via the founder's subscription (with spike 2a)

**Files:**
- Create: `crates/vk-arch-claude-code/Cargo.toml`, `src/lib.rs`, `src/output.rs`, `tests/output.rs`, `tests/fake_claude.rs`, `tests/live.rs`
- Modify: `crates/vk-cli/src/main.rs` (`vk mount claude-code [--draft-model claude-sonnet-5] [--judge-model claude-opus-5] [--bin claude] [--timeout 180]` mounts two arches, `claude-code/<draft-model>` and `claude-code/<judge-model>`, and prints both ids), `README.md` (subscription vs customer note)

**Spike 2a (time-box 30 min, Fable):** on the installed Claude Code: confirm `-p`, `--output-format json`, `--model`, `--max-turns`, the flag that disables every tool (candidates: `--tools ""`, `--disallowedTools "*"`, `--allowedTools ""`), whether a prompt can be passed on stdin with `-p` and no positional argument, and the JSON fields (`result`, `is_error`, `usage.input_tokens`, `usage.output_tokens`, `total_cost_usd`, `duration_ms`, `session_id`, `modelUsage`). Time a 300-token completion under the subscription login. Record the exact launch line in this task's "Pinned values" block. **Founder checkpoint** only if no flag disables tools (then the adapter runs in an empty, read-only temp dir and the TCB note says so).

**Pinned values (filled by spike 2a on 2026-09-24; full log in `.superpowers/sdd/2026-09-23-sp1b-arches-harness-passkeys-service-demo/spike-2a-report.md`):**
- Claude Code 2.1.281 (native `claude.exe`); auth `claude.ai` subscription; no `ANTHROPIC_*` variable; no nested-session variable needs clearing.
- Launch line (argv; prompt on stdin, no positional argument; cwd = `<state_dir>/claude-code-cwd`): `claude -p --output-format json --model <id> --max-turns 1 --tools "" --safe-mode --strict-mcp-config --no-session-persistence --system-prompt "You are a text completion engine with no tools. Answer the prompt directly in plain text."`
- Tool disabling: `--tools ""` removes every built-in; `--safe-mode --strict-mcp-config` keep MCP connectors out (verified `tools: []`, `mcp_servers: []`, `num_turns: 1`, zero tool_use on a tempting prompt); `--allowedTools ""` is a no-op; never `--bare` (drops the login); `--max-turns` is enforced (exit 1, `error_max_turns`).
- JSON: `result`, `is_error` (also `terminal_reason`, `api_error_status`; `subtype` stays `"success"` on API errors; process exit 1 on error), `session_id`, `num_turns`, `duration_ms`, `duration_api_ms`, `ttft_ms`, `total_cost_usd` (list-price equivalent, `modelUsage.<id>.costBasis == "list"`, not billed under the subscription), `usage.input_tokens` (uncached only; prompt total = `input_tokens + cache_creation_input_tokens + cache_read_input_tokens`), `usage.output_tokens`, `modelUsage.<id>.{inputTokens, outputTokens, cacheReadInputTokens, cacheCreationInputTokens, costUSD, contextWindow}`.
- Latency: ≈ 9–11 s wall for ~500 output tokens on `claude-sonnet-5`, ≈ 14 s on `claude-opus-5`, ~3 s of it process start-up; a 6 KB stdin prompt works.
- Session files: `--no-session-persistence` writes no transcript but still creates an empty `~/.claude/projects/<mangled-cwd>/memory/` per call → one fixed cwd (Ruling 4).

**Interfaces:**

```rust
pub struct ClaudeCodeConfig { pub binary: PathBuf, pub model: String, pub max_turns: u32, pub timeout: std::time::Duration, pub context_ceiling: u32 }
impl Default for ClaudeCodeConfig { /* "claude", "claude-sonnet-5", 1, 180 s, 200_000 */ }
pub struct ClaudeCodeAdapter { … }
impl ClaudeCodeAdapter {
    pub fn new(cfg: ClaudeCodeConfig) -> ClaudeCodeAdapter;
    pub fn manifest_for(cfg: &ClaudeCodeConfig, claude_version: &str) -> ArchManifest;   // locality Cloud, jurisdiction "US", retention_days Some(30), clearance Business / third_party_allowed false, governed false, identity (model, claude_version, max_turns)
    pub fn launch_line(cfg: &ClaudeCodeConfig) -> Vec<String>;   // pinned by spike 2a; prompt on stdin
    pub fn estimate_tokens(text: &str) -> u32;   // text.len() / 3 + 64
}
impl ArchAdapter for ClaudeCodeAdapter { … }
// complete: pre-check estimate > 0.9 * context_ceiling → I4′ error; spawn the launch line with cwd = fresh empty temp dir, stdin = prompt, wait ≤ timeout (kill on expiry, error names the timeout); parse JSON; is_error → Err with the result text; usage from usage.*; cost recorded from total_cost_usd (0 under a subscription is fine) — never guessed
// count_tokens: estimate_tokens (no tokenizer endpoint); the measured usage.input_tokens is what the ledger records after the call
pub mod output { pub struct ClaudeJson { pub result: String, pub is_error: bool, pub input_tokens: u64, pub output_tokens: u64, pub total_cost_usd: f64, pub duration_ms: u64, pub session_id: String } pub fn parse(s: &str) -> anyhow::Result<ClaudeJson>; }
```

- [ ] **Step 1: Failing tests** — `tests/output.rs`: `parse` on a canned JSON (from spike 2a) yields the fields; a JSON with `is_error:true` yields an error carrying `result`; malformed input errors. `tests/fake_claude.rs`: a scripted stand-in binary (`fake-claude.cmd` on Windows / `fake-claude.sh` on Unix, written by the test into a temp dir) that echoes a canned JSON and records its argv and stdin to a file; assert the launch line, that the prompt arrived on stdin, that a slow stand-in is killed at the timeout, and that `tokens_in == usage.input_tokens`. `tests/live.rs` (`#[ignore]`, `VK_CLAUDE=1`): the real CLI completes "Reply with the single word ok" and the manifest's `claude_version` is non-empty.
- [ ] **Step 2: Implement**; **Step 3: Wire** `vk mount claude-code`; **Step 4: TCB note** in `contracts/tcb.md`: "Claude Code adapter: pure completion, no tools, egress to Anthropic not observed in SP1b; subscription use is the founder's own; customer nodes use API arches."
- [ ] **Step 5: Commit** — `feat(arch): Claude Code adapter — Claude via the subscription as a pure-completion arch with measured usage`.

---

### Task 2b: Anthropic API adapters — first-party (US) and EU-hosted (Bedrock), when keys exist

Unchanged from rev. 1; needed for customer nodes and the EU jurisdiction, not for the demo.

**Files:**
- Create: `crates/vk-arch-anthropic/Cargo.toml`, `src/lib.rs`, `src/bedrock.rs`, `tests/mock.rs`
- Modify: `crates/vk-cli/src/main.rs` (`vk mount anthropic [--model M]`, `vk mount bedrock --region eu-central-1 [--model M]`), `crates/vkd/src/main.rs` (keyring lookup `vk/anthropic`)

**Interfaces:**
- `AnthropicAdapter::new(api_key: SecretString, model: &str, base_url: &str) -> Self` with manifest `locality: Cloud, jurisdiction: "US", retention_days: Some(30), clearance: Business / third_party_allowed: false` by default (policy may raise it); `complete` posts `/v1/messages` with `{"model", "max_tokens", "thinking": {"type":"adaptive"}, "messages":[{"role":"user","content": prompt}]}` and concatenates `text` blocks; `count_tokens` posts `/v1/messages/count_tokens`.
- `BedrockAdapter::new(region, model_id) -> Result<Self>` (async client wrapped with a small runtime handle); manifest `jurisdiction: "EU"`, `retention_days: None`, clearance as above.

- [ ] **Step 1: Failing tests** (`tests/mock.rs`) — a tiny axum server on loopback returning a canned `/v1/messages` JSON; assert `complete` returns the concatenated text, sends `anthropic-version` and `x-api-key`, and `manifest().jurisdiction == "US"`. For Bedrock, unit-test only the manifest and `bedrock::converse_input(prompt, max_tokens)`.
- [ ] **Step 2: Implement** per interface; keys via `keyring::Entry::new("vk", "anthropic")` in `vkd` when mounting; `vk mount anthropic` fails with a clear message if the entry is missing and prints the one-liner to set it (`vk secret set anthropic` → prompts on the terminal, stores in keyring; never echoes).
- [ ] **Step 3: Run, commit** — `feat(arch): Anthropic first-party (US) and Bedrock EU adapters with jurisdiction-tagged manifests`.

---

### Task 3: Governor — Job Object containment on Windows (with spike 3a)

Unchanged from rev. 1. Applies to kernel-launched processes: the harness (Task 4) and the optional llama-server. The Ollama arch is governed by its container caps (Task 1), not by a Job Object.

**Files:**
- Create: `crates/vk-harness/src/confine.rs` (the `Governor` trait and `JobGovernor` live here now; `vk-arch-llama` imports it if built)
- Modify: `crates/vk-harness/Cargo.toml` (`[target.'cfg(windows)'.dependencies] windows = { version = "0.61", features = ["Win32_Foundation", "Win32_System_JobObjects", "Win32_System_Threading", "Win32_Security"] }`)

**Spike 3a (time-box 2 h):** confirm on this machine that a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS` kills a child when `vkd` exits and enforces the memory cap; record the exact `windows` crate version and any API-name corrections in this task before implementing.

**Interfaces:**
- `pub trait Governor: Send + Sync { fn contain(&self, child: &std::process::Child) -> anyhow::Result<()>; }`
- `JobGovernor::new(max_memory_bytes: u64, cpu_rate_percent: Option<u32>) -> Result<JobGovernor>` implementing `Governor::contain(&Child)`; `Drop` closes the handle (which kills the job). On Linux/macOS `NoopGovernor` logs "ungoverned" and the manifest sets `governed: false` until SP4 (cgroups / `sandbox-exec`).

- [ ] **Step 1: Failing test** (Windows-only, `#[cfg(windows)]`): spawn `cmd /c ping -n 30 127.0.0.1` under a `JobGovernor`, drop the governor, assert the child exits within 2 s (`child.try_wait()` loop). Second test: a 64 MiB cap makes `powershell -c "$a = New-Object byte[] 268435456"` fail (non-zero exit) while the same command without the cap succeeds.
- [ ] **Step 2: Implement** (the rev. 1 code block is in git history at `9da7859:docs/superpowers/plans/2026-09-23-sp1b-arches-harness-passkeys-service-demo.md` lines 246–279; field and constant names are from `windows` 0.5x–0.6x, expect a short compile-fix loop — that is what spike 3a is for).
- [ ] **Step 3: Run, commit** — `feat(governor): Job Object containment for kernel-launched processes (Windows)`.

---

### Task 4: MCP façade and confined Claude Code harness (with spike 4a)

Unchanged from rev. 1. Note the difference with Task 2: the **adapter** is a tool-less completion used as an arch for plan/draft/judge steps; the **harness** is an agent with tools, confined, used for `StepKind::Harness`.

**Files:**
- Create: `crates/vk-mcp/…` (binary `vk-mcp`), `crates/vk-harness/…`
- Modify: `crates/vk-kernel/src/tasks.rs` (`StepKind::Harness` executes), `crates/vk-kernel/src/lib.rs` (`harness_lease`, `record_harness_connection`), `crates/vk-cli/src/main.rs` (`vk harness run TASK --name claude-code`, `--dry-run` prints the launch line)

**Spike 4a (time-box 3 h):** (i) verify the Claude Code CLI flags on the installed version (`claude --help`): `-p`, `--mcp-config`, `--allowedTools`, `--permission-mode`, `--output-format json`; (ii) verify Claude Code connects to a stdio MCP server declared in a JSON config and lists `mcp__vk__*` tools; (iii) try `CreateRestrictedToken` + `CreateProcessAsUser` for the harness — if it cannot be made to work within the box, SP1b ships **Job Object + workspace ACL + netwatch** and records restricted-token launch as the open TCB item (spec §5), stated in the gate checklist. **Founder checkpoint** on (iii).

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

### Task 5: Passkeys — WebAuthn enrolment and approval inside vkd; kernel-issued approval challenges

Rev. 1 plus review items M5 and recommendation 2: the kernel mints every approval challenge (nonce, resource, expiry) and `approve` rejects a challenge it did not mint; the same rule applies to the SP1a node-key path so the two ceremonies share one verifier.

**Files:**
- Create: `crates/vk-web/Cargo.toml` (`axum`, `webauthn-rs = "0.5"`, `tokio`, `serde`), `src/lib.rs`, `src/passkey.rs`, `static/enroll.html`, `static/approve.html`
- Modify: `crates/vk-kernel/src/lib.rs` (`mint_approval_challenge(task_id) -> Challenge`, `record_verified_human_approval`, `pending_approvals()`), `crates/vk-ipc/src/server.rs` (`approval.challenge {task_id}` RPC; `approve` verifies the nonce was minted, unspent and unexpired), `crates/vkd/src/main.rs` (serve `vk-web` on `127.0.0.1:<port>` alongside IPC), `crates/vk-cli/src/main.rs` (`vk approve TASK` uses `approval.challenge`; `vk passkey enroll` opens the browser; `vk approve TASK --passkey` opens the approval page and waits)

**Interfaces:**
- `passkey::Registry` persisted in the `devices` table with `trust_class: "passkey"` and the serialised `Passkey`; `Webauthn` built with `rp_id = "localhost"`, `rp_origin = http://localhost:<port>`.
- Routes: `GET /enroll` → page; `POST /enroll/start` → `CreationChallengeResponse` (state kept server-side keyed by session id); `POST /enroll/finish` → stores the passkey as device `passkey:<credential_id_b64>` and appends `device.enrolled`. `GET /approve/<task_id>` → page showing goal + artefact hash + "Approve with Windows Hello"; `POST /approve/<task_id>/start` → `RequestChallengeResponse`, state stored **together with the kernel-minted `Challenge`** (its `action_digest` is the approval subject); `POST /approve/<task_id>/finish` → `finish_passkey_authentication`; on success the kernel records `Approval { subject_hash, kind: Human, approver: Human { device_id }, challenge: Some(<the minted Challenge>), signature_hex: Some(hex(assertion signature)) }` via `record_verified_human_approval` — an in-process method not reachable over IPC — and logs `approval.recorded` with `proof: "webauthn"`.
- I1 argument, written in the code comment: the only path to a human approval without an ed25519 device key is this in-process handler, whose verification is done by `webauthn-rs` against a passkey enrolled through the admin flow; the client never supplies a principal, and never a challenge.

- [ ] **Step 1: Failing tests** — `vk-web/tests/flow.rs` with `webauthn-rs`'s software authenticator (`webauthn-authenticator-rs` `SoftPasskey`): enrol, then approve a task; assert the kernel now holds one human approval for the task's artefact hash and the scheduler's `Approve` step completes. Negative: an assertion for a different challenge/state is rejected and no approval is recorded. `vk-ipc/tests/roundtrip.rs`: `approve` with a client-made challenge (valid signature, unminted nonce) → E_INVARIANT; with a minted one → ok; the same nonce twice → E_INVARIANT.
- [ ] **Step 2: Implement** — pages are minimal HTML + the standard `navigator.credentials.create/get` JS with base64url helpers; `vk approve --passkey` prints the URL and opens it (`start` on Windows).
- [ ] **Step 3: Run, commit** — `feat(web): passkey enrolment and approval (WebAuthn, loopback secure context) inside vkd; kernel-minted approval challenges`.

---

### Task 6: Windows service, virtual account, pipe DACL (with spike 6a)

Unchanged from rev. 1. The single-writer lock and the ledger head commitment from the SP1a fix wave are what make a service restart safe (review recommendation 4); the spike must show a restart passing `vk ledger verify`.

**Files:**
- Create: `crates/vk-service/Cargo.toml` (`windows-service`, `windows` with `Win32_Security_Authorization`), `src/main.rs`, `src/pipe_acl.rs`
- Modify: `crates/vk-ipc/src/transport.rs` (accept an optional security descriptor for the pipe), `crates/vkd/src/main.rs` (`--as-service`)

**Spike 6a (time-box 2 h):** install `vkd` as a service running as `NT SERVICE\vkd` (virtual account) with `sc.exe` semantics through `windows-service`; confirm the keyring (Credential Manager) works under that account; build a pipe security descriptor (SDDL) that grants `GA` to the service SID and the interactive user's SID only; confirm `vk status` from the user's shell connects and a second local user is refused; confirm Docker Desktop's engine is reachable from the service account (or record that the Ollama container must be started by the interactive user and mounted `--external`). Record the SDDL string here. **Founder checkpoint** on the Docker finding.

**Interfaces:**
- `vkd-service install [--user-sid S]` / `uninstall` / `start` / `stop`; state dir under `C:\ProgramData\VerticalAI\vk` for the service account (still refuses sync folders); pipe created with the SDDL `D:(A;;GA;;;<service SID>)(A;;GA;;;<user SID>)`.

- [ ] **Step 1: Test** (manual, recorded in the gate checklist): install, start, `vk status` works, `vk ls /arches` works, service restart survives (ledger and head verified at boot), uninstall clean.
- [ ] **Step 2: Implement**; **Step 3: Commit** — `feat(service): vkd as a Windows service under a virtual account; pipe DACL admits the interactive user only`.

---

### Task 7: The demo, both role orders (H1), scripted

**Files:**
- Create: `scripts/demo-sp1.ps1`, `docs/demo/brief/acme-brief.md` (a realistic two-page client brief for a freelance designer), `docs/demo/README.md`

**Interfaces:**
- `demo-sp1.ps1 [-Roles gemma-plans|claude-plans|harness] [-Model <VK_DEMO_MODEL>]`: starts `vkd` (or uses the service), mounts Ollama (`vk mount ollama --model $Model`) and Claude Code (`vk mount claude-code`), creates the task with steps `[Plan(A), Draft(B), Judge(B), Approve, Release out]` where A/B are the Gemma and Claude arch ids in the chosen order (`harness` mode replaces Draft with `Harness(claude-code)`), drives `vk task step --all`, opens the passkey page, waits, verifies `<export_root>/out/*.proposal` exists, prints `vk dmesg -n 40` and `vk ledger verify`; then runs the swapped order and asserts the register's decisions from run 1 are absent in run 2's register (fresh task) but that run 2's plan (by Claude) and draft (by Gemma) both raised into the same IR fields — the H1 check is that `vk task show` for run 2 lists both arch ids on consecutive steps with a non-empty `decisions` after each. Every model call's measured `tokens_in`/`tokens_out` must appear in `vk dmesg`.
- [ ] **Step 1: Write the brief and the script**; **Step 2: Run both orders on this machine**, save the two `vk dmesg` outputs under `docs/demo/runs/<date>/`; **Step 3: Commit** — `docs(demo): SP1 demo script, brief and recorded runs`.

---

### Task 8: `vk` shell additions, `top` with governed/ungoverned, cost and locality, `vk fsck`

- `vk mount ollama|claude-code|anthropic|bedrock|mock …`, `vk umount`, `vk arch show ID` (manifest incl. identity tuple and clearance), `vk top` columns: arch, locality, jurisdiction, governed, calls, tokens, projected, cost (from `cost_per_1k_tokens_eur`), `vk task submit --harness claude-code`, `vk passkey enroll|ls`, `vk secret set NAME`, `vk approve --passkey`.
- **`vk fsck`** (review recommendation 8 and N1): verifies the chain, the recorded head, every blob's address against its plaintext, and every DEK's wrap; prints one line per tier; `--rebase-head` re-records the head from the current ledger **only** together with `--force` and a typed confirmation, appends `boot.forced`-class evidence as a `fsck` payload on the next `boot` event (no new event kind), and is documented as the recovery path after a legitimate restore. `vk status` gains the `boot.forced` marker from Task 0.
- Tests: smoke test extended for `mount mock` + `arch show` + `fsck` on a healthy store (all ok) and on a cut store (head mismatch reported, exit 1); `top` renders cost for a cloud arch.
- Commit — `feat(cli): arch management, harness steps, passkeys, secrets and fsck in the vk shell`.

---

### Task 9: Signing, packaging scaffold, the VM gate checklist

**Files:**
- Modify: `.github/workflows/ci.yml` (`sign` job: `azure/trusted-signing-action` when `AZURE_*` secrets exist, else `signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f cert.pfx` when `SIGNING_CERT_B64` exists; uploads `vk.exe`, `vkd.exe`, `vk-mcp.exe`, `vkd-service.exe` as artifacts), `.github/workflows/release.yml` (same binaries), `README.md`
- Create: `docs/sp1-gate-checklist.md`, `scripts/install-windows.ps1` (copies signed binaries to `%LOCALAPPDATA%\Programs\VerticalAI`, adds to user PATH, checks Docker Desktop, runs `vkd-service install`)

**Gate checklist (all must be ticked on the VirtualBox stock Windows 11 image with Smart App Control on):**
1. Signed binaries install without SmartScreen/SAC prompts.
2. `vkd` runs as a service under `NT SERVICE\vkd`; `vk status` from the user account works; another local user is refused.
3. `vk ledger verify` and `vk fsck` ok after a service restart; a second `vkd` start is refused by the lock.
4. Harness run: Claude Code cannot read a file outside its workspace (attempt logged, fails); `harness.connections` shows only Anthropic endpoints.
5. Passkey approval with Windows Hello completes; a replayed assertion is rejected; a client-made approval challenge is rejected.
6. Property tests green on the real kernel; `cargo test --workspace` green in CI on three OSes; `arch-ollama` job green.
7. Demo script passes in both role orders with the Ollama container and the Claude Code adapter; recorded runs committed.
8. TCB statement updated with spike outcomes (restricted token, network egress, Docker under the service account).

- Commit — `ci: signing job (Trusted Signing or OV cert), Windows install script, SP1 gate checklist`.

---

### Task 10: SP1a review backlog — storage and kernel hardening

From `docs/superpowers/reviews/2026-09-24-sp1a-final-review.md`. One commit per group; every item has a test that fails before the change.

**Group A — key material (M4, N4; recommendation 6):** `zeroize` on `MasterKey`, DEKs, the node seed and their base64 strings (`ZeroizeOnDrop`, no `Clone` on key types); DEK wrapping uses the subject id as AEAD associated data so a `.dek` file renamed to another subject is detected on open; `shred` verifies the subject before destroying.
**Group B — payload tier modes (N2):** blob directories 0700 and blob/DEK files 0600 on Unix, set explicitly.
**Group C — ledger and clock (M3, M13):** HLC re-seeded from the ledger tail on open (monotonic across restarts with a backwards wall clock, tested); `boot.info` caches the verify verdict per append instead of re-verifying the whole ledger per call.
**Group D — read surfaces and errors (N3, M1, M10):** `visible_to` fails loudly on a registers read error (Ruling 8 discipline) instead of hiding the task; `write_register` in-process callers cannot relabel or re-parent (documented and asserted for the pipe path); `liveness.renew` RPC exposed as an admin syscall so `vk top`'s liveness column is real.
**Group E — process and paths (M6, M7, M9):** `private_dir` checks ownership as well as mode; Unix detach uses `setsid` via `pre_exec`; sync-folder refusal canonicalises the deepest existing ancestor before matching.
**Group F — docs and tests (M8, M14, M16, and the Windows temp-dir leak):** every test that opens a store closes it before its `TempDir` drops (the `vk-ipc` roundtrip server is joined/aborted and the kernel dropped first), so `cargo test` leaves no `.tmp*` directories in `%TEMP%` — asserted by a test-support guard that counts `%TEMP%` entries before and after a suite on Windows; README states the real default Windows state dir (`%LOCALAPPDATA%\VerticalAI\vk\data`), the SP1a trust model (every same-user process holding the node key counts as the human until passkeys) and the headless-Linux key path; the I1 property exercises one valid human approval per run.

- Commit per group — `hardening(store): …`, `hardening(kernel): …`, `docs: …`.

---

## Self-review

**Spec coverage (SP1 design §4–§9, spec §3.3/§3.6/§3.7/§3.8):** governed local arch with honest context → Task 1 (container caps + I4′), optional llama-server path retained in history; Claude via subscription → Task 2; API arches US + EU-hosted → Task 2b; MCP façade + confined harness + egress telemetry + TCB gap stated → Tasks 3, 4; passkey ceremony in-process with kernel-minted challenges and the I1 argument → Task 5; service account, DACL, state dir → Task 6; demo with role swap (H1) → Task 7; shell additions and `vk fsck` → Task 8; signing, install, gate → Task 9; the SP1a review backlog → Tasks 0, 1, 5, 8, 10. Out-of-scope items match SP1 design §9.

**Placeholder scan:** spikes 1a, 2a, 3a, 4a, 6a are explicit, time-boxed, and each names the values it must pin (tags, digest, tokenize availability, launch line, constant names, flag verification, SDDL, Docker under the service account); Task 1's and Task 2's "Pinned values" blocks were filled by spikes 1a and 2a on 2026-09-24 before either task's Step 1.

**Type consistency:** `ArchAdapter` methods as defined in SP1a Task 4; `Governor::contain(&Child)` identical in Tasks 3 and 4; `StepKind::Harness { name }` as in SP1a Task 6; `Approval`/`Challenge` fields as in SP0; `record_verified_human_approval` and `mint_approval_challenge` named identically in Task 5 and the file structure; `boot.forced` payload identical in Task 0 and Task 8.
