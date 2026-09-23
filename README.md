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
cargo test --workspace                          # 119 tests: unit, schema drift, examples, stub, properties, end-to-end shell
cargo run -p vk-contracts --bin gen-schemas     # regenerate contracts/schemas/ after changing a contract type
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Windows notes:
- Install Visual Studio 2022 Build Tools with the "Desktop development with C++" workload before `rustup`. The GNU host toolchain does not work here: rustup's self-contained `dlltool` cannot build the import libraries that `raw-dylib` crates (`getrandom`, `windows-sys`) need.
- Build outside OneDrive-synced folders: `set CARGO_TARGET_DIR=%USERPROFILE%\.cargo-target\verticalai`.

## Running the kernel (SP1a)

`vkd` is the kernel daemon — one per user account, one endpoint, one store.
`vk` is the shell: every verb is one syscall over that endpoint, printed as a
table or, with `--json`, as the daemon's own answer.

### The OS surface

| `vk` verb | OS concept |
|---|---|
| `vk boot [--force]` | `init`: start `vkd` over a state directory and wait until it answers |
| `vk status` | `uname`: what this node is, and what its boot sequence found |
| `vk ls PATH` | the namespace: `/arches`, `/tasks`, `/ledger` as directories |
| `vk ps`, `vk top` | the scheduler: what every task is doing, what each arch has cost |
| `vk mount mock NAME`, `vk umount ID` | drivers: an arch is a device this kernel drives |
| `vk task submit` / `step` / `show` | processes: a task is the unit of work, its register is its address space |
| `vk stop [SCOPE]`, `vk resume ID` | signals: a STOP halts a scope until a human lifts it |
| `vk approve ID` | the human ceremony: an approval signed by an enrolled device (invariant I1) |
| `vk dmesg -n N` | the kernel ring buffer: the tail of the hash-chained ledger |
| `vk ledger verify` | `fsck` for the record |
| `vk man [NAME]` | the contracts this kernel speaks — the syscall ABI, out of `contracts/schemas/` |

### What boot does

`vkd` verifies the ledger chain before it serves anything and reports what it
found: `ledger_ok`, `ledger_len`, `recovered_partial_line` (a crash mid-append
left an unterminated last line, which the store dropped and truncated away),
the mounted arches, the enrolled devices, the stopped scopes, and
`policies_version` — a placeholder in SP1a, where there is no policy engine
yet. The report goes to the log at info level (`<state_dir>/vkd.log` for a
detached daemon) and into the record: the `boot` event's payload is that
report's canonical hash. `vk status` shows the parts a person acts on.

**A chain that does not verify does not serve.** `vkd` exits non-zero and says
where the ledger is; `vkd --force` (or `vk boot --force`) serves anyway, for
recovering a node whose record was damaged — everything appended afterwards
chains onto a record already known not to hold.

### Defaults

| | default | override |
|---|---|---|
| state directory | this user's local app data, never a synced folder | `--state-dir DIR` |
| master key | OS keyring, service `vk`, user `master` | `--master-key-file FILE` (tests and CI) |
| node device key | OS keyring | `--node-key-file FILE`, or `$VK_NODE_KEY_FILE` |
| endpoint | `\\.\pipe\vk-<user>` (Windows), `$XDG_RUNTIME_DIR/vk.sock` (Unix) | `--endpoint EP`, or `$VK_ENDPOINT` |

`$VK_ENDPOINT` and `$VK_NODE_KEY_FILE` are read by `vk` only. `vkd` never reads
the environment: a daemon on a non-default endpoint is always started with
`--endpoint`, and `vk boot` passes on the endpoint it resolved.

### A node, end to end

A throwaway state directory and file-backed keys, so nothing here touches the
keyring. Paste it a line at a time and read what each verb prints; `$ARCH`,
`$TASK` and `$STOP` are the ids the commands before them printed.

```
D=$TEMP/vk-demo                         # any local path outside a synced folder
export VK_NODE_KEY_FILE=$D/node.key

vk boot --state-dir $D --master-key-file $D/master.key
vk status                               # node-1, 2 events, chain verified, stopped nothing

vk mount mock gemma-mock --ctx 4096     # ARCH=sha256:fd4b8acf...
vk ls /arches

vk task submit --goal "Draft a proposal for Acme" --artefact proposal \
      --plan $ARCH --draft $ARCH --approve --release out      # TASK=task-node-1-2
vk task step $TASK --all                # runs until it waits: status waiting_human
vk ps
vk task show $TASK                      # the same task in full, with where it writes

vk stop                                 # STOP=stop-node-1-3, and nothing steps
vk task step $TASK --all                # vk: scope is stopped: node (-32001), exit 1
vk resume $STOP
vk approve $TASK                        # signed with this node's device key
vk task step $TASK --all                # status done
ls $D/exports/out                       # 3c2c07fa23e9.proposal

vk top
vk dmesg -n 6
vk ledger verify                        # 18 events, chain verifies

vk man                                  # the 19 contracts
vk man clearance                        # one of them, rendered
vk man clearance --json                 # the schema itself
```

Stopping the node: the `vk boot` that starts a daemon prints its `pid` (and
`--json` gives it as a field) — `taskkill /F /PID <pid>` on Windows, `kill
<pid>` elsewhere. A later `vk boot` on the same endpoint and state directory
starts nothing, says `already_running` and has no pid to give, so find it with
`tasklist /FI "IMAGENAME eq vkd.exe"` or `pgrep vkd`. A `vk boot` naming a
*different* state directory on that endpoint is refused, because one endpoint
means one store — and it creates nothing before refusing.

Shell notes: `vk boot` without `--state-dir` and `--master-key-file` uses this
user's local app data and writes a `vk`/`master` entry in the OS keyring, which
is the intended everyday path. In Git Bash on Windows, set `MSYS_NO_PATHCONV=1`
first, or namespace paths like `/arches` are rewritten into filesystem paths
before `vk` ever sees them — and pass a named-pipe endpoint from PowerShell or
`cmd` rather than Git Bash, which eats the leading `\` of `\\.\pipe\...` even
with that set.
