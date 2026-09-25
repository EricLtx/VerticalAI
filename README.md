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
cargo test --workspace                          # 121 tests: unit, schema drift, examples, stub, properties, end-to-end shell
cargo run -p vk-contracts --bin gen-schemas     # regenerate contracts/schemas/ after changing a contract type
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Windows notes:
- Install Visual Studio 2022 Build Tools with the "Desktop development with C++" workload before `rustup`. The GNU host toolchain does not work here: rustup's self-contained `dlltool` cannot build the import libraries that `raw-dylib` crates (`getrandom`, `windows-sys`) need.
- Build outside OneDrive-synced folders: `set CARGO_TARGET_DIR=%USERPROFILE%\.cargo-target\verticalai`.
- The passkey verifier (`vk-web`, SP1b) is `webauthn-rs`, which verifies with OpenSSL built from source (`openssl/vendored`). That build needs a **Windows-native Perl**: install [Strawberry Perl](https://strawberryperl.com/) (`winget install StrawberryPerl.StrawberryPerl`) or point `OPENSSL_SRC_PERL` at a portable one's `perl.exe`. Git for Windows' Perl does not do — OpenSSL's `Configure` cannot even load under it. The first build takes about fifteen minutes (no assembler: `nasm` is optional and speeds it up); every later build reuses it. GitHub's Windows runners have Strawberry Perl already; Linux and macOS need only `perl` and a C compiler.

## Running the kernel (SP1a)

`vkd` is the kernel daemon — one per user account, one endpoint, one store.
`vk` is the shell: every verb is one syscall over that endpoint, printed as a
table or, with `--json`, as the daemon's own answer.

### The OS surface

| `vk` verb | OS concept |
|---|---|
| `vk boot [--force]` | `init`: start `vkd` over a state directory and wait until it answers |
| `vk status` | `uname`: what this node is, and what its boot sequence found |
| `vk ls PATH` | the namespace: `/arches`, `/tasks`, `/artefacts`, `/devices`, `/ledger` as directories |
| `vk ps`, `vk top` | the scheduler: what every task is doing, what each arch has cost |
| `vk mount mock NAME`, `vk mount claude-code`, `vk mount anthropic`, `vk mount bedrock`, `vk mount ollama --model TAG`, `vk umount ID` | drivers: an arch is a device this kernel drives — and, for `ollama`, a process it starts and caps |
| `vk secret set NAME` | the credential store: a secret this node's daemon reads, put in this account's OS keyring without ever being echoed or printed |
| `vk task submit` / `step` / `show` | processes: a task is the unit of work, its register is its address space |
| `vk stop [SCOPE]`, `vk resume ID` | signals: a STOP halts a scope until a human lifts it |
| `vk approve ID [--passkey]` | the human ceremony: an approval of a kernel-minted challenge, signed by this node's device key or by a passkey in the browser (invariant I1) |
| `vk passkey enroll [--open]`, `vk passkey ls` | the human's own device: a passkey (Windows Hello, a phone) enrolled through the browser |
| `vk dmesg -n N` | the kernel ring buffer: the tail of the hash-chained ledger |
| `vk ledger verify` | `fsck` for the record |
| `vk man [NAME]` | the contracts this kernel speaks — the syscall ABI, out of `contracts/schemas/` |

### Arches: this machine's Claude, and a customer's

`vk mount claude-code` mounts two arches — a draft one and a judge one —
through the Claude Code already installed on this machine, driven as a pure
completion engine: every built-in tool removed, MCP off, one turn, no session
on disk, and the prompt on stdin so no process list shows it.

```
vk mount claude-code                                    # sonnet to draft, opus to judge
vk mount claude-code --draft-model claude-sonnet-5 --judge-model claude-opus-5 \
                     --bin /path/to/claude --timeout 180
```

It runs on **the founder's own claude.ai subscription**, which is a person's
and not a product's. Nothing is billed per call, so the manifest's
`cost_per_1k_tokens_eur` is `0`; what the same call would have cost on the
meter is recorded beside it, as `cost_list_usd` on the `infer` event and on the
arch's running counters. **Customer nodes do not use this arch**: they mount
API arches, which carry a key, a per-token price and — for the EU jurisdiction
— a different host.

Because this arch counts its own prompts, `vk top` shows what the calls
actually cost rather than what this node guessed they would:

```
ARCH            GOVERNED  CALLS  TOKENS  MEASURED  COST (LIST USD)  PROJECTED
sha256:2ee2...  no            2   28870     28870          0.02964          0
sha256:fd4b...  yes           1      74        74                -          0
```

`TOKENS` is the best number available per call, `MEASURED` how much of it the
arch itself counted — a dash where an arch reports no usage, so an estimate is
never mistaken for a figure anyone could bill against.

Inference happens on Anthropic's servers, so the manifest is honest about it:
`governed: false`, `locality: cloud`, `jurisdiction: US`, 30-day retention, and
a clearance that stops at Business and refuses third-party data. I2 will not
lower anything above that into it. `contracts/tcb.md` says the same in prose.

### Arches: Claude through the API, US and EU

`vk mount claude-code` is the founder's. A **customer** node mounts the API
arches instead: they carry a key, a per-token price, and — for the EU
jurisdiction — a different host.

```
vk secret set anthropic                                 # prompts, no echo, keyring only
vk mount anthropic                                      # claude-opus-5, US
vk mount anthropic --model claude-sonnet-5 --ctx 200000 --max-tokens 2048
vk mount bedrock --region eu-central-1                  # EU-hosted, Frankfurt or Dublin
```

The key lives in this account's OS keyring under `vk`/`anthropic` and nowhere
else: not in the mount spec (which is stored unencrypted, and which the kernel
refuses to build out of anything credential-shaped), not in a manifest, not in
a log line, not in an error — every message these adapters produce has the key
scrubbed out of it on the way. The daemon reads it at `vk mount anthropic` and
again each time it re-creates that arch at boot, so rotating the key is `vk
secret set anthropic` and a restart. A daemon that finds no key refuses the
mount and prints the one line that fixes it. (`vkd --anthropic-key-file` reads
it from a file instead, for CI and for a headless node whose OS has no
credential store.)

The two differ in exactly the things a manifest exists to say:

| | `vk mount anthropic` | `vk mount bedrock` |
|---|---|---|
| host | `api.anthropic.com`, raw HTTPS | Amazon Bedrock `Converse` |
| `jurisdiction` | `US` | `EU` — `eu-central-1` or `eu-west-1`, and no other |
| `retention_days` | 30 | none: AWS keeps neither input nor output |
| price | Anthropic's list price, in the manifest and per call | AWS's, which this node has not read, so none is claimed |

Both are `governed: false`, `locality: cloud`, clearance capped at Business
with third-party data refused, neither streams, and both bound one answer at
4096 tokens. The first-party one sends `anthropic-version: 2023-06-01` and
`thinking: {"type":"adaptive"}`; the Bedrock one sends the smallest `Converse`
request that works, because it is the one that has never been exercised.

Their **context ceiling is the model's documented window** — 1 000 000 tokens
for the Claude 5 family — and a prompt past nine tenths of it is refused before
anything is sent (I4′). The first-party arch counts the prompt with the API's
own `/v1/messages/count_tokens` and falls back to the `bytes/3 + 64` estimate
when that call fails; afterwards both check the answer's own
`usage.input_tokens` against the ceiling. Unlike Ollama, this provider
*refuses* an oversize prompt rather than truncating it, so the post-check is a
belt to that suspender rather than the load-bearing one. `--ctx` pins a smaller
ceiling for a node that wants one.

`vk mount bedrock`'s transport is the AWS SDK, behind the `bedrock` cargo
feature — **on by default**: it is 83 extra crates and about a minute on a
clean Windows build (15 s to 1 m 15 s), which was the budget. A node that
wants neither the SDK nor those crates in its supply chain builds
`--no-default-features`, and a daemon without them refuses the mount by name
and says how to get a build that has them.

### Arches: a model this kernel governs

`vk mount ollama` is the other kind. It runs a Gemma-class model in an Ollama
container **this kernel starts**, on loopback, under a memory cap and a CPU cap
it sets — so the inference is a process the node contains, and nothing about
the call leaves the machine.

```
vk mount ollama --model gemma4:e4b                      # the demo model, 12 GiB, 6 CPUs
vk mount ollama --model gemma3:1b --ctx 8192 --memory 4g --cpus 2 --max-tokens 512
vk mount ollama --model gemma4:e4b --recreate           # replace a container with other caps
vk mount ollama --model gemma3:1b --external http://127.0.0.1:11434   # ungoverned
```

`GOVERNED` on the mount line and in `vk top` is not a promise, it is a reading:
the caps are read back off the running container, and an existing `vk-ollama`
is adopted only when its image and both caps are exactly the ones asked for —
otherwise the mount is refused and names what differs, because a container
started at 4 GiB is not a 12 GiB governor. `--recreate` replaces it and keeps
the volume, so the models are not downloaded again. `--external` points at an
Ollama somebody else is running: loopback only until SP4, never `governed`, and
its clearance stops at Business.

Its context ceiling is **half** the window asked for. Ollama 0.33.3 truncates
an oversize prompt to `num_ctx / 2 + 3` tokens and answers `200 OK` with
`done_reason: "stop"`, so this node refuses the prompt instead — before the
call from its own estimate, and after it from the server's `prompt_eval_count`.
Nothing is billed, so there is no `COST`; what `vk top` shows is the tokens the
server itself counted.

### The human ceremony: passkeys and kernel-minted challenges

Every human approval answers a **challenge the kernel minted** for the task:
`vk approve` asks the daemon for it (`approval.challenge`), signs its digest
with the node's device key and presents it; the daemon accepts a challenge it
minted, once, while it is unexpired — and nothing a client built itself. That
is invariant I1 made concrete: no client ever chooses the subject, the nonce or
the expiry a human signs.

The device key in the OS keyring is SP1a's stand-in for a human. The passkey
is the human's own device: Windows Hello today, a phone's passkey later.

```
vk passkey enroll                       # prints http://localhost:7734/enroll?t=…; --open opens it
vk passkey ls                           # DEVICE  ENROLLED (ms)
vk approve $TASK --passkey              # prints the approval link, waits for Windows Hello
vk approve $TASK --passkey --open --timeout 120
```

`vkd` serves the two pages on both loopback addresses, `127.0.0.1` and `[::1]`
(`--web-port`, default 7734; `0` lets the OS pick, and `vk status` shows the
`web` origin), and refuses to start if either is taken. The pages open only
from a link the daemon minted over its endpoint, good for ten minutes, for one
page and one task; `vk passkey enroll` signs a presence proof with the node's
device key to get its link, because enrolling a passkey is a human act. On the
approval page the daemon mints the task's challenge with the WebAuthn challenge
as its nonce — so what Windows Hello signs is the challenge the kernel minted —
verifies the assertion in-process with `webauthn-rs` against the enrolled
passkey, records the approval with `proof: webauthn` and the signed bytes
beside it (so the signature can be checked again from the record), and runs
the step that was waiting; `vk approve --passkey` sees the task leave
`waiting_human` and prints the result. `contracts/tcb.md` says what is and is
not claimed of it.

**Windows Hello, by hand** (the check no test can make):

1. `vk boot` (any state directory), `vk mount mock m1`, then a task with
   `--approve` stepped to `waiting_human`, as in the walk-through below.
2. `vk passkey enroll --open`. Edge or Chrome opens
   `http://localhost:7734/enroll?t=…`; press *Enrol with Windows Hello*, choose
   *This device* when the browser asks where to save the passkey, and confirm
   with your PIN, fingerprint or face. The page prints `Enrolled passkey:…`;
   `vk passkey ls` lists it and `vk dmesg` shows `device.enrolled`.
3. `vk approve $TASK --passkey --open`. The page shows the goal and the hash;
   press *Approve with Windows Hello* and confirm. The page says the task is
   `done` (or `running`, with more steps to go), the shell prints
   `approved sha256:…`, and `vk dmesg` shows `approval.recorded`.
4. Open the same link again: `404`. Run `vk approve $TASK --passkey` for a
   task that is not waiting: refused, no link minted. Open
   `http://localhost:7734/enroll` without a link: `404`.

A phone's passkey works through the same pages once the browser can reach it
(a QR code from Edge or Chrome); nothing on the daemon's side is different.

### What boot does

`vkd` verifies the ledger chain before it serves anything and reports what it
found: `ledger_ok`, `ledger_len`, `recovered_partial_line` (a crash mid-append
left an unterminated last line, which the store dropped and truncated away),
the mounted arches, the enrolled devices, the stopped scopes, and
`policies_version` — a placeholder in SP1a, where there is no policy engine
yet. The report goes to the log at info level (`<state_dir>/vkd.log` for a
detached daemon) and into the record: the `boot` event's payload is that
report's canonical hash. `vk status` shows the parts a person acts on, and
`vk status --json` carries them all.

**A chain that does not verify does not serve.** `vkd` exits non-zero and says
where the ledger is; `vkd --force` (or `vk boot --force`) serves anyway, for
recovering a node whose record was damaged — everything appended afterwards
chains onto a record already known not to hold. A `vk boot` whose daemon
refused comes back with the daemon's own last words, not with a timeout.
Serving under `--force` is itself on the record: the daemon appends a
`boot.forced` event naming the verdict it overrode, and `vk status` marks the
node `forced boot`, next to the chain line, for as long as that process runs.

### The SP1 demo

`scripts/demo-sp1.ps1` is the milestone end to end, and the shortest way to see
what this is for: a client proposal written from a two-page brief by **Gemma in
a container this kernel caps** and **Claude through the installed Claude Code**,
co-working through one register, approved by a human ceremony and released as a
file — then the same brief again with the two models' roles swapped, and ten
checks that the register did not care which was which (H1).

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo-sp1.ps1
```

Twelve minutes, a throwaway state directory, file keys, a private endpoint and
an OS-chosen web port, so it never touches the node you already have. The
recorded runs — both orders, the harness variant, the two proposals, the
ledgers and the H1 verdict — are in `docs/demo/runs/2026-09-25/`, and
`docs/demo/README.md` says what to expect, what it needs, and how to run the
Windows Hello variant by hand.

### Running as a Windows service

A node that belongs to the machine rather than to a logged-in shell:
`vkd-service` registers `vkd` under the **virtual account** `NT SERVICE\vkd`,
which Windows creates and manages from the service's own name — no password to
store, no password to rotate, and a Credential Manager of its own, so the
master key and the node's device key are not in the founder's.

```
# build somewhere the synced repository is not, then put the binaries
# where only administrators may write
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\.cargo-target\verticalai-sp1"
cargo build --release
mkdir "$env:ProgramFiles\VerticalAI"                       # elevated
copy "$env:CARGO_TARGET_DIR\release\vk*.exe" "$env:ProgramFiles\VerticalAI\"

# from an elevated PowerShell, once
& "$env:ProgramFiles\VerticalAI\vkd-service.exe" install   # --user-sid defaults to you
& "$env:ProgramFiles\VerticalAI\vkd-service.exe" start

# from an ordinary shell, from then on
$env:VK_ENDPOINT = '\\.\pipe\vk'
vk status
```

**Where the binary lives is part of the trust boundary.** The registered
`ImagePath` runs as `NT SERVICE\vkd` at every start, so a binary under a user
profile — or inside OneDrive — is one that account can replace, and the next
start would hand it the service account's keyring. `vkd-service install`
refuses such a path outright; `%ProgramFiles%\VerticalAI\` is the answer,
because an elevated `mkdir` there is owned by the administrators. (Signing is
the SP1 gate's job; until then nothing verifies *what* is at that path, only
who may change it.)

The endpoint is the machine-wide `\\.\pipe\vk`, not the per-user
`\\.\pipe\vk-<user>` a `vk boot` daemon takes, and the state directory is
`%ProgramData%\VerticalAI\vk` rather than any one person's app data. `vk` needs
`$VK_ENDPOINT` (or `--endpoint`) to reach it; everything else about the shell is
unchanged. Stopping the service is `vkd-service stop`, and `vkd-service
uninstall` removes it — leaving the state directory and the service account's
keyring entries behind, which is where the node's whole record still is.

**The endpoint's ACL is the first authentication factor, and it is written
out — for every daemon, not only the service.** The default DACL of a named
pipe grants SYSTEM, the administrators and the creator full access *and
Everyone and Anonymous read access*. So `vkd` never takes it: a daemon a person
started binds `D:(A;;GA;;;<that person's SID>)`, and the service binds two
accounts and nobody else:

```
D:(A;;GA;;;<the NT SERVICE\vkd SID>)(A;;GA;;;<the interactive user's SID>)
```

The daemon reads its own half off its process token at bind time and logs the
whole list; the other half is `--user-sid`, which `vkd-service install` fills
in from whoever ran it (an elevated shell has the same user SID as the desktop
that raised it) and which `whoami /user` prints if you want to name another. It
must be a **user** account: `S-1-1-0` is Everyone and is a perfectly
well-formed SID, so the string is resolved and its type checked before it
becomes an entry. `vkd-service install` prints the SIDs, the endpoint, the DACL
and the `ImagePath` before the service has ever run.

**The store's directory carries its own ACL too.** `%ProgramData%` hands
inheritable read *and* create rights to every local account, so the service
creates `%ProgramData%\VerticalAI\vk` — and its parent — with a protected
list, Full Control to the service account, SYSTEM and the administrators,
inherited by everything underneath, and **refuses to start** on a directory
whose owner or entries name anybody else, naming the one that stopped it. A store somebody else
created first is not adopted: they would own the ledger.

**Who is on the other end.** Windows lets any local account claim a pipe name
nobody is serving yet, so `vkd` refuses to start on a name already taken
(naming the holder's pid and account), and `vk`, after connecting, reads the
pipe object's **owner** off its own handle and refuses to speak to anything that
is neither the caller's own account nor `NT SERVICE\vkd`. The owner rather than
the server's process, because an ordinary account may not open a service's
process at all. The residual — a pipe whose owner cannot be read — is in
`contracts/tcb.md`.

Two things the DACL does **not** cover. The passkey pages are still served on
`127.0.0.1:7734`, and loopback has no ACL — what protects them is the
single-use link tokens minted only over the endpoint (`contracts/tcb.md`).
And the service has no console: its log is `%ProgramData%\VerticalAI\vk\vkd.log`,
the same `vkd.log` a detached `vk boot` daemon writes.

`scripts/spike-6a.ps1` is the whole thing end to end — stage the binaries,
install, start, `vk status`, `vk ls /arches`, `vk ledger verify`, a restart and
the same checks again, the DACL the daemon actually bound, whether Docker's
engine is reachable from the service account, a second local account's attempt,
uninstall and tidy up after itself — and it prints a summary block. It needs an
elevated PowerShell and builds nothing:

```
.\scripts\spike-6a.ps1            # binaries from %USERPROFILE%\.cargo-target\verticalai-sp1\release
```

| `vkd-service` verb | what it does |
|---|---|
| `install [--user-sid S] [--binary PATH] [--probe-docker] [-- <vkd args>]` | create the service under `NT SERVICE\vkd`; print the SIDs, the endpoint, the DACL and the `ImagePath` |
| `uninstall` | stop it if it is running, delete it |
| `start` / `stop` | control it and wait for the new state |
| `run --user-sid S` | the service control manager's own entry point; it runs `vkd --as-service --user-sid S` in this process. Not for a terminal |

`vkd --as-service --user-sid <SID>` is that daemon on its own, without the SCM:
same state directory, same endpoint, same DACL. It refuses without
`--user-sid`, because a service that did not know which user to admit would
serve nobody.

### Defaults

| | default | override |
|---|---|---|
| state directory | this user's local app data, never a synced folder; `%ProgramData%\VerticalAI\vk` under `--as-service` | `--state-dir DIR` |
| master key | OS keyring, service `vk`, user `master` | `--master-key-file FILE` (tests and CI) |
| node device key | OS keyring | `--node-key-file FILE`, or `$VK_NODE_KEY_FILE` |
| endpoint | `\\.\pipe\vk-<user>` (Windows), `\\.\pipe\vk` under `--as-service`; `$XDG_RUNTIME_DIR/vk.sock`, else `/tmp/vk-<user>/vk.sock` (Unix) | `--endpoint EP`, or `$VK_ENDPOINT` |
| endpoint ACL | the creating account's — Unix: `0600` in a `0700` directory; Windows: `D:(A;;GA;;;<that account>)` | `--as-service`: `D:(A;;GA;;;<service SID>)(A;;GA;;;<--user-sid>)` |
| state directory ACL | Unix `0700`; Windows, the parent's (per user under `%LOCALAPPDATA%`) | `--as-service`: the service account, SYSTEM and the administrators, protected and inherited |
| passkey pages | `http://localhost:7734`, on loopback only | `--web-port PORT` (`0`: one the OS picks) |

`$VK_ENDPOINT` and `$VK_NODE_KEY_FILE` are read by `vk` only: a daemon on a
non-default endpoint is always started with `--endpoint`, and `vk boot` passes
on the endpoint it resolved. The one variable `vkd` reads is `$RUST_LOG`, and
with it unset it logs at **info** — which is why the boot report is in
`<state_dir>/vkd.log` without anybody having had to ask for it.

### A node, end to end

A throwaway state directory and file-backed keys, so nothing here touches the
keyring. Paste it a line at a time and read what each verb prints; `$ARCH`,
`$TASK` and `$STOP` are the ids the commands before them printed.

```
D=${TMPDIR:-${TEMP:-/tmp}}/vk-demo      # any local path outside a synced folder
export VK_NODE_KEY_FILE=$D/node.key

vk boot --state-dir $D --master-key-file $D/master.key
vk status                               # node-1, 2 events, chain verified, stopped nothing

vk mount mock gemma-mock --ctx 4096     # ARCH=sha256:fd4b8acf...
vk ls /arches

vk task submit --goal "Draft a proposal for Acme" --artefact proposal \
      --plan $ARCH --draft $ARCH --approve --release out      # TASK=task-node-1-2
# --judge $ARCH adds a judging step after the draft; --harness claude-code
# drafts with the confined agent instead of an arch (`vk harness run` runs it).
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

Arches and their state: `vk ls /arches` has a `STATE` column, and `vk top` has
one beside each arch's counters. An arch is `ready` when its adapter is there,
`starting` while the daemon is re-creating it, and `unavailable` when it cannot
be re-created — with the reason in the `WHY` column (under the table in `vk
top`). `vk status` says `arches  3 (1 unavailable)` when any of them is not
`ready`.

`starting` is the window just after a restart. A daemon re-creates the arches
it had mounted *behind* its endpoint, so it answers `vk status` and `vk ls`
from the moment `vk boot` returns — which it does at once, saying `; 2 arches
starting` — while a container starts or a model loads behind it. A `vk task
step` that names an arch in that window exits non-zero with `arch <id> is
starting; retry`, and the task stays `queued` with its step still `pending`:
run the same `vk task step` again when the arch is `ready` and it goes on from
where it was. Nothing is failed and nothing has to be re-submitted.

**Upgrading a store made before this:** a node records *how* to re-create each
arch from the moment it is mounted, and a store written by an earlier build has
no such record. Every arch in one of those comes back once as `unavailable  no
mount spec was recorded for this arch…`; mount each of them again (`vk mount
ollama …`, `vk mount claude-code …`) and they persist across every restart
afterwards. An arch whose engine has genuinely changed underneath — a new
image, newer weights, a newer `claude` — comes back `unavailable  manifest
changed: …` instead, and the reason names the `vk umount <id>` that retires the
old id; its replacement is the mount you make next, under a new id, because an
arch id names particular weights and is never re-pointed at different ones.

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
