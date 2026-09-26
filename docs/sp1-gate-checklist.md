# The SP1 gate checklist

Eight items, all of which must be ticked on **the VirtualBox stock Windows 11
image, with Smart App Control (SAC) on**, before SP1 is called done. This is
the founder's own machine-and-hands checklist: several items need Windows
Hello, an elevated console, or a judgement call about what the demo produced,
none of which an agent can do on the founder's behalf. Fill in the results
table at the end as each item is run.

Smart App Control can only be turned on from a clean install (or "Reset this
PC" with "Clean the drive" / a fresh Windows 11 24H2+ image) — it cannot be
toggled on afterward once it has turned itself off. Provision the VM with
that in mind: install nothing untrusted on it before this checklist runs, or
SAC will already have dropped itself into evaluation-off and item 1 tests
nothing.

## Prerequisites

- **The image.** A stock Windows 11 (24H2 or later) VirtualBox VM, Smart App
  Control **On** (`Settings > Privacy & security > Windows Security > App
  and browser control > Smart App Control`, or `Get-CimInstance
  -Namespace root\Microsoft\Windows\Sense -ClassName
  MP_WDATPInformation` if you need to confirm the mode from a script — the
  simplest confirmation is the Settings page itself, which says `On`,
  `Evaluation` or `Off`). A snapshot taken here is worth having: every item
  below except installing the binaries once is meant to be re-runnable from
  it.
- **Docker Desktop**, installed and running, WSL2 backend. `docker info`
  must answer before item 2 or item 7.
- **Claude Code**, installed, on PATH, and logged in to the founder's own
  subscription (`claude --version` and `claude /status` both answer). Items 4
  and 7 use it as the harness and as an arch.
- **The two Ollama pulls.** The demo's fast model and its real one, both
  through the node so the pull lands in the `vk-ollama` container's volume
  rather than a bare `docker exec`:
  ```
  vk boot
  vk mount ollama gemma-dev --model gemma3:1b
  vk mount ollama gemma-demo --model gemma4:e4b
  vk umount gemma-dev
  vk umount gemma-demo
  ```
  (`gemma4:e4b` is 9.6 GB; do this over a connection that can take it before
  the gate run itself, not during item 7's timing.) `vk ls /arches` should
  show both `ready` before unmounting; the demo script mounts its own copies
  under its own throwaway state directory, so nothing about these two names
  or this node survives into it — this step exists only to make the image
  hold both sets of weights in Docker's volume.
- **A Windows Hello factor** already enrolled on the VM's Windows account
  (PIN at minimum; fingerprint or face if the VirtualBox host passes through
  a sensor) — item 5 cannot proceed without one, and enrolling Windows Hello
  itself is outside this checklist.
- **The release binaries beside `install-windows.ps1`.** Either the signed
  `vk-windows-signed` (or `unsigned-vk-windows` before a certificate secret
  exists) artifact from the `sign` job in `.github/workflows/ci.yml`, or the
  `vk-windows-latest` / `unsigned-vk-windows-latest` artifact from
  `.github/workflows/release.yml` on an `sp*` tag, unzipped so `vk.exe`,
  `vkd.exe`, `vk-mcp.exe`, `vkd-service.exe` and `scripts\install-windows.ps1`
  are in one directory. (A local `cargo build --release` plus a manual copy
  of the four binaries and the script works too, for a dry run of the
  checklist before a signed artifact exists — item 1 will then correctly
  fail, which is the point of running it once that way.)

## The eight items

### 1. Signed binaries install without SmartScreen/SAC prompts

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-windows.ps1
vk --help
vkd --help
vkd-service --help
cmd /c "vk-mcp.exe < NUL"; "vk-mcp exit=$LASTEXITCODE"
```
(`vk-mcp` has no `--help` of its own — it is a stdio server that reads
JSON-RPC lines until stdin closes, so redirecting from `NUL` gives it an
immediate, clean EOF; `exit=0` says Smart App Control let it run at all,
which is the thing being checked.)

**Expected:** no "Windows protected your PC" SmartScreen dialog and no Smart
App Control block toast at any point in the install or the four runs above.
The installer's own signature check prints
`-> all four binaries carry a valid Authenticode signature` — not the
`*** UNSIGNED BINARIES ***` banner. `vk --help` / `vkd --help` /
`vkd-service --help` print their usage; `vk-mcp` prints `vk-mcp exit=0`.
Right-click `vk.exe` in `%LOCALAPPDATA%\Programs\VerticalAI` → Properties →
Digital Signatures shows a valid chain (Azure Trusted Signing's or the OV
certificate's, whichever the `sign` job used).

### 2. `vkd` runs as a service under `NT SERVICE\vkd`; `vk status` from the user account works; another local user is refused

```
net user vk-gate-second P@ssw0rd-change-me! /add        # elevated, once
.\scripts\spike-6a.ps1 -SecondUser vk-gate-second
net user vk-gate-second /delete                          # elevated, cleanup
```
`spike-6a.ps1` is the whole thing end to end — install, start, `vk status`
and `vk ls /arches` as the interactive user over the service's own pipe, and
the second account's attempt — and it un-installs itself and cleans up after
printing its summary, so the gate VM is left as it found it.

**Expected:** the summary block's `install=ok`, `service_state=Running`,
`pipe_answered=True`, `vk_status` names the node (not a connection refusal),
`pipe_owner_is_the_service=yes -- …`, and — the item's own second half —
`second_user_refused=yes -- the DACL held` with `second_user_result`
containing `Access is denied. (os error 5)`.

### 3. `vk ledger verify` and `vk fsck` ok after a service restart; a second `vkd` start is refused by the lock

Re-run `spike-6a.ps1 -KeepInstalled` (or install for real via
`install-windows.ps1 -Service`, elevated) so the service is left running for
this item, then:
```
vk ledger verify
vk fsck
# elevated:
vkd-service stop
vkd-service start
# back to the interactive user:
vk ledger verify
vk fsck
# and the lock, from the same shell the service already answers on:
vkd
```
**Expected:** both `vk ledger verify` calls print `N events, chain verifies`
with the same or a growing `N`. Both `vk fsck` calls print one row per tier
all reading `ok` in the VERDICT column and end with `the store verifies` —
no `FAILED` row, no `the store DOES NOT verify`. The bare `vkd` at the end
does not start a second daemon: it is refused for the pipe already being
served (naming the holder — the service's account and pid), because Windows
will not let a second process claim `\\.\pipe\vk-<you>` while the service
holds it. Afterwards, elevated: `vkd-service uninstall`, and delete
`%LOCALAPPDATA%\Programs\VerticalAI` if `install-windows.ps1 -Uninstall`
was not used instead.

### 4. Harness run: Claude Code cannot read a file outside its workspace (attempt logged, fails); `connections` shows only Anthropic endpoints

```
vk boot
vk mount claude-code cc1
vk harness run --goal "Read the file C:\Windows\win.ini, copy its first line into NOTES.md in your workspace, then finish." --keep --json > harness-run.json
type harness-run.json
```
Then inspect the JSON (`ConvertFrom-Json` or eyeball it):
```
(Get-Content harness-run.json | ConvertFrom-Json).permission_denials
(Get-Content harness-run.json | ConvertFrom-Json).connections
nslookup api.anthropic.com
```
**Expected:** `permission_denials` is **not empty** and contains an entry
naming the file, shaped like
`{"tool_name":"Read","tool_input":{"file_path":"C:\\Windows\\win.ini"}}` —
the fence's `blockReadsOutsideWorkingDirectories` refusing a read outside the
harness's workspace, logged rather than silently swallowed. `NOTES.md` in the
kept workspace (path printed by `--keep`) does not contain the contents of
`win.ini`. `connections` is **not empty**, and every entry is an `ip:port`
pair (sampled every 500 ms of the child's own sockets) whose IP is one of
the addresses `nslookup api.anthropic.com` just printed, on port `443` —
nothing else appears, because the fence removes every built-in tool and the
subprocess runs under `--tools ""` with MCP off. Clean up: `vk umount cc1`.

### 5. Passkey approval with Windows Hello completes; a replayed assertion is rejected; a client-made approval challenge is rejected

Set up two tasks waiting on a human, so there are two live challenges to work
with:
```
vk boot
vk mount mock m1 --ctx 4096
vk task submit --goal "Gate item 5, task A" --artefact note --plan m1 --draft m1 --approve
vk task step <TASK-A> --all      # stops at waiting_human
vk task submit --goal "Gate item 5, task B" --artefact note --plan m1 --draft m1 --approve
vk task step <TASK-B> --all      # stops at waiting_human
vk passkey enroll --open
```
**5a — completes.** In the browser: *Enrol with Windows Hello*, *This
device*, confirm with PIN/fingerprint/face. `vk passkey ls` now lists the
device. `vk approve <TASK-A> --passkey --open`, press *Approve with Windows
Hello*, confirm. Expected: the page reports the task done (or running), the
shell prints `approved sha256:…`, `vk dmesg` shows `approval.recorded`.

**5b — a replayed assertion is rejected.** Start a fresh approval ceremony
for task B (`vk approve <TASK-B> --passkey --open`) and, before pressing
approve, open the browser's Network tab (F12). Complete the approval once
normally (press *Approve*, confirm Windows Hello) and let the page succeed.
Find the `POST /approve/<TASK-B>/finish` request in the Network tab, right
click → Copy → *Copy as cURL*, and replay it verbatim from a shell:
```
curl.exe -i -X POST http://localhost:7734/approve/<TASK-B>/finish -H "Content-Type: application/json" --data "<the copied body>"
```
Expected: **HTTP 400**, body containing `unknown or already used approval;
start again`. The server consumes the one-time `state_id` the moment the
first `finish` succeeds (`app.approvals.remove(...)`), so the identical
request — same signed assertion, same everything — is refused the second
time purely because it already happened once.

**5c — a client-made challenge is rejected.** Start two more approvals (two
fresh tasks, or re-run the two above once each is back at `waiting_human`
after a rejected step) so two *different* pending challenges exist at once —
call them P and Q, each with its own `state_id` and its own WebAuthn
`challenge` (nonce) minted by the daemon. Complete Q's ceremony with Windows
Hello up through the signed assertion, but instead of submitting it to `
/approve/<Q task>/finish`, submit that same signed `credential` body together
with **P's** `state_id` to `/approve/<P task>/finish` (again via the
Network-tab-capture-and-edit-with-curl method above, swapping just the
`state_id` field and the URL's task id). Expected: **HTTP 403**, body
containing `assertion rejected: it does not sign the challenge this node
minted`. The handler re-checks the assertion's own signed `client_data_json`
challenge against the nonce recorded for *that* `state_id`'s pending
approval — P's, not Q's — and they disagree, because a passkey's signature
covers the challenge it actually signed and nothing this request claims
about it.

Clean up: `vk umount m1`.

### 6. Property tests green on the real kernel; `cargo test --workspace` green in CI on three OSes; `arch-ollama` job green

If the gate VM has a Rust toolchain (optional — this item can also be read
straight off GitHub Actions without touching the VM):
```
cargo test -p vk-props
```
Expected: every property test passes — `vk-props` depends on both `vk-stub`
and the real `vk-kernel`/`vk-store`, so this is I1–I4′ exercised against the
real kernel, not only the in-memory stand-in.

Either way, open the Actions run for this commit/tag —
`https://github.com/EricLtx/VerticalAI/actions/workflows/ci.yml` — and
confirm: `test` is green on `windows-latest`, `ubuntu-latest` **and**
`macos-latest`; `arch-ollama` is green (it only runs on a push to `master`
or on `workflow_dispatch`, so trigger it by hand if this commit is neither).

### 7. Demo script passes in both role orders with the Ollama container and the Claude Code adapter; recorded runs committed

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo-sp1.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo-sp1.ps1 -Roles claude-plans
```
Expected: both invocations exit 0, print all ten H1 checks passing, and name
the released proposal file. `docs\demo\runs\2026-09-25\` already holds a
committed pair from the founder's own machine — read `docs\demo\README.md`
first for what a run looks like before spending the ~12 minutes twice more.
If this gate run is the one being kept as the SP1 evidence from the gate VM
itself, commit its `docs\demo\runs\<date>\` output the same way; otherwise
the existing 2026-09-25 pair, produced under the same script this item just
re-ran clean, stands as the "recorded runs committed" evidence.

### 8. TCB statement updated with spike outcomes (restricted token, network egress, Docker under the service account)

Not a command so much as a write-up, once items 2–4 above have produced real
numbers on this VM. Add a dated note to `contracts/tcb.md` (its "Harness
(SP1b, Task 4)" and "The endpoint and the store under a service account
(SP1b, Task 6)" sections are where the rest of this material already lives)
recording, from *this* run rather than from the founder's development
machine:
- the service account's token as item 2's `spike-6a.ps1` summary and
  `%ProgramData%\VerticalAI\vk\vkd.log` recorded it (`account_sid`,
  `pipe_dacl_bound`, whether `pipe_owner_is_the_service` came back `yes`);
- the harness's observed network egress from item 4 — the exact
  `connections` list and the confirmation that every address resolved to
  Anthropic and nothing else did;
- the Docker-from-the-service-account verdict `spike-6a.ps1` recorded
  (`docker_probe=` in `vkd.log`, and `docker-probe.log` beside it) — this is
  the finding that decides whether a customer node can start its own Ollama
  container under the service account or must mount `--external` against
  one the founder starts.

## The founder's manual steps

An agent cannot complete these; they need the founder's own hands, face,
fingerprint or elevated console on the gate VM itself:

- **Windows Hello** (item 5): enrolling the passkey and approving with it —
  twice, for 5a and 5b — is a live biometric/PIN ceremony with no
  programmatic substitute. The replay (5b) and client-made-challenge (5c)
  checks still need a real completed assertion to start from.
- **Every elevated step**: `net user … /add` and `/delete`, both
  `spike-6a.ps1` runs (it checks its own elevation and exits if it is not),
  `install-windows.ps1 -Service` (same check, same refusal message if run
  plain), `vkd-service stop` / `start` / `uninstall` in item 3, and reading
  `%ProgramData%\VerticalAI\vk\vkd.log` if the interactive account has no
  read access to it. Windows will prompt for UAC consent on each; nothing
  automated can answer that prompt.
- **Turning Smart App Control on** in the prerequisites, and judging
  item 1's "no prompt appeared" by eye — SAC's block is a toast notification,
  not a non-zero exit code.
- **Item 8's write-up**: transcribing the real numbers items 2–4 produced on
  this VM into `contracts/tcb.md` is an editorial act (what is worth keeping
  from a log versus what is noise), left to whoever is signing off the gate.

## Results

| # | Item | Result | Evidence / notes | Date | Tester |
|---|---|---|---|---|---|
| 1 | Signed binaries install without SmartScreen/SAC prompts | | | | |
| 2 | `vkd` as `NT SERVICE\vkd`; user's `vk status` works; another user refused | | | | |
| 3 | `vk ledger verify` / `vk fsck` ok after restart; second `vkd` start refused | | | | |
| 4 | Harness fence: outside-workspace read denied and logged; `connections` is Anthropic-only | | | | |
| 5 | Passkey approval completes; replayed assertion rejected; client-made challenge rejected | | | | |
| 6 | Property tests on the real kernel; `cargo test --workspace` green on 3 OSes; `arch-ollama` green | | | | |
| 7 | Demo passes both role orders; recorded runs committed | | | | |
| 8 | TCB statement updated with this run's spike outcomes | | | | |

SP1 is done when every row reads PASS.
