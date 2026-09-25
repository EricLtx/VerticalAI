#Requires -Version 5.1
<#
.SYNOPSIS
    The SP1 demo: a client proposal, drafted from a brief by two models that
    have never met, through one kernel register, approved by a human and
    released as a file.

.DESCRIPTION
    Gemma runs in an Ollama container this kernel starts and caps; Claude runs
    through the Claude Code already installed on this machine. Neither knows
    the other exists. What they share is the register — the kernel's IR — and
    the demo's whole point is that it does not matter which of them holds
    which role.

    So the script runs the task twice: once with Gemma planning and Claude
    drafting, once the other way round, as a *new* task with a new register.
    Then it checks H1: run 2 names both arches on consecutive steps, each one
    leaves a decision in the register the next one reads, and nothing of run
    1's register is in run 2's.

    Nothing here touches the machine's own node. A fresh state directory, file
    keys (never the OS keyring), a private endpoint and an OS-chosen web port;
    the daemon and the container are stopped again at the end unless -Keep.

.PARAMETER Roles
    Which model plans first.
      gemma-plans   run 1 Plan=Gemma,  Draft=Claude, Judge=Claude;  run 2 swapped
      claude-plans  run 1 Plan=Claude, Draft=Gemma,  Judge=Gemma;   run 2 swapped
      harness       one run only: Plan=Gemma, Harness(claude-code), Judge=Gemma.
                    No swap and no H1 check — the harness is an agent, not an
                    arch, and it is not a role two models can trade.

.PARAMETER Model
    The Ollama model tag. gemma4:e4b is the demo model; gemma3:1b is the one to
    develop against — it is small, fast and wrong, which is all a dry run needs.

.PARAMETER Approval
    nodekey  the node's device key signs the kernel-minted challenge (scripted).
    passkey  the loopback page and Windows Hello (a person has to be there).

.PARAMETER StateDir
    Where the node lives. A fresh directory under $env:TEMP by default, removed
    at the end unless -Keep.

.PARAMETER Bin
    The directory holding vk.exe and vkd.exe.

.PARAMETER Ctx
    The context window asked of Ollama. Half of it is usable (spike 1a), and
    the brief plus three decisions has to fit in that half.

.PARAMETER Keep
    Leave the daemon, the container and the state directory up afterwards.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/demo-sp1.ps1

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/demo-sp1.ps1 -Roles claude-plans -Approval passkey -Keep
#>
[CmdletBinding()]
param(
    [ValidateSet('gemma-plans', 'claude-plans', 'harness')]
    [string] $Roles = 'gemma-plans',

    [string] $Model = 'gemma4:e4b',

    [ValidateSet('nodekey', 'passkey')]
    [string] $Approval = 'nodekey',

    [string] $StateDir,

    [string] $Bin,

    [int] $Ctx = 16384,

    [switch] $Keep
)

$ErrorActionPreference = 'Stop'

# Numbers in a record are read by whoever opens the file, and `164,7` is not a
# number to half of them. The invariant culture for this process only.
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

# ---------------------------------------------------------------- plumbing --

# A native argument as CommandLineToArgvW will read it back. Windows PowerShell
# 5.1 has no ProcessStartInfo.ArgumentList, so the command line is built here —
# and the goal this script passes is a two-page brief with quotes and newlines
# in it, which is exactly the argument naive quoting mangles.
function ConvertTo-NativeArg {
    param([string] $Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $i = 0
    while ($i -lt $Value.Length) {
        $slashes = 0
        while ($i -lt $Value.Length -and $Value[$i] -eq '\') { $slashes++; $i++ }
        if ($i -ge $Value.Length) {
            [void]$sb.Append('\' * ($slashes * 2))
            break
        }
        if ($Value[$i] -eq '"') {
            [void]$sb.Append('\' * ($slashes * 2 + 1))
            [void]$sb.Append('"')
        }
        else {
            [void]$sb.Append('\' * $slashes)
            [void]$sb.Append($Value[$i])
        }
        $i++
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# Run a native program and hand back its exit code and both streams. Not
# `& $exe @args`: PowerShell 5.1 wraps a native command's stderr in error
# records and decides `$?` for itself, and this script has to be able to read a
# refusal as an answer.
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)] [string] $FilePath,
        [string[]] $Arguments = @(),
        # Let the child write straight to this console instead of capturing it:
        # for `vk approve --passkey`, whose whole output is a link a person has
        # to see while it is still waiting.
        [switch] $Interactive
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $quoted = @()
    foreach ($a in $Arguments) { $quoted += (ConvertTo-NativeArg $a) }
    $psi.Arguments = ($quoted -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = (Get-Location).Path
    foreach ($name in @('VK_ENDPOINT', 'VK_NODE_KEY_FILE')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($null -ne $value) { $psi.EnvironmentVariables[$name] = $value }
    }
    if (-not $Interactive) {
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $out = ''
    $err = ''
    if ($Interactive) {
        $p.WaitForExit()
    }
    else {
        # Both streams at once: a child that fills a pipe nobody is reading
        # blocks for ever, and `vk dmesg --json` is long enough to.
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        $out = $outTask.Result
        $err = $errTask.Result
    }
    $code = $p.ExitCode
    $p.Dispose()
    return New-Object psobject -Property @{ ExitCode = $code; StdOut = $out; StdErr = $err }
}

function Invoke-Vk {
    param([string[]] $Arguments, [switch] $Interactive)
    return Invoke-Native -FilePath $script:Vk -Arguments $Arguments -Interactive:$Interactive
}

# `vk …`, which must succeed. The refusal, not a stack trace: a syscall this
# node declined is an answer, and the person running the demo needs to read it.
function Use-Vk {
    param([string[]] $Arguments)
    $r = Invoke-Vk -Arguments $Arguments
    if ($r.ExitCode -ne 0) {
        throw ("vk {0} exited {1}:`n{2}{3}" -f ($Arguments -join ' '), $r.ExitCode, $r.StdErr, $r.StdOut)
    }
    return $r.StdOut
}

function Use-VkJson {
    param([string[]] $Arguments)
    $text = Use-Vk -Arguments ($Arguments + '--json')
    return ($text | ConvertFrom-Json)
}

# UTF-8 without a byte-order mark. `Set-Content -Encoding utf8` on 5.1 writes
# one, and a BOM in front of `[` is a JSON file half the world cannot parse.
function Write-Utf8 {
    param([string] $Path, [string] $Text)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Force -Path $dir) }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding $false))
}

function Write-Json {
    param([string] $Path, $Value)
    Write-Utf8 -Path $Path -Text (ConvertTo-Json -InputObject $Value -Depth 24)
}

function Write-Head {
    param([string] $Text)
    Write-Host ''
    Write-Host ('== ' + $Text + ' ' + ('=' * [Math]::Max(1, 68 - $Text.Length))) -ForegroundColor Cyan
}

function Write-Fact {
    param([string] $Name, $Value)
    Write-Host ('   {0,-22} {1}' -f $Name, $Value)
}

# A property of a JSON object that may simply not be there (`kind.arch_id` on
# an approve step).
function Get-Prop {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# --------------------------------------------------------------- the stage --

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Bin) { $Bin = Join-Path $env:USERPROFILE '.cargo-target\verticalai-sp1\release' }
$script:Vk = Join-Path $Bin 'vk.exe'
$Vkd = Join-Path $Bin 'vkd.exe'
$BriefPath = Join-Path $RepoRoot 'docs\demo\brief\acme-brief.md'
$RunDate = Get-Date -Format 'yyyy-MM-dd'
$RunDir = Join-Path $RepoRoot ('docs\demo\runs\' + $RunDate)

Write-Head 'SP1 demo'
Write-Fact 'roles' $Roles
Write-Fact 'model' $Model
Write-Fact 'approval' $Approval
Write-Fact 'binaries' $Bin
Write-Fact 'records' $RunDir

foreach ($p in @($script:Vk, $Vkd, $BriefPath)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "not found: $p (build the release binaries, or pass -Bin)" }
}
if ($Roles -eq 'harness') {
    # The daemon refuses to launch a harness without its kernel channel beside
    # it, and refusing here costs nothing where refusing there costs a boot, a
    # container and a model load.
    $mcp = Join-Path $Bin 'vk-mcp.exe'
    if (-not (Test-Path -LiteralPath $mcp)) {
        throw "not found: $mcp - harness mode needs vk-mcp next to vkd. Run a full 'cargo build --release'."
    }
}

$docker = Invoke-Native -FilePath 'docker' -Arguments @('version', '--format', '{{.Server.Version}}')
if ($docker.ExitCode -ne 0) { throw "Docker's engine is not reachable; start Docker Desktop. $($docker.StdErr)" }
Write-Fact 'docker' $docker.StdOut.Trim()

$claude = Invoke-Native -FilePath 'claude' -Arguments @('--version')
if ($claude.ExitCode -ne 0) { throw "no claude binary on this PATH; install Claude Code and log in. $($claude.StdErr)" }
Write-Fact 'claude' $claude.StdOut.Trim()

$Temporary = $false
if (-not $StateDir) {
    $StateDir = Join-Path $env:TEMP ('vk-demo-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    $Temporary = $true
}
[void](New-Item -ItemType Directory -Force -Path $StateDir)
$Endpoint = '\\.\pipe\vk-demo-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$env:VK_ENDPOINT = $Endpoint
$env:VK_NODE_KEY_FILE = Join-Path $StateDir 'node.key'
Write-Fact 'state dir' $StateDir
Write-Fact 'endpoint' $Endpoint

$BootPid = 0
$Ok = $false

# ------------------------------------------------------------- the two runs --

# One task, end to end: submit, step until it waits, approve, step to done, and
# read back everything the record can be asked for.
function Invoke-DemoRun {
    param(
        [string] $Label,
        [string] $Order,
        [string] $Goal,
        [string] $PlanArch,
        [string] $DraftArch,
        [string] $JudgeArch,
        [string] $HarnessName,
        [string] $ExportOut
    )

    Write-Head ("run {0}: {1}" -f $Label, $Order)
    Write-Fact 'plan' $PlanArch
    if ($HarnessName) { Write-Fact 'harness' $HarnessName } else { Write-Fact 'draft' $DraftArch }
    Write-Fact 'judge' $JudgeArch

    $before = @()
    if (Test-Path -LiteralPath $ExportOut) {
        $before = @(Get-ChildItem -LiteralPath $ExportOut -File | ForEach-Object { $_.Name })
    }
    # Where this run's events start on the chain, so its own `infer` pairs can
    # be picked out of the tail afterwards.
    $seqFrom = [int](Use-VkJson -Arguments @('ledger', 'verify')).len

    $submit = @('task', 'submit', '--goal', $Goal, '--artefact', 'proposal', '--plan', $PlanArch)
    if ($HarnessName) { $submit += @('--harness', $HarnessName) } else { $submit += @('--draft', $DraftArch) }
    $submit += @('--judge', $JudgeArch, '--approve', '--release', 'out')
    $created = Use-VkJson -Arguments $submit
    $task = $created.id
    Write-Fact 'task' $task
    Write-Fact 'register' $created.register

    $clock = [System.Diagnostics.Stopwatch]::StartNew()

    # Drive it. `--all` runs one step per call until the task settles, which
    # here means the human it is waiting for. A harness step is the exception:
    # the scheduler refuses it by name and says which verb runs it, so the
    # drive is in two halves around `vk harness run`.
    if ($HarnessName) {
        $refused = Invoke-Vk -Arguments @('task', 'step', $task, '--all', '--json')
        if ($refused.ExitCode -eq 0) { throw "a harness step should stop vk task step: $($refused.StdOut)" }
        if ($refused.StdErr -notmatch 'harness') { throw "unexpected refusal: $($refused.StdErr)" }
        Write-Host ('   ' + $refused.StdErr.Trim())
        Write-Host '   launching the confined harness (minutes)...'
        $ran = Use-VkJson -Arguments @('harness', 'run', $task, '--name', $HarnessName)
        Write-Fact 'harness exit' (Get-Prop $ran 'exit')
        Write-Fact 'harness governed' (Get-Prop $ran 'governed')
        Write-Fact 'harness artefact' (Get-Prop $ran 'artefact_hash')
    }
    Write-Host '   stepping to the human...'
    $waiting = Use-VkJson -Arguments @('task', 'step', $task, '--all')
    if ($waiting.status -ne 'waiting_human') {
        throw ("task {0} is {1}, not waiting_human" -f $task, $waiting.status)
    }
    $toHuman = $clock.Elapsed.TotalSeconds

    # The ceremony. Either way what is signed is a challenge this kernel minted
    # for this task — never one the shell chose (invariant I1).
    Write-Head ("run {0}: the human ceremony ({1})" -f $Label, $Approval)
    $subject = ''
    if ($Approval -eq 'passkey') {
        Write-Host '   open the link below and confirm with Windows Hello.' -ForegroundColor Yellow
        $r = Invoke-Vk -Arguments @('approve', $task, '--passkey', '--timeout', '900') -Interactive
        if ($r.ExitCode -ne 0) { throw "the passkey approval of $task did not land" }
    }
    else {
        $approved = Use-VkJson -Arguments @('approve', $task)
        $subject = $approved.subject_hash
        Write-Fact 'approved' $subject
    }

    Write-Host '   stepping to done...'
    $done = Use-VkJson -Arguments @('task', 'step', $task, '--all')
    if ($done.status -ne 'done') { throw ("task {0} is {1}, not done" -f $task, $done.status) }
    $clock.Stop()

    # The artefact, on the filesystem, outside the kernel. Found by difference
    # rather than by name: a release step writes *every* artefact its register
    # holds, so "exactly one new file" is also the answer to whether this
    # register inherited anything from the run before it.
    $after = @(Get-ChildItem -LiteralPath $ExportOut -File | ForEach-Object { $_.Name })
    $new = @($after | Where-Object { $before -notcontains $_ })
    if ($new.Count -ne 1) {
        throw ("this run released {0} files, expected exactly one: {1}" -f $new.Count, ($new -join ', '))
    }
    $releasedName = $new[0]
    $releasedPath = Join-Path $ExportOut $releasedName
    $bytes = (Get-Item -LiteralPath $releasedPath).Length
    if ($bytes -le 0) { throw "the released artefact $releasedPath is empty" }
    if ($releasedName -notlike '*.proposal') { throw "not a .proposal: $releasedName" }
    if ($subject) {
        $expected = ($subject -replace '^sha256:', '').Substring(0, 12) + '.proposal'
        if ($releasedName -ne $expected) {
            throw ("the released file {0} is not the artefact that was approved ({1})" -f $releasedName, $subject)
        }
    }
    $text = [System.IO.File]::ReadAllText($releasedPath)
    $sha = (Get-FileHash -LiteralPath $releasedPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $shown = Use-VkJson -Arguments @('task', 'show', $task)
    $top = Use-VkJson -Arguments @('top')
    $tailText = Use-Vk -Arguments @('dmesg', '-n', '40')
    $tailJson = Use-VkJson -Arguments @('dmesg', '-n', '1000')
    $verify = Use-VkJson -Arguments @('ledger', 'verify')
    if (-not $verify.ok) { throw "the ledger does not verify after run $Label" }

    # How long each call to a model took, off the record rather than off this
    # script's clock. The kernel writes two `infer` events per call — one when
    # the prompt leaves it, one when the answer comes back, and the second is
    # stamped with the wall clock of that moment, so the pair is the call. A
    # step's own `started_ms`/`ended_ms` both come from the one `Ctx` the
    # syscall was given and are always equal, which is why they are not used.
    $calls = @()
    $pending = $null
    foreach ($e in $tailJson) {
        if ($e.seq -lt $seqFrom) { continue }
        if ($e.kind -ne 'infer') { continue }
        if ($null -eq $pending) { $pending = $e; continue }
        $calls += [Math]::Round(($e.wall_ms - $pending.wall_ms) / 1000.0, 1)
        $pending = $null
    }

    Write-Head ("run {0}: the record" -f $Label)
    Write-Host $tailText
    Write-Fact 'ledger' ("{0} events, chain verifies" -f $verify.len)
    Write-Fact 'released' $releasedPath
    Write-Fact 'bytes' $bytes
    Write-Fact 'sha256' $sha
    Write-Fact 'wall (s)' ([Math]::Round($clock.Elapsed.TotalSeconds, 1))

    # Per step: what ran it, what the arch counted the prompt at, and — for the
    # steps that called a model — how long the call took, in the order the
    # `infer` pairs went onto the chain.
    $steps = @()
    $i = 0
    $call = 0
    foreach ($s in $shown.steps) {
        $who = ''
        foreach ($f in @('arch_id', 'name', 'to_dir')) {
            $v = Get-Prop $s.kind $f
            if ($v) { $who = $v }
        }
        $secs = $null
        if (@('plan', 'draft', 'judge') -contains $s.kind.kind) {
            if ($call -lt @($calls).Count) { $secs = $calls[$call] }
            $call++
        }
        $steps += New-Object psobject -Property @{
            index = $i; kind = $s.kind.kind; who = $who; status = $s.status
            tokens_in = $s.tokens; seconds = $secs
        }
        $i++
    }
    Write-Host ''
    Write-Host (($steps | Format-Table index, kind, status, tokens_in, seconds, who -AutoSize | Out-String).TrimEnd())

    $prefix = Join-Path $RunDir ('{0}-{1}' -f $Label, $Order)
    Write-Json ($prefix + '-task.json') $shown
    Write-Json ($prefix + '-dmesg.json') $tailJson
    Write-Json ($prefix + '-top.json') $top
    Write-Utf8 ($prefix + '-dmesg.txt') $tailText
    Write-Utf8 ($prefix + '-proposal.md') $text

    return New-Object psobject -Property @{
        label            = $Label
        order            = $Order
        task             = $task
        register         = $shown.register
        plan_arch        = $PlanArch
        draft_arch       = $DraftArch
        judge_arch       = $JudgeArch
        harness          = $HarnessName
        steps            = $steps
        subject_hash     = $subject
        released         = $releasedPath
        released_name    = $releasedName
        bytes            = $bytes
        sha256           = $sha
        text             = $text
        seconds_total    = [Math]::Round($clock.Elapsed.TotalSeconds, 1)
        seconds_to_human = [Math]::Round($toHuman, 1)
        first_seq        = $seqFrom
        ledger_len       = $verify.len
        arch_counters    = $top.arches
    }
}

function New-Check {
    param([string] $Name, [bool] $Pass, [string] $Detail)
    return New-Object psobject -Property @{ check = $Name; pass = $Pass; detail = $Detail }
}

# H1: one register, either model in either role. What is checkable from the
# shell — and what each check actually proves — is written out beside it: the
# claim is the demo, not the summary line.
function Test-H1 {
    param($One, $Two)

    $p1 = $One.steps[0]; $d1 = $One.steps[1]; $j1 = $One.steps[2]
    $p2 = $Two.steps[0]; $d2 = $Two.steps[1]; $j2 = $Two.steps[2]
    $out = @()

    $pass = ($p2.kind -eq 'plan') -and ($d2.kind -eq 'draft') -and ($p2.who -ne $d2.who) -and (($p2.index + 1) -eq $d2.index)
    $out += New-Check 'run 2 names both arches on consecutive steps' $pass (
        "step {0} plan={1}; step {2} draft={3}" -f $p2.index, $p2.who, $d2.index, $d2.who)

    $pass = ($p2.who -eq $d1.who) -and ($d2.who -eq $p1.who)
    $out += New-Check 'run 2 is the swap of run 1' $pass (
        "run 1 plan={0} draft={1}; run 2 plan={2} draft={3}" -f $p1.who, $d1.who, $p2.who, $d2.who)

    $pass = ($p1.status -eq 'done') -and ($d1.status -eq 'done') -and ($j1.status -eq 'done') -and
            ($p2.status -eq 'done') -and ($d2.status -eq 'done') -and ($j2.status -eq 'done')
    $out += New-Check 'every inference step is done' $pass (
        "run 1 {0}/{1}/{2}; run 2 {3}/{4}/{5}" -f $p1.status, $d1.status, $j1.status, $p2.status, $d2.status, $j2.status)

    # A decision after the plan, measured by the arch that read it. Run 2's
    # draft and run 1's plan are the *same* arch over the *same* goal; the only
    # difference between the two prompts is the plan decision run 2's register
    # carried into it. Prompt tokens are the arch's own count, so this is one
    # model saying, in its own tokenizer, that it read what the other wrote
    # into the IR — and the second check says the same in the other direction.
    $pass = $d2.tokens_in -gt $p1.tokens_in
    $out += New-Check 'the plan left a decision the drafter read (arch B)' $pass (
        "{0}: {1} prompt tokens planning from the goal alone, {2} drafting from the goal plus a decision" -f $d2.who, $p1.tokens_in, $d2.tokens_in)

    $pass = $d1.tokens_in -gt $p2.tokens_in
    $out += New-Check 'the plan left a decision the drafter read (arch A)' $pass (
        "{0}: {1} prompt tokens planning from the goal alone, {2} drafting from the goal plus a decision" -f $d1.who, $p2.tokens_in, $d1.tokens_in)

    # And a decision after the draft: the judge's prompt carries it, and the
    # released file *is* it — a Draft step attaches `decisions.last()` byte for
    # byte, which is why every proposal on disk begins `draft:`.
    $pass = ($j2.tokens_in -gt $d2.tokens_in) -and ($j1.tokens_in -gt $d1.tokens_in)
    $out += New-Check 'the draft left a decision the judge read' $pass (
        "run 1 draft {0} -> judge {1}; run 2 draft {2} -> judge {3}" -f $d1.tokens_in, $j1.tokens_in, $d2.tokens_in, $j2.tokens_in)

    $pass = ($One.text.TrimStart() -like 'draft:*') -and ($Two.text.TrimStart() -like 'draft:*') -and
            ($One.bytes -gt 0) -and ($Two.bytes -gt 0)
    $out += New-Check "the draft decision is the file that was released" $pass (
        "{0} bytes and {1} bytes, each the register's last decision" -f $One.bytes, $Two.bytes)

    # Isolation. Two registers, two artefacts, and — because a release step
    # writes *every* artefact its register holds — exactly one new file each.
    $pass = $One.register -ne $Two.register
    $out += New-Check "run 1's register is not run 2's" $pass ("{0} vs {1}" -f $One.register, $Two.register)

    $pass = ($One.sha256 -ne $Two.sha256) -and (-not $Two.text.Contains($One.text.Trim())) -and
            (-not $One.text.Contains($Two.text.Trim()))
    $out += New-Check "run 1's decisions are absent from run 2's register" $pass (
        "run 2 released exactly one file, {0}, and it is not run 1's {1}" -f $Two.released_name, $One.released_name)

    return $out
}

# ------------------------------------------------------------------- do it --

try {
    Write-Head 'boot'
    $booted = Use-VkJson -Arguments @(
        'boot',
        '--state-dir', $StateDir,
        '--master-key-file', (Join-Path $StateDir 'master.key'),
        '--node-key-file', (Join-Path $StateDir 'node.key'),
        # An OS-chosen port: the founder's own daemon may hold 7734, and this
        # node must never be the reason it cannot.
        '--web-port', '0'
    )
    $BootPid = [int](Get-Prop $booted 'pid')
    Write-Fact 'pid' $BootPid
    $status = Use-VkJson -Arguments @('status')
    $ExportRoot = $status.export_root
    Write-Fact 'node' $status.node_id
    Write-Fact 'web' $status.web
    Write-Fact 'export root' $ExportRoot
    Write-Fact 'ledger' ("{0} events, ok={1}" -f $status.ledger_len, $status.ledger_ok)

    Write-Head 'mount'
    Write-Host ("   starting the Ollama container and loading {0} (a cold load is ~25 s)..." -f $Model)
    $ollama = Use-VkJson -Arguments @('mount', 'ollama', '--model', $Model, '--ctx', "$Ctx")
    $GemmaArch = $ollama.arch_id
    Write-Fact ('ollama/' + $Model) ("{0}  governed={1}" -f $GemmaArch, $ollama.governed)

    $cc = Use-VkJson -Arguments @('mount', 'claude-code')
    $ClaudeDraft = $cc.draft.arch_id
    $ClaudeJudge = $cc.judge.arch_id
    Write-Fact 'claude-code draft' $ClaudeDraft
    Write-Fact 'claude-code judge' $ClaudeJudge
    Write-Host (Use-Vk -Arguments @('ls', '/arches'))
    Write-Json (Join-Path $RunDir 'arches.json') (Use-VkJson -Arguments @('ls', '/arches'))

    if ($Approval -eq 'passkey') {
        Write-Head 'enrol a passkey'
        Write-Host '   this node is brand new, so it knows no passkey yet.' -ForegroundColor Yellow
        $enrol = Use-VkJson -Arguments @('passkey', 'enroll')
        Write-Host ('   open ' + $enrol.url) -ForegroundColor Yellow
        Write-Host '   press "Enrol with Windows Hello", choose *This device*, confirm.' -ForegroundColor Yellow
        $deadline = (Get-Date).AddMinutes(10)
        while ($true) {
            $keys = Use-VkJson -Arguments @('passkey', 'ls')
            if ($null -ne $keys -and @($keys).Count -ge 1) { break }
            if ((Get-Date) -gt $deadline) { throw 'no passkey was enrolled within ten minutes' }
            Start-Sleep -Seconds 2
        }
        Write-Host (Use-Vk -Arguments @('passkey', 'ls'))
    }

    $goal = [System.IO.File]::ReadAllText($BriefPath)
    $exportOut = Join-Path $ExportRoot 'out'
    $runs = @()

    if ($Roles -eq 'harness') {
        $runs += Invoke-DemoRun -Label '01' -Order 'harness' -Goal $goal -PlanArch $GemmaArch `
            -DraftArch '' -JudgeArch $GemmaArch -HarnessName 'claude-code' -ExportOut $exportOut
    }
    else {
        if ($Roles -eq 'gemma-plans') {
            $firstName = 'gemma-plans'
            $firstPlan = $GemmaArch; $firstDraft = $ClaudeDraft; $firstJudge = $ClaudeJudge
            $secondName = 'claude-plans'
            $secondPlan = $ClaudeDraft; $secondDraft = $GemmaArch; $secondJudge = $GemmaArch
        }
        else {
            $firstName = 'claude-plans'
            $firstPlan = $ClaudeDraft; $firstDraft = $GemmaArch; $firstJudge = $GemmaArch
            $secondName = 'gemma-plans'
            $secondPlan = $GemmaArch; $secondDraft = $ClaudeDraft; $secondJudge = $ClaudeJudge
        }
        $runs += Invoke-DemoRun -Label '01' -Order $firstName -Goal $goal -PlanArch $firstPlan `
            -DraftArch $firstDraft -JudgeArch $firstJudge -HarnessName '' -ExportOut $exportOut
        $runs += Invoke-DemoRun -Label '02' -Order $secondName -Goal $goal -PlanArch $secondPlan `
            -DraftArch $secondDraft -JudgeArch $secondJudge -HarnessName '' -ExportOut $exportOut
    }

    $h1 = @()
    if (@($runs).Count -eq 2) {
        Write-Head 'H1: one register, either model in either role'
        $h1 = Test-H1 -One $runs[0] -Two $runs[1]
        foreach ($c in $h1) {
            if ($c.pass) { Write-Host ('   [ok  ] ' + $c.check) -ForegroundColor Green }
            else { Write-Host ('   [FAIL] ' + $c.check) -ForegroundColor Red }
            Write-Host ('          ' + $c.detail) -ForegroundColor DarkGray
        }
    }

    Write-Head 'summary'
    $summary = New-Object psobject -Property @{
        date        = $RunDate
        roles       = $Roles
        model       = $Model
        ctx         = $Ctx
        approval    = $Approval
        node        = $status.node_id
        state_dir   = $StateDir
        export_root = $ExportRoot
        arches      = New-Object psobject -Property @{
            gemma = $GemmaArch; claude_draft = $ClaudeDraft; claude_judge = $ClaudeJudge
        }
        runs        = @($runs | Select-Object label, order, task, register, plan_arch, draft_arch,
            judge_arch, harness, subject_hash, released, released_name, bytes,
            sha256, seconds_total, seconds_to_human, first_seq, ledger_len,
            steps, arch_counters)
        h1          = $h1
        # The ledger commits to the *hash* of each event's payload and never to
        # the payload (spec §3.9), so the measured token counts are not in
        # dmesg and cannot be. They are here, and in the saved task and top
        # answers, which is where this node reports them.
        tokens_note = 'measured prompt tokens per call: runs[].steps[].tokens_in (vk task show) and *-top.json (vk top, per arch, with tokens_in_measured beside tokens_in). vk dmesg carries the two infer events per call and their payload hashes, not the payloads.'
    }
    # Named for the invocation, not for the day: `-Roles harness` and the pair
    # both land in the same dated directory and neither may overwrite the
    # other's summary.
    Write-Json (Join-Path $RunDir ('summary-' + $Roles + '.json')) $summary
    foreach ($r in $runs) {
        Write-Host ('   run {0}  {1,-13} {2,7}s  {3,7} bytes  {4}' -f $r.label, $r.order, $r.seconds_total, $r.bytes, $r.released_name)
    }
    if (@($h1).Count -gt 0) {
        $failed = @($h1 | Where-Object { -not $_.pass })
        if ($failed.Count -gt 0) { throw ('H1 failed: ' + (($failed | ForEach-Object { $_.check }) -join '; ')) }
        Write-Host ('   H1: {0} checks, all pass' -f @($h1).Count) -ForegroundColor Green
    }
    Write-Fact 'records' $RunDir
    $Ok = $true
}
finally {
    Write-Head 'tidy up'
    if ($Keep) {
        Write-Host '   -Keep: the daemon, the container and the state directory are left up.'
        Write-Fact 'endpoint' $Endpoint
        Write-Fact 'state dir' $StateDir
        if ($BootPid -gt 0) { Write-Fact 'vkd pid' $BootPid }
    }
    else {
        if ($BootPid -gt 0) {
            # The daemon holds the Ollama adapter and dropping that is a
            # `docker stop`: stop the node first and the container second.
            Stop-Process -Id $BootPid -Force -ErrorAction SilentlyContinue
            Write-Fact 'stopped vkd' $BootPid
        }
        $stop = Invoke-Native -FilePath 'docker' -Arguments @('stop', 'vk-ollama')
        if ($stop.ExitCode -eq 0) { Write-Fact 'stopped container' 'vk-ollama' }
        if ($Temporary -and (Test-Path -LiteralPath $StateDir)) {
            Start-Sleep -Milliseconds 500
            Remove-Item -LiteralPath $StateDir -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $StateDir) { Write-Fact 'state dir' ('left behind: ' + $StateDir) }
            else { Write-Fact 'removed' $StateDir }
        }
    }
}

if (-not $Ok) { exit 1 }
Write-Host ''
Write-Host 'the demo ran.' -ForegroundColor Green
