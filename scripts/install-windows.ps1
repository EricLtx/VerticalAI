<#
.SYNOPSIS
    Installs (or removes) the VerticalAI binaries for one Windows user: vk,
    vkd, vk-mcp and vkd-service, copied to %LOCALAPPDATA%\Programs\VerticalAI
    and put on that user's own PATH -- no elevation, no admin share, nothing
    system-wide. `-Service` is the one elevated step, and it is opt-in.

.DESCRIPTION
    What a plain run does:
      1. finds the four binaries -- beside this script by default, which is
         where a release archive already puts them, or wherever -Source
         names -- and checks whether they carry a valid Authenticode
         signature, warning loudly if they do not (Smart App Control and
         SmartScreen will not be quiet about it either: SP1 gate item 1);
      2. copies them to -Root (%LOCALAPPDATA%\Programs\VerticalAI by default);
      3. adds -Root to this user's PATH, once -- idempotent: running the
         installer again does not grow a duplicate entry;
      4. checks Docker Desktop is on PATH and its engine answers `docker
         info` (the Ollama arch needs both);
      5. checks Claude Code (`claude`) is on PATH (the Claude Code arch and
         the harness need it);
      6. prints a summary.

    `-Service` additionally registers `vkd` as a Windows service under `NT
    SERVICE\vkd` (`vkd-service install`, then `start`) and needs an elevated
    shell. Run without one, it refuses and prints the exact command to
    re-run elevated, rather than doing half the job from the wrong account.

    `-Uninstall` reverses what a plain run did, and, if it finds one, what
    `-Service` did too, whether or not this invocation also passes -Service:
    it looks for the service rather than trusting the flag. It removes -Root
    from PATH, deletes the copied binaries and the directory once it is
    empty, and -- elevated -- stops and deletes the service. It never
    touches `%ProgramData%\VerticalAI\vk` (the node's store) or anything in
    the OS keyring: uninstalling the program is not the same act as
    discarding a node's ledger, and this script does only the first.

    `-DryRun` (or the built-in `-WhatIf`) prints every action this run would
    take and performs none of them. The exceptions are the read-only checks
    -- signatures, `docker info`, `claude --version`, the elevation test --
    which are not actions and always run, because their output is the point
    of a dry run too: `-Service -DryRun` from an ordinary shell still tells
    you it would have been refused, and shows you the elevated command.

.PARAMETER Source
    Where to find vk.exe, vkd.exe, vk-mcp.exe and vkd-service.exe. Defaults
    to the directory this script is in.

.PARAMETER Root
    Where to install. Defaults to %LOCALAPPDATA%\Programs\VerticalAI. Pass a
    scratch directory here to try the script without touching the real one.

.PARAMETER Service
    Also register and start `vkd` as a Windows service (elevated; SP1 gate
    item 2).

.PARAMETER Uninstall
    Reverse the install instead of performing one.

.PARAMETER DryRun
    Print every action without doing it. Equivalent to -WhatIf; both are
    accepted because this script always prints its own summary regardless,
    and -DryRun reads better in that sentence than "ran with -WhatIf".

.PARAMETER PathVarName
    Testing hook, not needed for a real install: the environment variable
    name the PATH logic reads and writes. Defaults to `Path`.

.PARAMETER PathScope
    Testing hook, not needed for a real install: the
    `[Environment]::SetEnvironmentVariable` scope the PATH logic uses -- `User`
    (default) or `Process`. Tests pass `Process` with a scratch -PathVarName
    so nothing persists past the session and the real user PATH is never
    touched.

.EXAMPLE
    .\install-windows.ps1
    # binaries beside the script -> %LOCALAPPDATA%\Programs\VerticalAI, PATH updated

.EXAMPLE
    # from an elevated PowerShell, after a plain run has copied the binaries
    .\install-windows.ps1 -Service

.EXAMPLE
    .\install-windows.ps1 -Uninstall

.EXAMPLE
    .\install-windows.ps1 -DryRun -Root C:\temp\vk-test -Source C:\temp\vk-build

.NOTES
    Windows PowerShell 5.1: no `&&` / `||`, no ternary, explicit -Encoding
    anywhere text is written to a file (nothing here currently is). Builds
    nothing, mounts no arch and never touches the store or the keyring --
    see `scripts\demo-sp1.ps1` and `scripts\spike-6a.ps1` for the checks that
    do.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Source = $PSScriptRoot,
    [string]$Root = (Join-Path $env:LOCALAPPDATA 'Programs\VerticalAI'),
    [switch]$Service,
    [switch]$Uninstall,
    [switch]$DryRun,
    [string]$PathVarName = 'Path',
    [ValidateSet('User', 'Process')]
    [string]$PathScope = 'User'
)

$ErrorActionPreference = 'Stop'
# $WhatIfPreference is set by the common -WhatIf switch that
# SupportsShouldProcess adds; -DryRun is the same thing under the name this
# script's own messages use.
$NoAct = [bool]($DryRun -or $WhatIfPreference)
$Binaries = @('vk.exe', 'vkd.exe', 'vk-mcp.exe', 'vkd-service.exe')

function Say([string]$text) { Write-Host "== $text" -ForegroundColor Cyan }
function Warn([string]$text) { Write-Host "!! $text" -ForegroundColor Yellow }
function Fail([string]$text) { Write-Host "xx $text" -ForegroundColor Red }

# Every mutating step goes through this, so -DryRun / -WhatIf prints exactly
# what a real run would do and does none of it. Read-only checks (a
# signature, `docker info`, an elevation test) are not steps -- they call
# Say/Warn/Write-Host directly and run unconditionally, dry run or not.
function Step([string]$description, [scriptblock]$action) {
    if ($NoAct) {
        Write-Host "[dry-run] would $description" -ForegroundColor DarkYellow
        return
    }
    try {
        & $action
        Write-Host "-> $description"
    } catch {
        Fail "$description -- $($_.Exception.Message)"
        throw
    }
}

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Quote the way CommandLineToArgvW reads it back -- this repository's own
# path has a space in it, and so may -Source or -Root.
function Quote-Arg([string]$a) {
    if ($a -eq '') { return '""' }
    if ($a -notmatch '[\s"]') { return $a }
    $e = $a -replace '(\\*)"', '$1$1\"'
    $e = $e -replace '(\\+)$', '$1$1'
    return '"' + $e + '"'
}

# Run a command with a timeout, never throwing: used for the probes (`docker
# info`, `claude --version`) and for the vkd-service verbs, none of which
# should be able to hang an installer.
function Try-Run {
    param([string]$File, [string[]]$Arguments, [int]$TimeoutSec = 20)
    $out = New-TemporaryFile
    $err = New-TemporaryFile
    try {
        $line = (($Arguments | ForEach-Object { Quote-Arg $_ }) -join ' ')
        $sp = @{
            FilePath               = $File
            NoNewWindow            = $true
            PassThru               = $true
            RedirectStandardOutput = $out.FullName
            RedirectStandardError  = $err.FullName
        }
        if ($line) { $sp['ArgumentList'] = $line }
        $p = Start-Process @sp
        $null = $p.Handle
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill() } catch {}
            return [pscustomobject]@{ Code = -1; Out = ''; Err = "timed out after ${TimeoutSec}s" }
        }
        $p.WaitForExit()
        $stdout = (Get-Content -Raw -Path $out -ErrorAction SilentlyContinue)
        $stderr = (Get-Content -Raw -Path $err -ErrorAction SilentlyContinue)
        if ($null -eq $stdout) { $stdout = '' }
        if ($null -eq $stderr) { $stderr = '' }
        return [pscustomobject]@{ Code = $p.ExitCode; Out = $stdout.Trim(); Err = $stderr.Trim() }
    } catch {
        return [pscustomobject]@{ Code = -1; Out = ''; Err = $_.Exception.Message }
    } finally {
        Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
    }
}

function Get-PathEntries {
    $current = [Environment]::GetEnvironmentVariable($PathVarName, $PathScope)
    if ($null -eq $current) { $current = '' }
    return ,($current.Split(';') | Where-Object { $_ -ne '' })
}

function Test-InPath([string]$dir) {
    $target = $dir.TrimEnd('\')
    foreach ($p in (Get-PathEntries)) {
        if ($p.TrimEnd('\') -ieq $target) { return $true }
    }
    return $false
}

# Idempotent: a directory already on the named PATH is left exactly as it
# was, so installing twice does not grow a duplicate entry.
function Add-ToPath([string]$dir) {
    if (Test-InPath $dir) {
        Write-Host "-> $dir is already on $PathScope $PathVarName"
        return
    }
    Step "add $dir to $PathScope $PathVarName" {
        $entries = @(Get-PathEntries) + $dir
        [Environment]::SetEnvironmentVariable($PathVarName, ($entries -join ';'), $PathScope)
    }
}

function Remove-FromPath([string]$dir) {
    if (-not (Test-InPath $dir)) {
        Write-Host "-> $dir is not on $PathScope $PathVarName"
        return
    }
    $target = $dir.TrimEnd('\')
    Step "remove $dir from $PathScope $PathVarName" {
        $entries = @(Get-PathEntries) | Where-Object { $_.TrimEnd('\') -ine $target }
        [Environment]::SetEnvironmentVariable($PathVarName, ($entries -join ';'), $PathScope)
    }
}

function Test-DockerDesktop {
    $cmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Warn 'Docker Desktop was not found on PATH. The Ollama arch needs it: https://www.docker.com/products/docker-desktop/'
        return
    }
    $info = Try-Run 'docker' @('info') 20
    if ($info.Code -eq 0) {
        Write-Host '-> Docker Desktop is installed and its engine answers `docker info`'
    } else {
        Warn 'docker is on PATH but `docker info` did not answer. Start Docker Desktop before mounting the Ollama arch.'
    }
}

function Test-ClaudeCode {
    $cmd = Get-Command claude -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Warn 'Claude Code (`claude`) was not found on PATH. Install it and sign in before using the Claude Code arch or the harness.'
        return
    }
    $v = Try-Run 'claude' @('--version') 15
    if ($v.Code -eq 0) {
        Write-Host "-> Claude Code is on PATH ($($v.Out))"
    } else {
        Warn "claude is on PATH but --version did not answer: $($v.Err)"
    }
}

# Informational, not a gate: this script installs what it is given either
# way (SP0/SP1 nodes before a signing secret exists have nothing else to
# install), but an unsigned binary is exactly what SmartScreen and Smart App
# Control will stop the founder at (SP1 gate item 1), so it says so loudly
# rather than leaving that discovery to the next reboot.
function Test-Signatures([string[]]$paths) {
    $unsigned = @()
    foreach ($p in $paths) {
        $sig = Get-AuthenticodeSignature -LiteralPath $p
        if ($sig.Status -ne 'Valid') {
            $unsigned += (Split-Path $p -Leaf)
        }
    }
    if ($unsigned.Count -gt 0) {
        Write-Host ''
        Write-Host '*** UNSIGNED BINARIES ***' -ForegroundColor Red
        Write-Host ("These do not carry a valid Authenticode signature: {0}" -f ($unsigned -join ', ')) -ForegroundColor Red
        Write-Host 'Smart App Control and SmartScreen will warn on or block these (SP1 gate item 1).' -ForegroundColor Red
        Write-Host 'Expected until the CI `sign` job has a signing secret configured -- see README.md, "Signing release binaries".' -ForegroundColor Red
        Write-Host ''
    } else {
        Write-Host '-> all four binaries carry a valid Authenticode signature'
    }
}

# The re-run command this script prints whenever an elevated step is
# refused: this same script, this same invocation, from an elevated prompt.
function Get-ElevatedCommand([string[]]$extraArgs) {
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Definition }
    $parts = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Quote-Arg $scriptPath)) + $extraArgs
    return 'powershell ' + ($parts -join ' ')
}

# ---------------------------------------------------------------- Uninstall

function Do-Uninstall {
    Say "uninstall from $Root"

    $svc = Get-Service -Name 'vkd' -ErrorAction SilentlyContinue
    if ($svc) {
        if (-not (Test-Elevated)) {
            Warn 'a vkd service is installed; removing it needs an elevated shell. From an elevated PowerShell:'
            Warn ("    " + (Get-ElevatedCommand @('-Uninstall', '-Root', (Quote-Arg $Root))))
        } else {
            $svcBin = Join-Path $Root 'vkd-service.exe'
            if (Test-Path -LiteralPath $svcBin) {
                Step 'stop and delete the vkd service' {
                    $r = Try-Run $svcBin @('uninstall') 60
                    if ($r.Out) { Write-Host $r.Out }
                    if ($r.Code -ne 0) { throw $r.Err }
                }
            } else {
                Warn "vkd service is installed but $svcBin is gone; remove it directly: sc.exe stop vkd, then sc.exe delete vkd"
            }
        }
    } else {
        Write-Host '-> no vkd service is installed'
    }

    Remove-FromPath $Root

    foreach ($b in $Binaries) {
        $p = Join-Path $Root $b
        if (Test-Path -LiteralPath $p) {
            Step "remove $p" { Remove-Item -LiteralPath $p -Force }
        }
    }

    if ($NoAct) {
        Write-Host "[dry-run] would remove $Root if nothing but this run's binaries were left in it" -ForegroundColor DarkYellow
    } elseif (Test-Path -LiteralPath $Root) {
        $left = Get-ChildItem -LiteralPath $Root -Force -ErrorAction SilentlyContinue
        if (-not $left) {
            Step "remove the now-empty $Root" { Remove-Item -LiteralPath $Root -Force }
        } else {
            Warn "$Root still has files this script did not put there; left in place: $($left.Name -join ', ')"
        }
    }

    Write-Host ''
    Write-Host "Left untouched, on purpose: %ProgramData%\VerticalAI\vk (the node's store) and this" -ForegroundColor DarkGray
    Write-Host "account's OS keyring entries. Uninstalling the program is not discarding a node." -ForegroundColor DarkGray
}

# -------------------------------------------------------------------- Install

function Do-Install {
    Say "install from $Source to $Root"

    $sourcePaths = @()
    $missing = @()
    foreach ($b in $Binaries) {
        $p = Join-Path $Source $b
        if (Test-Path -LiteralPath $p) { $sourcePaths += (Resolve-Path -LiteralPath $p).Path }
        else { $missing += $p }
    }
    if ($missing.Count -gt 0) {
        Fail "missing binaries: $($missing -join ', ')"
        Fail "-Source must hold all four: $($Binaries -join ', ')"
        exit 1
    }

    Test-Signatures $sourcePaths

    # From here on, a thrown Step (a copy that fails, an elevated
    # vkd-service install/start that fails) must still leave the operator
    # with the summary — that recap is what says which parts of the install
    # actually landed, and it is needed most exactly when something broke.
    try {
        if (-not (Test-Path -LiteralPath $Root)) {
            Step "create $Root" { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
        }
        foreach ($p in $sourcePaths) {
            $leaf = Split-Path $p -Leaf
            $dst = Join-Path $Root $leaf
            Step "copy $leaf to $Root" { Copy-Item -LiteralPath $p -Destination $dst -Force }
        }

        Add-ToPath $Root

        Test-DockerDesktop
        Test-ClaudeCode

        if ($Service) {
            Say 'register vkd as a Windows service'
            if (-not (Test-Elevated)) {
                Warn 'vkd-service install needs an elevated shell. From an elevated PowerShell:'
                $extra = @('-Service', '-Root', (Quote-Arg $Root))
                if ($Source -ne $PSScriptRoot) { $extra += @('-Source', (Quote-Arg $Source)) }
                Warn ("    " + (Get-ElevatedCommand $extra))
            } else {
                $svcBin = Join-Path $Root 'vkd-service.exe'
                Step 'vkd-service install' {
                    $r = Try-Run $svcBin @('install', '--binary', $svcBin) 30
                    if ($r.Out) { Write-Host $r.Out }
                    if ($r.Code -ne 0) { throw $r.Err }
                }
                Step 'vkd-service start' {
                    $r = Try-Run $svcBin @('start') 40
                    if ($r.Out) { Write-Host $r.Out }
                    if ($r.Code -ne 0) { throw $r.Err }
                }
            }
        }
    } finally {
        $serviceNote = 'not requested (pass -Service, elevated)'
        if ($Service) { $serviceNote = 'requested' }

        Write-Host ''
        Write-Host '=== INSTALL SUMMARY ===' -ForegroundColor Green
        Write-Host "root:      $Root"
        Write-Host ("binaries:  {0}" -f ($Binaries -join ', '))
        Write-Host ("path:      {0} ({1} {2})" -f $Root, $PathScope, $PathVarName)
        Write-Host "service:   $serviceNote"
        Write-Host 'Open a new shell for the PATH change to take effect.'
        Write-Host '========================'
    }
}

# ------------------------------------------------------------------- Main

if ($Uninstall) { Do-Uninstall } else { Do-Install }
