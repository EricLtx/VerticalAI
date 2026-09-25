<#
.SYNOPSIS
    Spike 6a -- vkd as a Windows service under the NT SERVICE\vkd virtual
    account, with a named-pipe DACL that admits the service and the
    interactive user only.

.DESCRIPTION
    Everything in Task 6 that needs an elevated prompt, in one run. It builds
    nothing: point it at binaries that are already built.

    What it does, in order:
      1.  checks it is elevated, that the binaries exist, and that nothing is
          already holding the service name, the pipe or the pages' port;
      2.  `vkd-service install --probe-docker` under NT SERVICE\vkd, and
          compares the service SID it derived with `sc.exe showsid vkd`;
      3.  starts the service and waits for `vk status` to answer;
      4.  `vk status`, `vk ls /arches`, `vk ledger verify` as the interactive
          user, over the service's pipe;
      5.  stops and starts it again, and re-runs `vk ledger verify` -- the
          restart is the whole reason the single-writer lock and the ledger
          head commitment exist;
      6.  reads the DACL the daemon logged and compares it with the one
          `install` predicted, and reads the Docker verdict the service
          recorded from inside the virtual account;
      7.  tries `vk status` as a second local user if there is one (it will
          prompt for that account's password), or prints how to make one;
      8.  uninstalls, unless -KeepInstalled.

    Then it prints a summary block. Paste that block back.

.PARAMETER ServiceBinary
    The vkd-service.exe to register. Required.

.PARAMETER VkBinary
    The vk.exe to drive it with. Defaults to vk.exe beside -ServiceBinary.

.PARAMETER UserSid
    The interactive user the pipe admits beside the service account. Defaults
    to the account running this script -- an elevated shell has the same user
    SID as the desktop that raised it.

.PARAMETER SecondUser
    A second local account to attempt a connection from. You will be prompted
    for its password by runas. Without it the script only reports whether such
    an account exists.

.PARAMETER MasterKeyFile
    Escape hatch for step 3: if the virtual account turns out to have no usable
    Credential Manager, install again with this and the daemon takes its master
    key from a file instead. Put it somewhere only SYSTEM and the service can
    read.

.PARAMETER KeepInstalled
    Leave the service installed and running at the end, to poke at it.

.EXAMPLE
    # From an elevated PowerShell, after `cargo build --release`:
    .\scripts\spike-6a.ps1 -ServiceBinary C:\vk\target\release\vkd-service.exe

.NOTES
    This creates C:\ProgramData\VerticalAI\vk (a store of its own, not the
    founder's) and, on first start, a Credential Manager entry belonging to
    NT SERVICE\vkd. Uninstalling the service does not delete either: the
    summary says where they are.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServiceBinary,
    [string]$VkBinary,
    [string]$UserSid,
    [string]$SecondUser,
    [string]$MasterKeyFile,
    [switch]$KeepInstalled
)

$ErrorActionPreference = 'Continue'

$ServiceName = 'vkd'
$Endpoint    = '\\.\pipe\vk'
$StateDir    = Join-Path $env:ProgramData 'VerticalAI\vk'
$DaemonLog   = Join-Path $StateDir 'vkd.log'
$DockerLog   = Join-Path $StateDir 'docker-probe.log'
$WebPort     = 7734

# Ordered so the summary block reads in the order things happened.
$Summary = [ordered]@{}
function Record([string]$key, $value) {
    if ($null -eq $value) { $value = '' }
    $Summary[$key] = ($value -replace "`r?`n", ' | ')
}
function Say([string]$text) { Write-Host "== $text" -ForegroundColor Cyan }
function Warn([string]$text) { Write-Host "!! $text" -ForegroundColor Yellow }

# Start-Process joins -ArgumentList with spaces and quotes nothing, so a path
# with a space in it (this repository's own, for one) arrives as two arguments.
# Quote them here, the way CommandLineToArgvW reads them back.
function Quote-Arg([string]$a) {
    if ($a -eq '') { return '""' }
    if ($a -notmatch '[\s"]') { return $a }
    $e = $a -replace '(\\*)"', '$1$1\"'   # double the backslashes before a quote
    $e = $e -replace '(\\+)$', '$1$1'     # and the run of them before the closer
    return '"' + $e + '"'
}

# Run a command, keep its output and its exit code, and never stop the script.
function Try-Run {
    param([string]$File, [string[]]$Arguments, [int]$TimeoutSec = 120)
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
        # Touching the handle is what keeps ExitCode readable once the process
        # has gone; without it Start-Process -PassThru hands back a blank.
        $null = $p.Handle
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill() } catch {}
            return [pscustomobject]@{ Code = -1; Out = ''; Err = "timed out after ${TimeoutSec}s" }
        }
        # The no-argument wait is what settles the exit code and the redirected
        # handles after a timed wait has already returned.
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

function Verdict($r) {
    if ($r.Code -eq 0) { return 'ok' }
    $why = $r.Err
    if (-not $why) { $why = $r.Out }
    if ($why.Length -gt 200) { $why = $why.Substring(0, 200) }
    return ("exit {0}: {1}" -f $r.Code, $why)
}

# `Test-Path` does not answer for a named pipe; the pipe filesystem does.
function Pipe-Exists([string]$leaf) {
    try {
        $names = [System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { Split-Path $_ -Leaf }
        return ($names -contains $leaf)
    } catch { return $false }
}

function Print-Summary {
    $tail = ''
    if (Test-Path -LiteralPath $DaemonLog) {
        $tail = (Get-Content -LiteralPath $DaemonLog -Tail 25) -join "`n"
    }
    Write-Host ''
    Write-Host '=== SPIKE 6A SUMMARY (paste this back) ===' -ForegroundColor Green
    Write-Host ("date={0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Write-Host ("windows={0}" -f (Get-CimInstance Win32_OperatingSystem).Version)
    foreach ($k in $Summary.Keys) { Write-Host ("{0}={1}" -f $k, $Summary[$k]) }
    Write-Host '--- vkd.log, last 25 lines ---'
    Write-Host $tail
    Write-Host '=== END SPIKE 6A SUMMARY ==='
}

# ---------------------------------------------------------------- 1. preflight

Say 'preflight'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This script installs, starts and deletes a Windows service. Run it from an elevated PowerShell.' -ForegroundColor Red
    exit 1
}
if (-not $UserSid) { $UserSid = $identity.User.Value }
Record 'interactive_user' $identity.Name
Record 'user_sid' $UserSid

if (-not (Test-Path -LiteralPath $ServiceBinary)) {
    Write-Host "no such file: $ServiceBinary" -ForegroundColor Red; exit 1
}
$ServiceBinary = (Resolve-Path -LiteralPath $ServiceBinary).Path
if (-not $VkBinary) { $VkBinary = Join-Path (Split-Path -Parent $ServiceBinary) 'vk.exe' }
if (-not (Test-Path -LiteralPath $VkBinary)) {
    Write-Host "no such file: $VkBinary (pass -VkBinary)" -ForegroundColor Red; exit 1
}
$VkBinary = (Resolve-Path -LiteralPath $VkBinary).Path
Record 'service_binary' $ServiceBinary
Record 'vk_binary' $VkBinary

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Warn "a service called $ServiceName is already installed ($($existing.Status)); removing it first"
    $null = Try-Run $ServiceBinary @('uninstall')
}
if (Pipe-Exists 'vk') {
    Warn "$Endpoint already exists -- another daemon is serving the machine-wide pipe. Stop it first."
}
$portHeld = Get-NetTCPConnection -LocalPort $WebPort -State Listen -ErrorAction SilentlyContinue
if ($portHeld) {
    Warn "port $WebPort is already listening (your own vkd?). The service will refuse to start until it is free."
}
Record 'preflight' 'ok'

# --------------------------------------------------------------- 2. install

Say 'install'

$installArgs = @('install', '--user-sid', $UserSid, '--binary', $ServiceBinary, '--probe-docker')
if ($MasterKeyFile) { $installArgs += @('--', '--master-key-file', $MasterKeyFile) }
$install = Try-Run $ServiceBinary $installArgs
Write-Host $install.Out
Record 'install' (Verdict $install)
if ($install.Code -ne 0) {
    Record 'install_error' $install.Err
    Write-Host $install.Err -ForegroundColor Red
}

# Everything install printed is key=value; keep the ones the summary wants.
$installed = @{}
foreach ($line in ($install.Out -split "`r?`n")) {
    if ($line -match '^([a-z_]+)=(.*)$') { $installed[$Matches[1]] = $Matches[2] }
}
Record 'service_sid_derived' $installed['service_sid']
Record 'pipe_dacl_predicted' $installed['pipe_dacl']
Record 'image_path' $installed['image_path']

# The derivation checked against Windows itself. `sc showsid` needs no
# elevation and no installed service -- it is the same SHA-1 of the uppercased
# name that pipe_acl computes.
$showsid = Try-Run 'sc.exe' @('showsid', $ServiceName)
$scSid = ''
if ($showsid.Out -match '(S-1-5-80-[0-9\-]+)') { $scSid = $Matches[1] }
Record 'service_sid_sc_showsid' $scSid
if ($scSid -and $installed['service_sid']) {
    if ($scSid -eq $installed['service_sid']) { Record 'service_sid_agrees' 'yes' }
    else { Record 'service_sid_agrees' 'NO -- the derivation and sc.exe disagree' }
}

if ($install.Code -ne 0) {
    Warn 'install failed; nothing further to do'
    Print-Summary
    exit 1
}

# ----------------------------------------------------------------- 3. start

Say 'start'

$start = Try-Run $ServiceBinary @('start')
Write-Host $start.Out
Record 'start' (Verdict $start)
if ($start.Code -ne 0) { Record 'start_error' $start.Err }

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) { Record 'service_state' $svc.Status }

# The service reports running as soon as the daemon has not fallen over; the
# pipe appears a moment later, and arches come up behind it.
$env:VK_ENDPOINT = $Endpoint
$answered = $false
for ($i = 0; $i -lt 30; $i++) {
    $probe = Try-Run $VkBinary @('status') 20
    if ($probe.Code -eq 0) { $answered = $true; break }
    Start-Sleep -Milliseconds 500
}
Record 'pipe_answered' $answered

# ------------------------------------------- 4. the shell, as the interactive user

Say 'vk status / vk ls /arches / vk ledger verify'

$status = Try-Run $VkBinary @('status')
Write-Host $status.Out
Record 'vk_status' (Verdict $status)
Record 'vk_status_first_line' (($status.Out -split "`r?`n")[0])

$ls = Try-Run $VkBinary @('ls', '/arches')
Record 'vk_ls_arches' (Verdict $ls)

$verify = Try-Run $VkBinary @('ledger', 'verify')
Write-Host $verify.Out
Record 'vk_ledger_verify' (Verdict $verify)

# ---------------------------------------------------------------- 5. restart

Say 'restart, then verify the chain again'

$stop = Try-Run $ServiceBinary @('stop')
Record 'restart_stop' (Verdict $stop)
$start2 = Try-Run $ServiceBinary @('start')
Record 'restart_start' (Verdict $start2)

$answered2 = $false
for ($i = 0; $i -lt 30; $i++) {
    $probe = Try-Run $VkBinary @('status') 20
    if ($probe.Code -eq 0) { $answered2 = $true; break }
    Start-Sleep -Milliseconds 500
}
Record 'pipe_answered_after_restart' $answered2

$verify2 = Try-Run $VkBinary @('ledger', 'verify')
Write-Host $verify2.Out
Record 'vk_ledger_verify_after_restart' (Verdict $verify2)

$status2 = Try-Run $VkBinary @('status')
Record 'vk_status_after_restart' (Verdict $status2)

# ------------------------------------------------- 6. the DACL and the keyring

Say 'what the daemon logged'

$log = ''
if (Test-Path -LiteralPath $DaemonLog) { $log = Get-Content -Raw -LiteralPath $DaemonLog }
Record 'daemon_log' $DaemonLog

$boundDacl = ''
foreach ($m in [regex]::Matches($log, 'pipe_dacl=("?)(D:[^\s"]+)\1')) { $boundDacl = $m.Groups[2].Value }
Record 'pipe_dacl_bound' $boundDacl
if ($boundDacl -and $installed['pipe_dacl']) {
    if ($boundDacl -eq $installed['pipe_dacl']) { Record 'pipe_dacl_agrees' 'yes' }
    else { Record 'pipe_dacl_agrees' 'NO -- install predicted one DACL and the daemon bound another' }
}

$accountSid = ''
foreach ($m in [regex]::Matches($log, 'account_sid=("?)(S-1-[0-9\-]+)\1')) { $accountSid = $m.Groups[2].Value }
Record 'daemon_account_sid' $accountSid

# The keyring question: the daemon logs the master key's fingerprint at boot,
# and it could only have one if Credential Manager worked for the virtual
# account (or if -MasterKeyFile was used).
$masterKey = ''
foreach ($m in [regex]::Matches($log, 'master_key=("?)([a-z0-9:]+)\1')) { $masterKey = $m.Groups[2].Value }
Record 'master_key_fingerprint' $masterKey
if ($masterKey) {
    if ($MasterKeyFile) { Record 'keyring_under_virtual_account' 'not tested (-MasterKeyFile was used)' }
    else { Record 'keyring_under_virtual_account' 'works -- the daemon opened a master key from Credential Manager' }
} else {
    Record 'keyring_under_virtual_account' 'NO master key in the log; see the log tail below'
}

# The Docker question -- the founder checkpoint.
$docker = ''
foreach ($m in [regex]::Matches($log, 'docker_probe="?([^\s"]+)"?')) { $docker = $m.Groups[1].Value }
Record 'docker_from_service_account' $docker
$dockerDetail = ''
foreach ($m in [regex]::Matches($log, 'docker_probe=\S+ detail=([^\r\n]*?) output=')) { $dockerDetail = $m.Groups[1].Value }
Record 'docker_detail' $dockerDetail
if (Test-Path -LiteralPath $DockerLog) {
    $dockerOut = Get-Content -LiteralPath $DockerLog -ErrorAction SilentlyContinue
    Record 'docker_probe_log' $DockerLog
    Record 'docker_probe_first_lines' (($dockerOut | Select-Object -First 6) -join ' | ')
}

# --------------------------------------------------------- 7. a second logon

Say 'a second local account'

$others = @(Get-LocalUser -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -and $_.Name -ne $identity.Name.Split('\')[-1] })
Record 'other_enabled_local_users' (($others | ForEach-Object { $_.Name }) -join ',')

if ($SecondUser) {
    # The second account must be able to read vk.exe, so it is copied
    # somewhere every account can: the founder's profile is not.
    $shared = Join-Path $env:PUBLIC 'vk-spike-6a'
    New-Item -ItemType Directory -Path $shared -Force | Out-Null
    Copy-Item -LiteralPath $VkBinary -Destination (Join-Path $shared 'vk.exe') -Force
    $out = Join-Path $shared 'second-user.txt'
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    $cmd = Join-Path $shared 'probe.cmd'
    @(
        '@echo off',
        'set VK_ENDPOINT=\\.\pipe\vk',
        ('"' + (Join-Path $shared 'vk.exe') + '" status > "' + $out + '" 2>&1'),
        ('echo exit=%ERRORLEVEL% >> "' + $out + '"')
    ) | Set-Content -LiteralPath $cmd -Encoding ascii
    Write-Host "runas will now ask for $SecondUser's password." -ForegroundColor Yellow
    & runas.exe "/user:$SecondUser" ('cmd.exe /c "' + $cmd + '"') | Out-Null
    Start-Sleep -Seconds 5
    if (Test-Path -LiteralPath $out) {
        $second = (Get-Content -Raw -LiteralPath $out).Trim()
        Record 'second_user_result' $second
        if ($second -match 'denied|refus|os error 5') {
            Record 'second_user_refused' 'yes -- the DACL held'
        } else {
            Record 'second_user_refused' 'NO -- that account reached the endpoint; the DACL did not hold'
        }
    } else {
        Record 'second_user_result' 'runas produced nothing (wrong password, or the account cannot log on)'
    }
    Remove-Item -LiteralPath $shared -Recurse -Force -ErrorAction SilentlyContinue
} elseif ($others.Count -gt 0) {
    Record 'second_user_result' 'not attempted'
    Write-Host ''
    Write-Host 'There is another enabled local account. To finish this check, re-run with:' -ForegroundColor Yellow
    Write-Host ("    .\scripts\spike-6a.ps1 -ServiceBinary {0} -SecondUser {1}" -f $ServiceBinary, $others[0].Name)
    Write-Host 'Expect: "Access is denied. (os error 5)" -- that is the DACL refusing a second logon.'
} else {
    Record 'second_user_result' 'no second local account on this machine'
    Write-Host ''
    Write-Host 'No second local account exists. To finish this check:' -ForegroundColor Yellow
    Write-Host '    net user vk-test <a password> /add'
    Write-Host ("    .\scripts\spike-6a.ps1 -ServiceBinary {0} -SecondUser vk-test" -f $ServiceBinary)
    Write-Host '    net user vk-test /delete'
    Write-Host 'Expect: "Access is denied. (os error 5)" -- that is the DACL refusing a second logon.'
}

# --------------------------------------------------------------- 8. uninstall

if ($KeepInstalled) {
    Say 'leaving the service installed (-KeepInstalled)'
    Record 'uninstall' 'skipped (-KeepInstalled)'
} else {
    Say 'uninstall'
    $uninstall = Try-Run $ServiceBinary @('uninstall')
    Write-Host $uninstall.Out
    Record 'uninstall' (Verdict $uninstall)
    $gone = -not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
    Record 'service_gone' $gone
}

Record 'state_dir_left_behind' $StateDir

# ----------------------------------------------------------------- summary

Print-Summary
