<#
.SYNOPSIS
    Spike 6a -- vkd as a Windows service under the NT SERVICE\vkd virtual
    account, with a named-pipe DACL that admits the service and the
    interactive user only.

.DESCRIPTION
    Everything in Task 6 that needs an elevated prompt, in one run. It builds
    nothing: build first, then point it at the binaries.

        $env:CARGO_TARGET_DIR = "$env:USERPROFILE\.cargo-target\verticalai-sp1"
        cargo build --release

    That is where -ServiceBinary defaults to. Building without
    CARGO_TARGET_DIR would put the binaries inside the OneDrive-synced
    repository, and a service must not be started from a file OneDrive (or the
    founder's own account) can replace -- `vkd-service install` refuses such a
    path outright.

    What it does, in order:
      1.  checks it is elevated, that the three binaries exist, that no vkd
          service is already installed, and that nothing is holding the pipe
          or the pages' port;
      2.  copies vk.exe, vkd.exe and vkd-service.exe to
          %ProgramFiles%\VerticalAI (admin-owned, because this shell is
          elevated) and installs the service from there, with --probe-docker;
      3.  starts it and waits for `vk status` to answer -- with nothing set
          in the environment, because the service binds the interactive
          user's own endpoint;
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
      8.  uninstalls and removes what it copied -- in a `finally`, so a
          Ctrl-C or an error in the middle still cleans up.

    Then it prints a summary block. Paste that block back.

.PARAMETER ServiceBinary
    The vkd-service.exe to install. Defaults to
    %USERPROFILE%\.cargo-target\verticalai-sp1\release\vkd-service.exe.

.PARAMETER VkBinary
    The vk.exe to drive it with. Defaults to vk.exe beside -ServiceBinary.

.PARAMETER VkdBinary
    The vkd.exe to ship beside them. Defaults to vkd.exe beside
    -ServiceBinary. Not used by the service (vkd-service hosts the daemon
    itself), but the founder will want it in the same place afterwards.

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

.PARAMETER Overwrite
    Replace binaries already staged in %ProgramFiles%\VerticalAI. Without it a
    stale one stops the run, because measuring a previous build and calling the
    result this one's is the worst answer this script could give.

.PARAMETER KeepInstalled
    Leave the service installed, running, and the binaries in place, to poke
    at. `vkd-service uninstall` (elevated) removes it afterwards. A run whose
    *install* failed still has its staged binaries removed.

.EXAMPLE
    # From an elevated PowerShell:
    .\scripts\spike-6a.ps1

.NOTES
    This creates %ProgramData%\VerticalAI\vk (a store of its own, not the
    founder's, with a DACL of its own) and, on first start, a Credential
    Manager entry belonging to NT SERVICE\vkd. Neither is deleted at the end:
    the summary says where they are.
#>
[CmdletBinding()]
param(
    [string]$ServiceBinary,
    [string]$VkBinary,
    [string]$VkdBinary,
    [string]$UserSid,
    [string]$SecondUser,
    [string]$MasterKeyFile,
    [switch]$Overwrite,
    [switch]$KeepInstalled
)

$ErrorActionPreference = 'Continue'

$ServiceName = 'vkd'
# The endpoint is the interactive user's own, derived in preflight from
# -UserSid: the service binds the name that user's `vk` already dials, so
# nothing here sets $env:VK_ENDPOINT.
$PipeLeaf    = $null
$Endpoint    = $null
$StateDir    = Join-Path $env:ProgramData 'VerticalAI\vk'
$DaemonLog   = Join-Path $StateDir 'vkd.log'
$DockerLog   = Join-Path $StateDir 'docker-probe.log'
$WebPort     = 7734
$BuildDir    = Join-Path $env:USERPROFILE '.cargo-target\verticalai-sp1\release'
$InstallDir  = Join-Path $env:ProgramFiles 'VerticalAI'

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

# The account name behind that SID, and so the pipe. `vkd-service install`
# resolves the same SID the same way (LookupAccountSid) and the daemon derives
# the same name from it, so this is the endpoint the founder's own `vk` will
# dial with nothing configured.
try {
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
    $UserAccount = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    $UserAccount = $UserAccount.Substring($UserAccount.LastIndexOf('\') + 1)
} catch {
    Write-Host "cannot resolve $UserSid to an account name: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
$PipeLeaf = "vk-$UserAccount"
$Endpoint = "\\.\pipe\$PipeLeaf"
Record 'user_account' $UserAccount
Record 'endpoint_expected' $Endpoint

if (-not $ServiceBinary) { $ServiceBinary = Join-Path $BuildDir 'vkd-service.exe' }
if (-not (Test-Path -LiteralPath $ServiceBinary)) {
    Write-Host "no such file: $ServiceBinary" -ForegroundColor Red
    Write-Host 'Build first, with a target directory outside the synced repository:' -ForegroundColor Yellow
    Write-Host ('    $env:CARGO_TARGET_DIR = "{0}"' -f (Join-Path $env:USERPROFILE '.cargo-target\verticalai-sp1'))
    Write-Host '    cargo build --release'
    Write-Host ("Binaries then land in {0}" -f $BuildDir)
    exit 1
}
$ServiceBinary = (Resolve-Path -LiteralPath $ServiceBinary).Path
$SourceDir = Split-Path -Parent $ServiceBinary
if (-not $VkBinary)  { $VkBinary  = Join-Path $SourceDir 'vk.exe' }
if (-not $VkdBinary) { $VkdBinary = Join-Path $SourceDir 'vkd.exe' }
foreach ($b in @($VkBinary, $VkdBinary)) {
    if (-not (Test-Path -LiteralPath $b)) {
        Write-Host "no such file: $b (pass -VkBinary / -VkdBinary)" -ForegroundColor Red; exit 1
    }
}
$VkBinary  = (Resolve-Path -LiteralPath $VkBinary).Path
$VkdBinary = (Resolve-Path -LiteralPath $VkdBinary).Path
Record 'binary_source' $SourceDir

# Never remove a service somebody else installed: it may carry `sc config`
# the founder applied, and deleting it would take that with it.
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host ''
    Write-Host ("A service called $ServiceName is already installed (state: $($existing.Status)).") -ForegroundColor Red
    Write-Host 'This script will not remove a service it did not create. Look at it first:'
    Write-Host "    sc.exe qc $ServiceName"
    Write-Host 'and then, if it is a leftover of an earlier run:'
    Write-Host ("    & '{0}' uninstall" -f $ServiceBinary)
    exit 1
}
if (Pipe-Exists $PipeLeaf) {
    # Now that the service binds this user's own endpoint, the likeliest thing
    # holding it is the founder's own `vk boot` daemon -- and the service will
    # refuse to start rather than join somebody else's pipe.
    Warn "$Endpoint is already served, and that is where the service will bind too."
    Warn 'Its start will be refused, naming the holder. Stop your own vkd first:'
    Warn '    tasklist /FI "IMAGENAME eq vkd.exe"   then   taskkill /F /PID <pid>'
    Record 'preflight_pipe_held' $Endpoint
}
$portHeld = Get-NetTCPConnection -LocalPort $WebPort -State Listen -ErrorAction SilentlyContinue
if ($portHeld) {
    Warn "port $WebPort is already listening (your own vkd?). The service will refuse to start until it is free."
}
Record 'preflight' 'ok'

# Everything from here is undone in the `finally` at the bottom.
$Installed    = $false
$Failed       = $false
$CopiedFiles  = @()
$CreatedDirs  = @()
$SharedDir    = $null
$InstalledSvc = $null

try {

    # ------------------------------------------------- 2. stage, then install

    Say 'stage the binaries somewhere only administrators may write'

    # The ImagePath runs as NT SERVICE\vkd at every start. A binary under a
    # user profile (or inside OneDrive) is one the founder's own account can
    # replace, which would make the account separation nominal -- so the
    # binaries are copied here, into a directory this elevated shell owns and
    # ordinary accounts may only read and execute. `vkd-service install`
    # refuses the other kind outright.
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        $CreatedDirs += $InstallDir
    }
    # A binary already there is *not* quietly reused: this is the run that
    # produces the attestation, and measuring a previous build while
    # attributing the result to this one would be the worst kind of wrong
    # answer. -Overwrite says "yes, replace it" (and then the run owns it, so
    # the cleanup removes it).
    $stale = @()
    foreach ($src in @($ServiceBinary, $VkBinary, $VkdBinary)) {
        $dst = Join-Path $InstallDir (Split-Path $src -Leaf)
        if ((Test-Path -LiteralPath $dst) -and -not $Overwrite) { $stale += $dst }
    }
    if ($stale.Count -gt 0) {
        Write-Host ''
        Write-Host 'These are already in the staging directory and may be an older build:' -ForegroundColor Red
        $stale | ForEach-Object { Write-Host "    $_" }
        Write-Host 'Re-run with -Overwrite to replace them, or remove them yourself:'
        Write-Host ("    Remove-Item -LiteralPath '{0}' -Recurse -Force" -f $InstallDir)
        Record 'stage' ('refused: already present, and -Overwrite was not given: ' + ($stale -join ', '))
        $Failed = $true
        return
    }
    Record 'stage' 'ok'
    foreach ($src in @($ServiceBinary, $VkBinary, $VkdBinary)) {
        $dst = Join-Path $InstallDir (Split-Path $src -Leaf)
        Copy-Item -LiteralPath $src -Destination $dst -Force
        $CopiedFiles += $dst
    }
    $SvcExe = Join-Path $InstallDir 'vkd-service.exe'
    $VkExe  = Join-Path $InstallDir 'vk.exe'
    Record 'install_dir' $InstallDir

    Say 'install'

    $installArgs = @('install', '--user-sid', $UserSid, '--binary', $SvcExe, '--probe-docker')
    if ($MasterKeyFile) { $installArgs += @('--', '--master-key-file', $MasterKeyFile) }
    $install = Try-Run $SvcExe $installArgs
    Write-Host $install.Out
    Record 'install' (Verdict $install)
    if ($install.Code -ne 0) {
        Record 'install_error' $install.Err
        Write-Host $install.Err -ForegroundColor Red
        $Failed = $true
    } else {
        $Installed = $true
        $InstalledSvc = $SvcExe
    }

    # Everything install printed is key=value; keep the ones the summary wants.
    $installed = @{}
    foreach ($line in ($install.Out -split "`r?`n")) {
        if ($line -match '^([a-z_]+)=(.*)$') { $installed[$Matches[1]] = $Matches[2] }
    }
    Record 'service_sid_derived' $installed['service_sid']
    Record 'endpoint_installed' $installed['endpoint']
    if ($installed['endpoint']) {
        if ($installed['endpoint'] -eq $Endpoint) { Record 'endpoint_agrees' 'yes' }
        else { Record 'endpoint_agrees' 'NO -- install resolved a different pipe than this script did' }
    }
    Record 'pipe_dacl_predicted' $installed['pipe_dacl']
    Record 'image_path' $installed['image_path']

    # The derivation checked against Windows itself. `sc showsid` needs no
    # elevation and no installed service -- it is the same SHA-1 of the
    # uppercased name that pipe_acl computes.
    $showsid = Try-Run 'sc.exe' @('showsid', $ServiceName)
    $scSid = ''
    if ($showsid.Out -match '(S-1-5-80-[0-9\-]+)') { $scSid = $Matches[1] }
    Record 'service_sid_sc_showsid' $scSid
    if ($scSid -and $installed['service_sid']) {
        if ($scSid -eq $installed['service_sid']) { Record 'service_sid_agrees' 'yes' }
        else { Record 'service_sid_agrees' 'NO -- the derivation and sc.exe disagree' }
    }

    if (-not $Installed) {
        Warn 'install failed; nothing further to do'
        return
    }

    # ------------------------------------------------------------- 3. start

    Say 'start'

    $start = Try-Run $SvcExe @('start')
    Write-Host $start.Out
    Record 'start' (Verdict $start)
    if ($start.Code -ne 0) { Record 'start_error' $start.Err }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) { Record 'service_state' $svc.Status }

    # The service reports running as soon as the daemon has not fallen over;
    # the pipe appears a moment later, and arches come up behind it. Nothing
    # is set in the environment, on purpose: the whole point of the per-user
    # endpoint is that `vk` finds the node with no configuration at all.
    Remove-Item Env:VK_ENDPOINT -ErrorAction SilentlyContinue
    $answered = $false
    for ($i = 0; $i -lt 30; $i++) {
        $probe = Try-Run $VkExe @('status') 20
        if ($probe.Code -eq 0) { $answered = $true; break }
        Start-Sleep -Milliseconds 500
    }
    Record 'pipe_answered' $answered

    # -------------------------------------- 4. the shell, as the interactive user

    Say 'vk status / vk ls /arches / vk ledger verify'

    $status = Try-Run $VkExe @('status')
    Write-Host $status.Out
    Record 'vk_status' (Verdict $status)
    Record 'vk_status_first_line' (($status.Out -split "`r?`n")[0])

    $ls = Try-Run $VkExe @('ls', '/arches')
    Record 'vk_ls_arches' (Verdict $ls)

    $verify = Try-Run $VkExe @('ledger', 'verify')
    Write-Host $verify.Out
    Record 'vk_ledger_verify' (Verdict $verify)

    # ------------------------------------------------------------ 5. restart

    Say 'restart, then verify the chain again'

    $stop = Try-Run $SvcExe @('stop')
    Record 'restart_stop' (Verdict $stop)
    $start2 = Try-Run $SvcExe @('start')
    Record 'restart_start' (Verdict $start2)

    $answered2 = $false
    for ($i = 0; $i -lt 30; $i++) {
        $probe = Try-Run $VkExe @('status') 20
        if ($probe.Code -eq 0) { $answered2 = $true; break }
        Start-Sleep -Milliseconds 500
    }
    Record 'pipe_answered_after_restart' $answered2

    $verify2 = Try-Run $VkExe @('ledger', 'verify')
    Write-Host $verify2.Out
    Record 'vk_ledger_verify_after_restart' (Verdict $verify2)

    $status2 = Try-Run $VkExe @('status')
    Record 'vk_status_after_restart' (Verdict $status2)

    # --------------------------------------- 6. the DACL, the keyring, Docker

    Say 'what the daemon logged'

    # The Docker probe now runs after the service reports Running, on a thread
    # of its own, so give it a moment to land in the log.
    Start-Sleep -Seconds 3

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

    # The client identity check, from this side of the pipe. `vk` reads the
    # pipe object's OWNER off its own connected handle and refuses anything
    # that is neither this account nor NT SERVICE\vkd; the same read is done
    # here so the summary records that it *answered* against a service-owned
    # pipe. (The server process's token is not readable by an ordinary user --
    # that is why the check reads the object and not the process.)
    $pipeOwner = ''
    try {
        $client = New-Object System.IO.Pipes.NamedPipeClientStream(
            '.', $PipeLeaf, [System.IO.Pipes.PipeDirection]::InOut)
        $client.Connect(5000)
        $pipeOwner = $client.GetAccessControl().GetOwner(
            [System.Security.Principal.SecurityIdentifier]).Value
        $client.Dispose()
    } catch {
        $pipeOwner = "could not be read: $($_.Exception.Message)"
    }
    Record 'pipe_owner_from_client' $pipeOwner
    if ($installed['service_sid'] -and $pipeOwner -eq $installed['service_sid']) {
        Record 'pipe_owner_is_the_service' 'yes -- the owner read answered, and it is NT SERVICE\vkd'
    } elseif ($pipeOwner -like 'S-1-*') {
        Record 'pipe_owner_is_the_service' "NO -- the owner read answered, but it is $pipeOwner"
    } else {
        Record 'pipe_owner_is_the_service' 'the owner could not be read; vk would take the residual branch'
    }

    # The state directory's own ACL, which the daemon now sets when it makes it.
    $acl = Try-Run 'icacls.exe' @($StateDir)
    Record 'state_dir_acl' $acl.Out

    # The keyring question: the daemon logs the master key's fingerprint at
    # boot, and it could only have one if Credential Manager worked for the
    # virtual account (or if -MasterKeyFile was used).
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

    # ----------------------------------------------------- 7. a second logon

    Say 'a second local account'

    $others = @(Get-LocalUser -ErrorAction SilentlyContinue |
                Where-Object { $_.Enabled -and $_.Name -ne $identity.Name.Split('\')[-1] })
    Record 'other_enabled_local_users' (($others | ForEach-Object { $_.Name }) -join ',')

    if ($SecondUser) {
        # The second account can read and run %ProgramFiles%\VerticalAI\vk.exe
        # (Program Files grants Users read and execute), but it needs
        # somewhere writable for the answer.
        $SharedDir = Join-Path $env:PUBLIC 'vk-spike-6a'
        New-Item -ItemType Directory -Path $SharedDir -Force | Out-Null
        $out = Join-Path $SharedDir 'second-user.txt'
        Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        $cmd = Join-Path $SharedDir 'probe.cmd'
        @(
            '@echo off',
            # Not that account's own endpoint -- the founder's, named
            # explicitly, because that is the connection that must be refused.
            ('set VK_ENDPOINT=' + $Endpoint),
            ('"' + $VkExe + '" status > "' + $out + '" 2>&1'),
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
    } elseif ($others.Count -gt 0) {
        Record 'second_user_result' 'not attempted'
        Write-Host ''
        Write-Host 'There is another enabled local account. To finish this check, re-run with:' -ForegroundColor Yellow
        Write-Host ("    .\scripts\spike-6a.ps1 -SecondUser {0}" -f $others[0].Name)
        Write-Host 'Expect: "Access is denied. (os error 5)" -- that is the DACL refusing a second logon.'
    } else {
        Record 'second_user_result' 'no second local account on this machine'
        Write-Host ''
        Write-Host 'No second local account exists. To finish this check:' -ForegroundColor Yellow
        Write-Host '    net user vk-test <a password> /add'
        Write-Host '    .\scripts\spike-6a.ps1 -SecondUser vk-test'
        Write-Host '    net user vk-test /delete'
        Write-Host 'Expect: "Access is denied. (os error 5)" -- that is the DACL refusing a second logon.'
    }

} finally {

    # ------------------------------------------------- 8. uninstall and tidy

    if ($SharedDir -and (Test-Path -LiteralPath $SharedDir)) {
        Remove-Item -LiteralPath $SharedDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($KeepInstalled -and $Installed) {
        Say 'leaving the service installed (-KeepInstalled)'
        Record 'uninstall' 'skipped (-KeepInstalled)'
        Record 'binaries_left' ($CopiedFiles -join ', ')
        Write-Host ''
        Write-Host 'To remove it later, from an elevated PowerShell:' -ForegroundColor Yellow
        Write-Host ("    & '{0}' uninstall" -f $InstalledSvc)
        Write-Host ("    Remove-Item -LiteralPath '{0}' -Recurse -Force" -f $InstallDir)
    } elseif ($Installed) {
        Say 'uninstall'
        $uninstall = Try-Run $InstalledSvc @('uninstall')
        Write-Host $uninstall.Out
        Record 'uninstall' (Verdict $uninstall)
        $gone = -not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
        Record 'service_gone' $gone
    }

    # Only what this run put there, and only while something still needs it:
    # -KeepInstalled keeps the binaries for the service it left running, but a
    # run whose install failed has nothing to keep them for.
    if (-not ($KeepInstalled -and $Installed)) {
        foreach ($f in $CopiedFiles) {
            Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
        }
        foreach ($d in $CreatedDirs) {
            if ((Test-Path -LiteralPath $d) -and -not (Get-ChildItem -LiteralPath $d -Force)) {
                Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue
            }
        }
        Record 'binaries_removed' ($CopiedFiles -join ', ')
    }

    # Never the store: deleting a ledger is the worst thing this script could do.
    Record 'state_dir_left_behind' $StateDir

    Print-Summary
    if ($Failed) { exit 1 }
}
