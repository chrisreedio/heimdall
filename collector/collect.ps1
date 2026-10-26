<#
.SYNOPSIS
  heimdall-collect for Windows: report installed programs and update status
  to Heimdall (snapshot format v3).

.DESCRIPTION
  -Print    write the snapshot (JSON) to stdout, to review or for `heimdall import`
  -Push     send it to $env:HEIMDALL_URL using the token in $env:HEIMDALL_TOKEN_FILE
            (default C:\ProgramData\Heimdall\token)
  -Push -AfterChanges
            first wait until no install, removal or Windows Update install
            has been logged for 60 seconds, so a burst of them is one report
            (the "Heimdall collector (changes)" task runs this)
  -Version  print the collector version

  Read-only and unprivileged (install-windows.ps1 runs it as LocalService):
  it reads the Uninstall registry keys, OS details, pending Windows updates,
  reboot flags, the state of its own two scheduled tasks and (with
  -AfterChanges) the times of recent install events in the Application and
  System logs; it never changes the system, makes one HTTPS request per
  report in -Push mode and reads only the status code and the hub's version
  header from the response. Works on Windows PowerShell 5.1 and PowerShell 7.

.NOTES
  SPDX-License-Identifier: AGPL-3.0-or-later
#>
[CmdletBinding(DefaultParameterSetName = 'Print')]
param(
    [Parameter(ParameterSetName = 'Print')][switch]$Print,
    [Parameter(ParameterSetName = 'Push')][switch]$Push,
    [Parameter(ParameterSetName = 'Push')][switch]$AfterChanges,
    [Parameter(ParameterSetName = 'Version')][switch]$Version
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:CollectorVersion = '0.4.34'
$script:Format = 'heimdall.snapshot/v3'

# Drop control characters, quotes and backslashes; cap the length. The hub
# validates every field again, so this only keeps a weird value from
# getting the whole snapshot rejected.
function Get-CleanText([string]$s, [int]$max = 200) {
    if ($null -eq $s) { return '' }
    $s = ($s -replace '[\x00-\x1f\x7f"\\<>]', '').Trim()
    if ($s.Length -gt $max) { $s = $s.Substring(0, $max).Trim() }
    return $s
}

$script:NamePattern = '^[\p{L}\p{N}][\p{L}\p{N} ._+()&,''#@/:-]{0,199}$'
$script:VersionPattern = '^[A-Za-z0-9][A-Za-z0-9._+~:^-]{0,127}$'

# Turns raw inventory (from Get-WindowsInventory, or a test fixture) into a
# snapshot document. Pure: no system access, so it's testable anywhere.
function ConvertTo-HeimdallSnapshot($inv) {
    $unavailable = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $packages = @(foreach ($p in @($inv.Programs)) {
        $name = Get-CleanText $p.Name
        $ver = Get-CleanText $p.Version 128
        $key = "$name|$ver"
        if ($name -match $script:NamePattern -and $ver -match $script:VersionPattern -and -not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            [ordered]@{ name = $name; version = $ver; arch = ''; source_name = ''; source_version = '' }
        }
    })
    if ($packages.Count -eq 0) { $unavailable.Add('packages') }

    $updates = @()
    if ($null -eq $inv.Updates) {
        $unavailable.Add('updates')
    } else {
        $updates = @(foreach ($u in @($inv.Updates)) {
            if ($u.KB -match '^\d{4,8}$') {
                [ordered]@{ name = "KB$($u.KB)"; arch = ''; version = "KB$($u.KB)"; security = [bool]$u.Security }
            }
        })
    }

    $reboot = $null
    if ($null -eq $inv.RebootRequired) { $unavailable.Add('reboot_required') } else { $reboot = [bool]$inv.RebootRequired }
    $uptime = 0
    if ($null -eq $inv.UptimeSeconds) { $unavailable.Add('uptime') } else { $uptime = [int64]$inv.UptimeSeconds }
    $sha = Get-CleanText $inv.CollectorSHA256 64
    if ($sha -notmatch '^[0-9a-f]{64}$') { $sha = ''; $unavailable.Add('collector_sha256') }
    $unavailable.Add('containers')

    $idLike = ''
    if ($inv.IsServer) { $idLike = 'windows-server' }
    $arch = switch -Regex ([string]$inv.Architecture) { 'ARM' { 'aarch64'; break } '64' { 'x86_64'; break } default { 'x86' } }

    return [ordered]@{
        format          = $script:Format
        collector       = [ordered]@{ version = $script:CollectorVersion; sha256 = $sha }
        collected_at    = $inv.CollectedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        os              = [ordered]@{
            id = 'windows'; id_like = $idLike; version_id = (Get-CleanText $inv.OSVersion 32)
            version_codename = ''; pretty_name = (Get-CleanText $inv.OSCaption 128)
        }
        kernel          = [ordered]@{ release = (Get-CleanText $inv.OSVersion 128); arch = $arch }
        uptime_seconds  = $uptime
        reboot_required = $reboot
        package_manager = 'windows'
        packages        = $packages
        updates         = $updates
        unavailable     = @($unavailable)
        sites           = @()
        containers      = @()
        lockfiles       = @()
    }
}

function ConvertTo-HeimdallJson($snapshot) {
    # -Depth matters: Windows PowerShell's default (2) would flatten objects.
    return ($snapshot | ConvertTo-Json -Depth 8 -Compress)
}

# --- When it reports -------------------------------------------------------
# install-windows.ps1 registers two tasks from Get-HeimdallTaskXml: hourly
# and after boot, and after software changes. They live here, next to the
# code that reports their state, so both always agree.
$script:TaskName = 'Heimdall collector'
$script:ChangesTaskName = 'Heimdall collector (changes)'

# The events that mean installed software or updates changed: Windows
# Installer installs and removals (11707/11724 succeeded, 1033/1034
# installed/removed with a status) and Windows Update installs. EXE
# installers that don't use Windows Installer log nothing reliable; the
# hourly report covers those.
$script:ChangeEvents = @(
    @{ Log = 'Application'; Provider = 'MsiInstaller'; Ids = @(11707, 11724, 1033, 1034) },
    @{ Log = 'System'; Provider = 'Microsoft-Windows-WindowsUpdateClient'; Ids = @(19) }
)

# An event-log query (XPath QueryList) for those events, optionally only the
# ones logged in the last $WithinMs milliseconds.
function Get-HeimdallEventQuery([int64]$WithinMs = 0) {
    $selects = foreach ($e in $script:ChangeEvents) {
        $ids = (@($e.Ids) | ForEach-Object { "EventID=$_" }) -join ' or '
        $time = ''
        if ($WithinMs -gt 0) { $time = " and TimeCreated[timediff(@SystemTime) &lt;= $WithinMs]" }
        "<Select Path=`"$($e.Log)`">*[System[Provider[@Name='$($e.Provider)'] and ($ids)$time]]</Select>"
    }
    return '<QueryList><Query Id="0">' + ($selects -join '') + '</Query></QueryList>'
}

# Task Scheduler XML (schema 1.2, Windows 7 / Server 2008 R2 and later) for
# one of the two tasks. Both run collect.ps1 as LocalService (UserId
# S-1-5-19, which the Task Scheduler runs as a service account; the schema
# has no LogonType for it) with the least privilege, on battery too, never two at once; the task's security
# descriptor lets LocalService read it, so the collector can report its state.
# Pure, so it's tested on Linux too.
function Get-HeimdallTaskXml {
    param(
        [Parameter(Mandatory)][ValidateSet('schedule', 'changes')][string]$Kind,
        [Parameter(Mandatory)][string]$PowerShell,
        [Parameter(Mandatory)][string]$Script,
        [datetime]$Start = (Get-Date).Date
    )
    $x = { param($s) [Security.SecurityElement]::Escape([string]$s) }
    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Script`" -Push"
    if ($Kind -eq 'schedule') {
        $description = 'Reports installed programs and updates to Heimdall: hourly, and 3 minutes after boot.'
        $limit = 'PT10M'
        # Repetition without a Duration repeats indefinitely.
        $triggers = @"
    <TimeTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>$($Start.ToString('yyyy-MM-ddTHH:mm:ss'))</StartBoundary>
      <Enabled>true</Enabled>
      <RandomDelay>PT15M</RandomDelay>
    </TimeTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT3M</Delay>
    </BootTrigger>
"@
    } else {
        $description = 'Reports to Heimdall about a minute after programs or Windows updates are installed or removed.'
        $arguments += ' -AfterChanges'
        $limit = 'PT1H' # up to 3 reports, each after waiting up to 10 minutes for installs to settle
        $triggers = @"
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>$(& $x (Get-HeimdallEventQuery))</Subscription>
    </EventTrigger>
"@
    }
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Heimdall</Author>
    <Description>$(& $x $description)</Description>
    <SecurityDescriptor>D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;LS)</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
$triggers  </Triggers>
  <Principals>
    <Principal id="LocalService">
      <UserId>S-1-5-19</UserId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>$limit</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalService">
    <Exec>
      <Command>$(& $x $PowerShell)</Command>
      <Arguments>$(& $x $arguments)</Arguments>
    </Exec>
  </Actions>
</Task>
"@
}

# One task's entry in the X-Heimdall-Triggers header: "<enabled>,<state>".
#   enabled  enabled | disabled, or missing (no such task) | unknown (couldn't ask)
#   state    the Task Scheduler's: ready | running | queued | disabled | unknown,
#            or no-triggers (enabled, but every trigger removed or disabled),
#            none (missing)
# A state with "unknown" in it never alerts on the hub.
function Format-HeimdallTaskState([string]$Found, [bool]$Enabled = $false, [int]$State = 0, [int]$EnabledTriggers = 0) {
    if ($Found -eq 'missing') { return 'missing,none' }
    if ($Found -ne 'found') { return 'unknown,unknown' }
    $en = 'disabled'
    if ($Enabled) { $en = 'enabled' }
    $st = switch ($State) { 1 { 'disabled' } 2 { 'queued' } 3 { 'ready' } 4 { 'running' } default { 'unknown' } }
    if ($Enabled -and $EnabledTriggers -eq 0 -and $st -ne 'unknown') { $st = 'no-triggers' }
    return "$en,$st"
}

function Get-HeimdallHResult($ex) {
    for (; $null -ne $ex; $ex = $ex.InnerException) {
        if ($ex.HResult -in -2147024894, -2147024893) { return $ex.HResult } # file / path not found
    }
    return 0
}

# Asks the Task Scheduler (COM, read-only) about one of the collector's tasks.
function Get-HeimdallTaskState([string]$Name) {
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $task = $svc.GetFolder('\').GetTask($Name)
    } catch {
        if ((Get-HeimdallHResult $_.Exception) -ne 0) { return (Format-HeimdallTaskState 'missing') }
        return (Format-HeimdallTaskState 'unknown') # e.g. access denied
    }
    try {
        $on = @(foreach ($t in $task.Definition.Triggers) { if ($t.Enabled) { $t } }).Count
        return (Format-HeimdallTaskState 'found' ([bool]$task.Enabled) ([int]$task.State) $on)
    } catch { return (Format-HeimdallTaskState 'unknown') }
}

# A hash of the machine ID (MachineGuid), never the ID itself, sent as
# X-Heimdall-Machine so the hub enrolls a server once. '' if unreadable.
function Get-HeimdallMachineHash {
    try {
        $guid = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    } catch { return '' }
    $guid = $guid.Trim().ToLowerInvariant()
    if ($guid -notmatch '^[0-9a-f-]{32,36}$') { return '' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes("heimdall-machine:$guid"))
    } finally { $sha.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

function Get-HeimdallTriggers {
    return "task=$(Get-HeimdallTaskState $script:TaskName); changes=$(Get-HeimdallTaskState $script:ChangesTaskName)"
}

# Waits until no change event has been logged for $Quiet seconds (at most
# $Max seconds in all). $Newest returns the time of the newest change event
# in the last N seconds, or $null; it throws if the logs can't be read.
function Wait-HeimdallQuiet([scriptblock]$Newest, [scriptblock]$Sleep, [scriptblock]$Now, [int]$Quiet = 60, [int]$Max = 600) {
    $waited = 0
    while ($true) {
        $last = & $Newest $Quiet
        if ($null -eq $last) { return }
        $left = [int][Math]::Ceiling($Quiet - ((& $Now) - $last).TotalSeconds)
        if ($left -le 0 -or $waited + $left -gt $Max) { return }
        & $Sleep $left
        $waited += $left
    }
}

function Get-HeimdallNewestChange([int]$WithinSeconds) {
    try {
        $events = @(Get-WinEvent -FilterXml ([xml](Get-HeimdallEventQuery ([int64]$WithinSeconds * 1000))) -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return $null }
        throw
    }
    return ($events | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
}

# Is release $Hub (e.g. "v0.4.14") newer than collector version $Mine?
function Test-HeimdallNewer([string]$Hub, [string]$Mine) {
    if ($Hub -notmatch '^v(\d+)(\.(\d+))?(\.(\d+))?$') { return $false }
    $h = @([int]$matches[1], [int]('0' + $matches[3]), [int]('0' + $matches[5]))
    $m = @(($Mine -split '\.') + @('0', '0', '0') | Select-Object -First 3 | ForEach-Object { [int]('0' + ($_ -replace '\D', '')) })
    for ($i = 0; $i -lt 3; $i++) {
        if ($h[$i] -ne $m[$i]) { return ($h[$i] -gt $m[$i]) }
    }
    return $false
}

# Reads the real system. Each source that fails is reported as unavailable
# (null) rather than failing the whole run.
function Get-WindowsInventory {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $programs = foreach ($k in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object {
            $_.PSObject.Properties['DisplayName'] -and $_.PSObject.Properties['DisplayVersion'] -and
            -not ($_.PSObject.Properties['SystemComponent'] -and $_.SystemComponent -eq 1)
        } | ForEach-Object { @{ Name = [string]$_.DisplayName; Version = [string]$_.DisplayVersion } }
    }

    $updates = $null
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $updates = @(foreach ($u in $result.Updates) {
            $kb = @($u.KBArticleIDs) | Select-Object -First 1
            $security = @($u.Categories | Where-Object { $_.Name -eq 'Security Updates' }).Count -gt 0
            @{ KB = [string]$kb; Security = $security }
        })
    } catch { $updates = $null } # e.g. no rights to the update agent

    $reboot = $null
    try {
        $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    } catch { $reboot = $null }

    $sha = ''
    if ($PSCommandPath) { $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant() }

    return @{
        CollectedAt     = Get-Date
        OSVersion       = [string]$os.Version            # e.g. 10.0.20348
        OSCaption       = [string]$os.Caption            # e.g. Microsoft Windows Server 2022 Standard
        IsServer        = ($os.ProductType -ne 1)        # 1 = workstation
        Architecture    = [string]$os.OSArchitecture
        UptimeSeconds   = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
        RebootRequired  = $reboot
        Programs        = @($programs)
        Updates         = $updates
        CollectorSHA256 = $sha
    }
}

function Send-HeimdallSnapshot([string]$json) {
    $url = $env:HEIMDALL_URL
    $urlFile = 'C:\ProgramData\Heimdall\hub-url' # written by install-windows.ps1
    if (-not $url -and (Test-Path -LiteralPath $urlFile)) { $url = (Get-Content -LiteralPath $urlFile -Raw).Trim() }
    # Plain http only to this machine (a local proxy or tests), as on Linux.
    if (-not $url -or -not ($url.StartsWith('https://') -or $url -match '^http://(127\.0\.0\.1|localhost|\[::1\])([:/]|$)')) {
        throw 'HEIMDALL_URL must be an https:// URL'
    }
    $tokenFile = $env:HEIMDALL_TOKEN_FILE
    if (-not $tokenFile) { $tokenFile = 'C:\ProgramData\Heimdall\token' }
    $token = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
    if ($token -notmatch '^hmd_ingest_[A-Za-z0-9_-]{43}$') { throw "$tokenFile does not contain a valid ingest token" }

    # gzip the body, as collect.sh does.
    $raw = [System.Text.Encoding]::UTF8.GetBytes($json)
    $buf = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($buf, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($raw, 0, $raw.Length)
    $gz.Close()
    $body = $buf.ToArray()

    $headers = @{ Authorization = "Bearer $token"; 'Content-Encoding' = 'gzip' }
    # The machine's hostname names a host added without one (on the hub).
    $hn = ([System.Net.Dns]::GetHostName() -replace '[^A-Za-z0-9._-]', '')
    if ($hn) { $headers['X-Heimdall-Hostname'] = $hn.Substring(0, [Math]::Min($hn.Length, 253)) }
    $machine = Get-HeimdallMachineHash
    if ($machine) { $headers['X-Heimdall-Machine'] = $machine }
    # The state of this collector's own two scheduled tasks.
    $tr = (Get-HeimdallTriggers) -replace '[^a-z,=; -]', ''
    if ($tr) { $headers['X-Heimdall-Triggers'] = $tr.Substring(0, [Math]::Min($tr.Length, 240)) }

    # Windows PowerShell defaults to old TLS versions; require 1.2+.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
    # Two retries, 10 seconds apart, when the hub can't be reached or fails.
    for ($try = 0; $try -lt 3; $try++) {
        if ($try -gt 0) { Start-Sleep -Seconds 10 }
        $resp = $null
        try {
            $resp = Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($url.TrimEnd('/') + '/api/v1/ingest') `
                -ContentType 'application/json' -Headers $headers -Body $body -TimeoutSec 120 -MaximumRedirection 0
            $code = [int]$resp.StatusCode
        } catch {
            $code = 0
            if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        }
        if ($code -ne 0 -and $code -lt 500) { break }
    }
    # Only the status code and the hub's release are read; the body never is.
    switch ($code) {
        { $_ -ge 200 -and $_ -lt 300 } {
            $hub = ''
            try { $hub = [string](@($resp.Headers['X-Heimdall-Version'])[0]) } catch { $hub = '' }
            if (Test-HeimdallNewer $hub $script:CollectorVersion) {
                [Console]::Error.WriteLine("heimdall-collect: the hub runs $hub and this collector is $($script:CollectorVersion); update with: install-windows.ps1 from the $hub release, as Administrator")
            }
            return
        }
        { $_ -in 401, 403 } { throw "hub rejected the token (HTTP $code); check $tokenFile" }
        409 { throw 'hub rejected a duplicate snapshot (HTTP 409)' }
        413 { throw 'snapshot too large for the hub (HTTP 413)' }
        422 { throw "hub rejected the snapshot as invalid (HTTP 422); run -Print and check it with 'heimdall import --check'" }
        429 { throw 'rate limited by the hub (HTTP 429)' }
        0 { throw "could not reach $url" }
        default { throw "hub returned HTTP $code" }
    }
}

# -Push -AfterChanges: report once installs have settled, and again if more
# were logged while that report ran (up to 3 reports). If the logs can't be
# read, wait a minute and report once.
function Send-HeimdallAfterChanges {
    for ($i = 0; $i -lt 3; $i++) {
        try {
            Wait-HeimdallQuiet -Newest ${function:Get-HeimdallNewestChange} -Sleep { param($s) Start-Sleep -Seconds $s } -Now { Get-Date }
        } catch {
            Start-Sleep -Seconds 60
            $i = 2
        }
        $started = Get-Date
        Send-HeimdallSnapshot (ConvertTo-HeimdallJson (ConvertTo-HeimdallSnapshot (Get-WindowsInventory)))
        if ($i -ge 2) { return }
        try { $last = Get-HeimdallNewestChange ([int]((Get-Date) - $started).TotalSeconds + 2) } catch { return }
        if ($null -eq $last -or $last -lt $started) { return }
    }
}

# Dot-sourcing with HEIMDALL_COLLECT_LIBRARY=1 loads the functions only (tests).
if ($env:HEIMDALL_COLLECT_LIBRARY -eq '1') { return }

if ($Version) { $script:CollectorVersion; exit 0 }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Error 'collect.ps1 only runs on Windows; use collect.sh on Linux.'
    exit 1
}
try {
    if ($Push -and $AfterChanges) {
        Send-HeimdallAfterChanges
    } else {
        $json = ConvertTo-HeimdallJson (ConvertTo-HeimdallSnapshot (Get-WindowsInventory))
        if ($Push) { Send-HeimdallSnapshot $json } else { $json }
    }
} catch {
    Write-Error "heimdall-collect: $($_.Exception.Message)"
    exit 1
}
