<#
.SYNOPSIS
  heimdall-collect for Windows: report installed programs and update status
  to Heimdall (snapshot format v3).

.DESCRIPTION
  -Print    write the snapshot (JSON) to stdout, to review or for `heimdall import`
  -Push     send it to $env:HEIMDALL_URL using the token in $env:HEIMDALL_TOKEN_FILE
            (default C:\ProgramData\Heimdall\token)
  -Version  print the collector version

  Read-only and unprivileged (install-windows.ps1 runs it as LocalService):
  it reads the Uninstall registry keys, OS details, pending Windows updates
  and reboot flags; it never changes the system, makes one HTTPS request in
  -Push mode and ignores the response body. Works on Windows PowerShell 5.1
  and PowerShell 7.

.NOTES
  SPDX-License-Identifier: AGPL-3.0-or-later
#>
[CmdletBinding(DefaultParameterSetName = 'Print')]
param(
    [Parameter(ParameterSetName = 'Print')][switch]$Print,
    [Parameter(ParameterSetName = 'Push')][switch]$Push,
    [Parameter(ParameterSetName = 'Version')][switch]$Version
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:CollectorVersion = '0.4.11'
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
    if (-not $url -or -not $url.StartsWith('https://')) { throw 'HEIMDALL_URL must be an https:// URL' }
    $tokenFile = $env:HEIMDALL_TOKEN_FILE
    if (-not $tokenFile) { $tokenFile = 'C:\ProgramData\Heimdall\token' }
    $token = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
    if ($token -notmatch '^hmd_ingest_[A-Za-z0-9_-]{43}$') { throw "$tokenFile does not contain a valid ingest token" }

    # Windows PowerShell defaults to old TLS versions; require 1.2+.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
    try {
        # The machine's hostname names a host added without one (on the hub).
        $headers = @{ Authorization = "Bearer $token" }
        $hn = ([System.Net.Dns]::GetHostName() -replace '[^A-Za-z0-9._-]', '')
        if ($hn) { $headers['X-Heimdall-Hostname'] = $hn.Substring(0, [Math]::Min($hn.Length, 253)) }
        $resp = Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($url.TrimEnd('/') + '/api/v1/ingest') `
            -ContentType 'application/json' -Headers $headers `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 120 -MaximumRedirection 0
        $code = [int]$resp.StatusCode
    } catch {
        $code = 0
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    }
    # Only the status code matters; the body is never read.
    switch ($code) {
        { $_ -ge 200 -and $_ -lt 300 } { return }
        { $_ -in 401, 403 } { throw "hub rejected the token (HTTP $code); check $tokenFile" }
        409 { throw 'hub rejected a duplicate snapshot (HTTP 409)' }
        413 { throw 'snapshot too large for the hub (HTTP 413)' }
        422 { throw "hub rejected the snapshot as invalid (HTTP 422); run -Print and check it with 'heimdall import --check'" }
        429 { throw 'rate limited by the hub (HTTP 429)' }
        0 { throw "could not reach $url" }
        default { throw "hub returned HTTP $code" }
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
    $json = ConvertTo-HeimdallJson (ConvertTo-HeimdallSnapshot (Get-WindowsInventory))
    if ($Push) { Send-HeimdallSnapshot $json } else { $json }
} catch {
    Write-Error "heimdall-collect: $($_.Exception.Message)"
    exit 1
}
