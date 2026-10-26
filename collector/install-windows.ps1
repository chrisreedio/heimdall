<#
.SYNOPSIS
  Install the Heimdall collector on Windows (run once, as Administrator).

.DESCRIPTION
  - copies collect.ps1 to C:\Program Files\Heimdall
  - stores the ingest token in C:\ProgramData\Heimdall\token, readable only
    by LocalService (and Administrators/SYSTEM, who could read it anyway)
  - registers two scheduled tasks that run the collector as
    NT AUTHORITY\LocalService, a built-in low-privilege account:
      "Heimdall collector"            hourly (random delay of up to 15
                                      minutes) and 3 minutes after boot
      "Heimdall collector (changes)"  about a minute after programs or
                                      Windows updates are installed or removed

  Re-run it to upgrade: it replaces collect.ps1 and both tasks (including
  the daily task older versions registered) and keeps the hub URL; press
  Enter at the token prompt to keep the current token.

  With -Enroll it asks for an enrollment key instead (from `heimdall enroll
  create` or the hub's Add servers page), and the hub adds this server and
  gives it its own token. A server that already has a token keeps it.

  Download collect.ps1, SHA256SUMS and SHA256SUMS.sigstore.json from the
  same release into one folder. The installer checks SHA256SUMS' Sigstore
  signature (with a pinned cosign it fetches once into
  C:\ProgramData\Heimdall) and collect.ps1 against SHA256SUMS before
  installing. -SkipSignatureCheck checks the checksums only (not advised).

.EXAMPLE
  .\install-windows.ps1 -HubUrl https://ingest.example.com

.EXAMPLE
  .\install-windows.ps1 -HubUrl https://ingest.example.com -Enroll

.NOTES
  SPDX-License-Identifier: AGPL-3.0-or-later
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HubUrl,
    [string]$Source = (Join-Path $PSScriptRoot 'collect.ps1'),
    [string]$At = '', # ignored: older versions reported daily at this time
    [switch]$Enroll,
    [switch]$SkipSignatureCheck
)
$ErrorActionPreference = 'Stop'

# The release signature. Keep the pins the same as collect.sh, install.sh,
# install-hub.sh and cmd/heimdall/signature.go (TestSignaturePinsMatch).
$CosignVersion = 'v3.1.4'
$ReleaseSigner = '^https://github.com/realmwatch/heimdall/\.github/workflows/release\.yml@refs/tags/v'
$CosignSHA256 = @{
    'windows-amd64.exe' = 'cbe953787074611f1334cbf37dc1cf953995bb8c45398eb4fc7bb781d29c1f2a'
    'linux-amd64'       = '424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa' # for tests on Linux
}

# Get-PinnedCosign: the path of the pinned cosign, fetched into $Dir first
# if it's missing or doesn't match its hash.
function Get-PinnedCosign([string]$Dir) {
    $build = if ($IsLinux) { 'linux-amd64' } else { 'windows-amd64.exe' }
    if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
        $c = Get-Command cosign -ErrorAction SilentlyContinue
        if ($c) { return $c.Source }
        throw 'No pinned cosign for this architecture to check the release signature; install cosign, or pass -SkipSignatureCheck'
    }
    $want = $CosignSHA256[$build]
    $bin = Join-Path $Dir "cosign-$CosignVersion-$build"
    if ((Test-Path -LiteralPath $bin) -and (Get-FileHash -Algorithm SHA256 -LiteralPath $bin).Hash.ToLowerInvariant() -eq $want) { return $bin }
    Write-Host "Fetching cosign $CosignVersion (once) to check the release signature"
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $tmp = "$bin.tmp"
    $ProgressPreference = 'SilentlyContinue' # much faster downloads
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/sigstore/cosign/releases/download/$CosignVersion/cosign-$build" -OutFile $tmp
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLowerInvariant() -ne $want) {
        Remove-Item -LiteralPath $tmp -Force
        throw 'The cosign download does not match its pinned hash; not using it'
    }
    if ($IsLinux) { chmod 0755 $tmp }
    Move-Item -LiteralPath $tmp -Destination $bin -Force
    return $bin
}

# Assert-ReleaseSignature: check $Sums against its Sigstore signature
# ($Sums.sigstore.json, next to it), or throw.
function Assert-ReleaseSignature([string]$Sums, [string]$CosignDir) {
    $bundle = "$Sums.sigstore.json"
    if (-not (Test-Path -LiteralPath $bundle)) { throw "SHA256SUMS.sigstore.json not found next to SHA256SUMS; download it from the same release" }
    $cosign = Get-PinnedCosign $CosignDir
    $out = & $cosign verify-blob $Sums --bundle $bundle --certificate-identity-regexp $ReleaseSigner `
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "SHA256SUMS signature verification FAILED; not installing: $(($out | Select-Object -Last 1))" }
    Write-Host 'Sigstore signature verified'
}
if ($env:HEIMDALL_INSTALL_LIBRARY) { return } # tests: functions only
if ($At) { Write-Warning '-At is ignored: the collector now reports hourly, after boot and after software changes.' }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell (as Administrator).'
}
if (-not $HubUrl.StartsWith('https://')) { throw '-HubUrl must be https://' }

# Verify SHA256SUMS' signature, then collect.ps1 against it (both
# downloaded next to it).
$sums = Join-Path (Split-Path -Parent $Source) 'SHA256SUMS'
if (-not (Test-Path -LiteralPath $sums)) { throw "SHA256SUMS not found next to $Source; download it from the same release" }
if ($SkipSignatureCheck) {
    Write-Warning "Not checking the release's signature (-SkipSignatureCheck); only its checksums"
} else {
    Assert-ReleaseSignature $sums (Join-Path $env:ProgramData 'Heimdall')
}
$want = (Get-Content -LiteralPath $sums | Where-Object { $_ -match '\scollect\.ps1$' } | Select-Object -First 1) -replace '\s.*$', ''
$got = (Get-FileHash -Algorithm SHA256 -LiteralPath $Source).Hash.ToLowerInvariant()
if (-not $want -or $want -ne $got) { throw 'collect.ps1 does not match SHA256SUMS; not installing' }

$programDir = Join-Path $env:ProgramFiles 'Heimdall'
$dataDir = Join-Path $env:ProgramData 'Heimdall'
New-Item -ItemType Directory -Force -Path $programDir, $dataDir | Out-Null
$collector = Join-Path $programDir 'collect.ps1'
Copy-Item -LiteralPath $Source -Destination $collector -Force

function Read-Secret([string]$Prompt) {
    $secure = Read-Host -AsSecureString $Prompt
    [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)).Trim()
}

# Token: paste it; it never appears on the command line or in history. On
# an upgrade, Enter keeps the current one.
$tokenFile = Join-Path $dataDir 'token'
$current = ''
if (Test-Path -LiteralPath $tokenFile) { $current = (Get-Content -LiteralPath $tokenFile -Raw).Trim() }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
$ingest = $HubUrl.TrimEnd('/') + '/api/v1/ingest'
# Does the hub still accept this token? Only a clear "no" (401) counts.
function Test-HeimdallToken([string]$Token) {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $ingest -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 30 | Out-Null
        return $true
    } catch {
        $r = $_.Exception.PSObject.Properties['Response']
        return -not ($r -and $r.Value -and [int]$r.Value.StatusCode -eq 401)
    }
}
if ($Enroll -and $current -match '^hmd_ingest_[A-Za-z0-9_-]{43}$' -and (Test-HeimdallToken $current)) {
    Write-Host 'This server already has a token; keeping it (not enrolling it again).'
    $token = $current
} elseif ($Enroll) {
    $key = Read-Secret 'Enrollment key from `heimdall enroll create` or the Add servers page'
    if ($key -notmatch '^hmd_enroll_[A-Za-z0-9_-]{43}$') { throw 'That does not look like an enrollment key.' }
    # A hash of the machine ID (never the ID itself), so the hub enrolls
    # this server once; collect.ps1 sends the same one.
    $headers = @{ Authorization = "Bearer $key"; 'X-Heimdall-Hostname' = ([System.Net.Dns]::GetHostName() -replace '[^A-Za-z0-9._-]', '') }
    $machine = & {
        $env:HEIMDALL_COLLECT_LIBRARY = '1'
        try { . $collector } finally { Remove-Item Env:HEIMDALL_COLLECT_LIBRARY }
        Get-HeimdallMachineHash
    }
    if ($machine) { $headers['X-Heimdall-Machine'] = $machine }
    try {
        $resp = Invoke-WebRequest -UseBasicParsing -Method Post -Uri $ingest `
            -Headers $headers -Body '' -TimeoutSec 60 -MaximumRedirection 0
    } catch {
        $msg = $_.ErrorDetails.Message
        if (-not $msg) { $msg = $_.Exception.Message }
        throw "The hub refused to enroll this server: $msg"
    }
    $token = ([string]$resp.Content).Trim()
    try { $name = [string](@($resp.Headers['X-Heimdall-Host'])[0]) } catch { $name = '' }
    try { $pending = [string](@($resp.Headers['X-Heimdall-Pending'])[0]) } catch { $pending = '' }
    if ($pending -eq '1') {
        Write-Host "Enrolled as $name; waiting for an admin to approve it on the hub (Hosts > Add servers). It reports on its next hourly run after that."
    } else {
        Write-Host "Enrolled as $name."
    }
} else {
    $prompt = 'Ingest token from `heimdall host add`'
    if ($current) { $prompt += ' (Enter keeps the current token)' }
    $token = Read-Secret $prompt
    if (-not $token) { $token = $current }
}
if ($token -notmatch '^hmd_ingest_[A-Za-z0-9_-]{43}$') { throw 'That does not look like an ingest token.' }
Set-Content -LiteralPath $tokenFile -Value $token -NoNewline -Encoding ASCII

# Lock the token down: no inheritance; SYSTEM and Administrators full,
# LocalService read, nobody else.
& icacls.exe $tokenFile /inheritance:r /grant:r 'SYSTEM:(F)' 'Administrators:(F)' 'LOCAL SERVICE:(R)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not set permissions on the token file.' }

# The hub URL lives in a file (a new machine environment variable isn't
# seen by the Task Scheduler until a reboot).
Set-Content -LiteralPath (Join-Path $dataDir 'hub-url') -Value $HubUrl -NoNewline -Encoding ASCII

# The two tasks, from the task definitions in the collect.ps1 just verified
# and installed (loaded in a child scope, functions only). Registering by
# name with -Force replaces an existing task whole, triggers included, so a
# re-run also turns the old daily task into the hourly one.
$exe = (Get-Command powershell.exe).Source
$tasks = & {
    $env:HEIMDALL_COLLECT_LIBRARY = '1'
    try { . $collector } finally { Remove-Item Env:HEIMDALL_COLLECT_LIBRARY }
    @{ Name = $script:TaskName; Xml = (Get-HeimdallTaskXml -Kind schedule -PowerShell $exe -Script $collector) },
    @{ Name = $script:ChangesTaskName; Xml = (Get-HeimdallTaskXml -Kind changes -PowerShell $exe -Script $collector) }
}
foreach ($t in $tasks) {
    Register-ScheduledTask -TaskName $t.Name -Xml $t.Xml -Force | Out-Null
}

Write-Host 'Installed. Run a first push now with:'
Write-Host "  Start-ScheduledTask -TaskName 'Heimdall collector'"
Write-Host 'Then check the hub: heimdall host show <this host>'
