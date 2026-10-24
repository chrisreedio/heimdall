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

  Verify collect.ps1 against the release's SHA256SUMS before installing.

.EXAMPLE
  .\install-windows.ps1 -HubUrl https://ingest.example.com

.NOTES
  SPDX-License-Identifier: AGPL-3.0-or-later
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HubUrl,
    [string]$Source = (Join-Path $PSScriptRoot 'collect.ps1'),
    [string]$At = '' # ignored: older versions reported daily at this time
)
$ErrorActionPreference = 'Stop'
if ($At) { Write-Warning '-At is ignored: the collector now reports hourly, after boot and after software changes.' }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell (as Administrator).'
}
if (-not $HubUrl.StartsWith('https://')) { throw '-HubUrl must be https://' }

# Verify collect.ps1 against the release's SHA256SUMS (downloaded next to it).
$sums = Join-Path (Split-Path -Parent $Source) 'SHA256SUMS'
if (-not (Test-Path -LiteralPath $sums)) { throw "SHA256SUMS not found next to $Source; download it from the same release" }
$want = (Get-Content -LiteralPath $sums | Where-Object { $_ -match '\scollect\.ps1$' } | Select-Object -First 1) -replace '\s.*$', ''
$got = (Get-FileHash -Algorithm SHA256 -LiteralPath $Source).Hash.ToLowerInvariant()
if (-not $want -or $want -ne $got) { throw 'collect.ps1 does not match SHA256SUMS; not installing' }

$programDir = Join-Path $env:ProgramFiles 'Heimdall'
$dataDir = Join-Path $env:ProgramData 'Heimdall'
New-Item -ItemType Directory -Force -Path $programDir, $dataDir | Out-Null
$collector = Join-Path $programDir 'collect.ps1'
Copy-Item -LiteralPath $Source -Destination $collector -Force

# Token: paste it; it never appears on the command line or in history. On
# an upgrade, Enter keeps the current one.
$tokenFile = Join-Path $dataDir 'token'
$prompt = 'Ingest token from `heimdall host add`'
if (Test-Path -LiteralPath $tokenFile) { $prompt += ' (Enter keeps the current token)' }
$secure = Read-Host -AsSecureString $prompt
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
if (-not $token -and (Test-Path -LiteralPath $tokenFile)) {
    $token = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
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
