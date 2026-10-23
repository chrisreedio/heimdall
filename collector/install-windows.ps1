<#
.SYNOPSIS
  Install the Heimdall collector on Windows (run once, as Administrator).

.DESCRIPTION
  - copies collect.ps1 to C:\Program Files\Heimdall
  - stores the ingest token in C:\ProgramData\Heimdall\token, readable only
    by LocalService (and Administrators/SYSTEM, who could read it anyway)
  - registers a daily scheduled task "Heimdall collector" that runs the
    collector as NT AUTHORITY\LocalService, a built-in low-privilege account

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
    [string]$At = '04:00'
)
$ErrorActionPreference = 'Stop'

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
Copy-Item -LiteralPath $Source -Destination (Join-Path $programDir 'collect.ps1') -Force

# Token: paste it; it never appears on the command line or in history.
$secure = Read-Host -AsSecureString 'Ingest token from `heimdall host add`'
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
if ($token -notmatch '^hmd_ingest_[A-Za-z0-9_-]{43}$') { throw 'That does not look like an ingest token.' }
$tokenFile = Join-Path $dataDir 'token'
Set-Content -LiteralPath $tokenFile -Value $token -NoNewline -Encoding ASCII

# Lock the token down: no inheritance; SYSTEM and Administrators full,
# LocalService read, nobody else.
& icacls.exe $tokenFile /inheritance:r /grant:r 'SYSTEM:(F)' 'Administrators:(F)' 'LOCAL SERVICE:(R)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not set permissions on the token file.' }

# Daily task as LocalService, with a random delay so hosts don't all report at once.
$exe = (Get-Command powershell.exe).Source
$taskArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $programDir 'collect.ps1')`" -Push"
$action = New-ScheduledTaskAction -Execute $exe -Argument $taskArgs
$trigger = New-ScheduledTaskTrigger -Daily -At $At -RandomDelay (New-TimeSpan -Hours 1)
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCALSERVICE' -LogonType ServiceAccount
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName 'Heimdall collector' -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null

# The hub URL lives in a file (a new machine environment variable isn't
# seen by the Task Scheduler until a reboot).
Set-Content -LiteralPath (Join-Path $dataDir 'hub-url') -Value $HubUrl -NoNewline -Encoding ASCII

Write-Host 'Installed. Run a first push now with:'
Write-Host "  Start-ScheduledTask -TaskName 'Heimdall collector'"
Write-Host 'Then check the hub: heimdall host show <this host>'
