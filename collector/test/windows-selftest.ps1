# SPDX-License-Identifier: AGPL-3.0-or-later
# Runs collect.ps1's document builder on a fixture inventory (no Windows
# needed) and prints the snapshot. run-containers.sh validates it with the
# hub's decoder. Usage: pwsh -File windows-selftest.ps1 /path/to/collect.ps1
param([Parameter(Mandatory)][string]$Collector)
$env:HEIMDALL_COLLECT_LIBRARY = '1'
. $Collector

$inv = @{
    CollectedAt     = [datetime]::UtcNow
    OSVersion       = '10.0.20348'
    OSCaption       = 'Microsoft Windows Server 2022 Standard'
    IsServer        = $true
    Architecture    = '64-bit'
    UptimeSeconds   = 864000
    RebootRequired  = $true
    CollectorSHA256 = ('ab' * 32)
    Programs        = @(
        @{ Name = 'Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.38.33130'; Version = '14.38.33130' },
        @{ Name = '7-Zip 23.01 (x64)'; Version = '23.01' },
        @{ Name = 'Google Chrome'; Version = '130.0.6723.70' },
        @{ Name = 'Google Chrome'; Version = '130.0.6723.70' },           # duplicate (32/64-bit views)
        @{ Name = 'Evil <script>alert(1)</script>'; Version = '1.0' },    # markup stripped, still valid
        @{ Name = 'Bad version'; Version = '1.0 beta' },                  # dropped: space in version
        @{ Name = ''; Version = '1.0' }                                   # dropped: no name
    )
    Updates         = @(
        @{ KB = '5044281'; Security = $true },
        @{ KB = '890830'; Security = $false },
        @{ KB = 'nope'; Security = $true }                                # dropped
    )
}
ConvertTo-HeimdallJson (ConvertTo-HeimdallSnapshot $inv)

# A host where every optional source failed.
$bare = @{ CollectedAt = [datetime]::UtcNow; OSVersion = '10.0.22631'; OSCaption = 'Microsoft Windows 11 Pro'
    IsServer = $false; Architecture = 'ARM 64-bit'; UptimeSeconds = $null; RebootRequired = $null
    CollectorSHA256 = ''; Programs = @(); Updates = $null }
$doc = ConvertTo-HeimdallJson (ConvertTo-HeimdallSnapshot $bare)
Set-Content -LiteralPath '/out/windows-bare.json' -Value $doc
