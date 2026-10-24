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

# Unit checks for the scheduling code. Failures go to stderr and fail the
# run; stdout stays the snapshot above.
$script:failed = 0
function Check([bool]$ok, [string]$what) {
    if (-not $ok) { [Console]::Error.WriteLine("FAIL: $what"); $script:failed++ }
}
$ns = @{ t = 'http://schemas.microsoft.com/windows/2004/02/mit/task' }
$exe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$script = 'C:\Program Files\Heimdall & Co\collect.ps1' # & must be escaped
$start = [datetime]'2026-10-23T00:00:00'

$sched = [xml](Get-HeimdallTaskXml -Kind schedule -PowerShell $exe -Script $script -Start $start)
$tt = Select-Xml -Xml $sched -Namespace $ns -XPath '//t:Triggers/t:TimeTrigger' | Select-Object -ExpandProperty Node
Check ($tt.Repetition.Interval -eq 'PT1H') 'hourly repetition'
Check ($null -eq $tt.Repetition.SelectSingleNode('*[local-name()="Duration"]')) 'repeats indefinitely (no Duration)'
Check ($tt.RandomDelay -eq 'PT15M') 'random delay of 15 minutes'
Check ($tt.StartBoundary -eq '2026-10-23T00:00:00') 'start boundary in local time'
$bt = Select-Xml -Xml $sched -Namespace $ns -XPath '//t:Triggers/t:BootTrigger' | Select-Object -ExpandProperty Node
Check ($bt.Delay -eq 'PT3M') 'boot trigger 3 minutes after boot'
Check (@(Select-Xml -Xml $sched -Namespace $ns -XPath '//t:Triggers/*').Count -eq 2) 'schedule task has exactly two triggers'
foreach ($d in @($sched, [xml](Get-HeimdallTaskXml -Kind changes -PowerShell $exe -Script $script))) {
    $p = $d.Task.Principals.Principal
    Check ($p.UserId -eq 'S-1-5-19' -and $null -eq $p.SelectSingleNode('*[local-name()="LogonType"]') -and $p.RunLevel -eq 'LeastPrivilege') 'runs as LocalService, least privilege'
    Check ($d.Task.Actions.Context -eq $p.id) 'action context matches the principal'
    Check ($d.Task.Actions.Exec.Command -eq $exe) 'command'
    Check ($d.Task.Settings.MultipleInstancesPolicy -eq 'IgnoreNew') 'never two at once'
    Check ($d.Task.Settings.DisallowStartIfOnBatteries -eq 'false' -and $d.Task.Settings.StopIfGoingOnBatteries -eq 'false') 'runs on battery'
    Check ($d.Task.RegistrationInfo.SecurityDescriptor -eq 'D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;LS)') 'LocalService can read its task'
}
Check ($sched.Task.Actions.Exec.Arguments -eq "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`" -Push") 'schedule arguments'
$changes = [xml](Get-HeimdallTaskXml -Kind changes -PowerShell $exe -Script $script)
Check ($changes.Task.Actions.Exec.Arguments.EndsWith('-Push -AfterChanges')) 'changes arguments'
$ev = Select-Xml -Xml $changes -Namespace $ns -XPath '//t:Triggers/t:EventTrigger' | Select-Object -ExpandProperty Node
Check (@(Select-Xml -Xml $changes -Namespace $ns -XPath '//t:Triggers/*').Count -eq 1) 'changes task has one trigger'
$sub = [xml]$ev.Subscription
$sel = @($sub.QueryList.Query.Select)
Check ($sel.Count -eq 2) 'two event selects'
Check ($sel[0].Path -eq 'Application' -and $sel[0].'#text' -eq "*[System[Provider[@Name='MsiInstaller'] and (EventID=11707 or EventID=11724 or EventID=1033 or EventID=1034)]]") 'MsiInstaller select'
Check ($sel[1].Path -eq 'System' -and $sel[1].'#text' -eq "*[System[Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and (EventID=19)]]") 'Windows Update select'
$recent = [xml](Get-HeimdallEventQuery 60000)
Check (@($recent.QueryList.Query.Select)[0].'#text'.EndsWith(' and TimeCreated[timediff(@SystemTime) <= 60000]]]')) 'recent-events query'

# Trigger states, and that they fit the hub's pattern for Windows
# (internal/triggers: windowsStateRe).
$pattern = '^(enabled|disabled|missing|unknown),(ready|running|queued|disabled|no-triggers|none|unknown)$'
foreach ($c in @(
        @(@('found', $true, 3, 2), 'enabled,ready'), @(@('found', $true, 4, 1), 'enabled,running'),
        @(@('found', $true, 2, 1), 'enabled,queued'), @(@('found', $false, 1, 2), 'disabled,disabled'),
        @(@('found', $true, 3, 0), 'enabled,no-triggers'), @(@('found', $true, 0, 1), 'enabled,unknown'),
        @(@('missing'), 'missing,none'), @(@('unknown'), 'unknown,unknown'))) {
    $a = $c[0]
    $got = Format-HeimdallTaskState @a
    Check ($got -eq $c[1]) "task state $($a -join ' ') = $got, want $($c[1])"
    Check ($got -match $pattern) "task state $got fits the hub's pattern"
}

# Debounce: with a fake clock, events at 0s and 50s, starting at 10s: wait
# until 110s (60s after the last one).
$clock = @{ now = [datetime]'2026-10-23T12:00:10'; slept = 0 }
$events = @([datetime]'2026-10-23T12:00:00', [datetime]'2026-10-23T12:00:50')
$newest = { param($within) $n = $clock.now; @($events | Where-Object { $_ -le $n -and ($n - $_).TotalSeconds -le $within } | Sort-Object -Descending) | Select-Object -First 1 }
$sleep = { param($s) $clock.now = $clock.now.AddSeconds($s); $clock.slept += $s }
Wait-HeimdallQuiet -Newest $newest -Sleep $sleep -Now { $clock.now }
Check ($clock.now -eq [datetime]'2026-10-23T12:01:50') "debounce ends 60s after the last event (ended $($clock.now))"
$clock.now = [datetime]'2026-10-23T13:00:00'; $clock.slept = 0
Wait-HeimdallQuiet -Newest $newest -Sleep $sleep -Now { $clock.now }
Check ($clock.slept -eq 0) 'no wait when nothing changed recently'
# An endless stream of events gives up after $Max seconds.
$clock.now = [datetime]'2026-10-23T14:00:00'; $clock.slept = 0
Wait-HeimdallQuiet -Newest { param($w) $clock.now.AddSeconds(-1) } -Sleep $sleep -Now { $clock.now } -Max 600
Check ($clock.slept -le 600 -and $clock.slept -ge 540) "gives up after 10 minutes (slept $($clock.slept))"

foreach ($c in @(@('v0.4.14', '0.4.13', $true), @('v0.5.0', '0.4.13', $true), @('v0.4.13', '0.4.13', $false),
        @('v0.4.12', '0.4.13', $false), @('v1', '0.4.13', $true), @('', '0.4.13', $false), @('v0.4.14-dev', '0.4.13', $false))) {
    Check ((Test-HeimdallNewer $c[0] $c[1]) -eq $c[2]) "Test-HeimdallNewer $($c[0]) $($c[1])"
}
if ($script:failed) { exit 1 }
