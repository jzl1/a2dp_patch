# Verify-LoadedDriver.ps1 - report which AltA2DP.sys is actually installed.
# Read-only. Run on the target machine (elevated not required for most of it).
$ErrorActionPreference = 'Continue'
function Hex2([byte[]]$b, [int]$o) { ($b[$o..($o + 1)] | ForEach-Object { $_.ToString('X2') }) -join ' ' }
function Hex5([byte[]]$b, [int]$o) { ($b[$o..($o + 4)] | ForEach-Object { $_.ToString('X2') }) -join ' ' }

Write-Host '=== AltA2DP service ==='
$d = Get-CimInstance Win32_SystemDriver -Filter "Name='AltA2DP'" -ErrorAction SilentlyContinue
if ($d) { $d | Format-List State, Started, PathName } else { Write-Host '  service not present' }

$paths = @()
if ($d.PathName) { $paths += $d.PathName }
$paths += (Get-ChildItem 'C:\Windows\System32\DriverStore\FileRepository' -Recurse -Filter 'AltA2DP.sys' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
$paths += (Get-ChildItem 'C:\Program Files\Luculent Systems\AltA2DP\Driver' -Recurse -Filter 'AltA2DP.sys' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
$paths = $paths | Select-Object -Unique

Write-Host ''
Write-Host '=== AltA2DP.sys copies on disk ==='
foreach ($p in $paths) {
    try {
        $b = [IO.File]::ReadAllBytes($p)
        $pe = [BitConverter]::ToInt32($b, 0x3C)
        $n = [BitConverter]::ToUInt16($b, $pe + 6)
        $state = Hex5 $b 0x8CEE1
        $verdict = switch ($state) {
            '83 F8 06 EB 27' { 'PATCHED  (expired-trial fix present)' }
            'EB 27 06 75 22' { 'PATCHED  (alt encoding, jmp over cmp)' }
            '83 F8 06 75 22' { 'STOCK    (NO expired-trial fix)' }
            default { 'UNKNOWN' }
        }
        $loaded = if ($d.PathName -and ($p -ieq $d.PathName)) { '   <== LOADED' } else { '' }
        Write-Host ("  {0}" -f $p)
        Write-Host ("      size={0} sec={1} gate={2} state={3}   {4}{5}" -f $b.Length, $n, (Hex2 $b 0x8AFB3), $state, $verdict, $loaded)
    } catch {
        Write-Host ("  {0}  (read failed: {1})" -f $p, $_.Exception.Message)
    }
}

Write-Host ''
Write-Host '=== alta2dp driver packages (pnputil) ==='
$raw = pnputil /enum-drivers
for ($i = 0; $i -lt $raw.Count; $i++) {
    if ($raw[$i] -match 'alta2dp\.inf') {
        $s = [Math]::Max(0, $i - 4)
        $e = [Math]::Min($raw.Count - 1, $i + 1)
        $raw[$s..$e] | ForEach-Object { Write-Host "  $_" }
        Write-Host ''
    }
}

Write-Host '=== A2DP media node ==='
Get-PnpDevice -Class MEDIA -PresentOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -match 'Stereo|A2DP' } |
    Format-List Status, Problem, FriendlyName, InstanceId

Write-Host '=== code-integrity errors (last 8) ==='
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 40 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 3004, 3033, 3077 } |
    Select-Object -First 8 TimeCreated, Id |
    Format-Table -AutoSize

Write-Host '=== testsigning ==='
bcdedit /enum '{current}' | Select-String testsigning
