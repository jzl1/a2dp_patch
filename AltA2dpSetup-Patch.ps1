# AltA2dpSetup-Patch.ps1
# Patches the Alternative A2DP Driver installer (AlternativeA2dpSetup-*.msi):
#   1) LaunchCondition: lowers the OS build floors (19045 -> 19041, 26100 -> 22000)
#      and drops the Bluetooth / 3rd-party-A2DP prerequisite rows
#   2) payload cab:     replaces the embedded AltA2dpConfig.exe with the licence-bypass build
#
#   .\AltA2dpSetup-Patch.ps1 -InMsi <src.msi> [-OutMsi <dst.msi>] [-SkipExePatch] [-KeepWork]

param(
    [Parameter(Mandatory = $true)][string]$InMsi,
    [string]$OutMsi,
    [switch]$SkipExePatch,
    [switch]$KeepWork
)
$ErrorActionPreference = 'Stop'

$HERE = Split-Path -Parent $MyInvocation.MyCommand.Path

function Read-U16([byte[]]$b, [int]$o) { return [BitConverter]::ToUInt16($b, $o) }
function Read-U32([byte[]]$b, [int]$o) { return [BitConverter]::ToUInt32($b, $o) }
function Read-I32([byte[]]$b, [int]$o) { return [BitConverter]::ToInt32($b, $o) }

# --------------------------------------------------------------- CFB helpers
# Compound File Binary reader/writer, scoped to what an MSI needs here.
function New-Cfb([byte[]]$data) {
    $sig = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
    for ($i = 0; $i -lt 8; $i++) {
        if ($data[$i] -ne $sig[$i]) { throw 'not a CFB/OLE file (bad signature)' }
    }
    $ss = 1 -shl (Read-U16 $data 0x1E)
    $firstDir = Read-U32 $data 0x30
    $miniCut = Read-U32 $data 0x38
    $firstDifat = Read-I32 $data 0x44

    # DIFAT: 109 entries in the header, then chained DIFAT sectors
    $difat = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -lt 109; $i++) {
        $v = Read-I32 $data (0x4C + $i * 4)
        if ($v -ge 0) { $difat.Add($v) }
    }
    $sec = $firstDifat
    while ($sec -ge 0) {
        $off = ($sec + 1) * $ss
        $n = [int]($ss / 4) - 1
        for ($i = 0; $i -lt $n; $i++) {
            $v = Read-I32 $data ($off + $i * 4)
            if ($v -ge 0) { $difat.Add($v) }
        }
        $sec = Read-I32 $data ($off + ($ss / 4 - 1) * 4)
    }

    # FAT
    $fat = New-Object System.Collections.Generic.List[int]
    foreach ($fs in $difat) {
        $off = ($fs + 1) * $ss
        for ($i = 0; $i -lt ($ss / 4); $i++) {
            $fat.Add((Read-I32 $data ($off + $i * 4)))
        }
    }

    # directory chain
    $dirChain = New-Object System.Collections.Generic.List[int]
    $s = $firstDir
    while ($s -ge 0 -and $s -lt $fat.Count) { $dirChain.Add($s); $s = $fat[$s] }
    $dirBytes = New-Object System.Collections.Generic.List[byte]
    foreach ($ds in $dirChain) {
        $off = ($ds + 1) * $ss
        for ($i = 0; $i -lt $ss; $i++) { $dirBytes.Add($data[$off + $i]) }
    }

    # directory entries (128 bytes each)
    $dirs = New-Object System.Collections.Generic.List[object]
    $count = [int]($dirBytes.Count / 128)
    for ($i = 0; $i -lt $count; $i++) {
        $o = $i * 128
        $nl = Read-U16 $dirBytes.ToArray() ($o + 64)
        $name = ''
        if ($nl -ge 2) { $name = [Text.Encoding]::Unicode.GetString($dirBytes.ToArray(), $o, $nl - 2) }
        $dirs.Add([pscustomobject]@{
            Index = $i
            Name  = $name
            Type  = $dirBytes[$o + 66]
            Start = Read-I32 $dirBytes.ToArray() ($o + 116)
            Size  = [BitConverter]::ToInt64($dirBytes.ToArray(), $o + 120)
        })
    }

    return [pscustomobject]@{
        Data      = $data
        Ss        = $ss
        Fat       = $fat
        Dirs      = $dirs
        DirChain  = $dirChain
        MiniCut   = $miniCut
    }
}

function Get-CfbChain([object]$cfb, [int]$start) {
    $chain = New-Object System.Collections.Generic.List[int]
    $s = $start
    while ($s -ge 0 -and $s -lt $cfb.Fat.Count) { $chain.Add($s); $s = $cfb.Fat[$s] }
    return $chain
}

function Get-CfbStream([object]$cfb, [object]$entry) {
    if ($entry.Size -lt $cfb.MiniCut) {
        throw ("stream '{0}' is a mini stream - unsupported for cab payload" -f $entry.Name)
    }
    $out = New-Object byte[] $entry.Size
    $off = 0
    foreach ($sec in (Get-CfbChain $cfb $entry.Start)) {
        if ($off -ge $entry.Size) { break }
        $base = ($sec + 1) * $cfb.Ss
        $n = [Math]::Min($cfb.Ss, $entry.Size - $off)
        [Array]::Copy($cfb.Data, $base, $out, $off, $n)
        $off += $n
    }
    return $out
}

function Set-CfbStream([object]$cfb, [object]$entry, [byte[]]$newData) {
    if ($entry.Size -lt $cfb.MiniCut) { throw 'mini stream resize unsupported' }
    $chain = Get-CfbChain $cfb $entry.Start
    $alloc = $chain.Count * $cfb.Ss
    if ($newData.Length -gt $alloc) {
        throw ("payload cab too large: {0} bytes > {1} bytes allocated" -f $newData.Length, $alloc)
    }
    $off = 0
    foreach ($sec in $chain) {
        if ($off -ge $newData.Length) { break }
        $base = ($sec + 1) * $cfb.Ss
        $n = [Math]::Min($cfb.Ss, $newData.Length - $off)
        [Array]::Copy($newData, $off, $cfb.Data, $base, $n)
        $off += $n
    }
    # directory entry size field: 64-bit at +120
    $byte = $entry.Index * 128
    $secIndex = [int]($byte / $cfb.Ss)
    $within = $byte % $cfb.Ss
    $deo = ($cfb.DirChain[$secIndex] + 1) * $cfb.Ss + $within
    [BitConverter]::GetBytes([int64]$newData.Length).CopyTo($cfb.Data, $deo + 120)
}

# --------------------------------------------------------------- PE helpers
function Get-RvaOffset([byte[]]$img, [int]$rva) {
    $pe = [BitConverter]::ToInt32($img, 0x3C)
    $n  = [BitConverter]::ToUInt16($img, $pe + 6)
    $so = [BitConverter]::ToUInt16($img, $pe + 20)
    $st = $pe + 24 + $so
    for ($i = 0; $i -lt $n; $i++) {
        $o  = $st + $i * 40
        $va = [BitConverter]::ToUInt32($img, $o + 12)
        $vs = [BitConverter]::ToUInt32($img, $o + 8)
        if ($rva -ge $va -and $rva -lt ($va + $vs)) {
            return [int]([BitConverter]::ToUInt32($img, $o + 20) + $rva - $va)
        }
    }
    throw ('RVA 0x{0:X} is not in any section' -f $rva)
}

function Get-SectionCount([byte[]]$img) {
    $pe = [BitConverter]::ToInt32($img, 0x3C)
    return [BitConverter]::ToUInt16($img, $pe + 6)
}

# Rewrites the vendor host inside the XOR-obfuscated URL strings, so the
# configuration utility cannot reach the activation/telemetry endpoints.
# Same-length substitution, re-encoded in place (no size change).
function Set-TelemetryHost([byte[]]$img) {
    $XORKEY = [long]0x1B07FEA723584405
    $OLD = 'www.bluetoothgoodies.com'
    $NEW = 'bluetoothgoodies.invalid'
    $IMG_BASE = [long]0x140000000
    $LOCS = @(
        [pscustomobject]@{ Va = [long]0x14023E670; Rot = 33 },
        [pscustomobject]@{ Va = [long]0x14023E540; Rot = 26 }
    )
    $renamed = 0
    foreach ($loc in $LOCS) {
        $off = Get-RvaOffset $img ([int]($loc.Va - $IMG_BASE))
        for ($j = 0; $j -lt $OLD.Length; $j++) {
            $widx = 8 + $j
            $pos = $off + 2 * $widx
            $stored = [int]$img[$pos] -bor ([int]$img[$pos + 1] -shl 8)
            $key = [int](($XORKEY -shr (($loc.Rot + $widx) % 48)) -band 0xFFFF)
            $plain = $stored -bxor $key
            $want = [int][char]$NEW[$j]
            if ($plain -eq $want) { continue }   # already renamed
            if ($plain -ne [int][char]$OLD[$j]) {
                throw ('telemetry host mismatch at VA 0x{0:X} word {1}' -f $loc.Va, $widx)
            }
            $newStored = $stored -bxor ($plain -bxor $want)
            $img[$pos] = [byte]($newStored -band 0xFF)
            $img[$pos + 1] = [byte](($newStored -shr 8) -band 0xFF)
            $renamed++
        }
    }
    return $renamed
}

# --------------------------------------------------------------- MSI helpers
# Windows Installer refuses a write-mode open while another handle to the same
# package is still alive, so open once per operation and release aggressively.
function Open-MsiDatabase([string]$path, [int]$mode) {
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $inst = New-Object -ComObject WindowsInstaller.Installer
        try {
            return [pscustomobject]@{ Installer = $inst; Database = $inst.OpenDatabase($path, $mode) }
        } catch {
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($inst)
            if ($attempt -eq 5) { throw }
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            Start-Sleep -Milliseconds 150
        }
    }
}

function Close-MsiDatabase([object]$handle) {
    if ($null -eq $handle) { return }
    if ($handle.Database) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($handle.Database) }
    if ($handle.Installer) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($handle.Installer) }
    $handle = $null
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}

# Lowers the OS build floors and removes the hardware-prerequisite rows in one
# transaction, reporting every change it makes.
function Set-LaunchConditions([string]$path) {
    $handle = Open-MsiDatabase $path 1
    $db = $handle.Database
    $before = New-Object System.Collections.Generic.List[string]
    $after = New-Object System.Collections.Generic.List[string]
    $changed = New-Object System.Collections.Generic.List[string]

    # Rows that block installation on hardware grounds. The OS floors are only
    # lowered (equal-length substitution keeps the package consistent), but
    # these two are removed outright: "AaNoHc" is set by binSetupDLL when no
    # Bluetooth radio is present, and "Aa3pSvc" flags a third-party A2DP
    # service. Both abort setup before the patched config utility can run.
    $dropExact = @(
        'Installed OR (NOT AaNoHc)',
        'Installed OR (NOT Aa3pSvc)'
    )

    try {
        $view = $db.OpenView('SELECT `Condition` FROM `LaunchCondition`')
        $view.Execute()
        while ($true) {
            $rec = $view.Fetch()
            if ($null -eq $rec) { break }
            $cond = [string]$rec.StringData(1)
            $before.Add($cond)

            if ($dropExact -contains $cond) {
                $view.Modify(6, $rec)          # 6 = msiViewModifyDelete
                $changed.Add(('deleted: {0}' -f $cond))
                continue
            }

            $newCond = $cond
            $newCond = $newCond -replace '19045', '19041'
            $newCond = $newCond -replace '26100', '22000'
            if ($newCond -ne $cond) {
                $rec.StringData(1) = $newCond
                $view.Modify(4, $rec)
                $changed.Add(('{0} -> {1}' -f $cond, $newCond))
            }
            $after.Add($newCond)
        }
        $view.Close()
        $db.Commit()
    } finally {
        $rec = $null
        $view = $null
        Close-MsiDatabase $handle
    }
    return [pscustomobject]@{ Before = $before; After = $after; Changed = $changed }
}

# ------------------------------------------------------------------ pipeline
if (-not (Test-Path -LiteralPath $InMsi)) { throw "source MSI not found: $InMsi" }
$InMsi = (Resolve-Path -LiteralPath $InMsi).Path
if (-not $OutMsi) {
    $OutMsi = [IO.Path]::Combine(
        [IO.Path]::GetDirectoryName($InMsi),
        ([IO.Path]::GetFileNameWithoutExtension($InMsi) + '.patched.msi'))
}

$work = Join-Path $env:TEMP ('a2dpmsi_' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    # --- 1) LaunchCondition -------------------------------------------------
    Copy-Item -LiteralPath $InMsi -Destination $OutMsi -Force
    Write-Host "source : $InMsi"
    Write-Host "output : $OutMsi"

    $condResult = Set-LaunchConditions $OutMsi
    Write-Host '--- LaunchCondition ---'
    if ($condResult.Changed.Count -eq 0) {
        Write-Host '  (no OS build floor matched - already lowered or different layout)'
    } else {
        foreach ($c in $condResult.Changed) { Write-Host "  patched: $c" }
    }
    Write-Host ('  rows: {0}' -f $condResult.After.Count)

    # --- 2) payload cab -----------------------------------------------------
    $cfb = New-Cfb ([IO.File]::ReadAllBytes($OutMsi))
    $cabEntry = $null
    foreach ($e in $cfb.Dirs) {
        if ($e.Type -ne 2) { continue }
        if ($e.Size -lt $cfb.MiniCut) { continue }
        if ($e.Name -eq '') { continue }
        try { $head = Get-CfbStream $cfb $e } catch { continue }
        if ($head.Length -ge 4 -and $head[0] -eq 0x4D -and $head[1] -eq 0x53 -and
            $head[2] -eq 0x43 -and $head[3] -eq 0x46) {
            $cabEntry = $e
            break
        }
    }
    if (-not $cabEntry) { throw 'no MSCF payload stream found in the MSI' }
    Write-Host '--- payload cab ---'
    Write-Host ("  stream '{0}' size={1}" -f $cabEntry.Name, $cabEntry.Size)

    if ($SkipExePatch) {
        Write-Host '  -SkipExePatch: payload cab left untouched'
    } else {
        $cabPath = Join-Path $work 'payload_orig.cab'
        [IO.File]::WriteAllBytes($cabPath, (Get-CfbStream $cfb $cabEntry))

        $stage = Join-Path $work 'stage'
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        & expand.exe -F:* $cabPath $stage | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "expand.exe failed ($LASTEXITCODE)" }

        $cfg = Join-Path $stage 'fAltA2dpConfig'
        if (-not (Test-Path -LiteralPath $cfg)) { throw "cab does not contain fAltA2dpConfig" }

        $img = [IO.File]::ReadAllBytes($cfg)
        $beforeHash = (Get-FileHash -LiteralPath $cfg -Algorithm SHA256).Hash
        $secBefore = Get-SectionCount $img

        # licence bypass (same three decision functions as AltA2dpConfig-Patch.ps1)
        $stubPaid = [byte[]](
            0xB8,0x07,0x00,0x00,0x00, 0x48,0x85,0xD2, 0x74,0x0D,
            0x48,0x8D,0x0D,0x04,0x00,0x00,0x00, 0x48,0x89,0x0A, 0xC3,
            0x50,0x45,0x52,0x50,0x45,0x54,0x55,0x41,0x4C,0x0D,0x00)
        $stubTrial = [byte[]](
            0xB8,0x06,0x00,0x00,0x00, 0x48,0x85,0xD2, 0x74,0x0D,
            0x48,0xB9,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F, 0x48,0x89,0x0A,
            0x4D,0x85,0xC0, 0x74,0x07, 0x49,0xC7,0x00,0x00,0x00,0x00,0x00, 0xC3)
        $stubSig = [byte[]](0xB8,0x06,0x00,0x00,0x00, 0xC3)

        $edits = @(
            [pscustomobject]@{ Name = 'paid '; Rva = 0xFC110; Stub = $stubPaid },
            [pscustomobject]@{ Name = 'trial'; Rva = 0xC6D10; Stub = $stubTrial },
            [pscustomobject]@{ Name = 'sig  '; Rva = 0xD6B40; Stub = $stubSig }
        )
        foreach ($e in $edits) {
            $e | Add-Member -NotePropertyName Off -NotePropertyValue (Get-RvaOffset $img $e.Rva)
        }

        $already = $true
        foreach ($e in $edits) {
            for ($i = 0; $i -lt $e.Stub.Length; $i++) {
                if ($img[$e.Off + $i] -ne $e.Stub[$i]) { $already = $false; break }
            }
            if (-not $already) { break }
        }

        if ($already) {
            Write-Host '  config exe already patched'
        } else {
            $out = [byte[]]$img.Clone()
            foreach ($e in $edits) {
                [Array]::Copy($e.Stub, 0, $out, $e.Off, $e.Stub.Length)
            }
            $renamed = Set-TelemetryHost $out
            Write-Host ("  telemetry host bytes rewritten: {0}" -f $renamed)
            [IO.File]::WriteAllBytes($cfg, $out)
            $secAfter = Get-SectionCount $out
            if ($secBefore -ne $secAfter -or $out.Length -ne $img.Length) {
                throw "unexpected PE layout: sections $secBefore -> $secAfter"
            }
            foreach ($e in $edits) {
                Write-Host ("  {0} RVA 0x{1:X6} -> off 0x{2:X6}  ({3} bytes)" -f
                    $e.Name, $e.Rva, $e.Off, $e.Stub.Length)
            }
        }

        # rebuild the cab with makecab, same descriptor as the vendor payload
        $files = Get-ChildItem -LiteralPath $stage -File | Sort-Object Name
        $ddf = Join-Path $stage 'payload.ddf'
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add('.OPTION EXPLICIT')
        $lines.Add('.Set CabinetNameTemplate=payload_new.cab')
        $lines.Add('.Set DiskDirectoryTemplate=.')
        $lines.Add('.Set CompressionType=MSZIP')
        $lines.Add('.Set Cabinet=on')
        $lines.Add('.Set Compress=on')
        $lines.Add('.Set MaxDiskSize=0')
        foreach ($f in $files) { if ($f.Name -ne 'payload.ddf') { $lines.Add($f.Name) } }
        [IO.File]::WriteAllLines($ddf, $lines)

        Push-Location $stage
        try {
            $null = & makecab.exe /F payload.ddf 2>&1
            $mk = $LASTEXITCODE
        } finally { Pop-Location }
        if ($mk -ne 0) { throw "makecab failed ($mk)" }

        $newCab = Join-Path $stage 'payload_new.cab'
        if (-not (Test-Path -LiteralPath $newCab)) { throw 'makecab produced no cab' }
        $newData = [IO.File]::ReadAllBytes($newCab)
        if ($newData.Length -lt 4 -or $newData[0] -ne 0x4D -or $newData[1] -ne 0x53 -or
            $newData[2] -ne 0x43 -or $newData[3] -ne 0x46) {
            throw 'rebuilt cab is not MSCF'
        }

        $alloc = (Get-CfbChain $cfb $cabEntry.Start).Count * $cfb.Ss
        Write-Host ('  rebuilt cab {0} bytes (alloc {1}, headroom {2})' -f
            $newData.Length, $alloc, ($alloc - $newData.Length))

        Set-CfbStream $cfb $cabEntry $newData
        [IO.File]::WriteAllBytes($OutMsi, $cfb.Data)
        Write-Host ('  config exe sha256 {0} -> {1}' -f $beforeHash,
            (Get-FileHash -LiteralPath $cfg -Algorithm SHA256).Hash)
    }

    # --- 3) verification ----------------------------------------------------
    Write-Host '--- verify ---'
    $verify = New-Cfb ([IO.File]::ReadAllBytes($OutMsi))
    $vEntry = $null
    foreach ($e in $verify.Dirs) {
        if ($e.Type -ne 2 -or $e.Size -lt $verify.MiniCut -or $e.Name -eq '') { continue }
        $head = Get-CfbStream $verify $e
        if ($head.Length -ge 4 -and $head[0] -eq 0x4D -and $head[1] -eq 0x53 -and
            $head[2] -eq 0x43 -and $head[3] -eq 0x46) { $vEntry = $e; break }
    }
    if (-not $vEntry) { throw 'verification failed: payload cab missing after write' }
    Write-Host ("  payload cab ok: {0} bytes" -f $vEntry.Size)
    Write-Host ("  output size: {0} bytes" -f (Get-Item -LiteralPath $OutMsi).Length)
    Write-Host 'done'
} finally {
    if (-not $KeepWork -and (Test-Path -LiteralPath $work)) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($KeepWork) {
        Write-Host "work dir kept: $work"
    }
}
