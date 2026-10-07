# AltA2dpConfig-Patch.ps1
# Patches AltA2dpConfig.exe so the UI reports a perpetual, AAC-capable licence.
#
#   .\AltA2dpConfig-Patch.ps1                 patch the installed exe in place
#   .\AltA2dpConfig-Patch.ps1 -WhatIf         report what would change
#   .\AltA2dpConfig-Patch.ps1 -Restore        put the .orig backup back
#   .\AltA2dpConfig-Patch.ps1 -InExe <path> -OutExe <path>    file to file
#
# Three license-decision functions are rewritten to their "valid" returns:
#   paid check   sub_1400FC110 -> 7 (perpetual) + writes a licence-code string
#   trial check  sub_1400C6D10 -> 6 (valid)
#   ECDSA verify sub_1400D6B40 -> 6 (pass)
#
# The stubs are written in place, so the image does not grow. The Authenticode
# signature is invalidated by the edit (expected for a local patch).
param(
    [string]$InExe,
    [string]$OutExe,
    [switch]$Restore,
    [switch]$WhatIf
)
$ErrorActionPreference = 'Stop'

$DEFAULT_EXE = 'C:\Program Files\Luculent Systems\AltA2DP\AltA2dpConfig.exe'

# RVAs of the three decision functions (image base 0x140000000)
$RVA_PAID  = 0xFC110
$RVA_TRIAL = 0xC6D10
$RVA_SIG   = 0xD6B40

# Position-independent stubs
$STUB_PAID = [byte[]](
    0xB8,0x07,0x00,0x00,0x00,               # mov eax, 7
    0x48,0x85,0xD2,                         # test rdx, rdx
    0x74,0x0D,                              # jz  +13
    0x48,0x8D,0x0D,0x04,0x00,0x00,0x00,     # lea rcx, [rip+4]
    0x48,0x89,0x0A,                         # mov [rdx], rcx
    0xC3,                                   # ret
    0x50,0x45,0x52,0x50,0x45,0x54,0x55,0x41,0x4C,0x0D,0x00   # "PERPETUAL\r\0"
)
$STUB_TRIAL = [byte[]](
    0xB8,0x06,0x00,0x00,0x00,               # mov eax, 6
    0x48,0x85,0xD2,                         # test rdx, rdx
    0x74,0x0D,                              # jz  +13
    0x48,0xB9,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,   # movabs rcx, INT64_MAX
    0x48,0x89,0x0A,                         # mov [rdx], rcx
    0x4D,0x85,0xC0,                         # test r8, r8
    0x74,0x07,                              # jz  +7
    0x49,0xC7,0x00,0x00,0x00,0x00,0x00,     # mov qword [r8], 0
    0xC3                                    # ret
)
$STUB_SIG = [byte[]](
    0xB8,0x06,0x00,0x00,0x00,               # mov eax, 6
    0xC3                                    # ret
)

function Get-RvaOffset([byte[]]$img, [int]$rva) {
    $pe = [BitConverter]::ToInt32($img, 0x3C)
    $n  = [BitConverter]::ToUInt16($img, $pe + 6)
    $so = [BitConverter]::ToUInt16($img, $pe + 20)
    $st = $pe + 24 + $so
    for ($i = 0; $i -lt $n; $i++) {
        $o = $st + $i * 40
        $va = [BitConverter]::ToUInt32($img, $o + 12)
        $vs = [BitConverter]::ToUInt32($img, $o + 8)
        if ($rva -ge $va -and $rva -lt ($va + $vs)) {
            return [int]([BitConverter]::ToUInt32($img, $o + 20) + $rva - $va)
        }
    }
    throw ('RVA 0x{0:X} is not in any section' -f $rva)
}

# ------------------------------------------------------------------ restore
if ($Restore) {
    if (-not $InExe) { $InExe = $DEFAULT_EXE }
    $bak = "$InExe.orig"
    if (-not (Test-Path -LiteralPath $bak)) { throw "no backup found: $bak" }
    if ($WhatIf) { Write-Host "would restore $bak -> $InExe"; exit 0 }
    Copy-Item -LiteralPath $bak -Destination $InExe -Force
    Write-Host "restored $InExe from $bak"
    exit 0
}

# -------------------------------------------------------------------- patch
if (-not $InExe) { $InExe = $DEFAULT_EXE }
if (-not (Test-Path -LiteralPath $InExe)) { throw "input not found: $InExe" }

$img = [IO.File]::ReadAllBytes($InExe)
$edits = @(
    [pscustomobject]@{ Name = 'paid '; Rva = $RVA_PAID;  Stub = $STUB_PAID  },
    [pscustomobject]@{ Name = 'trial'; Rva = $RVA_TRIAL; Stub = $STUB_TRIAL },
    [pscustomobject]@{ Name = 'sig  '; Rva = $RVA_SIG;   Stub = $STUB_SIG   }
)

foreach ($e in $edits) {
    $e | Add-Member -NotePropertyName Off -NotePropertyValue (Get-RvaOffset $img $e.Rva)
}

# detect an already-patched image (all three stubs present)
$already = $true
foreach ($e in $edits) {
    for ($i = 0; $i -lt $e.Stub.Length; $i++) {
        if ($img[$e.Off + $i] -ne $e.Stub[$i]) { $already = $false; break }
    }
    if (-not $already) { break }
}
if ($already) {
    Write-Host 'already patched - nothing to do'
    exit 0
}

Write-Host "input : $InExe"
Write-Host ("        {0} bytes" -f $img.Length)
foreach ($e in $edits) {
    Write-Host ("        {0} RVA 0x{1:X6} -> file 0x{2:X6}  ({3} bytes)" -f $e.Name, $e.Rva, $e.Off, $e.Stub.Length)
}

if ($WhatIf) { Write-Host 'whatif - no changes written'; exit 0 }

if (-not $OutExe) { $OutExe = $InExe }

# back up only when editing the file in place
if ($OutExe -eq $InExe) {
    $bak = "$InExe.orig"
    if (-not (Test-Path -LiteralPath $bak)) {
        Copy-Item -LiteralPath $InExe -Destination $bak -Force
        Write-Host "backup: $bak"
    } else {
        Write-Host "backup kept: $bak"
    }
}

$out = [byte[]]$img.Clone()
foreach ($e in $edits) {
    [Array]::Copy($e.Stub, 0, $out, $e.Off, $e.Stub.Length)
}
[IO.File]::WriteAllBytes($OutExe, $out)

Write-Host "wrote : $OutExe"
Write-Host 'done - restart AltA2dpConfig to see the licensed UI'
