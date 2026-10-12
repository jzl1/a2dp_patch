# AltA2DP-PatchTool.ps1
# Patches a stock AltA2DP.sys into the hashfix build (no beep, no AAC watermark),
# then signs it and builds a catalog.
#
#   .\AltA2DP-PatchTool.ps1 -InSys C:\path\AltA2DP.sys    patch + sign + catalog
#   .\AltA2DP-PatchTool.ps1 -PatchOnly                    patch only, no signing
#   .\AltA2DP-PatchTool.ps1 -Install                      ... and install it too
#
# Signs with the pinned cert if present, else creates a self-signed one.
# Trusting that cert (and installing the result) needs admin; the script
# re-launches itself elevated when needed.
#
# Requires test-signing ON and Secure Boot OFF for the result to load.
param(
    [string]$InSys,
    [string]$OutDir = "$PSScriptRoot\build",
    [string]$CertThumbprint = '375ED2BB1303CF7A27A425ACE6213941C13AE532',
    [string]$CertPath,
    [string]$InfSrc,
    [switch]$PatchOnly,
    [switch]$Install,
    [switch]$KeepTestsigning,
    [switch]$Relaunched
)
$ErrorActionPreference = 'Stop'

function Test-Admin {
    return ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# signing needs the cert trusted in LocalMachine Root, which needs admin
if (-not $PatchOnly -and -not (Test-Admin)) {
    if ($Relaunched) { throw 'elevation failed - run this script as Administrator' }
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Relaunched')
    if ($InSys)  { $a += @('-InSys', "`"$InSys`"") }
    if ($OutDir) { $a += @('-OutDir', "`"$OutDir`"") }
    if ($CertPath) { $a += @('-CertPath', "`"$CertPath`"") }
    if ($InfSrc) { $a += @('-InfSrc', "`"$InfSrc`"") }
    if ($Install) { $a += '-Install' }
    if ($KeepTestsigning) { $a += '-KeepTestsigning' }
    if ($CertThumbprint -ne '375ED2BB1303CF7A27A425ACE6213941C13AE532') {
        $a += @('-CertThumbprint', "`"$CertThumbprint`"")
    }
    Write-Host 'Requesting administrator rights...'
    Start-Process (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $a
    exit
}

# ---- fixed locations in the vendor image (file offsets) --------------------
$HASH_LO  = 0x6CDA8            # start of the self-hashed window
$HASH_HI  = 0x94F48            # end   of the self-hashed window
$HASH_LEN = $HASH_HI - $HASH_LO
$GATE_OFF = 0x8AFB3            # AAC watermark gate
$GATE_OLD = [byte[]](0x44, 0x38)
$GATE_NEW = [byte[]](0xEB, 0x49)

# Expired-trial gate.
#
# sub_14008DA18 branches on the paid verdict (n7 = sub_14007942C):
#     n7 == 6  -> FA8 = 1, FA9 = (trial == 6)
#     n7 == 7  -> FA8 = 1, FAA = 1      <- the fully licensed branch
#     n7 == 0  -> FA8 = 1, FA9 = 1  (only if trial == 6)
#
# The evaluator NEVER returns 0 - its returns are 1, 3, 4, 6, 7. So the
# n7 == 0 branch is dead code, and on a machine with an expired trial and no
# paid licence n7 == 1, which matches NO branch: FA8, FA9 and FAA all stay 0.
# The AAC encoder then skips sub_14008AE94 at 0x14008C19A and produces no audio.
#
# Force the n7 == 7 branch (FA8 = 1, FAA = 1 - the licensed state) by replacing
# the `jne` at 0x14008DB0B with a `jmp`. EB 27 lands on 0x14008DB0D.
$EXP_OFF = 0x8CEE1             # VA 0x14008DAE1: 83 F8 06 75 22 (cmp eax,6 / jne +0x22)
$EXP_OLD = [byte[]](0x83, 0xF8, 0x06, 0x75, 0x22)
$EXP_NEW = [byte[]](0x83, 0xF8, 0x06, 0xEB, 0x27)
$LEA1_VA  = 0x1400740F5        # lea rdx,[rip+d] -> hash start
$LEA2_VA  = 0x1400740FC        # lea r8, [rip+d] -> hash end
$VA_BASE  = 0x140000000
$SEC_ALIGN = 0x1000
$FILE_ALIGN = 0x200

# ---------------------------------------------------------------- PE helpers
function Get-U16([byte[]]$b, [int]$o) { [BitConverter]::ToUInt16($b, $o) }
function Get-U32([byte[]]$b, [int]$o) { [BitConverter]::ToUInt32($b, $o) }
function Set-U16([byte[]]$b, [int]$o, $v) { [Array]::Copy([BitConverter]::GetBytes([uint16]$v), 0, $b, $o, 2) }
function Set-U32([byte[]]$b, [int]$o, $v) { [Array]::Copy([BitConverter]::GetBytes([uint32]$v), 0, $b, $o, 4) }
function Set-I32([byte[]]$b, [int]$o, $v) { [Array]::Copy([BitConverter]::GetBytes([int]$v), 0, $b, $o, 4) }
function AlignUp([long]$v, [int]$a) { [int]([math]::Ceiling($v / $a) * $a) }

# Recompute the PE header CheckSum. The kernel loader does not verify this, but
# leaving it stale makes the patch-only artifact internally inconsistent.
# (Authenticode re-derives it when signing, so the signed output is unaffected.)
function Set-PeChecksum([byte[]]$img) {
    $pe = [BitConverter]::ToInt32($img, 0x3C)
    $cksumOff = $pe + 24 + 0x40

    [Array]::Copy([BitConverter]::GetBytes([uint32]0), 0, $img, $cksumOff, 4)

    [uint32]$sum = 0
    $len = $img.Length
    $i = 0
    while ($i -lt $len) {
        if ($i -eq $cksumOff) { $i += 4; continue }   # skip the field itself
        $lo = [uint32]$img[$i]
        $hi = if (($i + 1) -lt $len) { [uint32]$img[$i + 1] } else { [uint32]0 }
        $sum += $lo -bor ($hi -shl 8)
        $sum = ($sum -band 0xFFFF) + ($sum -shr 16)
        $i += 2
    }
    $sum = ($sum -band 0xFFFF) + ($sum -shr 16)
    $sum = $sum + [uint32]($len -band 0xFFFFFFFF)

    [Array]::Copy([BitConverter]::GetBytes([uint32]($sum -band 0xFFFFFFFF)), 0, $img, $cksumOff, 4)
    return [uint32]($sum -band 0xFFFFFFFF)
}

function Get-Sections([byte[]]$b) {
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    $n  = Get-U16 $b ($pe + 6)
    $so = Get-U16 $b ($pe + 20)
    $st = $pe + 24 + $so
    $list = @()
    for ($i = 0; $i -lt $n; $i++) {
        $o = $st + $i * 40
        $list += [pscustomobject]@{
            Off = $o
            VA  = Get-U32 $b ($o + 12)
            VS  = Get-U32 $b ($o + 8)
            Ptr = Get-U32 $b ($o + 20)
        }
    }
    return $list
}

function RvaToOff($sections, [long]$rva) {
    foreach ($s in $sections) {
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VS)) {
            return [int]($s.Ptr + $rva - $s.VA)
        }
    }
    throw ('RVA 0x{0:X} is not in any section' -f $rva)
}

# ------------------------------------------------------------- locate input
function Get-SectionCount([byte[]]$b) {
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    return [BitConverter]::ToUInt16($b, $pe + 6)
}
function Test-StockImage([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $b = [IO.File]::ReadAllBytes($path)
        if ($b.Length -lt 0x1000) { return $false }
        if ((Get-SectionCount $b) -ne 8) { return $false }
        return ($b[0x8AFB3] -eq 0x44 -and $b[0x8AFB4] -eq 0x38 -and
                $b[0x8CEE1] -eq 0x83 -and $b[0x8CEE2] -eq 0xF8 -and $b[0x8CEE3] -eq 0x06 -and
                $b[0x8CEE4] -eq 0x75 -and $b[0x8CEE5] -eq 0x22)
    } catch { return $false }
}

if ($InSys) {
    if (-not (Test-Path -LiteralPath $InSys)) { throw "input not found: $InSys" }
    $img = [IO.File]::ReadAllBytes($InSys)
    if ((Get-SectionCount $img) -eq 9 -or ($img[0x8AFB3] -eq 0xEB -and $img[0x8AFB4] -eq 0x49) -or
        ($img[0x8CEE4] -eq 0xEB -and $img[0x8CEE5] -eq 0x27)) {
        throw "$InSys is ALREADY the patched (hashfix) build - patching it again would corrupt it."
    }
    Write-Host "input : $InSys"
} else {
    # collect candidates, keep only genuine stock images
    $cand = @()
    foreach ($d in 'C:\Windows\System32\DriverStore\FileRepository',
                   'C:\Program Files\Luculent Systems\AltA2DP\Driver') {
        if (Test-Path -LiteralPath $d) {
            $cand += Get-ChildItem -LiteralPath $d -Recurse -Filter 'AltA2DP.sys' -File -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName
        }
    }
    $cand = $cand | Select-Object -Unique
    $stock = $cand | Where-Object { Test-StockImage $_ }
    $patched = $cand | Where-Object { -not (Test-StockImage $_) }

    if (-not $stock) {
        Write-Host "found $($cand.Count) AltA2DP.sys file(s), none are stock:"
        $patched | ForEach-Object {
            $b = [IO.File]::ReadAllBytes($_)
            Write-Host ("  {0}  ({1} bytes, {2} sections, gate {3:X2} {4:X2})" -f `
                $_, $b.Length, (Get-SectionCount $b), $b[0x8AFB3], $b[0x8AFB4])
        }
        throw @'

No stock AltA2DP.sys found - only already-patched copies exist.
The MSI uninstall does NOT restore the vendor driver (it only restores
.orig backups, and pnputil-created DriverStore copies have none).

Fix it one of these ways:
  1. Repair the driver: open the vendor "Alternative A2DP Driver" installer
     and reinstall/repair, which drops a clean AltA2DP.sys.
  2. Extract a clean driver from the vendor installer yourself and pass it:
         .\AltA2DP-PatchTool.ps1 -InSys <path\to\stock\AltA2DP.sys>
'@
    }
    if ($stock.Count -gt 1) {
        Write-Host "note: $($stock.Count) stock copies found, using the first:"
        $stock | ForEach-Object { Write-Host "  $_" }
    }
    $InSys = $stock | Select-Object -First 1
    Write-Host "input : $InSys"
}

# ------------------------------------------------------------------- patch
$img = [IO.File]::ReadAllBytes($InSys)
$sections = Get-Sections $img
$pe  = [BitConverter]::ToInt32($img, 0x3C)
$opt = $pe + 24
$nsec = Get-U16 $img ($pe + 6)
$secTab = $opt + (Get-U16 $img ($pe + 20))
$sizeOfImage = Get-U32 $img ($opt + 56)
$certDir = $opt + 112 + 4 * 8
$certOff = Get-U32 $img $certDir

if ((Get-U16 $img $opt) -ne 0x20B) { throw 'not a PE32+ image' }
if ($nsec -ne 8) { throw "expected 8 sections, found $nsec - already patched?" }
if ($img[$GATE_OFF] -ne $GATE_OLD[0] -or $img[$GATE_OFF + 1] -ne $GATE_OLD[1]) {
    throw ('gate bytes at 0x{0:X} are {1:X2} {2:X2}, expected 44 38' -f $GATE_OFF, $img[$GATE_OFF], $img[$GATE_OFF + 1])
}
$expGot = ($img[$EXP_OFF..($EXP_OFF + 4)] | ForEach-Object { $_.ToString('X2') }) -join ' '
$expWant = ($EXP_OLD | ForEach-Object { $_.ToString('X2') }) -join ' '
if ($expGot -ne $expWant) {
    throw ('expired-trial gate at 0x{0:X} is {1}, expected {2}' -f $EXP_OFF, $expGot, $expWant)
}
Write-Host ("        {0} bytes, {1} sections, cert at 0x{2:X}" -f $img.Length, $nsec, $certOff)

# 1. snapshot the original hashed bytes
$orig = New-Object byte[] $HASH_LEN
[Array]::Copy($img, $HASH_LO, $orig, 0, $HASH_LEN)

# 2. strip the existing certificate (re-signed after patching)
if ($certOff -gt 0) {
    $trim = New-Object byte[] $certOff
    [Array]::Copy($img, 0, $trim, 0, $certOff)
    $img = $trim
    Set-U32 $img $certDir 0
    Set-U32 $img ($certDir + 4) 0
}

# 3. append .origtx holding the original bytes
$rawPtr  = AlignUp $img.Length $FILE_ALIGN
$rawSize = AlignUp $HASH_LEN $FILE_ALIGN
$newVa   = AlignUp $sizeOfImage $SEC_ALIGN
$out = New-Object byte[] ($rawPtr + $rawSize)
[Array]::Copy($img, 0, $out, 0, $img.Length)
[Array]::Copy($orig, 0, $out, $rawPtr, $HASH_LEN)

$secOff = $secTab + $nsec * 40
[Array]::Copy([Text.Encoding]::ASCII.GetBytes(".origtx`0"), 0, $out, $secOff, 8)
Set-U32 $out ($secOff + 8)  $HASH_LEN
Set-U32 $out ($secOff + 12) $newVa
Set-U32 $out ($secOff + 16) $rawSize
Set-U32 $out ($secOff + 20) $rawPtr
Set-U32 $out ($secOff + 24) 0
Set-U32 $out ($secOff + 28) 0
Set-U16 $out ($secOff + 32) 0
Set-U16 $out ($secOff + 34) 0
Set-U32 $out ($secOff + 36) 0x40000040        # INITIALIZED_DATA | MEM_READ
Set-U16 $out ($pe + 6) ($nsec + 1)
Set-U32 $out ($opt + 56) (AlignUp ($newVa + $HASH_LEN) $SEC_ALIGN)

# 4. retarget the constructor's two lea instructions at .origtx
$copyVa    = $VA_BASE + $newVa
$copyEndVa = $copyVa + $HASH_LEN
$o1 = RvaToOff $sections ($LEA1_VA - $VA_BASE)
$o2 = RvaToOff $sections ($LEA2_VA - $VA_BASE)
if ($out[$o1] -ne 0x48 -or $out[$o1 + 1] -ne 0x8D -or $out[$o1 + 2] -ne 0x15) {
    throw ('unexpected bytes at lea1 0x{0:X}' -f $LEA1_VA)
}
if ($out[$o2] -ne 0x4C -or $out[$o2 + 1] -ne 0x8D -or $out[$o2 + 2] -ne 0x05) {
    throw ('unexpected bytes at lea2 0x{0:X}' -f $LEA2_VA)
}
Set-I32 $out ($o1 + 3) ($copyVa - ($LEA1_VA + 7))
Set-I32 $out ($o2 + 3) ($copyEndVa - ($LEA2_VA + 7))

# 5. AAC watermark gate patch
$out[$GATE_OFF]     = $GATE_NEW[0]
$out[$GATE_OFF + 1] = $GATE_NEW[1]

# 5b. expired-trial gate: force the n7 == 7 branch (FA8 = 1, FAA = 1)
for ($i = 0; $i -lt $EXP_NEW.Length; $i++) { $out[$EXP_OFF + $i] = $EXP_NEW[$i] }

# 6. refresh the PE header checksum
$cksum = Set-PeChecksum $out

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$patched = Join-Path $OutDir 'AltA2DP.patched.sys'
[IO.File]::WriteAllBytes($patched, $out)
Write-Host ''
Write-Host ("patched: {0}" -f $patched)
Write-Host ("  {0} bytes, {1} sections, .origtx VA 0x{2:X}" -f $out.Length, ($nsec + 1), $newVa)
Write-Host ("  gate 0x{0:X}: 44 38 -> EB 49" -f $GATE_OFF)
Write-Host ("  expired-trial gate 0x{0:X}: 75 22 -> EB 27 (forces licensed branch: 0xFA8=1, 0xFAA=1)" -f $EXP_OFF)
Write-Host ("  PE checksum recomputed: 0x{0:X8}" -f $cksum)

if ($PatchOnly) { Write-Host 'patch-only, stopping.'; exit 0 }

# -------------------------------------------------------------------- sign
# Find a signing cert, in order:
#   1. -CertPath <file.pfx|file.cer>  (PFX must be readable with no password)
#   2. the pinned thumbprint, if present in CurrentUser\My
#   3. otherwise create a fresh self-signed code-signing cert
$cert = $null

if ($CertPath) {
    if (-not (Test-Path -LiteralPath $CertPath)) { throw "cert not found: $CertPath" }
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
    if (-not $cert.HasPrivateKey) { throw "$CertPath has no private key - signing needs a .pfx" }
    Write-Host "cert  : $($cert.Subject)  (from $CertPath)"
} else {
    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Thumbprint -eq $CertThumbprint -and $_.HasPrivateKey } |
        Select-Object -First 1
    if ($cert) {
        Write-Host "cert  : $($cert.Subject)  (pinned $CertThumbprint)"
    }
}

if (-not $cert) {
    Write-Host "cert  : pinned cert not found - creating a new self-signed code-signing cert"
    $cert = New-SelfSignedCertificate `
        -Subject 'CN=AltA2DP Local Test Signing' `
        -Type CodeSigningCert `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(10) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')
    Write-Host "cert  : created $($cert.Thumbprint)"

}

# always export the public cert next to the payload, so it can be trusted on
# the target machine (LocalMachine Root + TrustedPublisher)
$cerOut = Join-Path $OutDir 'AltA2DP-TestSigning.cer'
[IO.File]::WriteAllBytes($cerOut, $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
Write-Host "public cert -> $cerOut"

# Authenticode refuses a chain that does not end in a trusted root, so trust the
# cert first (the script is already elevated by this point).
foreach ($store in 'Root', 'TrustedPublisher') {
    $path = "Cert:\LocalMachine\$store"
    if (-not (Test-Path "$path\$($cert.Thumbprint)")) {
        Import-Certificate -FilePath $cerOut -CertStoreLocation $path | Out-Null
        Write-Host "trusted: cert -> LocalMachine\$store"
    }
}

$s = Set-AuthenticodeSignature -FilePath $patched -Certificate $cert -HashAlgorithm SHA256
if ((Get-AuthenticodeSignature $patched).Status -ne 'Valid') { throw "driver signing failed: $($s.Status)" }
Write-Host 'signed: driver OK'

# The catalog must list the same file names as the installed package, so take
# the INF from wherever the driver is actually installed (or -InfSrc).
if (-not $InfSrc) {
    $cand = @()
    if ($InSys) { $cand += Join-Path (Split-Path -Parent $InSys) 'AltA2DP.inf' }
    foreach ($d in 'C:\Windows\System32\DriverStore\FileRepository',
                   'C:\Program Files\Luculent Systems\AltA2DP\Driver') {
        if (Test-Path -LiteralPath $d) {
            $cand += Get-ChildItem -LiteralPath $d -Recurse -Filter 'AltA2DP.inf' -File -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName
        }
    }
    $InfSrc = $cand | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $InfSrc) {
    throw @'

AltA2DP.inf not found - it is needed to build the catalog.
It normally sits next to the installed AltA2DP.sys. Pass it explicitly:
    .\AltA2DP-PatchTool.ps1 -InfSrc <path\to\AltA2DP.inf>
'@
}
Write-Host "inf   : $InfSrc"
Copy-Item $InfSrc (Join-Path $OutDir 'AltA2DP.inf') -Force
$catDir = Join-Path $OutDir 'catbuild'
New-Item -ItemType Directory -Force -Path $catDir | Out-Null
Copy-Item $patched (Join-Path $catDir 'AltA2DP.sys') -Force
Copy-Item (Join-Path $OutDir 'AltA2DP.inf') (Join-Path $catDir 'AltA2DP.inf') -Force
$cat = Join-Path $catDir 'AltA2DP.cat'
if (Test-Path -LiteralPath $cat) { Remove-Item -LiteralPath $cat -Force }
New-FileCatalog -Path $catDir -CatalogFilePath $cat -CatalogVersion 2 | Out-Null
if (-not (Test-Path -LiteralPath $cat) -or (Get-Item -LiteralPath $cat).Length -eq 0) {
    throw 'New-FileCatalog produced no catalog'
}
Set-AuthenticodeSignature -FilePath $cat -Certificate $cert -HashAlgorithm SHA256 | Out-Null
if ((Get-AuthenticodeSignature $cat).Status -ne 'Valid') { throw 'catalog signing failed' }
Copy-Item $cat (Join-Path $OutDir 'AltA2DP.cat') -Force
Write-Host 'signed: catalog OK'

# ---------------------------------------------------------------- install
if ($Install) {
    # Overwriting DriverStore\FileRepository\*\AltA2DP.sys in place does NOT
    # work: those files are TrustedInstaller-owned and the running package keeps
    # its catalog binding. Instead we stage a *new* driver package whose
    # DriverVer is strictly higher than anything installed, then let pnputil
    # bind the device to it.

    # 1. bump DriverVer so Windows ranks this package above EVERY installed one.
    #    Installed versions can be arbitrary (e.g. 1.8.3.90), so scan them all
    #    and go one above the highest - not just +1 on the INF's own value.
    $infTxt = Get-Content -LiteralPath (Join-Path $OutDir 'AltA2DP.inf') -Raw
    $m = [regex]::Match($infTxt, '(?m)^\s*DriverVer\s*=\s*(.+)$')
    if (-not $m.Success) { throw 'AltA2DP.inf has no DriverVer line' }
    $oldVer = $m.Groups[1].Value.Trim()

    $installed = @()
    foreach ($d in Get-ChildItem 'C:\Windows\System32\DriverStore\FileRepository' -Directory -Filter 'alta2dp.inf_amd64_*' -ErrorAction SilentlyContinue) {
        $i = Join-Path $d.FullName 'AltA2DP.inf'
        if (Test-Path -LiteralPath $i) {
            $mm = [regex]::Match((Get-Content -LiteralPath $i -Raw), '(?m)^\s*DriverVer\s*=\s*(.+)$')
            if ($mm.Success) { $installed += $mm.Groups[1].Value.Trim() }
        }
    }
    $bestDate = [datetime]::MinValue
    $bestVer  = [version]'0.0.0.0'
    foreach ($dv in (@($oldVer) + $installed)) {
        $p = $dv -split ','
        $d = [datetime]::ParseExact($p[0].Trim(), 'MM/dd/yyyy', $null)
        $v = [version]($p[1].Trim())
        if ($d -gt $bestDate -or ($d -eq $bestDate -and $v -gt $bestVer)) {
            $bestDate = $d
            $bestVer  = $v
        }
    }
    # go one above the highest installed (date AND version)
    $newDate = (Get-Date).Date
    if ($newDate -le $bestDate) { $newDate = $bestDate.AddDays(1) }
    $newVer = ($newDate.ToString('MM/dd/yyyy')) + ',' + $bestVer.Major + '.' + $bestVer.Minor + '.' + ($bestVer.Build + 1) + '.' + $bestVer.Revision
    $infTxt = [regex]::Replace($infTxt, '(?m)^(\s*DriverVer\s*=\s*).*$', ('${1}' + $newVer))
    Write-Host "inf   : DriverVer $oldVer -> $newVer  (installed: $($installed -join ' | '))"

    # 2. build the staged package (INF change invalidates the old catalog)
    $stage = Join-Path $OutDir 'stage'
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    Copy-Item -LiteralPath $patched -Destination (Join-Path $stage 'AltA2DP.sys') -Force
    Set-Content -LiteralPath (Join-Path $stage 'AltA2DP.inf') -Value $infTxt -Encoding ascii
    $stageCat = Join-Path $stage 'AltA2DP.cat'
    if (Test-Path -LiteralPath $stageCat) { Remove-Item -LiteralPath $stageCat -Force }
    New-FileCatalog -Path $stage -CatalogFilePath $stageCat -CatalogVersion 2 | Out-Null
    if (-not (Test-Path -LiteralPath $stageCat) -or (Get-Item -LiteralPath $stageCat).Length -eq 0) {
        throw 'New-FileCatalog produced no catalog for the staged package'
    }
    Set-AuthenticodeSignature -FilePath $stageCat -Certificate $cert -HashAlgorithm SHA256 | Out-Null
    if ((Get-AuthenticodeSignature $stageCat).Status -ne 'Valid') { throw 'staged catalog signing failed' }

    # 3. register + install the staged package
    & pnputil.exe /add-driver (Join-Path $stage 'AltA2DP.inf') /install
    $rc = $LASTEXITCODE
    if ($rc -ne 0 -and $rc -ne 3010) { throw "pnputil /add-driver failed (exit $rc)" }

    # 4. ALSO replace the copy the service is currently bound to, in place.
    #    A brand-new package only takes effect once the device re-enumerates;
    #    an already-installed (but disconnected) headset keeps the old binding.
    #    Overwriting the bound file + its catalog/inf makes the next load use
    #    the patched image regardless of driver ranking.
    $bound = $null
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\AltA2DP'
    if (Test-Path $svcKey) {
        $img = (Get-ItemProperty $svcKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
        if ($img) {
            $rel = $img -replace '^\\SystemRoot\\', "$env:SystemRoot\"
            if (Test-Path -LiteralPath $rel) { $bound = $rel }
        }
    }
    if ($bound) {
        $bd = Split-Path -Parent $bound
        Write-Host "bound : $bound"
        try {
            # DriverStore is TrustedInstaller-owned; take ownership of the whole
            # package directory (a new .orig/.cat also needs dir write access).
            & takeown.exe /f $bd /r /d y 2>&1 | Out-Null
            & icacls.exe $bd /grant '*S-1-5-32-544:(OI)(CI)F' /t 2>&1 | Out-Null
            if (-not (Test-Path -LiteralPath "$bound.orig")) {
                try { Copy-Item -LiteralPath $bound -Destination "$bound.orig" -Force -ErrorAction Stop }
                catch { Write-Host "note: backup skipped ($($_.Exception.Message))" }
            }
            Copy-Item -LiteralPath $patched -Destination $bound -Force -ErrorAction Stop
            # the package must stay coherent: same-name .cat/.inf covering the new .sys
            foreach ($pair in @(@((Join-Path $stage 'AltA2DP.cat'), 'AltA2DP.cat'),
                                 @((Join-Path $stage 'AltA2DP.inf'), 'AltA2DP.inf'))) {
                try { Copy-Item -LiteralPath $pair[0] -Destination (Join-Path $bd $pair[1]) -Force -ErrorAction Stop }
                catch { Write-Host "note: could not refresh $($pair[1]): $($_.Exception.Message)" }
            }
            Write-Host "patched: $bound (+ cat/inf)"
        } catch {
            Write-Host "note: in-place DriverStore overwrite blocked ($($_.Exception.Message))"
            Write-Host "      the staged package (higher DriverVer) will take over on reconnect"
        }
    } else {
        Write-Host 'note: could not resolve the bound DriverStore copy; staged package only'
    }

    # 5. keep the Program Files copy in sync (harmless, and some tools read it)
    $pf = 'C:\Program Files\Luculent Systems\AltA2DP\Driver\AltA2DP.sys'
    if (Test-Path -LiteralPath $pf) {
        if (-not (Test-Path -LiteralPath "$pf.orig")) {
            Copy-Item -LiteralPath $pf -Destination "$pf.orig" -Force -ErrorAction SilentlyContinue
        }
        Copy-Item -LiteralPath $patched -Destination $pf -Force -ErrorAction SilentlyContinue
    }

    # 6. force the bound A2DP node to re-evaluate its driver
    & pnputil.exe /scan-devices | Out-Null
    $dev = Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match '0000110B-0000-1000-8000-00805F9B34FB' -and $_.Status -eq 'OK' }
    foreach ($d in $dev) {
        try {
            Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
            Enable-PnpDevice  -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
            Write-Host "rebound: $($d.InstanceId)"
        } catch {
            Write-Host "note: could not cycle $($d.InstanceId): $($_.Exception.Message)"
        }
    }

    if (-not $KeepTestsigning) {
        & bcdedit.exe /set testsigning on | Out-Null
        Write-Host 'test-signing: on'
    }
    Write-Host 'installed - reboot recommended'
}

exit 0
