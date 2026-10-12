# AltA2DP PowerShell patchers

> ## ⚠️ Read this first
>
> **`AltA2DP-PatchTool.ps1` requires test mode ON and Secure Boot OFF.**
> The patched driver is signed with a locally-trusted certificate, which the
> kernel only accepts while test-signing is enabled, and Secure Boot cannot be
> enabled while test-signing is active.
>
> **This may cause problems with kernel-level anti-cheat.** Test-signing turns
> off one of the checks anti-cheat drivers rely on, and some anti-cheat systems
> refuse to run — or flag the machine — when it is enabled or when an
> unsigned/self-signed driver is loaded. Expect this to be unsafe on a PC used
> for competitive online games.
>
> **Using the driver after the trial expires requires `AltA2DP-PatchTool.ps1`.**
> Once the 7-day trial ends, the driver connects the headphones but produces no
> sound. `AltA2dpSetup-Patch.ps1` and `AltA2dpConfig-Patch.ps1` fix the licence
> UI only — they do not touch the driver, so they cannot restore audio. The
> driver-side patch is the only thing that does.
>
> It is the only script here that touches the kernel driver.
> `AltA2dpSetup-Patch.ps1`, `AltA2dpConfig-Patch.ps1` and
> `Verify-LoadedDriver.ps1` work on a normal, Secure Boot-enabled system.

Standalone PowerShell scripts for the **Alternative A2DP Driver 1.8.3.1**
(Luculent Systems). Each one targets a different piece of the product.
All offsets are hardcoded for 1.8.3.1 — they will not work on other versions.

| script | target | needs test-signing? |
|---|---|---|
| `AltA2dpSetup-Patch.ps1` | the vendor MSI installer | no |
| `AltA2dpConfig-Patch.ps1` | the userspace `AltA2dpConfig.exe` | no |
| `AltA2DP-PatchTool.ps1` | the kernel driver `AltA2DP.sys` (hashfix build) | **yes** |
| `Verify-LoadedDriver.ps1` | read-only: reports which `AltA2DP.sys` is loaded | no |

> **`-Install` behaviour.** Two failure modes are handled explicitly, because
> both used to leave the machine silently on the stock driver:
> 1. `New-FileCatalog` fails if `build\catbuild\AltA2DP.cat` already exists from
>    a previous run, which aborted the script *before* the install step. The cat
>    is now deleted first and the result is size-checked.
> 2. Overwriting `DriverStore\FileRepository\*\AltA2DP.sys` in place is blocked
>    by TrustedInstaller ACLs (access denied). The install now (a) builds a
>    staged package with a `DriverVer` strictly above every installed copy and
>    registers it with `pnputil`, and (b) best-effort takes ownership of the
>    currently-bound store directory and replaces that copy too, so a
>    disconnected headset still picks up the patch on its next connect.
>
> **Always verify after install.** Run `.\Verify-LoadedDriver.ps1`. The file the
> service points at (`Get-CimInstance Win32_SystemDriver -Filter "Name='AltA2DP'"`)
> must be 972200 bytes with state bytes `83 F8 06 EB 27`. If it is still 823304
> bytes with `83 F8 06 75 22`, the install did not take — do not report success.

---

## AltA2dpSetup-Patch.ps1

Takes the stock vendor MSI and produces a patched installer.

```powershell
.\AltA2dpSetup-Patch.ps1 -InMsi C:\path\AlternativeA2dpSetup-1.8.3.1.msi
```

Output defaults to `<name>.patched.msi` next to the source.

**What it changes**

1. **LaunchCondition** — lowers the OS build floors by equal-length substitution
   (`26100 → 22000` ARM64, `19045 → 19041` x64) and deletes the two hardware
   prerequisite rows `Installed OR (NOT AaNoHc)` (no Bluetooth radio present)
   and `Installed OR (NOT Aa3pSvc)` (third-party A2DP service running).
2. **Payload cab** — extracts `media1.cab`, applies the three licence stubs plus
   the telemetry host rename to `fAltA2dpConfig`, rebuilds it with `makecab`,
   and writes it back through a raw CFB stream rewrite.

| switch | effect |
|---|---|
| `-OutMsi <path>` | write somewhere else |
| `-SkipExePatch` | lower the OS floors only, leave the payload alone |
| `-KeepWork` | keep the temp staging directory |

**Note:** the cab swap is done by direct CFB editing, not COM —
`Record.SetStream()` inside an `UPDATE _Streams` view corrupts the MSI.

**Note:** this ships the **stock driver** in the payload. It fixes the licence
UI only; the AAC watermark lives in the driver and needs `AltA2DP-PatchTool.ps1`.

---

## AltA2dpConfig-Patch.ps1

Patches `AltA2dpConfig.exe` so the UI reports a perpetual, AAC-capable licence.
Use this if you already have the driver installed.

```powershell
.\AltA2dpConfig-Patch.ps1                                    # patch in place
.\AltA2dpConfig-Patch.ps1 -WhatIf                            # report only
.\AltA2dpConfig-Patch.ps1 -Restore                           # put .orig back
.\AltA2dpConfig-Patch.ps1 -InExe <in> -OutExe <out>          # file to file
```

Three licence-decision functions are rewritten to their "valid" returns:

| function | RVA | stub |
|---|---|---|
| paid check | `0xFC110` | `mov eax,7` (perpetual) + writes `"PERPETUAL\r"` |
| trial check | `0xC6D10` | `mov eax,6` (valid) + `INT64_MAX` expiry |
| ECDSA verify | `0xD6B40` | `mov eax,6` (pass) |

The stubs are position-independent and no larger than the code they replace, so
the image does not grow. An already-patched image is detected and left alone.

**Note:** this fixes the **UI only**. The AAC watermark is enforced by the
driver — see `AltA2DP-PatchTool.ps1`.

---

## AltA2DP-PatchTool.ps1

Patches a stock `AltA2DP.sys` into the hashfix build, then signs it and builds a
catalog.

> ⚠️ **Requires test mode ON and Secure Boot OFF.**
> The patched driver is signed with a locally-trusted certificate, which the
> kernel only accepts while test-signing is enabled. Secure Boot must be off —
> it cannot be enabled while test-signing is active, and it rejects this
> signature outright. Without both, Windows refuses to load the driver.
>
> ```powershell
> bcdedit /set testsigning on     # then reboot
> ```
>
> Revert with `bcdedit /set testsigning off`. The script enables test-signing
> itself when run with `-Install` (skip that with `-KeepTestsigning`).

```powershell
.\AltA2DP-PatchTool.ps1 -InSys C:\path\AltA2DP.sys     # patch + sign + catalog
.\AltA2DP-PatchTool.ps1 -PatchOnly                     # patch only, no signing
.\AltA2DP-PatchTool.ps1 -Install                       # ... and install it
```

With no `-InSys` the script auto-discovers installed copies and keeps only
genuine stock images (8 sections, gate `44 38`).

**Why the hashfix:** the driver SHA-512s its own code at startup and injects a
689 Hz tone into the PCM stream if the digest differs. Patching the code
directly therefore beeps. The fix keeps a verbatim copy of the original bytes
in a new `.origtx` section, points the hash at that copy, and executes the
patched code.

**The six edits**

| # | edit |
|---|---|
| 1 | snapshot the self-hashed window `[0x6CDA8, 0x94F48)` |
| 2 | strip the existing certificate |
| 3 | append `.origtx` holding that snapshot; section count 8 → 9 |
| 4 | retarget the two hash `lea` instructions at `.origtx` |
| 5 | flip the AAC gate `44 38` → `EB 49` at `0x8AFB3` |
| 6 | force the licensed branch `83 F8 06 75 22` → `83 F8 06 EB 27` at `0x8CEE1` (expired-trial fix) |

Edit 6 exists because the AAC encoder has a **second** licence test at
`0x14008C19A` that edit 5 does not reach. `sub_14008DA18` branches on the paid
verdict `n7 = sub_14007942C`, whose returns are `1, 3, 4, 6, 7` - **never 0**.
On a machine whose **trial has expired** (and with no paid licence) `n7 == 1`
matches **no** branch, so `0xFA8`, `0xFA9` and `0xFAA` all stay 0 and the
encoder skips its frame helper - **no audio at all**. Edit 6 turns the `jne`
after `cmp eax,6` into a `jmp` straight to the `n7 == 7` (fully licensed)
stores at `0x14008DB0D`, forcing `0xFA8 = 1, 0xFAA = 1` for every licence
state.

The PE checksum is then recomputed, the image signed (pinned cert, `-CertPath`
PFX, or a freshly created self-signed cert), and a `New-FileCatalog` v2 `.cat`
built and signed. Both signatures are hard-verified before the script continues.

| switch | effect |
|---|---|
| `-OutDir <path>` | output directory (default `build`) |
| `-PatchOnly` | patch only — runs unelevated, no signing |
| `-Install` | stage a higher-`DriverVer` package, `pnputil /add-driver /install`, and replace the currently-bound DriverStore copy |
| `-CertPath <pfx>` | sign with your own certificate |
| `-InfSrc <inf>` | INF to use for the catalog |
| `-KeepTestsigning` | do not run `bcdedit /set testsigning on` |

---

## Verify-LoadedDriver.ps1

Read-only diagnostic. Reports which `AltA2DP.sys` is actually installed and
loaded, so a "still no sound" report can be told apart from "the patch never
installed".

```powershell
.\Verify-LoadedDriver.ps1
```

For every `AltA2DP.sys` on disk it prints size, section count, gate bytes,
state bytes, and a verdict:

| state bytes | verdict |
|---|---|
| `83 F8 06 EB 27` | PATCHED (expired-trial fix present) |
| `83 F8 06 75 22` | STOCK (no expired-trial fix) |

The file the service points at is marked `<== LOADED`. Also dumps the `pnputil`
driver packages, the A2DP media node, recent CodeIntegrity events, and the
`testsigning` state.
