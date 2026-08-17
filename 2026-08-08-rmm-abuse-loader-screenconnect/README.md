# RMM abuse loader — ScreenConnect deployed via PyInstaller

*Detonated 2026-08-08 · severity **critical** · 0 correlated alerts across 0 rules*

**Tags:** `malware`, `sample-a`, `screenconnect`, `rmm-abuse`, `pyinstaller`, `workshop`, `secdis`, `T1219`, `T1562`


## Analysis

> Detonated in the workshop as **Sample A**. That label is kept in the quoted commands and
> file paths below because it is what the telemetry actually recorded — the directory on disk
> really was `Sample A`.

### Investigation
**Host:** `secdis` (192.168.2.2) · **User:** `analyst` · **Detonated:** 2026-08-08 15:59 UTC · **Status:** terminated (no activity after 16:27) · **Detections:** 76 Elastic Defend alerts

---

## Step 1 — Overview
The ScreenConnect RMM loader is a **PyInstaller-packaged Python dropper** that installs a **ScreenConnect (ConnectWise Control) RMM** implant for remote access and performs **aggressive Microsoft Defender neutralization**. Delivered as a 7-Zip archive, executed manually by the user.

## Step 2 — Layer 1: Initial Access / Delivery
- Archive extracted via **7-Zip** (`7zG.exe x`) to `C:\Users\analyst\Downloads\Sample A\`.
- User launched the sample from Explorer (T1204 User Execution).

## Step 3 — Layer 2: Execution & Payload
- Sample runs as a **PyInstaller** bundle (artifacts: `%Temp%\_MEI*` + `base_library.zip`).
- Drops second-stage payload **`C:\ProgramData\Microsoft\Windows\9yxt0.exe`** (masqueraded in a system-like path).

## Step 4 — Layer 3: RMM Deployment (ScreenConnect)
- Installs/executes **ScreenConnect 25.3.4.9288** via:
  `powershell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -File "C:\Windows\SystemTemp\ScreenConnect\25.3.4.9288\UcVUmdnD5EmUrun.ps1"`
- Provides attacker remote control (T1219 Remote Access Software).

## Step 5 — Layer 4: Defense Evasion
- **Defender exclusions** added via **PowerShell AND WMI**:
  - Paths: `C:\Users\analyst\Downloads\Sample A`, `%Temp%`, `C:\Users\Public\AccountPictures\tesurov`
  - Drives: `D:` `E:` `F:` `G:` `X:` `Y:` `Z:`
  - Processes: `cmd.exe`, `clip.exe`
- **UAC disabled** via registry modification.
- **PowerShell script-block logging disabled.**

## Step 6 — Layer 5: Command & Control / Network
- **`198.23.185.237:8041`** — ScreenConnect relay (port 8041 = ScreenConnect default), egress confirmed from victim in OPNsense firewall logs.
- Excluded: `172.211.123.249:443` — evaluated and found to be legitimate Azure/Microsoft traffic (svchost/msedge), NOT C2.

## Step 7 — MITRE ATT&CK
- Execution: T1204 User Execution, T1059.001 PowerShell
- Defense Evasion: T1562.001 Impair Defenses, T1112 Modify Registry, T1548.002 UAC Bypass, T1027 Obfuscated Files, T1620 Reflective Loading
- Persistence / C2: T1219 Remote Access Software (ScreenConnect)
- Collection: T1560 Archive Collected Data

## Step 8 — Detections (76 Elastic Defend alerts)
Malware Detection (on-disk), Windows Defender Exclusions via WMI, Windows Defender Exclusions via PowerShell, Suspicious Windows Defender Exclusions Added via PowerShell, Disabling User Account Control via Registry, PowerShell Script Block Logging Disabled, Suspicious Windows Schedule Child Process, File Compressed/Archived by Unsigned Process.

## Step 9 — Visibility Gap (finding)
Raw endpoint **event** telemetry (Elastic Defend `endpoint.events.*` and Sysmon) is **absent for the detonation window 15:59–16:27**; both resumed at **16:27:20** with `elastic_agent` "failed to index document" errors. Elastic Defend **alerts** (fast path) were unaffected — this reconstruction is alert-derived. Recommend investigating the secdis agent event-shipping interruption (possible malware interference with logging vs. an ingest/mapping failure).

---

## Step 10 — Indicators of Compromise (IOCs)

### File hashes
| Type | Value | Artifact |
|---|---|---|
| SHA256 | `12833af0f0d1c3c193cf0aeadb7c2dbb3b6b9f4a600e65b43e3997fcd6621e88` | the ScreenConnect RMM loader (dropper) |
| imphash | `dcaf48c1f10b0efa0a4472200f3850ed` | the ScreenConnect RMM loader |
| SHA256 | `4f8f750ffdd2a5df67946fdd29d4bb7a2d9b88d8495f9980d99f03e053f3b0a0` | Dropped payload `9yxt0.exe` |

### File-system artifacts
- `C:\Users\analyst\Downloads\Sample A\12833af0…6621e88.exe` (sample)
- `C:\ProgramData\Microsoft\Windows\9yxt0.exe` (dropped payload)
- `C:\Windows\SystemTemp\ScreenConnect\25.3.4.9288\UcVUmdnD5EmUrun.ps1` (ScreenConnect installer script)
- `C:\Users\Public\AccountPictures\tesurov` (staging directory)
- `%Temp%\_MEI*\base_library.zip` (PyInstaller unpack)

### Network artifacts
- **C2:** `198.23.185.237` **port `8041`** (ScreenConnect relay) — TCP
- Excluded (benign): `172.211.123.249:443` (Azure/Microsoft)

### Host artifacts
- Windows Defender exclusion paths: drives `D:–G:`, `X:–Z:`; `%Temp%`; `C:\Users\Public\AccountPictures\tesurov`; `Downloads\Sample A`
- Excluded processes: `cmd.exe`, `clip.exe`


## Detection results

Rules that fired, by alert volume:


_none_


## MITRE ATT&CK


_none_


## Indicators

_none_


## Attribution

**Family:** `elf.kuiper` (ThreatFox, confidence 95) — **recorded, not adopted**

**Sample SHA256:** `12833af0f0d1c3c193cf0aeadb7c2dbb3b6b9f4a600e65b43e3997fcd6621e88`

**MalwareBazaar filename:** `composer.dat`

ThreatFox labels this hash `elf.kuiper` (confidence 95). That is **not adopted here**: Kuiper is ransomware, the artefact is a Windows PE (MalwareBazaar `magika: pebin`) rather than an ELF, and nothing in the detonation encrypted anything. Named by observed behaviour instead.

## Provenance

Extracted from Elastic case `26ce6f7b-8cae-4ff9-910f-9fea0e5ade4e`. The case remains the live record; this is the written-up analysis.

Sources for attribution: the abuse.ch ThreatFox and MalwareBazaar feeds as ingested into this
lab's Elastic cluster, matched by exact SHA256. Community-sourced labels; treated as evidence,
not as ground truth.
