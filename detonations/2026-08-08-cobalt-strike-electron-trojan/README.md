# Cobalt Strike — shellcode beacon in a trojanised Electron app

*Detonated 2026-08-08 · severity **critical** · 101 correlated alerts across 15 rules*

**Tags:** `malware`, `sample-e`, `electron-trojan`, `shellcode`, `timestomp`, `ntdll-unhooking`, `c2`, `workshop`, `secdis`

**Alert window:** 2026-08-08T18:07:44Z → 2026-08-08T18:17:17Z

**Host:** secdis (101)


## Analysis

> Detonated in the workshop as **Sample E**. That label is kept in the quoted commands and
> file paths below because it is what the telemetry actually recorded — the directory on disk
> really was `Sample E`.

### Investigation
**Host:** `secdis` (192.168.2.2) · **User:** `analyst` · **Detonated:** 2026-08-08 18:07:15 UTC · **Alert window:** 18:07:44–18:12:15 · **Detections:** 93 alerts · **Family/attribution:** _left for analyst to determine from the IOCs below_

---

## Step 1 — Overview
The Cobalt Strike loader is delivered as a **trojanized Electron application** ("wczt-win-8.1.65-x64"). It side-loads shellcode with EDR-evasion (NTDLL unhooking), timestomps dropped files, and beacons to a Telegram-typosquat C2, pulling a stage from an AWS S3 bucket.

## Step 2 — Layer 1: Delivery & Execution
- 7-Zip-extracted to `C:\Users\analyst\Downloads\Sample E\`.
- `explorer.exe` → **loader** `39c69cb0…6c4f38.exe` (18:07:15) → spawns **`wczt-win-8.1.65-x64).exe`** (18:07:29) — the trojanized Electron installer.

## Step 3 — Layer 2: Payload Drop & Install
- `wczt-win…exe` → drops/runs **`C:\Users\Public\00C04FC964FF\6F9619FF.exe`** (staging dir + filename use well-known OLE GUID fragments as camouflage).
- Installs an Electron app **`C:\Users\analyst\AppData\Local\Programs\wczt\wczt.exe`** (user-data `%AppData%\Roaming\wczt`); self-checks with `tasklist | find "wczt.exe"`.
- Pulls a stage from **AWS S3**: `xjsjkjdsjjd.s3.ap-southeast-1.amazonaws.com` (`52.219.129.86`).

## Step 4 — Layer 3: Injection & Defense Evasion
- **Shellcode injection** (Memory Threat ×4), **Network Connect API from Unbacked Memory**, **NTDLL unhooking**, Suspicious NTDLL image load, Shellcode from Low-Reputation Module — EDR evasion.
- **Timestomping** ×34 ("Potential Timestomp in Executable Files" / spoofed image-load creation time) — T1070.006.
- Unsigned DLL side-loading from a suspicious folder; execution from unusual directory.
- ⚠️ "Elastic Defend Alert Followed by Telemetry Loss" ×2 (endpoint telemetry degradation).

## Step 5 — Layer 4: Command & Control
- **C2 domain: `dm.telegrem.store`** (22 alerts) — Telegram typosquat on abused `.store` TLD.
- **C2 IPs: `118.107.43.16`, `118.107.43.138`**.

## Step 6 — MITRE ATT&CK
- Execution: T1204 User Execution · Defense Evasion: T1055 Process Injection (shellcode), T1620 Reflective Loading, T1562.001 Impair Defenses, T1574.002 DLL Side-Loading, T1070.006 Timestomp, T1036 Masquerading · C2: T1071.001/T1102 (Telegram-typo domain, S3) · Ingress: T1105

## Step 7 — Detections (93 alerts, top)
Potential Timestomp ×34 · Network Activity to Suspicious TLD ×22 · Shellcode Injection (Memory Threat) ×4 · Network Connect API from Unbacked Memory ×4 · Malware Detection ×4 · Spoofed Image-Load Creation Time ×4 · Unsigned DLL Side-Loading ×3 · NTDLL unhooking / Suspicious NTDLL ×4 · Telemetry Loss ×2 · Windows.Trojan.Generic ×2

---

## Step 8 — Indicators of Compromise (IOCs)

### File hashes
| Type | Value | Artifact |
|---|---|---|
| SHA256 | `39c69cb0f29f8e9f41fa305cb1adf34762e5d8131ae348553b089377236c4f38` | the Cobalt Strike loader loader |
| imphash | `027ea80e8125c6dda271246922d4c3b0` | loader |
| SHA256 | `0f41af982ffa0570df698cf1f4227f8e5c5ee47820dc48bd647e077d611e8954` | `wczt-win-8.1.65-x64).exe` (Electron installer) |
| imphash | `9a2d056f27357b32cd4253e7955deb15` | wczt installer (signature invalid — `errorBadDigest`) |

### Network artifacts
- **C2 domain:** `dm.telegrem.store` (Telegram typosquat, `.store` TLD)
- **C2 IPs:** `118.107.43.16`, `118.107.43.138`
- **Payload host (AWS S3):** `xjsjkjdsjjd.s3.ap-southeast-1.amazonaws.com` (`52.219.129.86`)

### File-system artifacts
- `C:\Users\analyst\Downloads\Sample E\39c69cb0…6c4f38.exe` (loader)
- `C:\Users\analyst\Downloads\Sample E\wczt-win-8.1.65-x64).exe` (Electron installer)
- `C:\Users\Public\00C04FC964FF\6F9619FF.exe` (dropped)
- `C:\Users\analyst\AppData\Local\Programs\wczt\wczt.exe` + `%AppData%\Roaming\wczt` (installed app)


## Detection results

Rules that fired, by alert volume:


| Rule | Alerts |
|---|---|
| `Potential Timestomp in Executable Files` | 34 |
| `Network Activity to a Suspicious Top Level Domain` | 30 |
| `Memory Threat Detection Alert: Shellcode Injection` | 4 |
| `Malware Detection Alert` | 4 |
| `Malicious Behavior Detection Alert: Network Connect API from Unbacked Memory` | 4 |
| `Malicious Behavior Detection Alert: Potential Image Load with a Spoofed Creation Time` | 4 |
| `Process Execution from an Unusual Directory` | 4 |
| `Unsigned DLL Side-Loading from a Suspicious Folder` | 3 |
| `Elastic Defend Alert Followed by Telemetry Loss` | 2 |
| `File Compressed or Archived into Common Format by Unsigned Process` | 2 |
| `Memory Threat Detection Alert: Windows.Trojan.Generic` | 2 |
| `Malicious Behavior Detection Alert: Execution from Suspicious Directory` | 2 |
| `Malicious Behavior Detection Alert: Suspicious NTDLL Image Load` | 2 |
| `Malicious Behavior Detection Alert: Potential NTDLL Memory Unhooking` | 2 |
| `Malicious Behavior Detection Alert: Shellcode Execution from Low Reputation Module` | 2 |


Alert severity spread: **critical** 26, **high** 32, **low** 2, **medium** 41


## MITRE ATT&CK


| Tactic | Alerts |
|---|---|
| Defense Evasion | 78 |
| Command and Control | 32 |
| Execution | 4 |
| Collection | 2 |


Techniques observed: `T1027` Obfuscated Files or Information, `T1027.015` Compression, `T1036` Masquerading, `T1036.001` Invalid Code Signature, `T1036.005` Match Legitimate Resource Name or Location, `T1055` Process Injection, `T1070` Indicator Removal, `T1070.006` Timestomp, `T1071` Application Layer Protocol, `T1071.004` DNS, `T1074` Data Staged, `T1074.001` Local Data Staging, `T1127` Trusted Developer Utilities Proxy Execution, `T1127.001` MSBuild, `T1132` Data Encoding, `T1132.001` Standard Encoding, `T1204` User Execution, `T1204.002` Malicious File, `T1218` System Binary Proxy Execution, `T1560` Archive Collected Data, `T1560.001` Archive via Utility, `T1562` Impair Defenses, `T1562.001` Disable or Modify Tools, `T1574` Hijack Execution Flow, `T1574.001` DLL, `T1620` Reflective Code Loading


## Indicators

| Type | Value |
|---|---|
| SHA256 (sample) | `39c69cb0f29f8e9f41fa305cb1adf34762e5d8131ae348553b089377236c4f38` |
| SHA256 (component) | `0f41af982ffa0570df698cf1f4227f8e5c5ee47820dc48bd647e077d611e8954` |
| Domain (C2) | `dm.telegrem.store` |
| IP | `118.107.43.16` |
| IP | `118.107.43.138` |
| Payload host | `xjsjkjdsjjd.s3.ap-southeast-1.amazonaws.com` |


## Processes seen in alerts

| Process | Alerts |
|---|---|
| `6F9619FF.exe` | 61 |
| `wczt-win-8.1.65-x64).exe` | 37 |
| `39c69cb0f29f8e9f41fa305cb1adf34762e5d8131ae348553b089377236c4f38.exe` | 2 |
| `wczt.exe` | 1 |


## Attribution

**Family:** `win.cobalt_strike` (ThreatFox, confidence 95) — adopted

**Sample SHA256:** `39c69cb0f29f8e9f41fa305cb1adf34762e5d8131ae348553b089377236c4f38`

**MalwareBazaar filename:** `wczt-win-8.1.65-x64 (1).exe`

ThreatFox labels this hash `win.cobalt_strike` across four separate entries (confidence 95). Adopted: shellcode execution with ntdll unhooking, timestomping and C2 is consistent with a Cobalt Strike beacon delivered inside a trojanised Electron application.

## Provenance

Extracted from Elastic case `3e635dd6-62fa-4f4f-869f-509a831800f1`. The case remains the live record; this is the written-up analysis.

Sources for attribution: the abuse.ch ThreatFox and MalwareBazaar feeds as ingested into this
lab's Elastic cluster, matched by exact SHA256. Community-sourced labels; treated as evidence,
not as ground truth.
