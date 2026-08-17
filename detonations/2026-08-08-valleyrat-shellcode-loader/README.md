# ValleyRAT — shellcode loader with EDR evasion and Defender tampering

*Detonated 2026-08-08 · severity **critical** · 324 correlated alerts across 39 rules*

**Tags:** `malware`, `sample-c`, `shellcode-loader`, `edr-evasion`, `scheduled-task`, `defender-tamper`, `c2`, `threat-intel-match`, `workshop`, `analysis-host`, `T1055`, `T1053`, `T1562`

**Alert window:** 2026-08-08T17:28:17Z → 2026-08-08T17:36:33Z

**Host:** analysis-host (324)


## Analysis

> Detonated in the workshop as **Sample C**. That label is kept in the quoted commands and
> file paths below because it is what the telemetry actually recorded — the directory on disk
> really was `Sample C`.

### Investigation
**Host:** `analysis-host` (<analysis-host-ip>) · **User:** `analyst` · **Detonated:** 2026-08-08 17:27:55 UTC · **Alert window:** 17:28:17–17:34:53 · **Detections:** 319 Elastic Defend/SIEM alerts · **Telemetry:** healthy (clock correct; Aug-6 backlog from an earlier snapshot filtered out)

---

## Step 1 — Overview
ValleyRAT is an unsigned **shellcode-injecting loader** with heavy **EDR/AV evasion** (direct syscalls, unbacked shellcode) and **SYSTEM-level Windows Defender neutralization via scheduled tasks**. It drops a secondary payload and beacons to **threat-intel-confirmed C2**. Most capable of the samples tested.

## Step 2 — Layer 1: Delivery & Execution
- 7-Zip (`7zFM.exe`→`7zG.exe x`) extracted the archive to `C:\Users\analyst\Downloads\a43853c1…\`.
- `explorer.exe` → **Sample C** `C:\Users\analyst\Downloads\Sample C\a43853c1…efdb47c.exe` at 17:27:55 (ProblemChild-flagged), then self-spawned.

## Step 3 — Layer 2: Payload Drop & Shellcode Injection
- Dropped/ran **`C:\Users\Public\Br3N37\xhMLks.exe`** (launched via `svchost.exe`).
- **Shellcode injection & execution** — Memory Threat: Shellcode Injection ×20; Unbacked Shellcode from Unsigned Module; **Direct Syscall from Unsigned Module** (EDR bypass); Network Module Loaded from Suspicious Unbacked Memory; VirtualAlloc from unsigned DLL.

## Step 4 — Layer 3: Privilege Escalation & Defense Evasion (SYSTEM)
- **PowerShell**: `Add-MpPreference -ExclusionPath 'C:\ProgramData','C:\Users','C:\Program Files (x86)','C:\'` (excludes the entire C: drive).
- **SYSTEM scheduled-task loop**: repeatedly `SCHTASKS /Create /F /TN "Task1" /SC ONCE /RL HIGHEST /RU "SYSTEM" /TR "cmd.exe /c reg add …\Windows Defender\Exclusions…"` → `/Run` → `/Delete` — runs `reg add` as SYSTEM to add Defender exclusions, bypassing UAC (×60 scheduled-task creations).
- Also: Defender exclusions via WMI; Disable Defender via PowerShell; **UAC disabled**; **service disabled** via registry; **WDAC policy** written by an unusual process.
- ⚠️ **Elastic Defend Alert Followed by Telemetry Loss ×4** — the sample degraded endpoint telemetry (EDR tampering).

## Step 5 — Layer 4: Persistence
- Scheduled tasks (see above) · **Startup/Run Key** registry modification · Suspicious string value written to a Run key.

## Step 6 — Layer 5: Command & Control (threat-intel confirmed)
- **`134.209.42.122`** — **Threat-Intel IP Indicator Match** (62 alerts; bidirectional beaconing). Highest-confidence C2.
- **`39.103.20.88:443`**, **`47.79.64.254:443`** — endpoint-observed HTTPS egress (Alibaba Cloud ranges).
- 29× **Threat-Intel Hash Indicator Match** (sample/components matched known-bad hashes).

## Step 7 — MITRE ATT&CK
- Execution: T1204 User Execution, T1059.001 PowerShell, T1053.005 Scheduled Task, T1106 Native API (direct syscalls)
- Defense Evasion: T1562.001 Impair Defenses, T1055 Process Injection (shellcode), T1620 Reflective Loading, T1548.002 UAC Bypass, T1112 Modify Registry, T1562 (WDAC/Defend telemetry)
- Persistence / PrivEsc: T1053.005 Scheduled Task (SYSTEM), T1547.001 Run Key
- Command & Control: T1071.001 / T1571 (HTTPS)

## Step 8 — Detections (319 alerts, top)
Threat Intel IP Match ×62 · Local Scheduled Task Creation ×60 · Threat Intel Hash Match ×29 · Malware Detection ×20 · Memory Threat: Shellcode Injection ×20 · Suspicious Scheduled Task ×14 · Direct Syscall from Unsigned Module ×12 · Shellcode from Low-Rep Module ×12 · (+ Defender-exclusion, UAC, service-disable, Run-key, telemetry-loss, etc.)

---

## Step 9 — Indicators of Compromise (IOCs)

### File hashes
| Type | Value | Artifact |
|---|---|---|
| SHA256 | `a43853c12573d2dd8792b2380c895118266c289f10e659c457354a009efdb47c` | ValleyRAT (loader) |
| imphash | `380560563ebacca1589d8d38ac610187` | ValleyRAT |
| SHA256 | `676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7` | dropped `xhMLks.exe` |
| imphash | `c79e73eafa46ab4b3f81c361fe54c70d` | `xhMLks.exe` (signed/trusted — abused) |

### Network artifacts (C2)
- `134.209.42.122` — **threat-intel-matched** C2 (DigitalOcean)
- `39.103.20.88:443` — C2 (HTTPS)
- `47.79.64.254:443` — C2 (HTTPS)

### File-system / host artifacts
- `C:\Users\analyst\Downloads\Sample C\a43853c1…efdb47c.exe` (sample)
- `C:\Users\Public\Br3N37\xhMLks.exe` (dropped payload / staging dir `C:\Users\Public\Br3N37`)
- Scheduled task name: `Task1` (run-once, `/RU SYSTEM`)
- Defender exclusion paths added: `C:\`, `C:\Users`, `C:\ProgramData`, `C:\Program Files (x86)`


## Detection results

Rules that fired, by alert volume:


| Rule | Alerts |
|---|---|
| `Threat Intel IP Address Indicator Match` | 62 |
| `Local Scheduled Task Creation` | 60 |
| `Threat Intel Hash Indicator Match` | 29 |
| `Memory Threat Detection Alert: Shellcode Injection` | 20 |
| `Malware Detection Alert` | 20 |
| `Malicious Behavior Detection Alert: Suspicious Scheduled Task Creation` | 14 |
| `Malicious Behavior Detection Alert: Direct Syscall from Unsigned Module` | 12 |
| `Malicious Behavior Detection Alert: Shellcode Execution from Low Reputation Module` | 12 |
| `File and Directory Permissions Modification` | 10 |
| `Malicious Behavior Detection Alert: Shellcode Injection with Parent as Provenance` | 10 |
| `Malicious Behavior Detection Alert: Unbacked Shellcode from Unsigned Module` | 10 |
| `Malicious Behavior Detection Alert: Potential Process Creation via ShellCode` | 6 |
| `Unsigned DLL Loaded by a Trusted Process` | 6 |
| `Elastic Defend Alert Followed by Telemetry Loss` | 4 |
| `Windows Defender Exclusions Added via PowerShell` | 4 |
| `Disabling Windows Defender Security Settings via PowerShell` | 4 |
| `Malicious Behavior Detection Alert: Windows Defender Exclusions via WMI` | 4 |
| `Svchost spawning Cmd` | 3 |
| `Malicious Behavior Detection Alert: Network Module Loaded from Suspicious Unbacked Memory` | 2 |
| `Malicious Behavior Detection Alert: Scheduled Task by a Low Reputation Process` | 2 |
| `Malicious Behavior Detection Alert: Scheduled Task from a Browser or Compression Utility Descendant` | 2 |
| `Malicious Behavior Detection Alert: Scheduled Task Creation by an Unusual Process` | 2 |
| `Malicious Behavior Detection Alert: Suspicious Windows Schedule Child Process` | 2 |
| `Malicious Behavior Detection Alert: Untrusted DLL Loaded by a Persistent Program` | 2 |
| `Malicious Behavior Detection Alert: Unsigned DLL from Suspicious Directory` | 2 |
| `Malicious Behavior Detection Alert: Native API Call from Unsigned Module` | 2 |
| `Malicious Behavior Detection Alert: VirtualAlloc API Call from an Unsigned DLL` | 2 |
| `Malicious Behavior Detection Alert: Suspicious String Value Written to Registry Run Key` | 2 |
| `Malicious Behavior Detection Alert: Suspicious Windows Defender Exclusions Added via PowerShell` | 2 |
| `Malicious Behavior Detection Alert: Suspicious NTDLL Image Load` | 2 |
| `Process Execution from an Unusual Directory` | 2 |
| `File or Directory Deletion Command` | 1 |
| `Disabling User Account Control via Registry Modification` | 1 |
| `Service Control Spawned via Script Interpreter` | 1 |
| `Unsigned DLL Side-Loading from a Suspicious Folder` | 1 |
| `Service Disabled via Registry Modification` | 1 |
| `Startup or Run Key Registry Modification` | 1 |
| `WDAC Policy File by an Unusual Process` | 1 |
| `Executable File with Unusual Extension` | 1 |


Alert severity spread: **critical** 132, **high** 96, **low** 84, **medium** 12


## MITRE ATT&CK


| Tactic | Alerts |
|---|---|
| Persistence | 61 |
| Defense Evasion | 48 |
| Execution | 26 |
| Privilege Escalation | 2 |
| Impact | 1 |


Techniques observed: `T1036` Masquerading, `T1036.001` Invalid Code Signature, `T1036.005` Match Legitimate Resource Name or Location, `T1036.008` Masquerade File Type, `T1047` Windows Management Instrumentation, `T1053` Scheduled Task/Job, `T1053.005` Scheduled Task, `T1055` Process Injection, `T1059` Command and Scripting Interpreter, `T1059.001` PowerShell, `T1059.003` Windows Command Shell, `T1059.005` Visual Basic, `T1070` Indicator Removal, `T1070.004` File Deletion, `T1112` Modify Registry, `T1204` User Execution, `T1204.002` Malicious File, `T1218` System Binary Proxy Execution, `T1218.005` Mshta, `T1218.010` Regsvr32, `T1218.011` Rundll32, `T1222` File and Directory Permissions Modification, `T1222.001` Windows File and Directory Permissions Modification, `T1489` Service Stop, `T1543` Create or Modify System Process, `T1543.003` Windows Service, `T1547` Boot or Logon Autostart Execution, `T1547.001` Registry Run Keys / Startup Folder, `T1548` Abuse Elevation Control Mechanism, `T1548.002` Bypass User Account Control, `T1562` Impair Defenses, `T1562.001` Disable or Modify Tools, `T1562.006` Indicator Blocking, `T1569` System Services, `T1569.002` Service Execution, `T1574` Hijack Execution Flow, `T1574.001` DLL, `T1620` Reflective Code Loading


## Indicators

| Type | Value |
|---|---|
| SHA256 | `a43853c12573d2dd8792b2380c895118266c289f10e659c457354a009efdb47c` |
| SHA256 | `41f186e02c63bedd94c6451ab99259f28ec627528e9ad7072b4b436039d57e16` |
| SHA256 | `501a00cb66e3e45a4de890e81d3540e368e8616d3d478b58e61b9223d3869349` |
| SHA256 | `2363383be9c4b6f815cb0192ccd5efab0658d508402de1bf00c4d9617416688c` |
| SHA256 | `f0a10f8d919b4e785e04461ed2adde2d51608e50f69e1e4995c85b71472272b8` |
| SHA256 | `e5e88e145be3add238e49244361c50c501213264307bbb7143f7dd0cef720119` |
| IP | `134.209.42.122` (threat-intel matched) |
| IP | `39.103.20.88:443` |
| IP | `47.79.64.254:443` |


## Processes seen in alerts

| Process | Alerts |
|---|---|
| `xhMLks.exe` | 52 |
| `a43853c12573d2dd8792b2380c895118266c289f10e659c457354a009efdb47c.exe` | 43 |
| `schtasks.exe` | 34 |
| `cmd.exe` | 30 |
| `yYRb4B.exe` | 28 |
| `powershell.exe` | 14 |
| `Fqvg0m6.exe` | 10 |
| `icacls.exe` | 10 |
| `f0a10f8d919b4e785e04461ed2adde2d51608e50f69e1e4995c85b71472272b8.exe` | 9 |
| `7zG.exe` | 4 |
| `System` | 2 |
| `sc.exe` | 1 |


## Attribution

**Family:** `win.valley_rat` (ThreatFox, confidence 95) — adopted

**Sample SHA256:** `a43853c12573d2dd8792b2380c895118266c289f10e659c457354a009efdb47c`

**MalwareBazaar filename:** `install_b0n010.exe`

ThreatFox labels this hash `win.valley_rat` (confidence 95). Adopted: it agrees with what was observed — shellcode injection, scheduled-task persistence and Defender tampering are all characteristic of ValleyRAT (also tracked as Winos).

## Provenance

Extracted from Elastic case `74b26185-dcfc-4188-9cbc-e2065b0d75fc`. The case remains the live record; this is the written-up analysis.

Sources for attribution: the abuse.ch ThreatFox and MalwareBazaar feeds as ingested into this
lab's Elastic cluster, matched by exact SHA256. Community-sourced labels; treated as evidence,
not as ground truth.
