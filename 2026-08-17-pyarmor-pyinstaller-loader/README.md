# PyArmor-obfuscated PyInstaller loader — Defender exclusion abuse via WMIC (SECDIS, 2026-08-17)

*Detonated 2026-08-17 · severity **high** · 69 correlated alerts across 17 rules*

**Tags:** `malware`, `loader`, `pyinstaller`, `pyarmor`, `defense-evasion`, `wmic`, `defender-exclusion`, `detonation`, `sigma`, `secdis`, `T1027.002`, `T1562.001`, `T1047`, `T1204.002`

**Alert window:** 2026-08-17T10:23:34Z → 2026-08-17T10:35:59Z

**Host:** secdis (63), util-debian (1)


## Analysis

## Summary

A PyInstaller-packaged, **PyArmor-obfuscated Python loader** was detonated on `SECDIS` (192.168.2.2) at **10:22:48 UTC on 2026-08-17**. It extracted its obfuscated payload to `%TEMP%\_MEI*`, used **WMIC** to add Microsoft Defender exclusions for its own download directory and a `C:\Users\Public` staging path, then **exited cleanly without retrieving a second stage, establishing persistence, or contacting any C2**.

Sample: `d97ea10d1dbfe2a69e0d2387e8985635b20628495918abd54c4b052c0acf05b1` (MalwareBazaar; ships in the wild as `composer.php.exe`, imitating a Composer artefact so a developer double-clicking it believes they are opening a PHP file).

**Assessment: a first-stage loader that prepared the ground and declined to deploy.** It carved out Defender exclusions and then never wrote to the path it had just excluded. Because it made *no network attempt at all* — rather than a failed one — the most probable explanation is anti-analysis logic aborting execution, not dead infrastructure. A payload whose C2 was merely unreachable would still show a connection attempt in endpoint telemetry.

## Timeline (UTC)

| Time | Event | Evidence |
|---|---|---|
| 10:21:22 | Sample downloaded from `bazaar.abuse.ch` | Squid proxy log, Edge user-agent |
| 10:22:48 | `explorer.exe` launches the sample from `C:\Users\analyst\Downloads\` | endpoint.events.process |
| 10:22:50 | PyInstaller unpacks to `_MEI161842`, `_MEI57082`, `_MEI29322`; `pyarmor_runtime.pyd` written to each | endpoint.events.file |
| 10:22:59 | Payload spawns `cmd.exe` | endpoint.events.process |
| 10:23:08 | `cmd.exe /c wmic ... MSFT_MpPreference call Add ExclusionPath="C:\Users\analyst\Downloads"` | process command line |
| 10:23:09 | Second exclusion: `ExclusionPath="C:\Users\Public\IIPaint\ceduwoc"` | process command line |
| 10:23:02-13 | All six sample processes exit, **code 0** | process end events |
| - | **No further activity. Nothing was ever written to the excluded staging path.** | file telemetry |

**Elapsed download to execution: 86 seconds.**

## What it did

1. **T1204.002 User Execution: Malicious File** - launched interactively from `Downloads` by `explorer.exe`.
2. **T1027.002 Obfuscated Files: Software Packing** - PyInstaller one-file extraction to `%TEMP%\_MEI*`, with `pyarmor_runtime_000000\pyarmor_runtime.pyd` in each. The bundled bytecode was deliberately obfuscated with PyArmor before packaging. Three separate extractions, as it ran three times.
3. **T1059 Command and Scripting Interpreter** - `cmd.exe` used as the launcher for WMIC.
4. **T1562.001 / T1564.012 Impair Defenses: Disable or Modify Tools / File-Path Exclusions** - Defender exclusions added through the `MSFT_MpPreference` WMI class rather than the `Add-MpPreference` cmdlet. Administrators and vendor installers overwhelmingly use the cmdlet, so the WMIC path is a strong signal of automated payload behaviour.
5. **T1047 Windows Management Instrumentation** - WMIC as the execution vehicle for step 4.

## What it did NOT do, corroborated four ways

**No C2, no second-stage download, no exfiltration:**

- **Endpoint network telemetry** - zero connection events attributed to the sample or any child (`cmd.exe`, `WMIC.exe`). Elastic Defend records connection *attempts*, so a blocked or failed connection would still appear. There were none.
- **DNS** - only Microsoft names resolved during the window.
- **Firewall** - no blocked egress from 192.168.2.2.
- **Squid proxy, 874 parsed records across 10:20-11:10** - every non-Microsoft destination (`bazaar.abuse.ch`, `github.com`, `jamesgibbins.com`, `nova-labs.net`, `fonts.googleapis.com`, `bbc.gscontxt.net`, `update.googleapis.com`, `outlook.office365.com`) occurred **before 10:22:22** and carries a browser or named-updater user-agent. During the detonation itself the only proxy traffic was Microsoft telemetry, OneDrive and Edge.

**No persistence** - no Run keys, scheduled tasks, services, or COM hijacking by the sample. **No credential access, collection, or lateral movement.**

## Detections

Fired, all true positives:

| Rule | Alerts | Severity |
|---|---|---|
| `[Sigma] Suspicious Microsoft Defender Exclusion Added Via WMIC` | 10 | high |
| `[Sigma] Potential PyArmor Obfuscated PyInstaller Payload Extraction` | 6 | medium |
| `Malicious Behavior Detection Alert: Windows Defender Exclusions via WMIC` (Elastic built-in) | 20 | critical |
| ML: suspicious Windows event, high and low malicious probability | 15 | high / low |

**Correctly silent:** `[Sigma] Suspicious Double Extension Executable Launched From User Writable Path`. The sample was executed under its **hash filename**, not as `composer.php.exe`, so the double-extension condition did not match; the user-writable-path half did. This is correct rule behaviour. Re-running the sample renamed to `composer.php.exe` would exercise it.

**False positives identified during triage - do not chase these:**

- `Component Object Model Hijacking`, 4 alerts: `OneDrive.Sync.Service.exe` registering **its own** CLSIDs `{917E8742-...}` and `{47E6DCAF-...}` under `HKCU\..._Classes\CLSID\...\LocalServer32`. OneDrive was mid-setup throughout the window; unrelated to the intrusion.
- `File Compressed or Archived into Common Format by Unsigned Process`, 3 alerts: `base_library.zip` inside the `_MEI*` folders. That is PyInstaller's own standard-library archive, not data theft.

## Indicators

```
SHA256                  d97ea10d1dbfe2a69e0d2387e8985635b20628495918abd54c4b052c0acf05b1
Filename in the wild    composer.php.exe / composer.dat.exe
Artefact paths          %TEMP%\_MEI*\pyarmor_runtime_000000\pyarmor_runtime.pyd
                        C:\Users\Public\IIPaint\ceduwoc   (Defender exclusion, never written to)
Command pattern         cmd.exe /c "wmic /namespace:\\root\Microsoft\Windows\Defender
                                    path MSFT_MpPreference call Add ExclusionPath=..."
Source                  hxxps://bazaar.abuse[.]ch/sample/d97ea10d.../
```

No network indicators - none were observed.

## Lab findings raised by this investigation

1. **Squid proxy logs were unqueryable.** The pfsense integration JSON-decodes the relayed access log into a nested `squid` object but never maps it to ECS, leaving `source.ip`, `url.*`, `http.*` and `user_agent.*` empty, so egress was invisible to queries and detection rules. Fixed during this investigation with a `logs-pfsense.log@custom` ingest pipeline, chosen because version-pinned managed pipelines are replaced on package upgrade. Applies to new documents only; historical squid records remain nested.
2. **The WMIC rule covers only the WMIC path.** A payload using `Add-MpPreference` would not trigger it. Elastic's PowerShell-based Defender-exclusion rule should be confirmed enabled.
3. **`/var/log/squid/access.log` is 0 bytes** - the squid integration's `filestream` inputs collect nothing. All proxy visibility arrives via syslog into `pfsense.log`.
4. **Fleet reports the SECDIS agent as offline** (last check-in 2026-08-08) while telemetry flows normally. Data output works, Fleet check-in does not, so the agent receives no policy updates.

## Attack path diagram

Compromise Canvas export of the on-host attack path:
**https://github.com/Security-Distractions/lab/blob/main/canvases/pyarmor-loader-20260817.json**

Download it, then in [CompromiseCanvas](https://github.com/SagaLabs/CompromiseCanvas) choose **Import
JSON** and **double-click the `secdis` host** to walk the four steps. The full write-up is published alongside it in `cases/`.

(Case file attachments are disabled on this Elastic Cloud deployment — `POST /api/files/files/...`
returns "exists but is not available with the current configuration" — so canvases are versioned in
that repository rather than attached here.)


## Analyst note 1

### Process tree (endpoint.events.process, SECDIS)

```
explorer.exe
└─ d97ea10d…acf05b1.exe            10:22:48  C:\Users\analyst\Downloads\   pid 16184  exit 0
   ├─ d97ea10d…acf05b1.exe         10:22:50  PyInstaller child re-exec      pid 9568   exit 0
   │                                         → _MEI161842 / _MEI57082 / _MEI29322
   │                                           pyarmor_runtime_000000\pyarmor_runtime.pyd
   │                                           base_library.zip
   ├─ cmd.exe                      10:22:59  /c "C:\Users\analyst\Downloads\d97ea10d…exe"
   │  └─ d97ea10d…acf05b1.exe      10:23:00  third execution                pid 2932   exit 0
   └─ cmd.exe                      10:23:08  /c "wmic /namespace:\\root\Microsoft\Windows\Defender
      │                                          path MSFT_MpPreference call Add
      │                                          ExclusionPath=\"C:\Users\analyst\Downloads\""
      └─ WMIC.exe                  10:23:09  → and ExclusionPath="C:\Users\Public\IIPaint\ceduwoc"
```

Six process instances in total, all exiting with **code 0** between 10:23:02 and 10:23:13. Total
on-host lifetime approximately 25 seconds.


## Analyst note 2

### Egress analysis (Squid proxy, 874 parsed records, 10:20–11:10 UTC)

66 distinct destinations. Every non-Microsoft destination pre-dates the detonation and carries a
browser or named-updater user-agent:

| Time | Destination | Attribution |
|---|---|---|
| 10:21:17 | bbc.gscontxt.net | Edge |
| **10:21:22–30** | **bazaar.abuse.ch** | **sample download** |
| 10:21:45–48 | github.com, github.githubassets.com, avatars.githubusercontent.com | Edge |
| 10:21:48–49 | www.jamesgibbins.com | Edge |
| 10:21:50 | fonts.googleapis.com, fonts.gstatic.com | page assets |
| 10:21:51 | www.nova-labs.net (403) | Edge |
| 10:22:22 | update.googleapis.com | GoogleUpdater 152.0.7933.0 |
| 10:30:36 | outlook.office365.com | mail client |

Between **10:22:48 and 10:24:30** — the entire execution — proxy traffic consisted solely of Microsoft
telemetry (`*.events.data.microsoft.com`), OneDrive sync (`api.onedrive.com`,
`my.microsoftpersonalcontent.com`, `*.sharepoint.com`) and Edge/Windows Update. No candidate C2.

Note also that the sample's processes generated **no endpoint network events at all**, so the
possibility of C2 tunnelled inside the allowed Microsoft sessions is excluded as well — nothing of the
sample's opened a socket.


## Detection results

Rules that fired, by alert volume:


| Rule | Alerts |
|---|---|
| `Malicious Behavior Detection Alert: Windows Defender Exclusions via WMI` | 20 |
| `Machine Learning Detected a Suspicious Windows Event with a Low Malicious Probability Score` | 13 |
| `[Sigma] Suspicious Microsoft Defender Exclusion Added Via WMIC` | 10 |
| `[Sigma] Potential PyArmor Obfuscated PyInstaller Payload Extraction` | 6 |
| `Component Object Model Hijacking` | 4 |
| `File Compressed or Archived into Common Format by Unsigned Process` | 3 |
| `Multiple Alerts in Different ATT&CK Tactics on a Single Host` | 2 |
| `Machine Learning Detected a Suspicious Windows Event with a High Malicious Probability Score` | 2 |
| `LLM-Based Compromised User Triage by User` | 1 |
| `Multiple Alerts on a Host Exhibiting CPU Spike` | 1 |
| `My First Rule` | 1 |
| `Multiple Rare Elastic Defend Behavior Rules by Host` | 1 |
| `Multiple Elastic Defend Alerts by Agent` | 1 |
| `Multiple Alerts in Same ATT&CK Tactic by Host` | 1 |
| `LLM-Based Attack Chain Triage by Host` | 1 |
| `Multiple Alerts Involving a User` | 1 |
| `Alerts in Different ATT&CK Tactics by Host` | 1 |


Alert severity spread: **critical** 24, **high** 18, **low** 21, **medium** 6


## MITRE ATT&CK


| Tactic | Alerts |
|---|---|
| Defense Evasion | 38 |
| Execution | 10 |
| Persistence | 4 |
| Privilege Escalation | 4 |
| Collection | 3 |
| Command and Control | 3 |
| Impact | 1 |


Techniques observed: `T1027` Obfuscated Files or Information, `T1027.002` Software Packing, `T1027.015` Compression, `T1036` Masquerading, `T1036.004` Masquerade Task or Service, `T1047` Windows Management Instrumentation, `T1074` Data Staged, `T1074.001` Local Data Staging, `T1112` Modify Registry, `T1132` Data Encoding, `T1132.001` Standard Encoding, `T1546` Event Triggered Execution, `T1546.015` Component Object Model Hijacking, `T1560` Archive Collected Data, `T1560.001` Archive via Utility, `T1564` Hide Artifacts, `T1564.012` File/Path Exclusions


## Indicators

_none_


## Processes seen in alerts

| Process | Alerts |
|---|---|
| `WMIC.exe` | 30 |
| `cmd.exe` | 11 |
| `d97ea10d1dbfe2a69e0d2387e8985635b20628495918abd54c4b052c0acf05b1.exe` | 9 |
| `OneDriveSetup.exe` | 4 |
| `OneDrive.Sync.Service.exe` | 4 |


## Attribution

**Family:** none available

**Sample SHA256:** `d97ea10d1dbfe2a69e0d2387e8985635b20628495918abd54c4b052c0acf05b1`

**MalwareBazaar filename:** `composer.php`

No family label available: no ThreatFox entry and no MalwareBazaar signature for this hash. Named by packaging and behaviour. Worth noting the MalwareBazaar filename `composer.php` mirrors `composer.dat` from the 2026-08-08 RMM-abuse loader — same masquerade pattern, suggesting related tooling.

## Provenance

Extracted from Elastic case `fead879c-64db-4b55-ae10-922c4e3a143c`. The case remains the live record; this is the written-up analysis.

Sources for attribution: the abuse.ch ThreatFox and MalwareBazaar feeds as ingested into this
lab's Elastic cluster, matched by exact SHA256. Community-sourced labels; treated as evidence,
not as ground truth.
