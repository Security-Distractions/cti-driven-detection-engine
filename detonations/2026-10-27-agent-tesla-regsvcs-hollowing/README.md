# Agent Tesla — hollowed into RegSvcs.exe, credential vault and browser store access

*Detonated 2026-10-27 · severity **critical** · 35 alerts*

**Tags:** `malware`, `agent-tesla`, `process-hollowing`, `regsvcs`, `credential-access`, `infostealer`, `recorded-future`, `analysis-host`, `T1055.012`, `T1218.009`, `T1555.004`

## Investigation

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-10-27 21:20:27 UTC ·
**Alert window:** 21:21:03–21:30:18 · **Detections:** 35 alerts (26 detection-engine, 9 Elastic
Defend endpoint) · **Capture:** 10,652 documents over 15 minutes · **Telemetry:** healthy

**Sample:** `fdc9cb253a2ebb99df48133a5c2e0d35cfa5fb4ee7578f6648bded8b5187b42c`
(MD5 `afeb6d5fc91e7f54feb84544c13f086e`, SHA1 `c8fc8fdc508bfdbacced8192b229233f095e5771`)

**Family:** Agent Tesla (Keylogger, Trojan). Attribution **adopted**, on two independent methods:
a Recorded Future intelligence card keyed on the SHA256 (master ID `hd4fiZ`, risk 65/99, rule
*Positive Malware Verdict*), and an Elastic Defend memory scan matching
`Windows.Trojan.AgentTesla` inside the hollowed process. Triage scored it 10 with 14 signatures
and **0 C2 indicators**.

## Chain

| Time (UTC) | Event |
|---|---|
| 21:20:01 | `7zFM.exe` → `7zG.exe x` extracts the sample to a Downloads subdirectory named after its own SHA256 |
| 21:20:27.6 | `explorer.exe` → the sample, no arguments. Loads `clr.dll`: a .NET assembly |
| 21:20:59.3 | the sample → `"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"`, **no arguments** |
| 21:20:59.4 | the sample exits, 114 ms after spawning its container |
| 21:20:59.5 | `RegSvcs.exe` loads the WMI client stack: `wmiutils.dll`, `wbemcomn.dll`, `wbemprox.dll`, `WMINet_Utils.dll`, `wbemsvc.dll`, `fastprox.dll` |
| 21:21:01.6 | `RegSvcs.exe` connects outbound, to the internal proxy on 3128 |
| 21:21:02.18 | `RegSvcs.exe` opens `…\Google\Chrome\User Data\Default\Login Data` |
| 21:21:02.20 | `RegSvcs.exe` opens `…\Microsoft\Edge\User Data\Default\Login Data` |
| 21:21:02.23 | `RegSvcs.exe` loads `vaultcli.dll` |
| 21:22:42.1 | the socket closes. No further sample activity in the window |

**No persistence was established.** No Run key, no scheduled task, no service, no WMI
subscription. Recorded here so a later reader does not assume the capture is truncated.

## Detections

| Rule | Alerts |
|---|---|
| Threat Intel Hash Indicator Match | 6 |
| Access to Windows Passwords Vault by Unusual Process | 6 |
| Suspicious Vault Client Image Load | 3 |
| Suspicious Suspended Process Creation | 3 |
| Suspicious Remote Memory Allocation | 3 |
| Remote Thread Context Manipulation | 3 |
| Network Connection via Process with Unusual Arguments | 3 |
| Memory Threat Detection: `Windows.Trojan.AgentTesla` | 3 |
| Malware Detection Alert | 2 |
| Machine Learning — low malicious probability score | 1 |
| LLM-Based Attack Chain Triage by Host | 1 |
| unnamed endpoint alert | 1 |

Severity: 19 critical, 6 high, 1 low, 9 unscored endpoint events. Counts merge each
detection-engine alert with the endpoint alert it was escalated from, since both layers record the
same behaviour.

Techniques evidenced: T1204.002, T1055, T1055.012, T1218.009, T1036, T1555, T1555.004. The alerts
name the tactic *Defense Evasion*; ATT&CK v19 retired that tactic, so the Sigma rules below carry
`attack.stealth` instead. Both are right for their own vintage.

## Indicators

| Type | Indicator |
|---|---|
| SHA256 | `fdc9cb253a2ebb99df48133a5c2e0d35cfa5fb4ee7578f6648bded8b5187b42c` — the sample |
| MD5 | `afeb6d5fc91e7f54feb84544c13f086e` — the sample. No direct Recorded Future entity; resolves only through the SHA256's `fileHashes` list |
| SHA1 | `c8fc8fdc508bfdbacced8192b229233f095e5771` — the sample |

Two things are deliberately **not** indicators:

- `083bc9319eb8066131b8005dd7013f85f2a27c7908767f94183d3e153b8db12b` is `RegSvcs.exe` itself —
  .NET Framework v4.0.30319, 39,400 bytes, catalogued by NIST as a known software file, 0 of 17
  risk rules, Cleanset Match. It is the second most-seen hash in the capture and publishing it
  would send people hunting for a file present on every Windows host with .NET installed.
- One external address carried in the enrichment is not this sample's. See the correction in
  [`detection-package-summary.md`](detection-package-summary.md): it predates the detonation and its
  "30 sightings" were 30 rollups of a single flow rather than 30 connections.

No destination belonging to this sample is publishable. The only address host telemetry recorded
was the internal proxy, and no DNS query or TLS SNI in the window is attributable to it.

## Detections drafted from this detonation

Two draft Sigma rules, both `status: experimental`:

- [`proc_creation_win_dotnet_framework_utility_no_arguments.yml`](../../detections/sigma/proc_creation_win_dotnet_framework_utility_no_arguments.yml)
- [`net_connection_win_dotnet_framework_utility_outbound.yml`](../../detections/sigma/net_connection_win_dotnet_framework_utility_outbound.yml)

A third, matching `vaultcli.dll` loaded into a .NET utility, was drafted and **withdrawn** after
live testing showed it cannot fire on this estate as converted — a pipeline field-mapping problem,
not a logic problem. See [`detection-package-summary.md`](detection-package-summary.md).

Tested read-only against the production cluster: **19 true positives across 90 days and two
independent Agent Tesla samples, zero false positives** on a two-host estate. Full detail in
[`TEST-RESULTS.md`](TEST-RESULTS.md).

Each has a `.validation.md` beside it covering assumptions, false positives, evasion gaps, the
converted query and a test plan. [`detection-package-summary.md`](detection-package-summary.md)
carries the ranking, the further rule candidates, the telemetry gaps, and the enrichment
correction.
