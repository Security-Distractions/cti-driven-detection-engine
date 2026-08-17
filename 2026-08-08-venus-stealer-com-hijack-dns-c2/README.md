# Venus Stealer — COM hijack persistence and DNS C2

*Detonated 2026-08-08 · severity **critical** · 31 correlated alerts across 5 rules*

**Tags:** `malware`, `sample-b`, `c2-dns`, `suspicious-tld`, `strmer.top`, `com-hijack`, `application-shimming`, `workshop`, `secdis`, `T1546`, `T1568`

**Alert window:** 2026-08-08T17:00:00Z → 2026-08-08T17:02:15Z

**Host:** secdis (31)


## Analysis

# Sample B — Investigation

**Host:** `secdis` (192.168.2.2) · **User:** `analyst` · **Detonated:** 2026-08-08 16:59 UTC · **Alert window:** 17:00:00–17:02:15 · **Detections:** 31 Elastic Defend alerts · **Telemetry:** healthy (Defend events + Sysmon logging with correct timestamps — full reconstruction available)

---

## Step 1 — Overview
Sample B is an unsigned Windows executable that, on execution, attempts **C2 over DNS to a suspicious `.top` domain** and establishes host persistence via **Application Shimming (sdbinst)** and **COM registry modification**. Delivered as a 7-Zip archive and run manually. The C2 domain did not resolve during the run.

## Step 2 — Layer 1: Initial Access / Delivery
- Archive opened in 7-Zip (`7zFM.exe`), extracted via `7zG.exe x` to `C:\Users\analyst\Downloads\f0a10f8d…272b8\`.
- Sample staged in `C:\Users\analyst\Downloads\Sample B\`.

## Step 3 — Layer 2: Execution
- `explorer.exe` → **Sample B exe** at 16:59:36 (and again 16:59:41) — user execution.
- Flagged by ProblemChild ML (`problemchild.prediction=1`).

## Step 4 — Layer 3: Command & Control
- Sample issued **DNS queries for `strmer.top`** (suspicious `.top` TLD) at 16:59:40–45 (process `f0a10f8d…272b8.exe`, also via `svchost.exe` DNS client).
- **Domain did NOT resolve** (`dns.resolved_ip: []`, no firewall egress) — C2 dead/sinkholed in the isolated lab, so no session established. Domain is the key network IOC.

## Step 5 — Layer 4: Persistence / Defense Evasion
- **Application Shimming** — `C:\Windows\System32\sdbinst.exe -m -bg` at 17:02:48 (ProblemChild-flagged) — installs a shim database (T1546.011).
- **COM registry modification** — per-user CLSID overrides written:
  - `{47E6DCAF-41F8-441C-BD0E-A50D5FE6C4D1}` and `{917E8742-AA3B-7318-FA12-10485FB322A2}` → `LocalServer32` = `…\AppData\Local\Microsoft\OneDrive\26.129.0706.0004\OneDrive.Sync.Service.exe` (+ WOW6432Node).
  - ⚠️ The referenced `OneDrive.Sync.Service.exe` is **Microsoft-signed/trusted** — this may be legitimate OneDrive COM registration flagged as suspicious rather than confirmed malicious persistence. **Recommend validation.**

## Step 6 — Additional
- **Malicious Reputation of Executable Download** ×4 — a downloaded/executed component matched a bad-reputation indicator (T1105 Ingress Tool Transfer).

## Step 7 — MITRE ATT&CK
- Execution: T1204 User Execution
- Command & Control: T1071.004 / T1568 (DNS to suspicious TLD)
- Persistence: T1546.011 Application Shimming, T1546.015 COM Hijacking (candidate — see caveat)
- Command & Control / Ingress: T1105 Ingress Tool Transfer

## Step 8 — Detections (31 Elastic Defend alerts)
Network Activity to a Suspicious Top Level Domain ×15 · Malware Detection Alert ×6 · Component Object Model Hijacking ×4 · Malicious Reputation of Executable Download ×4 · DNS Query to Suspicious Top Level Domain ×2

---

## Step 9 — Indicators of Compromise (IOCs)

### File hashes
| Type | Value | Artifact |
|---|---|---|
| SHA256 | `f0a10f8d919b4e785e04461ed2adde2d51608e50f69e1e4995c85b71472272b8` | Sample B |
| imphash | `934864fad2e0d984459abdc576cdc4a7` | Sample B |
| signature | none (unsigned) | Sample B |

### Network artifacts
- **C2 domain:** `strmer.top` (suspicious `.top` TLD) — contacted via DNS by the sample; **did not resolve** (no IP / no session). Primary network IOC.

### File-system artifacts
- `C:\Users\analyst\Downloads\Sample B\f0a10f8d…272b8.exe` (sample)
- `C:\Users\analyst\Downloads\f0a10f8d…272b8\` (7-Zip extract dir)

### Host / persistence artifacts
- `sdbinst.exe -m -bg` (application-shim install)
- COM CLSIDs: `{47E6DCAF-41F8-441C-BD0E-A50D5FE6C4D1}`, `{917E8742-AA3B-7318-FA12-10485FB322A2}` (LocalServer32 overrides)


## Detection results

Rules that fired, by alert volume:


| Rule | Alerts |
|---|---|
| `Network Activity to a Suspicious Top Level Domain` | 15 |
| `Malware Detection Alert` | 6 |
| `Component Object Model Hijacking` | 4 |
| `Malicious Behavior Detection Alert: Malicious Reputation of Executable Download` | 4 |
| `Malicious Behavior Detection Alert: DNS Query to Suspicious Top Level Domain` | 2 |


Alert severity spread: **critical** 12, **high** 15, **low** 4


## MITRE ATT&CK


| Tactic | Alerts |
|---|---|
| Defense Evasion | 19 |
| Command and Control | 15 |
| Persistence | 4 |
| Privilege Escalation | 4 |
| Execution | 3 |


Techniques observed: `T1071` Application Layer Protocol, `T1071.004` DNS, `T1112` Modify Registry, `T1127` Trusted Developer Utilities Proxy Execution, `T1127.001` MSBuild, `T1204` User Execution, `T1204.002` Malicious File, `T1218` System Binary Proxy Execution, `T1546` Event Triggered Execution, `T1546.015` Component Object Model Hijacking


## Indicators

| Type | Value |
|---|---|
| SHA256 | `f0a10f8d919b4e785e04461ed2adde2d51608e50f69e1e4995c85b71472272b8` |
| Domain | `strmer.top` |


## Processes seen in alerts

| Process | Alerts |
|---|---|
| `f0a10f8d919b4e785e04461ed2adde2d51608e50f69e1e4995c85b71472272b8.exe` | 25 |
| `OneDrive.Sync.Service.exe` | 4 |
| `7zG.exe` | 2 |


## Attribution

**Family:** `py.venus_stealer` (ThreatFox, confidence 95) — adopted

**Sample SHA256:** `f0a10f8d919b4e785e04461ed2adde2d51608e50f69e1e4995c85b71472272b8`

**MalwareBazaar filename:** `097b3b7c38e22a3b1e5e434c907f5261.exe`

ThreatFox labels this hash `py.venus_stealer` (confidence 95), consistent with a Python-packed stealer. Note the collection stage was never observed: the C2 domain did not resolve in the isolated lab, so this is attribution by indicator, not by observed theft.

## Provenance

Extracted from Elastic case `76160582-5f31-4eb6-b026-c9a6b60ba9ca`. The case remains the live record; this is the written-up analysis.

Sources for attribution: the abuse.ch ThreatFox and MalwareBazaar feeds as ingested into this
lab's Elastic cluster, matched by exact SHA256. Community-sourced labels; treated as evidence,
not as ground truth.
