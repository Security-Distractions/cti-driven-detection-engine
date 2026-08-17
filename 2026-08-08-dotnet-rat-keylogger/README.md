# .NET RAT with keylogging and Run-key persistence

*Detonated 2026-08-08 · severity **critical** · 29 correlated alerts across 10 rules*

**Tags:** `malware`, `sample-d`, `rat`, `keylogger`, `persistence`, `run-key`, `masquerading`, `workshop`, `secdis`, `T1547`, `T1056`

**Alert window:** 2026-08-08T17:47:28Z → 2026-08-08T18:00:44Z

**Host:** secdis (29)


## Analysis

# Sample D — Investigation

**Host:** `secdis` (192.168.2.2) · **User:** `analyst` · **Detonated:** 2026-08-08 17:47:10 UTC · **Alert window:** 17:47:28–17:51:59 · **Detections:** 25 Elastic Defend alerts · **Family/attribution:** _left for analyst to determine from the IOCs below_

---

## Step 1 — Overview
Sample D is a **.NET remote-access trojan (RAT)** with **keylogging**. It self-copies for **Run-key/Startup persistence** under a System32-masquerading name and attempts C2. Delivered as a 7-Zip archive, run manually.

## Step 2 — Layer 1: Delivery & Execution
- 7-Zip (`7zFM.exe`→`7zG.exe x`) extracted to `C:\Users\analyst\Downloads\bc033453…\`.
- `explorer.exe` → **Sample D** `C:\Users\analyst\Downloads\Sample D\bc033453…e48674.exe` at 17:47:10 (ProblemChild-flagged).

## Step 3 — Layer 2: Persistence & Masquerading
- Self-copied to **`C:\Users\analyst\AppData\Roaming\MPC-AH\AggregatorHost.exe`** (identical SHA256) — masquerading as the legitimate System32 `AggregatorHost.exe` ("Potential Masquerading as System32 Executable").
- **Startup / Run-key persistence** pointing at the copy — "Startup Persistence by a Low Reputation Process" ×4, "Startup Persistence from a Browser/Compression Utility Descendant" ×4, "Startup or Run Key Registry Modification" ×2.

## Step 4 — Layer 3: Collection (keylogging)
- **Keystroke capture** — "Keystrokes Input Capture from a Managed Application" ×2 (T1056.001).

## Step 5 — Layer 4: Command & Control
- C2 attempted **via the system proxy `192.168.2.1:3128`**; **no external egress observed** (dead/sinkholed in the isolated lab) — no external C2 IP/domain captured this run.
- 2× "Malicious Reputation of Executable Download" (component matched a bad-reputation indicator — T1105).

## Step 6 — MITRE ATT&CK
- Execution: T1204 User Execution
- Persistence: T1547.001 Registry Run Key / Startup Folder
- Defense Evasion: T1036.005 Masquerading (System32 name)
- Collection: T1056.001 Keylogging
- Command & Control: T1571/T1071 (RAT channel; not established this run)

## Step 7 — Detections (25 alerts)
Malware Detection ×8 · Startup Persistence (Low-Rep) ×4 · Startup Persistence (Browser/Compression Descendant) ×4 · Keystrokes Input Capture ×2 · Malicious Reputation Download ×2 · Startup/Run Key Registry Modification ×2 · Masquerading as System32 ×1 · ProblemChild "Suspicious Windows Process" ×2

---

## Step 8 — Indicators of Compromise (IOCs)

### File hashes
| Type | Value | Artifact |
|---|---|---|
| SHA256 | `bc033453ae6a4965aac275ec154517bb55c428149ef4107951246ecf17e48674` | Sample D (also the `AggregatorHost.exe` persistence copy) |
| imphash | `f34d5f2d4577ed6d9ceec516c1f5a744` | *(generic .NET/mscoree imphash — NOT a reliable pivot)* |

### File-system / host artifacts
- `C:\Users\analyst\Downloads\Sample D\bc033453…e48674.exe` (sample)
- `C:\Users\analyst\AppData\Roaming\MPC-AH\AggregatorHost.exe` (persistence copy; masquerade)
- Staging dir: `%AppData%\Roaming\MPC-AH`

### Network artifacts
- C2 routed to proxy `192.168.2.1:3128`; **no external C2 endpoint resolved/observed** this run.


## Detection results

Rules that fired, by alert volume:


| Rule | Alerts |
|---|---|
| `Malware Detection Alert` | 8 |
| `Component Object Model Hijacking` | 4 |
| `Malicious Behavior Detection Alert: Startup Persistence by a Low Reputation Process` | 4 |
| `Malicious Behavior Detection Alert: Startup Persistence from a Browser or Compression Utility Descendant` | 4 |
| `Malicious Behavior Detection Alert: Keystrokes Input Capture from a Managed Application` | 2 |
| `Malicious Behavior Detection Alert: Malicious Reputation of Executable Download` | 2 |
| `Startup or Run Key Registry Modification` | 2 |
| `Parent Process Detected with Suspicious Windows Process(es)` | 1 |
| `Potential Masquerading as System32 Executable` | 1 |
| `User Detected with Suspicious Windows Process(es)` | 1 |


Alert severity spread: **critical** 20, **low** 9


## MITRE ATT&CK


| Tactic | Alerts |
|---|---|
| Defense Evasion | 9 |
| Persistence | 7 |
| Privilege Escalation | 4 |
| Execution | 4 |


Techniques observed: `T1036` Masquerading, `T1036.001` Invalid Code Signature, `T1036.005` Match Legitimate Resource Name or Location, `T1112` Modify Registry, `T1204` User Execution, `T1204.002` Malicious File, `T1218` System Binary Proxy Execution, `T1546` Event Triggered Execution, `T1546.015` Component Object Model Hijacking, `T1547` Boot or Logon Autostart Execution, `T1547.001` Registry Run Keys / Startup Folder, `T1553` Subvert Trust Controls, `T1553.002` Code Signing, `T1554` Compromise Host Software Binary


## Indicators

| Type | Value |
|---|---|
| SHA256 | `bc033453ae6a4965aac275ec154517bb55c428149ef4107951246ecf17e48674` |


## Processes seen in alerts

| Process | Alerts |
|---|---|
| `bc033453ae6a4965aac275ec154517bb55c428149ef4107951246ecf17e48674.exe` | 11 |
| `AggregatorHost.exe` | 10 |
| `OneDrive.Sync.Service.exe` | 4 |
| `7zG.exe` | 2 |


## Attribution

**Family:** none available

**Sample SHA256:** `bc033453ae6a4965aac275ec154517bb55c428149ef4107951246ecf17e48674`

**MalwareBazaar filename:** `ntmyebewekca.exe`

No family label available: this hash has no ThreatFox entry, and MalwareBazaar carries no signature for it. MalwareBazaar's TrID output identifies it as a Generic CIL (.NET) executable, so it is named by observed behaviour and runtime only.

## Provenance

Extracted from Elastic case `2747eaba-7963-4ca5-87dd-71c01a9f3c54`. The case remains the live record; this is the written-up analysis.

Sources for attribution: the abuse.ch ThreatFox and MalwareBazaar feeds as ingested into this
lab's Elastic cluster, matched by exact SHA256. Community-sourced labels; treated as evidence,
not as ground truth.
