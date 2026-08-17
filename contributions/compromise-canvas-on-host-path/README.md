# Elastic → Compromise Canvas generator

Turns a detonation window in Elastic into a [Compromise Canvas](https://github.com/SagaLabs/CompromiseCanvas)
diagram of the **on-host** attack path.

## Why

Compromise Canvas models host-to-host movement. What's missing is what happened
*inside* a host. Sysmon / Elastic Defend already record that as a process tree, so
the graph can be generated rather than drawn by hand.

## Three modes

| Mode | Shape | Needs tool changes? |
|---|---|---|
| `host` (default) | one host node; its ordered step list **is** the path, opened by double-clicking the host | yes — the on-host attack path feature, see [ON-HOST-ATTACK-PATH.md](ON-HOST-ATTACK-PATH.md) |
| `technique` | one node per MITRE technique, edges = real causality | no |
| `process` | one node per distinct process behaviour | no |

`host` is the mode to use. The other two model an on-host path as a *graph of
nodes on the canvas*, which works but competes with the topology for the same
space; `host` keeps the canvas an infrastructure diagram and puts the on-host
detail one level down.

## Usage

```bash
export ES_URL=https://your-deployment:9243 ES_USER=... ES_PASS=...

# drill-down view — one host node with an ordered step chain (default)
./elastic_to_canvas.py --host analysis-host \
    --from 2026-08-08T17:26:00Z --to 2026-08-08T17:40:00Z \
    --title "Sample C — on-host attack path (analysis-host)" --out sample-c-host.json

# one node per MITRE technique (works with upstream Compromise Canvas)
./elastic_to_canvas.py --host analysis-host \
    --from 2026-08-08T17:26:00Z --to 2026-08-08T17:40:00Z \
    --mode technique --out sample-c-technique.json

# detail view — one node per distinct process behaviour
./elastic_to_canvas.py --host analysis-host \
    --from 2026-08-08T17:26:00Z --to 2026-08-08T17:40:00Z \
    --mode process --out sample-c-process.json
```

Then in Compromise Canvas: **Import JSON** → pick the file.

## How it maps

`--mode host`:

| Concept | Canvas element |
|---|---|
| the host | `customNode`, type `workstation`, criticality Critical |
| attacker delivery / C2 | `customNode`, type `server` — fill in the real IP yourself |
| a step in the on-host path | one `NodeAction` on the host, in array order |
| MITRE technique of a step | `mitreAttackId` / `mitreAttackName` on the step |
| when it happened | `timestamp` on the step |
| detection alerts | `incidentLog` entries |

`--mode technique` / `--mode process`:

| Concept | Canvas element |
|---|---|
| the host | `labeledGroupNode`, red, as a boundary box |
| a technique (or process) | `customNode`, type `other` |
| "A led to B" | `customEdge` with `actionType` + `mitreAttackId` |
| SIEM-flagged | `criticality: Critical`, `investigationStatus: Investigating` |
| detection alerts | `incidentLog` entries |

## The three problems worth knowing about

**1. Volume.** A raw window is unreadable — Sample C produced **104 nodes**. Two
reductions fix it: collapse repeated identical behaviour, then aggregate to technique.
104 → 65 → **9**.

**2. Repeats key on behaviour, not parent.** Malware spawns a fresh `cmd.exe` per
action, so 15 identical `schtasks /Create /TN "Task1"` calls have 15 different parents.
Collapsing on `(parent, name, cmd)` barely helps; collapsing on `(name, normalised cmd)`
does. Command normalisation strips GUIDs, hashes, usernames and digits.

**3. The process graph has cycles.** A payload spawns `cmd.exe` which spawns the
payload again, so longest-path depth diverges (it produced depth 5600). Depth is
therefore **chronological rank of first appearance** — cycle-proof, and time is the
honest axis for an attack path. Causal edges still show which step led to which.

## Verified

`sample-c-technique.json` and `sample-c.json` pass a local reimplementation of
the tool's `handleImportJSON` validation: required `data` keys present, node/edge
types valid, no dangling edge endpoints, no duplicate ids, numeric positions.

`sample-c-host.json` was verified by loading it in a real browser against the
feature branch: it imports, the host node shows an 8-step ribbon, and
double-clicking opens the drill-down with all 8 steps in order, no console
errors.

## Sample C result (analysis-host, 2026-08-08 17:26–17:40 UTC)

206 process events → 65 distinct behaviours → **8 steps**, 27 incident log entries.

```
17:27:49  T1218.011 Rundll32                      rundll32.exe
17:27:55  T1204.002 Malicious File        CRIT    a43853c…​.exe, xhMLks.exe
17:30:11  T1562.001 Disable or Modify Tools CRIT  powershell.exe
17:30:11  T1053.005 Scheduled Task        CRIT    cmd.exe, schtasks.exe
17:30:18  T1112     Modify Registry               cmd.exe
17:31:03  Execution                       CRIT    Fqvg0m6.exe, icacls.exe, yYRb4B.exe
17:31:08  T1059     Command and Scripting         cmd, net, net1, powershell, reg, sc
17:31:32  T1490     Inhibit System Recovery       cmd.exe
```

## Limitations

- Classification is substring matching on command lines, not real ATT&CK mapping.
  It is a starting point an analyst edits in the canvas, not ground truth.
- Only `logs-endpoint.events.process-*` is read. Sysmon, file, registry and network
  events would enrich this considerably — network events in particular would let the
  on-host path connect to the C2 destination from the Squid proxy log.
- `--mode process` output is accurate but usually too dense to present.
