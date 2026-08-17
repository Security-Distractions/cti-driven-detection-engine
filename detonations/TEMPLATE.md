# <Malware name / behaviour> (<HOST>, <YYYY-MM-DD>)

*Detonated <date> · severity **<low|medium|high|critical>** · <n> correlated alerts across <n> rules*

**Tags:** `malware`, ...
**Alert window:** <first>Z -> <last>Z
**Host:** <host>

## Analysis

What was executed, what it did, in order. Cite the telemetry that shows each step.

## Detection results

| Rule | Alerts |
|---|---|

Note anything that *should* have fired and did not — that is the useful half.

## MITRE ATT&CK

| Tactic | Alerts |
|---|---|

## Indicators

| Type | Value |
|---|---|

## Attack path

`canvas/on-host-attack-path.json` — import into CompromiseCanvas, double-click the host.

Generate with:

```bash
export ES_URL=... ES_USER=... ES_PASS=...
python3 elastic_to_canvas.py --host <host> --since <ts> --mode host > canvas/on-host-attack-path.json
```

## Provenance

Extracted from Elastic case `<case-id>`.
