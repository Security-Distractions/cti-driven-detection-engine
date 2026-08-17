# Malware detonations

The validation half of this repo: one directory per detonation in the lab, showing which detections
actually fired against real malware. A rule that never fires against a live sample is a rule you
cannot trust.

One directory per detonation: the written-up analysis, the detections that fired, the
indicators, and a [CompromiseCanvas](https://github.com/SagaLabs/CompromiseCanvas) export of the
attack path where one exists.

The analysis here is pulled out of the Elastic cases so it can be read, diffed and linked without a
Kibana login. The cases remain the live record; each write-up cites its case ID.

| Date | Detonation | Family | Alerts | Rules | Severity | Canvas |
|---|---|---|---|---|---|---|
| 2026-08-17 | [PyArmor-obfuscated PyInstaller loader — Defender exclusion abuse via WMIC (analysis-host, 2026-08-17)](2026-08-17-pyarmor-pyinstaller-loader/) | — | 69 | 17 | high | yes |
| 2026-08-08 | [Venus Stealer — COM hijack persistence and DNS C2](2026-08-08-venus-stealer-com-hijack-dns-c2/) | `py.venus_stealer` | 31 | 5 | critical | — |
| 2026-08-08 | [ValleyRAT — shellcode loader with EDR evasion and Defender tampering](2026-08-08-valleyrat-shellcode-loader/) | `win.valley_rat` | 324 | 39 | critical | yes |
| 2026-08-08 | [RMM abuse loader — ScreenConnect deployed via PyInstaller](2026-08-08-rmm-abuse-loader-screenconnect/) | `elf.kuiper` (disputed) | 0 | 0 | critical | — |
| 2026-08-08 | [.NET RAT with keylogging and Run-key persistence](2026-08-08-dotnet-rat-keylogger/) | — | 29 | 10 | critical | — |
| 2026-08-08 | [Cobalt Strike — shellcode beacon in a trojanised Electron app](2026-08-08-cobalt-strike-electron-trojan/) | `win.cobalt_strike` | 101 | 15 | critical | — |

Family attribution comes from the abuse.ch ThreatFox and MalwareBazaar feeds ingested into the lab's
Elastic cluster, matched by exact SHA256. These are community labels, so each write-up states whether
the label was adopted or only recorded — one of them contradicts both the file type and the observed
behaviour and is deliberately not used in the name.

## Layout

```
YYYY-MM-DD-<short-name>/
  README.md              analysis, detection results, MITRE mapping, indicators
  canvas/*.json          CompromiseCanvas exports (import via Import JSON)
```

Canvas files with an on-host attack path open properly in CompromiseCanvas from
[PR #21](https://github.com/SagaLabs/CompromiseCanvas/pull/21) onward — double-click the host node to
walk the steps. Older builds still import them, but render the steps as a flat list.

## Related

- [`../detections/`](../detections/) — the detections these validate
- [`../lab/`](../lab/) — how the validation lab is built
- [`../tooling/elastic_to_canvas.py`](../tooling/elastic_to_canvas.py) — generates these canvases from Elastic telemetry

## A note on scope

These are detonations of live malware inside an isolated lab. Hashes and domains are published
deliberately as indicators. Lab hostnames and RFC 1918 addressing (`<detonation-subnet>`) are kept because the analysis is
unreadable without them. Cluster endpoints and access paths are redacted, and the lab account
name is normalised to `analyst`.
