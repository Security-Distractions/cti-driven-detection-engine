# Corrections Log

Errors found when auditing the first draft against other session transcripts and the
live Elastic cluster on 2026-08-09. Recorded so the pack is self-auditing and so a
future reader knows which claims were wrong and why.

| # | Wrong claim (first draft) | Verified reality | Source |
|---|---|---|---|
| 1 | "Squid ingestion is broken — the lab's biggest blind spot" | **Fixed 2026-08-08.** 9,147 docs with `squid.url.original` in the last 24h | live ES query |
| 2 | OPNsense ships directly to Elastic Cloud | OPNsense syslogs to **collector `<collector-ip>:9001`**; the agent input `tcp-pfsense.log` relays it | `elastic-agent inspect` |
| 3 | "`elastic-otel-collector` … may be unrelated to the security pipeline" | It **is** the pipeline — it hosts the `tcp-pfsense.log` input | `elastic-agent inspect` |
| 4 | `logs-network_traffic.dns` is the DNS source | **0 docs in 24h.** DNS actually comes from `pfsense.log` (5,816) and `endpoint.events.network` (560) | live ES query |
| 5 | Threat intel = MalwareBazaar only | **Six** AbuseCH feeds; `ti_abusech.url` (256,876) is the 2nd-largest dataset in the cluster | live ES query |
| 6 | Squid data lands in `logs-squid.log` | It lands in **`logs-pfsense.log-*`**; `squid.log` holds 10 docs and is a decoy | live ES query |

## Verified 24h volumes (2026-08-09)

| Dataset | Docs |
|---|---|
| `suricata.eve` | 447,784 |
| `ti_abusech.url` | 256,876 |
| `pfsense.log` | 160,672 |
| `network_traffic.flow` | 47,115 |
| `ti_abusech.sslblacklist` | 41,390 |
| `endpoint.events.file` | 23,681 |
| `ti_abusech.malware` | 15,446 |
| `system.security` | 11,169 |
| `windows.sysmon_operational` | 3,930 |
| `endpoint.events.process` | 2,135 |
| `endpoint.alerts` | 95 |

Reporting hosts, 24h: **`analysis-host` 96,279** · **`collector` 9,355**. OPNsense has no
`host.name` of its own — its events arrive through the relay.

## Method

1. Read every session transcript under `/root/.claude/projects/` for lab facts
2. Re-verified against the live cluster with authenticated `_count` / `_search` queries
3. Cross-checked the agent's own config via `elastic-agent inspect`

Anything still tagged **[?]** could not be settled by either route.
