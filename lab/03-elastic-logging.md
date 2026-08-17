# Elastic — Logging, Detection and the External Deployment

**[V]** verified 2026-08-09 · **[T]** from earlier transcripts · **[?]** needs confirmation

---

## 1. The external deployment

A managed **Elastic Cloud** deployment — no self-hosted cluster in the lab.

| Field | Value |
|---|---|
| Provider / region | Google Cloud, `europe-west4` |
| Kibana | `https://<ELASTIC-KB-ENDPOINT>` |
| Elasticsearch | `https://<ELASTIC-ES-ENDPOINT>` **[V]** |
| Version | **9.5.0** **[V]** |
| Login user | `David` |
| Solution | Elastic Security (SIEM + EDR) |

Every lab host ships **outbound** to this deployment. There is no inbound path from
Elastic into the lab — worth stating on the diagram, as people often assume otherwise.

---

## 2. Data sources and integrations **[T]**

Derived from data streams observed in use. Group them by origin when drawing.

### From `secdis` (Windows 11) — ships **direct** to Elastic Cloud **[V]**

| Integration | Dataset | 24h volume |
|---|---|---|
| Elastic Defend (EDR) | `endpoint.events.file` | 23,681 |
| | `endpoint.events.process` | 2,135 |
| | `endpoint.events.library` | 1,822 |
| | `endpoint.events.registry` | 1,451 |
| | `endpoint.events.api` | 996 |
| | `endpoint.events.network` | 942 |
| | `endpoint.events.security` | 264 |
| | **`endpoint.alerts`** | 95 |
| Windows — Security | `system.security` | 11,169 |
| Windows — Sysmon | `windows.sysmon_operational` | 3,930 |
| Windows — PowerShell | `windows.powershell` (+ `windows.powershell_operational`) | 102 |
| Windows — AppLocker | `windows.applocker_exe_and_dll`, `windows.applocker_msi_and_script` | present |

Note `secdis` ships **directly** to Elastic Cloud (it runs its own Elastic Agent),
unlike OPNsense which relays through util-debian. Two different paths — draw them
differently.

### From OPNsense (VM 100) — **relayed via util-debian** **[V]**

> **Correction (verified 2026-08-09):** OPNsense does **not** ship to Elastic Cloud
> directly. It syslogs to **util-debian `192.168.3.2:9001`**, where the Elastic Agent
> input `tcp-pfsense.log` receives it and forwards to Elastic Cloud. util-debian is the
> lab's **log relay**, not a peripheral node. Draw it that way.

| Integration | Dataset | 24h volume **[V]** |
|---|---|---|
| Suricata | `suricata.eve` | **447,784** — largest source in the lab |
| pfSense *(for OPNsense)* | `pfsense.log` | **160,672** — filterlog + Squid + DNS |
| Network Packet Capture | `network_traffic.flow` | 47,115 |
| Squid | `squid.log` | **10** — effectively unused, see below |

**Squid lands in `pfsense.log`, not `squid.log`.** Verified live: **9,147 documents
with `squid.url.original` in the last 24h** inside `logs-pfsense.log-*`, versus 10 docs
total in `logs-squid.log-*`. The `squid.log` dataset is a decoy — ignore it when hunting.

**DNS visibility does not come from `network_traffic.dns`** — that data stream has
**0 documents in 24h**. Actual DNS sources over the same window **[V]**:

| Dataset | Docs with `dns.question.name` |
|---|---|
| `pfsense.log` | 5,816 |
| `endpoint.events.network` | 560 |
| `endpoint.alerts` | 1 |

### Threat intel — six AbuseCH feeds **[V]**

Much larger than first documented. `ti_abusech.url` alone is the **second-biggest
dataset in the whole cluster**.

| Dataset | 24h volume |
|---|---|
| `ti_abusech.url` | **256,876** |
| `ti_abusech.sslblacklist` | 41,390 |
| `ti_abusech.malware` | 15,446 |
| `ti_abusech.threatfox` | 2,995 |
| `ti_abusech.malwarebazaar` | 737 |
| `ti_abusech.ja3_fingerprints` | 388 |

### From util-debian **[V]**

Two distinct roles — keep them separate on the diagram:

1. **Relay** — hosts the Elastic Agent inputs that receive OPNsense syslog:
   `tcp-pfsense.log` (bound to `192.168.3.2:9001`), plus `tcp/udp/filestream-squid.log`
   and `logfile-suricata.eve`.
2. **Monitored host** — ships its own `system.*` datasets (syslog, auth, security,
   application, plus CPU/memory/disk/network metrics).

The listener appears in `ss` as process **`elastic-otel-co`** — this is the Elastic
Agent's collector component hosting the input, **not** a separate unrelated OTel
deployment. (An earlier draft of this pack wrongly called it unrelated.)

**Only two hosts report telemetry** over 24h **[V]**: `secdis` (96,279 docs) and
`util-debian` (9,355). OPNsense has no `host.name` of its own because its events arrive
via the relay.

---

## 4. Squid proxy logging — root cause and fix **[T]**

> **Status: RESOLVED.** Fixed in session `e9e3ff26` on 2026-08-08. Squid access logs
> are parsing into Elastic with full HTTPS URLs. This section supersedes any earlier
> note calling Squid a blind spot.

### Path the data takes

```
Squid on OPNsense
  └─ logformat "opnsense" = ECS-JSON      (squid.conf line 152)
      access_log syslog:local4.info opnsense  (line 153)
  └─ syslog-ng  ──► util-debian 192.168.3.2:9001  (tcp-default input)
      └─ Elastic Agent 9.3.2 (Fleet-managed filebeat)
          └─ ingest pipeline logs-pfsense.log-1.25.2-squid
              └─ data stream logs-pfsense.log-*
```

### Root cause

Squid always emits **ECS-JSON** (regardless of the GUI's `syslog` vs `syslog_json`
target — both produce the identical `access_log` directive). The pfSense integration's
Squid pipeline expected **classic text** and applied a **grok** processor, which failed
on JSON — so documents landed in `pfsense.log` **unparsed**.

### The fix

The `logs-pfsense.log-1.25.2-squid` ingest pipeline was edited to **decode the JSON**
instead of grokking it — a `json` processor with `add_to_root: true`,
`add_to_root_conflict_strategy: replace`, `ignore_failure: true`, tagged
`json_decode_opnsense_squid_ecs`, preserving the existing processors and `on_failure`.

### Two dead ends worth recording

1. **`logs-pfsense.log@custom`** — a custom pipeline (JSON decode + reroute to a
   `squid.access` data stream) was created and then **deleted**: it never fired,
   because the grok failure aborted the pipeline *before* `@custom` runs.
2. **`192.168.3.2:9537`** — syslog-ng had a stale Squid destination pointing at a port
   with no listener, producing a "Connection refused" flood. Pure noise: the `9001`
   forward has **no program filter**, so it was already carrying Squid all along.

### Querying it

Kibana data view **`logs-pfsense.log-*`**, filter `squid.url.original: *`.

| Field | Example |
|---|---|
| `squid.url.original` | full URL — HTTPS included, sslbump decrypts |
| `squid.http.request.method` | `GET`, `CONNECT` |
| `squid.http.response.body.status_code` | `200` |
| `squid.labels.request_status` | `TCP_MISS`, `TCP_DENIED`, `NONE_NONE` |
| `squid.source.ip` | `192.168.2.2` (dropped when `"-"`) |
| `squid.service.type` | `squid` |

Verified working at the time: **20 parsed events in 5 minutes**, live browsing from
`192.168.2.2` captured with full HTTPS URLs.

### Related fixes from the same session

- **Traffic wasn't reaching Squid at all** initially — empty `access.log`, zero
  connections to `:3128`. Resolved with OPNsense port redirects: **HTTP `80→3128`** and,
  via sslbump, **HTTPS `443→3129`**. The Windows box also has the proxy set explicitly
  and the Squid CA installed.
- **OPNsense capacity** — at 4.3 GB RAM, detonation traffic through sslbump + Suricata
  IPS caused swapping and repeated **Squid segfaults (signal 11)**, dropping packets on
  both segments. RAM was increased.

---

## 5. Detection and analytics — **verified 2026-08-09** **[V]**

| Area | Verified state |
|---|---|
| Detection rules | **1,790 installed, 620 enabled** — the "286 not yet installed" note is long superseded |
| ML anomaly jobs | **44 total: 6 opened, 35 closed, 3 failed** |
| Opened jobs | the **ProblemChild / LotL** set: `problem_child_high_sum_by_{host,parent,user}`, `problem_child_rare_process_by_{host,parent,user}` |
| **Failed jobs** ⚠️ | `packetbeat_rare_server_domain`, `packetbeat_rare_urls`, `packetbeat_rare_user_agent` |
| Cases | per-sample investigation record |

The three failed jobs are all **packetbeat** models. Given `network_traffic.dns` has
0 documents while `network_traffic.flow` is still flowing, these likely failed for lack
of input data. Worth either fixing the packetbeat inputs or closing the jobs so they
stop showing as failed.

---

## 6. Retention / ILM — **verified 2026-08-09** **[V]**

The custom policies are named **`cti-*`** (the first draft's `logs-30d` / `logs-90d`
came from a transcript and do not exist):

| Policy | Actual retention | Applied to |
|---|---|---|
| `cti-logs-90d` | **delete at 365d** ⚠️ name says 90d | 199 indices — the main `logs-*` set |
| `cti-metrics-30d` | delete at 30d | 51 indices — `metrics-elastic_agent.*` |
| `cti-network-logs-30d` | **delete at 365d** ⚠️ name says 30d | 12 indices — `logs-network_traffic.*` |
| `cti-kibana-eventlog-7d` | delete at 7d | Kibana event log |

> ⚠️ **Two policy names are misleading.** `cti-logs-90d` and `cti-network-logs-30d`
> both actually delete at **365 days** — consistent with the stated intent of keeping
> security data longer, but the names will mislead anyone reading the console. Consider
> renaming, and note it on any diagram that shows retention tiers.

Elastic also ships built-in `7/30/90/180/365-days` policies (hot → warm 2d → cold 30d
→ delete), unused by the lab's own data streams.

### Cluster capacity **[V]**

| Metric | Value |
|---|---|
| Nodes | 2 × 720 GB |
| Used | **41.7 GB / 42.4 GB (5%)** |
| Available | ~678 GB per node |
| Shards | 556 per node |

**The disk pressure documented earlier is resolved** — the cluster is at 5%. Any note
saying "recheck storage before a workshop" is stale; there is ample headroom.

## 7. Known gaps **[T]**

| Gap | Impact |
|---|---|
| ~~Squid log ingestion broken~~ | ✅ **RESOLVED 2026-08-08** — see §4 |
| OPNsense memory under load | sslbump + Suricata IPS caused Squid segfaults at 4.3 GB; RAM raised. Re-check before a heavy workshop |
| Agent health after rollback ⚠️ | **Live example:** `secdis` last shipped **2026-08-08 19:44 UTC** (~19h before this audit) despite the VM running |
| Clock drift on `secdis` | Events land outside the expected time window and appear "missing" |
| ~~Storage pressure~~ | ✅ **Resolved** — cluster at 5% (678 GB free/node) |

---

## 8. Diagram brief — telemetry pipeline

Draw **left → right**, four columns:

**Sources** → **Shipper** → **Elastic Cloud** → **Analyst outputs**

- **Sources:** `secdis` (Defend, Sysmon, PowerShell, Security, AppLocker) — its own
  agent, shipping **direct**; OPNsense (Suricata, filterlog, Squid, DNS) — syslog to
  **util-debian:9001**; util-debian's own `system.*`; six AbuseCH TI feeds pulled by
  Elastic Cloud itself
- **Shipper:** two distinct paths — `secdis` agent → Elastic Cloud, and OPNsense →
  **util-debian relay** (Elastic Agent) → Elastic Cloud. Do **not** draw OPNsense
  connecting straight to Elastic Cloud; that was wrong in the first draft.
- **Elastic Cloud:** data streams → ILM tiers → detection rules → ML jobs → alerts
- **Outputs:** Alerts → Cases → workshop narrative

Show the **Squid path as working** (it was fixed 2026-08-08); if you want to teach the
blind-spot lesson, draw it as a *before/after* pair rather than a current gap. Mark all arrows
**outbound-only** into Elastic Cloud. If you want one diagram to carry the teaching
point, make it this one with the proxy blind spot highlighted.
