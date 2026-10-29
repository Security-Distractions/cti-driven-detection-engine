# Test results — Sigma rules against live Elastic

**Outcome: two rules shipped, one withdrawn.** `cbdbe5ea` was tested here, found unable to fire on
this estate as converted, and withdrawn from the package. Its results are kept below because they
are the evidence for that decision.

**Run:** 2026-10-29 · **Cluster:** Elastic Cloud, Elasticsearch 9.5.3 · **Access:** read-only
`_search` only. No rule was installed, no index written, no cluster setting changed.
**Method:** each rule converted with `sigma convert -t lucene -p ecs_windows`, and the resulting
query submitted verbatim as a `query_string` against `logs-*,.alerts-*,metrics-*`.

The rules are pure Sigma — generic logsources and spec field names only. Nothing product-specific
is in the YAML, and nothing below asks for any to be added.

## Estate context, which limits every number here

| Hosts reporting `event.category:process` in 90 days | 2 |
|---|---|
| `linux-collector` | 4,943,695 process documents |
| `analysis-host` (Windows 11, the detonation target) | 43,358 process documents |

**One Windows host.** Every false-positive number below is therefore "zero on a single lab
workstation", not "zero across an estate". That is the most important caveat in this document and
it is not resolved by any amount of querying this cluster.

## Test 1 — true positive, the detonation window

Window `2026-10-27T21:17:00Z` to `21:32:00Z`, `host.name` = the analysis host.

| Rule | Unscoped | + `event.category` | Verdict |
|---|---|---|---|
| `f378e7a8` no-arguments | 19 | **4** | **FIRES** on the hollowing event |
| `cbdbe5ea` vaultcli | **0** | **0** | **MISSES** — see Test 4 |
| `682ee4ba` outbound | 23 | **2** | **FIRES** on the C2 channel |

Rule `f378e7a8`, scoped, returned the real events:

```
2026-10-27T21:20:59.3014254Z  RegSvcs.exe   endpoint.events.process
2026-10-27T21:20:59.301Z      RegSvcs.exe   windows.sysmon_operational
2026-10-27T21:21:02.4822041Z  RegSvcs.exe   endpoint.alerts
2026-10-27T21:26:24.483Z      RegSvcs.exe   endpoint.events.process
```

Rule `682ee4ba`, scoped, returned the socket:

```
2026-10-27T21:21:01.6059121Z  connection_attempted
2026-10-27T21:22:42.1162197Z  disconnect_received
```

All three queries were accepted by Elasticsearch's parser. No syntax errors, no refused constructs.

## Test 2 — 90-day production retrohunt, all hosts

This is the step every validation note names as a prerequisite. Properly scoped by
`event.category`, `now-90d` to `now`, no host filter.

| Rule | Hits in 90 days | Hosts | Datasets | Query time |
|---|---|---|---|---|
| `f378e7a8` | **13** | analysis-host only | `endpoint.events.process` 6, `windows.sysmon_operational` 4, `endpoint.alerts` 3 | 0.4 s |
| `cbdbe5ea` | **0** | — | — | 0.2 s |
| `682ee4ba` | **6** | analysis-host only | `endpoint.events.network` 6 | 0.2 s |

**Zero hits on the Linux collector**, which holds 99.1% of the estate's process telemetry. The
rules are Windows-scoped and behave accordingly.

## Test 3 — the retrohunt hits that are not the October detonation

Both firing rules returned hits dated **2026-08-06**, 82 days before the October run. Those needed
attribution before the rules could be called clean, because an unexplained hit is a false positive
until proven otherwise.

They are **true positives from a second, independent Agent Tesla detonation**:

- The parent is a different sample — SHA256-named binary `5067ae4261feea16e5b765d748a743eb9f55d86cf795c0213ac3769049e7dfba`, not October's `fdc9cb25…b42c`.
- Same technique: `RegSvcs.exe` spawned with an empty command line, `OriginalFileName` = `RegSvcs.exe`, parent in a Downloads subdirectory named after its own hash.
- The cluster's own alerts for that window confirm the family — **51 signal alerts**, including
  `Memory Threat Detection Alert: Windows.Trojan.AgentTesla` ×4, `Suspicious Suspended Process
  Creation` ×6, `Remote Thread Context Manipulation` ×4, `Suspicious Remote Memory Allocation` ×4,
  `Access to Windows Passwords Vault by Unusual Process` ×8 and `Suspicious Vault Client Image
  Load` ×4.
- That August run also did things October's did not: Defender exclusions via PowerShell and via
  WMI, and `Disabling Windows Defender Security Settings via PowerShell`.

**So across 90 days the two firing rules produced 19 hits, every one of them a true positive, across
two independent samples of the same family 82 days apart.** The rules generalise past the single
sample they were drafted from. That is the strongest evidence available short of a populated estate.

**False positives in 90 days: 0.** Caveated as above — one Windows host, and no .NET Framework
utility was invoked on it for any legitimate purpose in the entire period.

## Test 4 — why `cbdbe5ea` returns nothing, settled

The August detonation raised `Suspicious Vault Client Image Load` ×4, so `vaultcli.dll` demonstrably
was loaded. The rule still returned 0 for that window. Three queries settle why:

| Query, 2026-08-06 window | Docs |
|---|---|
| `wildcard` on the module-path field this estate populates, `*vaultcli.dll` | **23** |
| `wildcard` on the field `ecs_windows` targets, `*vaultcli.dll` | **0** |

Estate-wide over 90 days, for `event.category:library`:

| Field | Documents where it exists |
|---|---|
| The field this estate's module-load events populate | **39,033** |
| The field `ecs_windows` maps `ImageLoaded` to | **9** |

**The rule's logic is correct and its pipeline is wrong.** `ImageLoaded` is the right Sigma field
for `category: image_load`; `ecs_windows` encodes the Winlogbeat/Sysmon mapping, which this estate's
module-load telemetry does not use. Fix belongs in a pipeline supplied at conversion time, not in the
YAML — a rule that hard-codes one shipper's field name stops being a Sigma rule.

Until that pipeline exists, **a zero result from this rule means the pipeline is pointing at the
wrong field, never that the credential vault was untouched.** Deployed as converted today it is a
rule that cannot fire.

## Test 5 — a case-sensitivity gap introduced by the pipeline

`ecs_windows` maps `Image` to a case-insensitive sub-field but `CommandLine` to the case-**sensitive**
base field. The converted query is therefore mixed:

```
process.executable.caseless:(... OR *\\RegSvcs.exe)   <- case-insensitive
process.command_line:(... OR *RegSvcs.exe\")          <- case-SENSITIVE
```

| Query variant, 90 days | Hits |
|---|---|
| As converted | 13 |
| Same query with the command-line clause lowercased | **0** |
| Documents with lowercase `regsvcs.exe` in `command_line` | **0** |

No lowercase invocation exists in 90 days, so this has not been exercised in the wild. The exposure
is still real: Windows accepts `"c:\windows\microsoft.net\framework\v4.0.30319\regsvcs.exe"`
perfectly happily, the anchor clause would still match it, and the discriminator would not — so the
rule misses. **Recorded as a residual gap in `f378e7a8`.** It is a pipeline artifact, not a rule
defect, and the remedy is the same: a pipeline that maps `CommandLine` to a case-insensitive
sub-field where one exists.

## Summary

| Rule | True positives | False positives | Deployable as converted today? |
|---|---|---|---|
| `f378e7a8` no-arguments | 13 over 2 samples | 0 | **Yes, with `event.category:process` scoping.** Carries the argument-evasion and case-sensitivity gaps |
| `cbdbe5ea` vaultcli | 0 | 0 | **Withdrawn.** Logic sound, pipeline wrong — it cannot fire on this estate as converted |
| `682ee4ba` outbound | 6 over 2 samples | 0 | **Yes, with `event.category:network` scoping.** Unscoped it returns 23 for 2 real events |

The two shipped rules remain `status: experimental`. Both now have a clean 90-day retrohunt behind
them on a single-Windows-host estate, which satisfies the letter of their test plans and not the
spirit: nothing here demonstrates behaviour against a populated fleet with real administrative
tooling.

`cbdbe5ea` was withdrawn on the strength of Test 4. A rule that converts cleanly, passes every
validator and returns zero is worse than no rule, because zero reads as a quiet estate. Restoring it
needs one conversion pipeline and no change to its YAML.

**Reproducing this:** the queries are the `.lucene.txt` files beside each rule. Connection details
come from `ELASTIC_URL` / `ELASTIC_USER`; the password in `/opt/agentic-threat-hunter/.env` is stale
and returns HTTP 401, so supply it out of band.
