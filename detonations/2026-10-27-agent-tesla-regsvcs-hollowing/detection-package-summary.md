# Detection package summary — Agent Tesla, RegSvcs hollowing (2026-10-27)

Drafted 2026-10-29 by David Clayton - CTI @ thetechcollective using the create-sigma-rule skill.
**Two rules shipped**, both `status: experimental`. A third was drafted, tested against the live
cluster, and **withdrawn** — see "The rule that was withdrawn".

| Rule | File | Level |
|---|---|---|
| Suspicious .NET Framework Utility Started Without Arguments | `detections/sigma/proc_creation_win_dotnet_framework_utility_no_arguments.yml` | high |
| Potential Outbound Connection From .NET Framework Utility | `detections/sigma/net_connection_win_dotnet_framework_utility_outbound.yml` | medium |

Each has a `.validation.md` and a `.lucene.txt` beside it. The two are linked with
`related: type: similar`, because they are two cuts at one intrusion chain and are meant to be
deployed together: the first catches current tradecraft cheaply, the second survives the evasion
that defeats it.

## Read-back: what came in

A 15-minute telemetry capture from the lab host `analysis-host`, 2026-10-27 21:17–21:32 UTC: 10,652
documents and 35 alerts, with full `_source`. Enrichment came from the Recorded Future MCP
server, `intelligence_cards` and a malware-family pivot only, no org-context tools and no
watchlists.

**The chain, as the telemetry records it:**

| Time (UTC) | Event |
|---|---|
| 21:20:01 | `7zFM.exe` → `7zG.exe x -o"C:\Users\analyst\Downloads\fdc9cb25…b42c\"` |
| 21:20:09.9 | `7zG.exe` writes `fdc9cb25…b42c.exe` into that directory |
| 21:20:27.6 | `explorer.exe` → the sample. User execution, no argument. It loads `clr.dll`: a .NET assembly |
| 21:20:59.3 | the sample → `"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"`, **no arguments** |
| 21:20:59.4 | the sample exits, 114 ms after spawning its container |
| 21:20:59.5 | `RegSvcs.exe` loads the WMI client stack: `wmiutils.dll`, `wbemcomn.dll`, `wbemprox.dll`, `WMINet_Utils.dll`, `wbemsvc.dll`, `fastprox.dll` |
| 21:21:01.6 | `RegSvcs.exe` connects outbound, to the internal proxy at `<proxy-ip>:3128` |
| 21:21:02.18 | `RegSvcs.exe` opens `…\Google\Chrome\User Data\Default\Login Data` |
| 21:21:02.20 | `RegSvcs.exe` opens `…\Microsoft\Edge\User Data\Default\Login Data` |
| 21:21:02.23 | `RegSvcs.exe` loads `vaultcli.dll` |
| 21:22:42.1 | the socket closes. No further sample activity in the window |

**Observed techniques, from the alerts:** T1055 Process Injection (14 alerts), T1555 /
T1555.004 Credentials from Password Stores, Windows Credential Manager (9 each), T1036
Masquerading (3). Severity split across the 35 alerts: 19 critical, 6 high, 1 low, 9 unscored
endpoint events.

**Family attribution:** Agent Tesla, from the Recorded Future enrichment (master ID `hd4fiZ`,
categories Keylogger and Trojan, risk 65/99, "Positive Malware Verdict"), corroborated
independently by Elastic Defend's own memory signature `Windows.Trojan.AgentTesla` and by a
Triage score of 10.

## Ranking: why these three

Candidates were ranked on telemetry availability, durability, chain position and standing
requirements, in that order.

1. **The hollowing spawn** came first because it sits at the chokepoint. The loader cannot skip
   it, every later behaviour depends on it, and process creation is the best-collected log
   source in the estate.
2. **The vault client load** came second because it is the most durable thing in the capture.
   A stealer that wants Credential Manager contents must load that DLL into whatever it is
   running as; nothing about a rebuild changes it.
3. **The outbound connection** came third because it survives the cheap evasion that defeats
   rule one, and because module-load and network telemetry are both already onboarded.

Rule one is deliberately the most fragile of the three. One junk argument on the `RegSvcs.exe`
command line defeats it, and that is stated plainly in its note. It earns its place by being
cheap, precise and aimed at the chokepoint; the other two are the ones that hold when the
author adapts.

**Rule one was re-drafted on 2026-10-29** after the skill's evidence ledger was applied to it.
See "The condition that came out" below.

## The rule that was withdrawn

A third rule was drafted, validated and tested: `image_load_win_vaultcli_by_dotnet_framework_utility`
(`cbdbe5ea-54da-44c6-8208-f6ddf618fd5b`), matching `vaultcli.dll` loaded into a .NET Framework
utility. It was the most durable logic in the set — an infostealer after Credential Manager contents
has to load that library into whatever process it is running as, and no rebuild changes that.

**It was withdrawn because it cannot fire on this estate as converted**, and the evidence is
unambiguous rather than suspected:

- 90 days, scoped `event.category:library`: **0 hits**.
- The 2026-08-06 Agent Tesla detonation raised `Suspicious Vault Client Image Load` ×4, so the
  behaviour demonstrably occurred. Querying that window on the module-path field this estate
  populates returns **23** documents containing `vaultcli.dll`. Querying the field `ecs_windows`
  maps `ImageLoaded` to returns **0**.
- Estate-wide across 90 days for `event.category:library`: the field this estate populates exists on
  **39,033** documents; the field `ecs_windows` targets exists on **9**.

The logic was never the problem. `ImageLoaded` is the correct Sigma field for `category: image_load`,
and hard-coding this estate's field name would have stopped it being a Sigma rule at all. The missing
piece is a conversion pipeline that maps `ImageLoaded` to the field the target index uses.

**Shipping it would have been worse than not shipping it.** A rule that converts cleanly, passes
every validator and returns zero looks like a quiet estate, and would have been read as evidence the
credential vault was never touched — on an estate where it demonstrably was, twice.

It is recorded as further rule candidate 0 below. The rule file and its validation note are not in
this repository; the behaviour is covered instead by the Elastic Defend behavioural rules that
already fired on it, which is where that coverage currently lives.

## Further rule candidates

Not drafted, in priority order. Candidate 0 was drafted and withdrawn; the rest were never drafted.

0. **Credential vault client loaded by a .NET Framework utility.** Drafted, tested, withdrawn — see
   above. **Blocked on a conversion pipeline, not on rule logic.** The single highest-value item on
   this list, and the cheapest to unblock: one pipeline mapping `ImageLoaded` to the module-path
   field the endpoint index uses, after which the withdrawn rule can be restored unchanged.
1. **Browser credential store opened by a non-browser process.** The sample read Chrome's and
   Edge's `Login Data` 30 ms apart. Highest-value remaining behaviour, and **not expressible in
   standard Sigma**: there is no `file_access` category, `file_event` covers creation and
   modification only, and a file *open* is EDR-specific telemetry. Right answer is a native
   Elastic rule on `event.action:open` in `logs-endpoint.events.file-*`, not a Sigma rule.
2. **Correlation rule for the injection API triad.** `Suspicious Suspended Process Creation` +
   `Suspicious Remote Memory Allocation` + `Remote Thread Context Manipulation` fired within
   25 ms of each other. That shape is a Sigma correlation rule over three base rules, and the
   base rules need `create_remote_thread` (EID 8) and `process_access` (EID 10), which the lab
   gets from Elastic Defend's API events rather than from Sysmon. Worth doing; needs the base
   rules first.
3. **WMI client stack loaded by a .NET Framework utility.** Six WMI DLLs loaded in 150 ms,
   consistent with system and security-product discovery from inside the hollowed image. Same
   logsource as rule two and a one-line variant of it; held back because the false-positive
   profile is unknown and `image_load` is noisy.
4. **Hollowing containers beyond the registration utilities.** `MSBuild.exe`,
   `aspnet_compiler.exe`, `jsc.exe`, `csc.exe`. Deliberately excluded from all three rules: each
   has legitimate argument-bearing use that the empty-argument clause does not separate well.
   Extending `selection_process` in rules two and three is safe and is the first widening to
   make once their retrohunts come back clean.
5. **Executable run from a directory named after its own hash.** A real artefact of this
   capture, and an artefact of *analyst* behaviour, not of the malware. Explicitly not a rule.

## Telemetry gaps found

- **No organizational profile exists.** `sigma-org-profile-DRAFT.md` was written from what the
  repository and this capture actually show, and is marked unconfirmed. Everything it asserts is
  evidence-backed; what it cannot know is flagged inside it.
- **`ImageLoaded` maps to `file.path` under `ecs_windows`, but Elastic Defend carries
  a different name.** Rule two's converted query returns nothing against the endpoint index, which looks
  exactly like the behaviour being absent. Both variants are given in its note. This is the
  highest-consequence finding in the package.
- **No event-category binding survives conversion.** Neither `ecs_windows` nor
  `windows-logsources` adds one, so all three queries must be scoped by index pattern or by an
  added `event.category` clause. Rule three is the dangerous one here: unscoped, it matches
  process-creation documents as well, because `process.executable` is populated there too.
- **`Initiated` is not usable on the ECS path.** It maps to `network.direction`, which carries
  `ingress`/`egress`, never a boolean. The clause was dropped from rule three rather than left to
  convert into a query that matches nothing. `sigma check` passed the broken version cleanly;
  only reading the converted query caught it.

## Behaviours in the capture that are not detectable from log telemetry

- **The injection itself.** `VirtualAllocEx`, `SetThreadContext` and `ResumeThread` against a
  suspended process are visible to Elastic Defend's API telemetry and to its memory scanner, and
  are not in any Sysmon-shaped Sigma logsource. The alert that actually named the family,
  `Memory Threat Detection Alert: Windows.Trojan.AgentTesla`, came from a memory scan, which no
  Sigma rule can reproduce.
- **What the sample exfiltrated, and whether it succeeded.** The capture shows one 100-second
  socket to the proxy and nothing about its contents.
- **Persistence.** None was observed. No Run key, no scheduled task, no service. Either this
  variant does not persist, the operator did not ask it to, or it was waiting on a command that
  never came. Nothing to detect, and worth recording so a future reader does not assume the
  capture is incomplete.

## One correction to the enrichment

One external address is carried in `rf-enrichment.json` as an "external destination" with 30
local sightings. **It is not related to this sample.** Specifically:

- the only session to it is a single TCP flow carrying one `network.community_id`, whose
  `event.start` is `21:16:48.667Z`, before the sample executed at `21:20:27`;
- the 30 sightings are 30 repeats of that one flow by Packetbeat's rollup interval, not 30
  connections;
- the hollowed `RegSvcs.exe` never connected to it. Its only destination was the proxy at
  `<proxy-ip>:3128`, and the sandbox reported 0 C2 indicators for the sample, which agrees.

It is unrelated background traffic on the host, open across the capture window.

No rule in this package references that address, and none should.

## The condition that came out

The first draft of rule one carried a third selection requiring the parent process to be running
from a user-writable directory:

```yaml
selection_parent_user_writable:
    ParentImage|contains:
        - '\Users\Public\'
        - '\Downloads\'
        - '\AppData\Local\Temp\'
        - '\AppData\Roaming\'
        - '\Windows\Temp\'
        - '\ProgramData\'
        - '\$Recycle.Bin\'
```

Labelling each condition against the capture showed what that was. Only `\Downloads\` was
`SOURCED` — the observed parent really did run from there. The other six paths were inference,
and more to the point **requiring any user-writable parent at all was an `INFERRED` condition
that narrowed the rule**. It read as deliberate and defensible, and it was neither: staging the
dropper into a new directory under `C:\`, or into a writable subdirectory of `Program Files`,
would have defeated the entire rule without anything in the telemetry looking wrong.

The selection was removed. `ParentImage` and `ParentCommandLine` stay in `fields` as a triage
aid, which is where a parent belongs when it cannot be defended as a condition, and the path list
survives in the validation note as a tuning pattern with the values openly left to the analyst.

Three consequences, stated plainly because two of them are costs:

- **The rule is more durable.** Path variation no longer defeats it at all, which removes one of
  the residual gaps the first draft had to admit.
- **The rule is broader.** It will now fire on an administrator running `RegSvcs.exe`
  interactively to read its usage text. That was the false positive the parent clause had been
  quietly suppressing, and the retrohunt now carries the weight of establishing how often it
  happens.
- **Nothing was substituted for it.** A `filter_main_*` block on shell parentage would have
  needed a value this environment has not confirmed, and a fabricated filter looks tested while
  excluding nothing.

Rules two and three were re-examined the same way and needed no logic change. Every narrowing
condition in both is `SOURCED` directly from the capture; their `INFERRED` labels sit only on
broadening alternatives inside OR lists, which widen the match rather than tightening it.

## What the profile's backend answer changed

The profile names Elastic Security and nothing else, so everything below follows from that one
answer and would have been different for a Splunk or Sentinel shop:

- **Target and pipeline:** `-t lucene` and `-t eql`, both with `-p ecs_windows`. Note the plugin
  name and the target are different strings — `sigma plugin install elasticsearch` provides
  `lucene`, `eql`, `esql` and `elastalert`, and `-t elasticsearch` is an error.
- **Field names:** `process.executable.caseless`, `process.pe.original_file_name`,
  `process.command_line`, `file.path`. Not Sysmon's raw names.
- **One construct kept that Splunk would have forced a decision on:** the `Image` OR
  `OriginalFileName` pair in rule one. `check_grouping.py -t lucene` confirms it is bracketed
  under the AND. On Splunk it would not be, and there is no in-rule fix.
- **One construct refused outright:** `Initiated: 'true'` in rule three, which `ecs_windows` maps
  to `network.direction` — a field that carries `ingress`/`egress`, never a boolean.
- **No `--without-pipeline` fallback exists.** `sigma list targets` reports "Processing Pipeline
  Required: Yes" for every Elastic target.
- **Artifact format:** the profile does not name a deployable output format, so the fallback
  applies — `-f default` and a bare query per rule, shipped as `<stem>.lucene.txt` beside each
  rule. If the team wants importable Kibana rules instead, one run of
  `sigma convert -t lucene -p ecs_windows -f siem_rule_ndjson` produces them.
- **Nothing was dropped for want of telemetry.** All three behaviours land in log sources the
  profile marks as collected, so the telemetry gate excluded no behaviour from the three. The
  browser-credential-store read was excluded for a different reason — no Sigma category expresses
  a file *open* — and is listed as candidate 1.

## Replay against the captured detonation

All three compiled queries were evaluated offline against the capture — 10,652 documents and 35
alerts from the detonation window. This is a replay against the data the rules were drafted from,
so it proves the logic matches the events it was written for. **It is not a production retrohunt
and does not establish a false-positive rate.**

| Rule | As compiled | Correctly scoped | True positives | False positives |
|---|---|---|---|---|
| f378e7a8 no-arguments | 21 | 6 (`event.category:process`) | **2** RegSvcs `start` events | **0** |
| cbdbe5ea vaultcli (`file.path`, as shipped) | **0** | 0 | **0 — misses the behaviour** | 0 |
| cbdbe5ea vaultcli (logic re-mapped to this index's module-path field) | 1 | 1 (`event.category:library`) | **1** the real module load | **0** |
| 682ee4ba outbound | 38 | 3 (`event.category:network`) | **3** the real channel | **0** |

Zero false positives across the whole capture, under every rule: every matching document is the
sample's `RegSvcs.exe`. That is a weak result rather than a reassuring one — **no other .NET
Framework utility was invoked anywhere in the 15-minute window**, so the capture contains no
opportunity for a false positive and says nothing about behaviour on a populated estate.

Three things the replay settled that static validation could not.

**1. Rule cbdbe5ea returns nothing through the `ecs_windows` pipeline.** 0 hits against a capture
that unquestionably contains the vault load. The field census shows why: the field that pipeline
targets is populated on 67 documents here, 60 of them *file* events, while the capture's module-load
events name it differently — 78 documents, all of them library events. Run the same rule logic
against the field this index actually uses and it returns the real event.

**This is a pipeline finding, not a rule finding.** `ImageLoaded` is the correct Sigma field for
`category: image_load`, the rule stays pure Sigma, and nothing product-specific goes into the YAML.
What it means is that `ecs_windows` is the wrong pipeline for this estate's module-load telemetry,
and the fix belongs in a pipeline mapping supplied at conversion time. A zero result from this query
means the pipeline is pointing at the wrong field, never that the vault was untouched.

**2. Rule 682ee4ba unscoped returns 12.7x what it should.** 38 documents against 3 real network
events, pulling in module loads, file events and alert documents that carry `process.executable` for
the same process. The scoping instruction is quantified, not merely asserted.

**3. Renaming the utility defeats all three rules, and rule f378e7a8's note previously claimed
otherwise.** A mutation test with the image renamed to `svchost32.exe` and `OriginalFileName` still
reading `RegSvcs.exe` **missed**, because the no-arguments discriminator independently requires a
known utility filename on the command line. The earlier note's claim that `OriginalFileName` covered
renaming for three of five images was wrong and has been corrected. There is no in-rule fix on this
backend: `CommandLine|endswith|fieldref` is refused at parse time with *"Field references must not
contain wildcards"* and `CommandLine|fieldref: Image` at conversion with *"ES Lucene backend can't
handle field references."* Rules cbdbe5ea and 682ee4ba anchor on `Image|endswith` alone and are
defeated the same way. **The package has no coverage for a renamed .NET utility** — a package-level
gap, with nothing in the three rules closing it.

The mutation tests also confirmed the ledger decision empirically. With the parent moved to
`C:\staging\loader.exe` or `C:\Program Files\Vendor\loader.exe`, the re-drafted rule **fires**
and the first draft — with its user-writable-parent clause — **missed**. That clause was an
`INFERRED` narrowing, and the coverage it was costing is now measured rather than predicted.

**Method caveat:** `process.executable.caseless` is an index-time multi-field and is absent from
`_source`, so the replay matches case-insensitively on `process.executable` to emulate it.
Everything else is evaluated exactly as the compiled query specifies.

## Stage 8 not run: the lookups it would have made

The Feedly MCP server is not connected to this session — `search_ttps`,
`get_malware_relationships` and `search_entities` are absent — so the grounding stage could not
run. Recorded here so the gap is visible rather than silent, with the lookups it would have made:

| Lookup | Tool | What it would have contributed |
|---|---|---|
| Agent Tesla, observed procedures, last 12 months | `search_ttps` filtered to the family and to T1055.012 / T1218.009 | Real command lines behind the hollowing, which would confirm or correct the five-binary image list and tell us whether the empty-argument form is current tradecraft or just this sample |
| Agent Tesla relationships | `get_malware_relationships` on the resolved entity | Related techniques for the further-candidates list, independent of the RF rollup already used |
| **Existing community Sigma rules for Agent Tesla** | `get_malware_info`, reading its detection-rules data | **The highest-value check of the four.** RegSvcs hollowing and `vaultcli.dll` loads are well-trodden ground; if SigmaHQ already covers either, adapting a tested rule beats these drafts |
| Reporting to seed `references` | `search_articles` then `get_article` | All three rules currently cite only the Triage report. Article permalinks would give each a second source |

Partial substitute already applied: the Recorded Future family pivot on master ID `hd4fiZ` supplied
a 14-technique rollup over 90 references, which fed the further-candidates list and the two local
corroboration matches. It does not answer the community-rules question, which is Feedly-specific.

## Validation summary

```
sigma-cli 3.1.0 / pySigma 1.5.1 / pySigma-backend-elasticsearch 2.1.1
pysigma-pipeline-windows 2.0.1 / pysigma-pipeline-sysmon 2.0.0
Sigma specification v2.1.0 / ATT&CK Enterprise v20.0

attack_check.py --rules detections/sigma      → exit 0; 22 valid, 0 invalid, 0 unverified
sigma check -i <rules>                       → exit 0; 0 errors, 0 condition errors, 0 issues
check_grouping.py -t lucene -p ecs_windows . → exit 0; 6 clean, 0 needing attention
sigma convert -t lucene -p ecs_windows       → all three succeed
sigma convert -t eql    -p ecs_windows       → all three succeed
```

Three things about that block are worth stating rather than leaving to be inferred.

**`attack_check.py` exited 0**, which means the tags were checked and all are valid. Exit 2 or 3
would have meant the tags were never checked at all, which is a different claim entirely and is
the one that has to be disclosed in those words. Zero `[UNV]` results, so nothing taxonomically
valid-but-unconfirmed is being rounded up to valid.

**`sigma check` was run without `-x d3_fendtag`.** The first pass of this package excluded that
validator by default. On this network it reaches its data and passes, so excluding it was
skipping a check that works — the exclusion is for restricted egress, not a standing flag.

**`check_grouping.py` is new to this package** and is the only gate that inspects the compiled
query's operator grouping. `sigma check` and `sigma convert` say nothing about it.

sigma-cli 4.0.0 is current on PyPI, but it ships pySigma 2.x and the elasticsearch, sysmon and
windows plugins do not yet support it. 3.1.0 is the newest version where they install
compatibly, and it is what was used. ATT&CK v20.0 is one release newer than the v19 the skill's
notes describe; tags were checked against v20.0, machine-verified, not by hand.
