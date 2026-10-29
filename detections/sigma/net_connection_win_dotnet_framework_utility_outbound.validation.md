# Validation Note: Potential Outbound Connection From .NET Framework Utility

**Rule id:** 682ee4ba-481f-4c48-9f31-2b74df146976
**File:** `net_connection_win_dotnet_framework_utility_outbound.yml`
**Drafted:** 2026-10-29 by David Clayton - CTI @ thetechcollective using the create-sigma-rule skill
**Status:** experimental. This rule has not been run against production data.

## Source

Raw telemetry: the lab detonation of 2026-10-27 on `analysis-host`. Two network events in
`endpoint.events.network`:

```
2026-10-27T21:21:01.6059121Z  RegSvcs.exe  <proxy-ip>:3128  connection_attempted
2026-10-27T21:22:42.1162197Z  RegSvcs.exe  <proxy-ip>:3128  disconnect_received
```

Elastic Defend raised *Network Connection via Process with Unusual Arguments*, tagged T1055 and
T1036.

## Behavior targeted

A .NET Framework registration utility opens a network socket. The observable is the connection
attributed to that process image. Nothing about the destination is part of the logic.

## Abstraction level

**Chosen:** invariant behavior, tagged `stp.4`.

**Why:** assembly registration is a purely local operation. A payload hollowed into one of these
binaries that wants to reach its operator has to open a socket from inside the signed image. The
rule is indifferent to the C2 address, which is the part of this campaign with the shortest life.

**Layers:** `selection_anchor` holds the anchor and is the whole rule. **There is no invariant and
no discriminator layer.** Within `category: network_connection` the anchor *is* the discriminator —
these binaries have no network role at all — so there is nothing to put in the other two layers
and nothing has been parked unreferenced. The cost is real and is stated in the caveats: the
rule's entire specificity rests on assumption 2, which the retrohunt must confirm before this is
allowed to alert.

## Default state

**With no arguments, the tool or behavior does:** not applicable. This is a network-connection
rule with no argument surface.

**In scope?** No meaningful default.

**Consequence for the condition:** none, and this is the rule's main virtue. It fires regardless
of how the utility was invoked, so it survives the one-junk-argument evasion that defeats sibling
rule f378e7a8.

## Resilience record

| # | Question | Answer | Outcome |
|---|---|---|---|
| 1 | Anchor a known Windows binary in a `process_creation` rule? | **No — a different logsource.** `category: network_connection` | `OriginalFileName` **N/A**. It is not part of the Sysmon EventID 3 schema at all, so asserting it would produce a clause the pipeline cannot map. Renaming gap recorded; sibling f378e7a8 partially covers it |
| 2 | `OriginalFileName` added, and is the target Splunk? | Not added, and not Splunk | Nothing further. `check_grouping.py -t lucene` clean |
| 3 | Rule matches on command-line flags? | **No** | `\|windash` **N/A** |

## Evidence ledger

| Condition | Label | Locator / citation |
|---|---|---|
| `Image\|endswith: '\RegSvcs.exe'` | `SOURCED` | Capture, `endpoint.events.network`, `process.name` on the 21:21:01.6059121Z event |
| `Image\|endswith:` the other four images | `INFERRED` | Broadening alternatives within an OR list, permitted because each widens the match |

**Dropped or broadened by the `INFERRED` rule:**

The first draft carried `Initiated: 'true'`, which is correct for Sysmon EventID 3. Through
`ecs_windows` it converted to **`network.direction:true`**. ECS `network.direction` carries
`ingress`, `egress`, `inbound`, `outbound` or `internal` — **never a boolean** — so the clause
reduced the rule to a query that can never be true, while passing every validator cleanly. It was
removed rather than left in place. This was a field-semantics defect rather than a ledger one, but
it is recorded here because it is the single most useful thing Stage 6 caught in this package.

There is also a narrowing condition this rule deliberately **does not** carry: a destination
filter. Restricting to external or non-RFC1918 addresses would be an `INFERRED` narrowing, and on
this estate it is also factually wrong — every user-process connection in the capture terminates
at the internal proxy, so an "external destination" clause would have missed the C2 channel
entirely. The profile records forced proxy egress as an environment fact.

**Description provenance:** "assembly registration is a local operation" is `GENERIC`, from the
utilities' documented purpose. "In a proxied environment the only destination the endpoint ever
sees is the internal proxy" is `SOURCED` — from this capture and recorded in the profile.

## ATT&CK mapping rationale

```
Hollowed RegSvcs.exe opens the operator channel over TCP
  -> T1071 (Application Layer Protocol)     tactics: command-and-control
The socket is opened from inside a signed Microsoft .NET registration utility
  -> T1218.009 (Regsvcs/Regasm)             tactics: stealth
```

Both verified by `attack_check.py` against ATT&CK Enterprise v20.0: valid, correct tactics, not
revoked. On fit: T1071 is the primary and is a clean match. **T1218.009 is the weaker of the two** —
it describes proxy *execution* via these binaries, and this rule detects a consequence of that
rather than the execution itself. It is kept because the signed-binary provenance is what makes
the connection notable at all, but a reviewer who wanted it dropped would have a fair case.
`attack_check.py` cannot adjudicate that; it only confirmed the tag exists and carries the
declared tactic.

## Assumptions

| # | Assumption | How to confirm |
|---|---|---|
| 1 | Network telemetry carries the initiating process image. Sysmon EventID 3 and Elastic Defend both do; NetFlow and firewall logs do not | Check `process.executable` is populated on a sample network event |
| 2 | **These utilities never open sockets in this estate.** This is the whole rule | Retrohunt, step 2. Nothing else establishes it |
| 3 | The host routes egress through a proxy, so the recorded destination is the proxy, not the C2 | Compare the endpoint flow against the proxy or firewall log for the same flow. Recorded as an environment fact in the profile |
| 4 | Profile defaults relied on: output format unknown, so `-f default`; noise tolerance unknown, treated as low | Confirm with the team |

## Expected false positives

| Benign trigger | Likelihood | Tuning action |
|---|---|---|
| InstallUtil registering a commercial .NET assembly whose installer class contacts a licence or configuration server during registration | possible where commercial .NET components are deployed | Identify by `ParentImage` and the assembly argument from the retrohunt, then filter on those. **Never filter on the destination** |
| Telemetry attributing a connection to the wrong process as an injected image is torn down | unlikely | Correlate against the process-creation event for the same pid |
| Proxy auto-configuration or WPAD lookups made by the .NET runtime on the process's behalf | possible | Expected destination is the internal proxy or WPAD host — which is also exactly where real C2 appears on this estate. Confirm against the proxy log before filtering anything |

No `filter_*` block ships. Every candidate value would have been invented.

## Evasion review

| Evasion | Covered? |
|---|---|
| Binary renaming | **Not covered.** `OriginalFileName` is not in the EventID 3 schema. Sibling f378e7a8 partially covers it |
| Flag obfuscation | **N/A.** No flags matched |
| Path variation | **Covered.** A relocated copy of the utility is still matched by `Image\|endswith` |
| Default state | **N/A.** No argument surface, which is this rule's strength |
| Equivalent tooling | **Not covered.** `MSBuild.exe` and friends are excluded for the reason given in the package summary |

**Residual gaps:** a payload that proxies its traffic through a browser, a COM server or
`svchost` is not matched at all. On raw Sysmon this rule will also match *inbound* connections to
these processes, since the `Initiated` clause was removed — an analyst deploying against raw
Sysmon should add `Initiated: 'true'` back; one deploying against ECS must not.

## Validation evidence

```
sigma-cli 3.1.0 / pySigma 1.5.1 / pySigma-backend-elasticsearch 2.1.1
pysigma-pipeline-windows 2.0.1 / pysigma-pipeline-sysmon 2.0.0
Sigma specification v2.1.0 / ATT&CK Enterprise v20.0

attack_check.py --rules .            -> exit 0; 22 valid, 0 invalid, 0 unverified
sigma check -i <rules>               -> exit 0; 0 errors, 0 condition errors, 0 issues
check_grouping.py -t lucene -p ecs_windows .  -> exit 0; 6 clean, 0 needing attention
sigma convert -t lucene -p ecs_windows       -> success
```

**Exit code read and reported:** `attack_check.py` exited **0** — tags checked, all valid, zero
`[UNV]`. `sigma check` ran **without** `-x d3_fendtag` and the D3FEND validator passed.

**Converted query:** `net_connection_win_dotnet_framework_utility_outbound.lucene.txt`

```
process.executable.caseless:(*\\AddInProcess.exe OR *\\AddInProcess32.exe OR *\\InstallUtil.exe OR *\\RegAsm.exe OR *\\RegSvcs.exe)
```

**Conversion caveats — this rule must not be deployed unscoped.**

- The query carries **no event-category binding**, and with the rule reduced to a single image
  list that is dangerous here specifically: unscoped, it matches **process-creation documents
  too**, because `process.executable` is populated on those as well. Scope by index pattern or add
  `event.category:network`.
- `lucene` requires a pipeline (`sigma list targets` reports "Processing Pipeline Required: Yes"),
  so `--without-pipeline` is not an available fallback on this backend.

### Replay against the captured detonation

Evaluated offline against the capture — 10,652 documents, 35 alerts. **The unscoped result is the
one to look at, because it quantifies the warning above rather than merely asserting it.**

| Query | Hits in 10,652 docs | By dataset |
|---|---|---|
| **As compiled, unscoped** | **38** | process 2, library 12, network 2, file 2, sysmon 2, alerts 18 |
| **Scoped `event.category:network`** | **3** | `windows.sysmon_operational` 1, `endpoint.events.network` 2 |
| False positives across the whole capture | **0** | Every hit, scoped or not, is the sample's `RegSvcs.exe` |

Unscoped, the rule returns **12.7x** the documents it should, pulling in every module load, file
event and alert document that carries `process.executable` for the same process. None of those is a
network connection. On a real estate the same multiplier applies to every `RegSvcs.exe` document
ever written, which is why this rule must not be deployed without index or category scoping.

Scoped, the three hits are the real channel:

```
2026-10-27T21:20:59.860Z   RegSvcs.exe  Network connection        (sysmon)
2026-10-27T21:21:01.6059121Z  RegSvcs.exe  connection_attempted   (endpoint)
2026-10-27T21:22:42.1162197Z  RegSvcs.exe  disconnect_received    (endpoint)
```

Note what assumption 2 looks like when measured: across the whole 15-minute window **no .NET
Framework utility other than the sample's `RegSvcs.exe` was invoked at all**, so the capture gives
zero evidence either way about how often these binaries legitimately open sockets on a populated
estate. A 15-minute window on one lab host cannot answer that. The 90-day production retrohunt in
step 2 remains a prerequisite, not a formality.

Mutation note: this rule survives the argument-based evasion that defeats sibling f378e7a8. It is
defeated by renaming the utility — a package-level gap recorded in f378e7a8's note. It is also the
rule that still fires when the hollowing spawn carries arguments, which is the whole reason the two
are deployed as a pair.

### Live retrohunt result (2026-10-29)

Read-only against production Elastic Cloud, ES 9.5.3. Detail in `TEST-RESULTS.md`.

- **90 days, all hosts, scoped `event.category:network`: 6 hits, 0 false positives**, spanning the
  same two Agent Tesla samples as sibling f378e7a8.
- **Assumption 2 is now supported rather than assumed** — on this estate these utilities opened a
  socket only during the two detonations. But the estate is two hosts, one of them Windows, so the
  support is thin. The assumption remains the rule's whole specificity.
- Unscoped over the detonation window the query returned **23** documents for **2** real network
  events. The scoping requirement is not advisory.

## Test plan

1. **Convert:** `sigma convert -t lucene -p ecs_windows net_connection_win_dotnet_framework_utility_outbound.yml`
2. **Retrohunt:** run the converted query, scoped to `logs-endpoint.events.network-*` and the
   Sysmon network channel, over 90 days. **This step decides whether the rule is viable at all.**
3. **Triage:** any hit above zero needs attribution. If a legitimate source exists in the estate,
   this becomes a `level: informational` hunting rule tagged `detection.threat-hunting` rather
   than an alert.
4. **Tune:** filter on the identified parent and assembly, never on the destination address.
5. **Test positive detection:** re-detonate the sample. The destination recorded will be the
   internal proxy; confirm the real destination from the proxy or firewall log for the same flow.
6. **Promote:** to `status: test` after a clean retrohunt. Keep at `level: medium` until the
   retrohunt proves the estate is quiet, then consider `high`.

**What the profile's backend answer changed for this rule:** Elastic gave `-t lucene` with
`-p ecs_windows`, and that is what exposed the `Initiated` → `network.direction` mismatch that
would have silently reduced this rule to nothing. The same answer also means the single-selection
shape is more hazardous than it looks, because `process.executable` is populated outside the
network index. Output format unknown in the profile, so `-f default` and a bare query file.

**Tuning owner:** CTI @ thetechcollective
**Review date:** 2027-01-29

---

*This is a draft detection derived from a lab detonation and intelligence reporting, not a tested
detection. It has never run against this environment's production data. Promotion beyond
`experimental` is the detection engineering team's decision after the test plan above has been
completed.*
