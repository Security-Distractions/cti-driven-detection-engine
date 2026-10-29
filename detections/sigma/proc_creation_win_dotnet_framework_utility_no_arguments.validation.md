# Validation Note: Suspicious .NET Framework Utility Started Without Arguments

**Rule id:** f378e7a8-15ba-48f5-b976-19fecd013933
**File:** `proc_creation_win_dotnet_framework_utility_no_arguments.yml`
**Drafted:** 2026-10-29 by David Clayton - CTI @ thetechcollective using the create-sigma-rule skill
**Status:** experimental. This rule has not been run against production data.

## Source

Raw telemetry: the lab detonation of 2026-10-27 on `analysis-host`, sample
`fdc9cb253a2ebb99df48133a5c2e0d35cfa5fb4ee7578f6648bded8b5187b42c`, identified as Agent Tesla by
the Recorded Future MCP enrichment (master ID `hd4fiZ`, risk 65/99, rule *Positive Malware
Verdict*) and independently by an Elastic Defend memory scan matching
`Windows.Trojan.AgentTesla`. The logic comes from one process-creation event in
`endpoint.events.process`:

```
2026-10-27T21:20:59.3014254Z  start  pid=25204 ppid=14396
  image   C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
  cmdline "C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"
  parent  C:\Users\analyst\Downloads\fdc9cb25…b42c\fdc9cb25…b42c.exe
```

The parent exited 114 ms later, at `21:20:59.4158534Z`.

## Behavior targeted

A .NET Framework registration utility is created with a command line consisting of nothing but
its own quoted path. The observable is the empty argument list, not the injection it contains.

## Abstraction level

**Chosen:** technique implementation, tagged `stp.4`.

**Why:** the sample's hash, its file name and the hash-named directory it ran from all die with
this campaign. What survives a rebuild is the shape — a signed Microsoft .NET utility is the
practical hollowing container for a .NET payload, and it is started with no arguments because the
loader never intends it to register anything.

**Layers:** `selection_anchor` holds the anchor (the utility image, plus `OriginalFileName`).
`selection_discriminator_no_arguments` holds the discriminator (the empty argument list).
**There is no invariant layer.** For this behaviour the anchor and the invariant are the same
object — there is no cmdlet or syntax separate from the binary itself — so the layer is absent
rather than parked in an unreferenced selection. The cost is that the rule's whole specificity
rests on the discriminator.

## Default state

**With no arguments, the tool or behavior does:** `RegSvcs.exe`, `RegAsm.exe` and
`InstallUtil.exe` print their usage text and exit without acting on any assembly.

**In scope?** Yes — and this rule is the inverse of the usual case. The no-arguments invocation
is not a gap the rule must avoid missing; it **is** the thing being detected.

**Consequence for the condition:** no flag selection exists to require, so the Stage 1 hazard
does not apply. The mirror-image hazard does: by requiring the empty argument list the rule is
blind to the *flagged* invocation. One junk argument defeats it. That is recorded as the primary
residual gap below and is the reason sibling rule 682ee4ba exists.

## Resilience record

| # | Question | Answer | Outcome |
|---|---|---|---|
| 1 | Anchor a known Windows binary in a `process_creation` rule? | **Yes, and the telemetry carries the field.** Confirmed empirically: `process.pe.original_file_name` is populated on all 76 `endpoint.events.process` documents in the capture | **Added**, using confirmed values from `sigma-spec.md`: `RegSvcs.exe`, `RegAsm.exe`, `InstallUtil.exe`. `AddInProcess.exe` / `AddInProcess32.exe` are not in that table and were not invented. **But see the correction below: the field is inert in this rule.** |
| 2 | `OriginalFileName` added, and is the target Splunk? | **Not Splunk.** Profile names Elastic only | Kept. `check_grouping.py -t lucene` confirms the OR group is bracketed under the AND. Not validated against Splunk, per the profile-scoping rule |
| 3 | Rule matches on command-line flags? | **No.** It matches the *absence* of arguments, via `CommandLine\|endswith` on the terminal image name | `\|windash` **N/A** — there is no dash character for an adversary to substitute in an empty argument list |

## Evidence ledger

| Condition | Label | Locator / citation |
|---|---|---|
| `Image\|endswith: '\RegSvcs.exe'` | `SOURCED` | Capture, `endpoint.events.process`, `process.executable` on the 21:20:59.3014254Z event |
| `Image\|endswith:` the other four images | `INFERRED` | Broadening alternatives within an OR list. Each widens the match, so the `INFERRED` constraint permits them |
| `OriginalFileName:` three values | `GENERIC` | `references/sigma-spec.md` OriginalFileName table — `RegSvcs.exe`, `RegAsm.exe`, `InstallUtil.exe` as they appear in the PE header. Checkable, not asserted |
| `CommandLine\|endswith:` the empty-argument forms | `SOURCED` | Capture, `process.command_line` was exactly `"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"`. Both terminal quoting forms are matched so the rule does not depend on how the collector preserved quoting |

**Dropped or broadened by the `INFERRED` rule:**

The first draft of this rule carried a third selection:

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

Only `\Downloads\` was `SOURCED`; the other six were my own inference, and more importantly
**requiring any user-writable parent at all was an `INFERRED` condition that narrowed the rule**.
It was reasonable — a delivered dropper usually does run from such a path — and reasonable
inferences that tighten a match are exactly the failure the ledger exists to catch. Staging the
dropper into a new directory under `C:\`, or into a writable subdirectory of `Program Files`,
would have defeated the whole rule silently.

**The selection has been removed.** `ParentImage` and `ParentCommandLine` stay in `fields` as a
triage aid, which is where the parent belongs when it cannot be defended as a condition. The
tuning action, with the values openly left to the analyst, is below.

**Description provenance:** "start the signed Microsoft utility suspended, overwrite its image
with the payload, resume it, and exit the dropper" is `SOURCED` — Elastic Defend raised
*Suspicious Suspended Process Creation*, *Suspicious Remote Memory Allocation* and *Remote
Thread Context Manipulation* within 25 ms, which is that sequence in API calls. "These utilities
act on an assembly named on the command line" is `GENERIC`, from the utilities' own documented
syntax.

## ATT&CK mapping rationale

```
RegSvcs.exe spawned as an empty container, image overwritten, dropper exits
  -> T1055.012 (Process Hollowing)        tactics: stealth, privilege-escalation
The container is a signed Microsoft .NET registration utility
  -> T1218.009 (Regsvcs/Regasm)           tactics: stealth
```

Both verified by `attack_check.py` against ATT&CK Enterprise v20.0: valid, correct tactics, not
revoked. The script cannot confirm the *fit* — that T1055.012 rather than plain T1055 is the
right granularity here. It is, because the capture shows the container being created and
abandoned rather than an existing process being injected into.

## Assumptions

| # | Assumption | How to confirm |
|---|---|---|
| 1 | `OriginalFileName` is populated. Sysmon 10+ and Elastic Defend both emit it; Windows 4688 does not carry it at all | Check `process.pe.original_file_name` on a known RegSvcs event |
| 2 | The command line is logged with the quoting Windows passed it. Mitigated by matching both terminal forms | Confirmed in the capture: the quoted form was recorded |
| 3 | Interactive invocation of these utilities is rare in this estate. **This is now the rule's main open question**, since the parent-path narrowing was removed | Retrohunt, step 2 of the test plan |
| 4 | Profile defaults relied on: output format unknown, so `-f default` and a bare query per rule; noise tolerance unknown, treated as low | Confirm with the team |

## Expected false positives

| Benign trigger | Likelihood | Tuning action |
|---|---|---|
| Administrator or developer running the utility interactively to read its usage text | possible, and now unfiltered | Triage on `ParentImage`: an interactive run has a shell or console host under System32 as parent. If the retrohunt shows this is routine, exclude on your own shell parentage — `ParentImage\|endswith: '\cmd.exe'` is the shape — **after** confirming it against a week of hits. This draft does not encode it, because no confirmed event in this environment supports the value |
| Vendor agent invoking InstallUtil through a wrapper that supplies the assembly by configuration | possible where commercial .NET components are deployed | Identify the real wrapper from the retrohunt, then filter on its confirmed `ParentImage`. No value is pre-written |
| Software packaging tools staging to a temporary directory | unlikely | Identify by `ParentCommandLine` and filter on the packaging tool |

No `filter_*` block ships with this rule. Every candidate value would have been invented, and a
fabricated filter looks tested while excluding nothing.

## Evasion review

Worked against the five-item table in `rule-quality.md` Step 5:

| Evasion | Covered? |
|---|---|
| Binary renaming | **NOT covered — corrected after mutation testing.** The earlier draft of this note claimed `OriginalFileName` covered three of five images. It does not: the no-arguments discriminator requires the utility filename on the command line, so a renamed copy defeats the rule regardless of the PE header. Verified by Mutation 3. Unfixable on this backend — `fieldref` is refused both as `endswith\|fieldref` (wildcard) and plain (backend limitation) |
| Flag obfuscation | **N/A.** No flags are matched |
| **Command-line case** | **NOT covered, and this is a pipeline artifact.** `ecs_windows` maps `Image` to a case-insensitive sub-field but `CommandLine` to the case-sensitive base field. Lowercasing the command-line clause takes the live 90-day result from 13 hits to **0**. A lowercase invocation such as `"c:\windows\...\regsvcs.exe"` is valid on Windows and would be missed. Remedy is a pipeline mapping `CommandLine` to a case-insensitive sub-field, not a change to this rule |
| Path variation | **Covered**, and improved by this re-draft. The rule no longer constrains the parent path at all, so staging the dropper anywhere on disk does not defeat it |
| **Default state** | **This is the rule's exposure.** It requires the bare invocation. One junk argument defeats it outright — the cheapest evasion available and not closed |
| Equivalent tooling | **Not covered.** `MSBuild.exe`, `aspnet_compiler.exe`, `jsc.exe` and `csc.exe` work the same way and are excluded deliberately: each has legitimate argument-bearing use that an empty-argument clause does not separate well |

**Residual gaps:** two, and the second is worse than the first draft of this note admitted.

1. **The argument gap.** One junk argument defeats this rule. Verified by Mutation 1: appending
   `/x`, `-q`, `foo` or two spaces each turns a FIRES into a miss. Rule 682ee4ba survives it, which
   is why the two ship linked and are meant to be deployed together.
2. **Renaming defeats this rule, and in fact defeats all three.** A copy of `RegSvcs.exe` placed
   elsewhere under another name is missed here (Mutation 3) and is also missed by 682ee4ba, which
   anchors on `Image|endswith` alone. **The package has no coverage for a renamed utility.** This is
   a package-level gap, not a rule-level one, and neither rule closes it.

## Validation evidence

```
sigma-cli 3.1.0 / pySigma 1.5.1 / pySigma-backend-elasticsearch 2.1.1
pysigma-pipeline-windows 2.0.1 / pysigma-pipeline-sysmon 2.0.0
Sigma specification v2.1.0 / ATT&CK Enterprise v20.0

NOTE: sigma-cli 4.0.0 is current on PyPI. It ships pySigma 2.x, which the elasticsearch,
sysmon and windows plugins do not support; 3.1.0 is the newest version where they install
compatibly. Older tooling can be missing validators entirely, so this clean result is
evidence from sigma-cli 3.1.0's validator set, not from 4.0.0's.

attack_check.py --rules .            -> exit 0; 22 valid, 0 invalid, 0 unverified
sigma check -i <rules>               -> exit 0; 0 errors, 0 condition errors, 0 issues
check_grouping.py -t lucene -p ecs_windows .  -> exit 0; 6 clean, 0 needing attention
sigma convert -t lucene -p ecs_windows       -> success
```

**Exit code read and reported:** `attack_check.py` exited **0**, meaning the tags were checked
and all are valid. Not exit 2 or 3, so this is a real check, not an unreachable taxonomy. Zero
`[UNV]` results — nothing is being rounded to valid.

**`sigma check` was run without `-x d3_fendtag`.** The D3FEND validator reached its data on this
network and passed. The previous draft excluded it by default, which skipped a check that works
here.

**Converted query:** `proc_creation_win_dotnet_framework_utility_no_arguments.lucene.txt`

```
((process.executable.caseless:(*\\AddInProcess.exe OR *\\AddInProcess32.exe OR *\\InstallUtil.exe OR *\\RegAsm.exe OR *\\RegSvcs.exe)) OR (process.pe.original_file_name:(InstallUtil.exe OR RegAsm.exe OR RegSvcs.exe))) AND (process.command_line:(*AddInProcess.exe OR *AddInProcess.exe\" OR *AddInProcess32.exe OR *AddInProcess32.exe\" OR *InstallUtil.exe OR *InstallUtil.exe\" OR *RegAsm.exe OR *RegAsm.exe\" OR *RegSvcs.exe OR *RegSvcs.exe\"))
```

**Conversion caveats:** the converted query carries **no event-category binding**. Neither
`ecs_windows` alone nor `windows-logsources` chained ahead of it adds one, so the query matches
on field presence only and must be scoped by index pattern or by adding `event.category:process`
before deployment. Note also that `lucene` requires a pipeline — `sigma list targets` reports
"Processing Pipeline Required: Yes" — so `--without-pipeline` is not an available fallback on
this backend.

### Replay against the captured detonation

The compiled query was evaluated offline against the capture — 10,652 documents and 35 alerts from
`/opt/rf-webinar/detonation-2026-10-27`. Not a production retrohunt, and not a substitute for one.

| Corpus / scoping | Hits | Reading |
|---|---|---|
| All 10,652 documents, query exactly as compiled | 21 | Fires, but 18 are `endpoint.alerts` documents that embed `process.*`. That is the missing event-category binding showing up in practice, on this rule too, not only on rule three |
| Scoped with `event.category:process` | 6 | 2 `endpoint.events.process`, 1 `windows.sysmon_operational`, 3 alert documents also categorised as process |
| **Distinct true-positive process events** | **2** | Both are `RegSvcs.exe` `start` events with the empty command line — 21:20:59.3014254Z (the hollowing) and a second at 21:26:24.483Z |
| **False positives across the whole capture** | **0** | Every matching document in the capture, under every rule in this package, is the sample's `RegSvcs.exe`. No other .NET Framework utility was invoked at all during the window |

Mutation tests against the real `start` event:

| Mutation | Result |
|---|---|
| Unmodified, as detonated | **FIRES** |
| `command_line` + `' /x'`, `' -q'`, `' foo'`, `'  '` | **misses** — all four. The argument gap is real and cheap |
| Parent moved to `C:\staging\loader.exe` | **FIRES** — the first draft, with the user-writable-parent clause, **missed** this |
| Parent moved to `C:\Program Files\Vendor\loader.exe` | **FIRES** — first draft **missed** |
| Image renamed to `svchost32.exe`, `OriginalFileName` still `RegSvcs.exe` | **misses** — see the correction above |

The parent mutations are the empirical check on the ledger decision. Removing that clause bought
real coverage against a dropper staged outside the listed paths, which is exactly the blind spot
the `INFERRED`-narrowing constraint predicted.

**Caveat on the method:** `process.executable.caseless` is an index-time multi-field and does not
exist in `_source`, so the replay matches case-insensitively on `process.executable` to emulate it.
Everything else is matched exactly as the compiled query specifies.

### Live retrohunt result (2026-10-29)

Run read-only against the production Elastic Cloud cluster, ES 9.5.3. Full detail in
`detonations/2026-10-27-agent-tesla-regsvcs-hollowing/TEST-RESULTS.md`.

- **90 days, all hosts, scoped `event.category:process`: 13 hits, 0 false positives.**
- The hits span **two independent Agent Tesla samples** — 2026-08-06 (`5067ae42…dfba`) and
  2026-10-27 (`fdc9cb25…b42c`) — so the rule generalises beyond the sample it was drafted from.
  The August hits were attributed before being counted clean: that window carries 51 signal alerts
  including `Memory Threat Detection Alert: Windows.Trojan.AgentTesla` ×4.
- **Estate caveat:** two hosts report process telemetry and only one runs Windows. "Zero false
  positives" means zero on a single lab workstation over 90 days, during which no .NET Framework
  utility was invoked for any legitimate purpose. It does not characterise a populated fleet.

Step 2 of the plan below is therefore satisfied in letter and not in spirit. Promotion past
`experimental` still wants exposure to real administrative tooling.

## Test plan

1. **Convert:** `sigma convert -t lucene -p ecs_windows proc_creation_win_dotnet_framework_utility_no_arguments.yml`
2. **Retrohunt:** run the converted query, scoped to `logs-endpoint.events.process-*` and
   `winlogbeat-*`, over the last 90 days. **This step now carries more weight than it did before
   the parent-path selection was removed** — that clause was suppressing the interactive-usage
   case, and nothing suppresses it now.
3. **Triage:** classify a sample of hits. If interactive usage turns out to be routine, the right
   fix is a `filter_*` block on the *confirmed* shell parentage, not reinstating a guessed path list.
4. **Tune:** add filters only with real values, each carrying a `# sourced:` comment.
5. **Test positive detection:** already done against the captured detonation — see validation
   evidence. The rule fires on the real hollowing event. For a live re-test, re-detonate
   `fdc9cb253a2ebb99df48133a5c2e0d35cfa5fb4ee7578f6648bded8b5187b42c`. Atomic Red Team T1218.009
   passes an assembly path, so it exercises `selection_anchor` but **not**
   `selection_discriminator_no_arguments`; a true end-to-end positive needs the sample.
6. **Promote:** to `status: test` once the retrohunt is clean and the sample fires it in the lab.
   To `stable` after 30 days in the non-paging queue with no unexplained noise.

**What the profile's backend answer changed for this rule:** Elastic gave `-t lucene` with
`-p ecs_windows`, which put the query on `process.executable.caseless`,
`process.pe.original_file_name` and `process.command_line` rather than Sysmon's raw names. It
also made the `Image` OR `OriginalFileName` pair safe to keep, which on Splunk it would not have
been. Output format was unknown in the profile, so the artifact is `-f default`: a bare query in
its own `.lucene.txt` file.

**Tuning owner:** CTI @ thetechcollective
**Review date:** 2027-01-29

---

*This is a draft detection derived from a lab detonation and intelligence reporting, not a tested
detection. It has never run against this environment's production data. Promotion beyond
`experimental` is the detection engineering team's decision after the test plan above has been
completed.*
