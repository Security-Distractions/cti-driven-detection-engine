# On-host attack paths in Compromise Canvas

Compromise Canvas models movement **between** assets: a node is a host, an edge
is an attacker action that got them from one host to the next. That is the right
model for infrastructure, but it has nothing to say about the part of an
intrusion that happens **inside** a single machine — the rundll32 → payload →
`Add-MpPreference` → scheduled task → `vssadmin delete shadows` chain that is the
whole story of a malware detonation.

This is the design and implementation of a drill-down that adds that layer.

## The problem with faking it

The export schema already has a per-node `actions: NodeAction[]`. It is tempting
to stuff the on-host steps in there and call it done — no code changes. That was
tried first, and the result was unusable:

* `actions` rendered as an **unordered bullet list**. An attack path is an
  ordered sequence; order was the one thing the rendering threw away.
* There was no timestamp on a step, and no MITRE technique on a step (only edges
  carried MITRE metadata).
* Steps that carried real command lines blew the fixed-width node apart, and a
  node with 8 steps grew taller than the viewport, burying the topology it was
  supposed to sit in.
* Detail smuggled into the wrong fields (event counts in `hostname`, time ranges
  in `os`, process names in `services`) is a lie the tool will happily
  re-export, and the next person to open the file has no idea what they are
  looking at.

Conclusion: the capability belongs in the tool, not in a generator's abuse of
existing fields.

## The model

One idea, applied consistently: **a host node owns an ordered list of steps, and
array order is the path.**

```ts
export interface NodeAction {
  id: string
  type: ActionType          // MITRE tactic — colours the step
  technique: string         // free text, e.g. "Scheduled Task via schtasks.exe"
  details: string           // the evidence: command line(s)
  timestamp?: string        // ISO8601
  mitreAttackId?: string    // e.g. T1053.005
  mitreAttackName?: string
}
```

`timestamp`, `mitreAttackId` and `mitreAttackName` are new and optional, so
every existing canvas file still loads unchanged.

Ordering is deliberately **array order, not timestamp order**. Analysts
reconstruct paths where timestamps are missing, equal, or misleading (clock
skew, batched telemetry), so the sequence has to be something a human can state
directly. A "Sort by time" button is offered for when the timestamps *are*
trustworthy.

## Two views, one source of truth

| | Canvas node | Drill-down |
|---|---|---|
| Shows | that a path exists, and its shape | the path itself |
| Content | step count, one colour-coded marker per step, first → last tactic | every step: tactic, technique, MITRE ID, timestamp, command lines |
| Edited here? | no | no |

Both read the same `node.data.actions`. Editing happens only in the properties
panel, so there is exactly one place where a path is authored.

The node stays compact on purpose. The canvas answers "which hosts have an
on-host story, and roughly what kind?"; the drill-down answers "what happened on
this one?". A node that inlined the full chain answered the second question
badly and destroyed the first.

`displaySettings.showActionPath` chooses the compact ribbon over the legacy
bullet list. Default off — existing diagrams look exactly as they did.

## Interaction

* **Double-click a host** → drill-down opens. Double-click is already free on
  nodes, so no existing gesture is taken away, and single-click still selects
  for editing.
* Group nodes are excluded — a group is not a host.
* Disabled in presentation mode, where clicks drive playback.
* `Esc` or the close button returns to the canvas. The drill-down is read-only,
  so there is nothing to save or discard.
* Breadcrumb reads `Canvas > <host> > on-host attack path` so it is obvious you
  are one level down, not on a different canvas.

## Files

| File | Change |
|---|---|
| `lib/types.ts` | `NodeAction` gains `timestamp`, `mitreAttackId`, `mitreAttackName`; `DisplaySettings` gains `showActionPath`; new shared `ACTION_COLORS` |
| `components/custom-node.tsx` | compact step ribbon when `showActionPath` is on |
| `components/host-path-drilldown.tsx` | new — the drill-down dialog |
| `components/compromise-canvas.tsx` | `onNodeDoubleClick` wiring, drill-down state |
| `components/properties-panel.tsx` | step reordering, "Sort by time", timestamp + MITRE fields |
| `e2e/on-host-attack-path.spec.ts` | new — 5 tests |

## Generating one from Elastic

`elastic_to_canvas.py --mode host` reads Elastic Defend process telemetry for one
host and window, folds it into technique-level steps, and writes the canvas:

```bash
export ES_URL=https://...:9243 ES_USER=... ES_PASS=...
./elastic_to_canvas.py --host analysis-host \
    --from 2026-08-08T17:26:00Z --to 2026-08-08T17:40:00Z \
    --mode host --out sample-c-host.json
```

206 raw process events → 65 interesting processes → **8 steps**. The folding is
the point: a 65-node process tree is technically accurate and humanly useless.

Steps are keyed on behaviour (normalised command signature), not on process
instance, because a payload that respawns `cmd.exe` 40 times is one step, not 40.
See `elastic_to_canvas.py` for the collapse rules.
