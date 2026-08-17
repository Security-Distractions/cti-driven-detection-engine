# PR text for SagaLabs/CompromiseCanvas

Branch: `feat/on-host-attack-path`

---

## Title

feat: drill down into a single host's on-host attack path

## Body

### What this adds

Compromise Canvas models movement **between** assets. This adds the layer below
that: what the attacker did **inside** one host. Double-click a host and you get
its attack path as an ordered chain of steps — tactic, technique, MITRE ID,
timestamp, and the command lines that evidence it.

The motivation is malware detonation write-ups. A detonation is almost entirely
an on-host story (`rundll32` → payload → `Add-MpPreference` → scheduled task →
`vssadmin delete shadows`), and today there is nowhere to put it.

### Why it needs a code change

`NodeAction[]` already exists on a node, so the obvious move is to put the steps
there and change nothing. We tried that first. It doesn't work:

* `actions` renders as an **unordered bullet list** — order is the one thing an
  attack path can't lose.
* A step had nowhere to record **when** it happened or **which technique** it
  was (MITRE metadata lived only on edges).
* A node with 8 real steps grew **taller than the viewport** and buried the
  topology around it.

The alternative — modelling on-host steps as ordinary canvas nodes — works, but
it puts intra-host detail in direct competition with the infrastructure diagram
for the same screen space, and one busy host swamps the picture.

### Design

**One host owns an ordered list of steps; array order is the path.**

Order is array order, not timestamp order, because analysts reconstruct paths
where timestamps are missing, identical, or skewed. A *Sort by time* button
covers the case where they are trustworthy.

**Two views, one source of truth.** The canvas node shows a compact ribbon (step
count, one colour-coded marker per step, first → last tactic). The drill-down
shows the steps in full. Both read the same `node.data.actions`; editing happens
only in the properties panel.

The drill-down opens at 1:1 zoom rather than fit-to-view, because steps are meant
to be read — fitting an 8-step chain into the dialog makes the text unreadable,
and worse the longer the path. The Controls' fit-view button gives the overview.

### Backwards compatibility

* New `NodeAction` fields (`timestamp`, `mitreAttackId`, `mitreAttackName`) are
  all optional. Existing canvas files load unchanged.
* The ribbon is behind `displaySettings.showActionPath`, default off, so
  existing diagrams render exactly as before.
* Double-click was an unused gesture on nodes; single-click still selects.
  Group nodes are excluded, and the drill-down is disabled in presentation mode.
* Export round-trips the new fields (covered by a test).

### Changes

| File | |
|---|---|
| `lib/types.ts` | optional step metadata, `showActionPath`, shared `ACTION_COLORS` |
| `components/custom-node.tsx` | compact step ribbon |
| `components/host-path-drilldown.tsx` | **new** — the drill-down dialog |
| `components/compromise-canvas.tsx` | double-click wiring |
| `components/properties-panel.tsx` | reorder steps, sort by time, timestamp + MITRE fields |
| `e2e/on-host-attack-path.spec.ts` | **new** — 9 tests |
| `examples/on-host-attack-path-example.json` | **new** — importable example, real telemetry |

Six commits, each one concern, meant to be read in order: types → node ribbon → drill-down → authoring → tests → example. 8 files, +1015 / −34 (of which 215 lines are tests and 306 the example canvas and its README).

### Testing — read this before reviewing

**Everything here was tested by automation. Nobody has sat and clicked through
it.** That is the honest state of it, and it means the interaction is the part
most likely to need work — pointer behaviour on trackpads, keyboard focus,
touch, screen readers, and anything that only shows up when a human uses it in
anger.

What was actually run:

* `tsc --noEmit` clean.
* Full Playwright suite: **74 passed**, including the 9 new tests, on a branch
  rebased onto current `main` (so it includes your `node-defaults` and
  status-card work).
* `node --test` unit suites: all pass.
* Headless-browser verification against real data — 206 Elastic Defend process
  events from a malware detonation, imported and drilled into, screenshots
  checked, no console errors.

Not run: `next lint`. `eslint.config.mjs` imports `@eslint/eslintrc`, which
isn't in the dependency tree, so it fails before reaching any of this code.
That's independent of this change, but it means lint has not covered it.

### Provenance

This was built with Claude (AI-assisted) against a real lab, and I've tested it
as described above rather than hand-writing it. Flagging that up front so you
can weight the review accordingly — the design decisions are argued in the
commit messages, and I'm happy to change any of them.

### Try it without generating data

`examples/on-host-attack-path-example.json` — **Import JSON**, then double-click
the `analysis-host` host. It's a real detonation reduced to eight steps, with genuine
command lines.

### Screenshots

* Canvas — host carries a compact 8-step ribbon
* Drill-down — the same host's path, step by step

---

## Notes for David before opening this

1. **`ACTION_COLORS` placement.** I put the tactic palette in `lib/types.ts`
   because both views need it. If SagaLabs would rather keep `types.ts` types-only,
   it moves to `lib/action-visuals.ts` in one commit.
2. **Discoverability.** Double-click is only hinted by the ribbon's caption. If
   they want, add an explicit "Open path" button to the properties panel — small
   follow-up, deliberately left out to keep this diff tight.
3. The generator (`elastic_to_canvas.py`) is **not** part of this PR — it lives
   in your lab-docs. Offer it separately if they're interested.
4. The branch is pushed to your fork
   (`dclayton454/CompromiseCanvas`, branch `feat/on-host-attack-path`), rebased
   onto current upstream `main`. **No PR is open.**
5. The example canvas contains a real Windows path with your first name in it
   (`C:\Users\analyst\Downloads\...`). It is genuine telemetry so I left it
   alone, but say the word and I'll neutralise it.
