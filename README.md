# CTI-driven detection engine

Turning threat intelligence into working Elastic detections, and the lab that proves they fire.
Kept in my own time, outside of work.

The loop this repo documents: take a rule or a piece of reporting, convert it into a detection,
detonate something real against it, and keep only what actually fired. Each round is written up
under [`detonations/`](detonations/).
The companion blog is [www.securitydistractions.com](https://www.securitydistractions.com), whose
source lives in [Security-Distractions/blog](https://github.com/Security-Distractions/blog).

## What's here

| Path | |
|---|---|
| [`lab/`](lab/) | The validation lab this engine runs against: network segments, Windows analysis VM, Elastic logging pipeline, open questions, and a running list of corrections |
| [`detonations/`](detonations/) | Per-detonation analysis, the detections that fired, indicators and attack-path canvases |
| [`detections/`](detections/) | The detection rules in **Sigma** format, plus their Elastic conversions and notes on which prebuilt rules were disabled |
| [`tooling/`](tooling/) | Scripts — chiefly `elastic_to_canvas.py`, which turns Elastic telemetry into an attack-path canvas |
| [`contributions/`](contributions/) | Work sent upstream: the pfSense/Squid integration fix and the CompromiseCanvas on-host attack path feature |

## Highlights

**On-host attack paths in CompromiseCanvas** — the tool modelled movement *between* hosts but had
nowhere to record what happened *inside* one. Added a drill-down: double-click a host and walk its
attack path step by step, with tactic, technique, MITRE ID and the command lines that evidence it.
Merged upstream as [SagaLabs/CompromiseCanvas#21](https://github.com/SagaLabs/CompromiseCanvas/pull/21).
See [`contributions/compromise-canvas-on-host-path/`](contributions/compromise-canvas-on-host-path/).

**Sigma rules, validated by detonation** — three rules written in Sigma, converted to Elastic with
pySigma and the `ecs_windows` pipeline, then tested against live malware rather than assumed correct.
Two fired; the third was correctly silent because its precondition never occurred, so it is recorded
as untested rather than working. Source YAML in [`detections/sigma/`](detections/sigma/), conversions
in [`detections/elastic/`](detections/elastic/).

**The proxy blind spot** — Squid access logs were reaching Elasticsearch but arriving as
un-decoded JSON in `message`, so a proxy query for outbound traffic returned nothing while
tens of thousands of records sat unread. Two different log shapes, both now promoted to ECS.
Written up on the [blog](https://www.securitydistractions.com/posts/proxy-blind-spot/).

**PyArmor-obfuscated loader** — full detonation analysis: a double-extension executable unpacking a
PyArmor-protected PyInstaller payload, then adding Defender exclusions via WMIC. That write-up and
five others are under [`detonations/`](detonations/).

## Reproducing the tooling

`elastic_to_canvas.py` reads Elastic and writes a canvas JSON:

```bash
export ES_URL=https://your-cluster:9243 ES_USER=... ES_PASS=...
python3 tooling/elastic_to_canvas.py --host analysis-host --since 2026-08-17T10:00:00Z --mode host \
        > canvas/on-host-attack-path.json
```

Import the result into CompromiseCanvas with **Import JSON**, then double-click the host node.

## A note on redaction

This is a public repo describing a live lab, so some things are deliberately absent or replaced with
placeholders such as `<ELASTIC-ES-ENDPOINT>` and `<SSH-TUNNEL-HOST>`:

- cluster endpoints, tunnel hostnames and certificate references
- the remote-access architecture document, and the CTI agent's code and design docs
  (that application stays private)
- infrastructure backups (Cloudflare Access policies, tunnel config, DNS zones)
- operational screenshots of internal systems

Internal RFC 1918 addressing and the lab hostnames are kept, because the network documentation is
worthless without them and they are not reachable from the internet. Malware hashes are kept
deliberately — they are indicators, meant to be shared.

## A note on redaction

Hostnames and addressing in `lab/` and `detonations/` are replaced with descriptive placeholders —
`analysis-host`, `<collector-ip>`, `<proxmox-host>` and similar. The topology is documented because
the detection logic depends on it; the actual addresses are not.

The one exception is `contributions/pfsense-squid-integration/`, which is reproduced exactly as
submitted upstream. Altering the sample log data there would misrepresent a live pull request.
