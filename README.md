# securitydistractions — lab & research

Detection engineering, malware detonation and lab-build notes from my own time, outside of work.
The companion blog is [www.securitydistractions.com](https://www.securitydistractions.com), whose
source lives in [`blog/`](blog/).

## What's here

| Path | |
|---|---|
| [`lab/`](lab/) | How the detonation lab is built: network segments, Windows analysis VM, Elastic logging pipeline, open questions, and a running list of corrections |
| [`detections/`](detections/) | Detection content — Sigma rules converted to Elastic, and notes on which rules were disabled and why |
| [`cases/`](cases/) | Detonation write-ups: full analysis from detections and telemetry |
| [`canvases/`](canvases/) | Attack-path exports for [CompromiseCanvas](https://github.com/SagaLabs/CompromiseCanvas) |
| [`tooling/`](tooling/) | Scripts — chiefly `elastic_to_canvas.py`, which turns Elastic telemetry into an attack-path canvas |
| [`contributions/`](contributions/) | Work sent upstream: the pfSense/Squid integration fix and the CompromiseCanvas on-host attack path feature |
| [`blog/`](blog/) | Hugo source for the blog (PaperMod, vendored) |

## Highlights

**On-host attack paths in CompromiseCanvas** — the tool modelled movement *between* hosts but had
nowhere to record what happened *inside* one. Added a drill-down: double-click a host and walk its
attack path step by step, with tactic, technique, MITRE ID and the command lines that evidence it.
Submitted as [SagaLabs/CompromiseCanvas#21](https://github.com/SagaLabs/CompromiseCanvas/pull/21).
See [`contributions/compromise-canvas-on-host-path/`](contributions/compromise-canvas-on-host-path/).

**Sigma → Elastic conversions** — three rules converted with pySigma and the `ecs_windows` pipeline,
then validated by live detonation rather than assumed correct. All three fired.
See [`detections/sigma-derived/`](detections/sigma-derived/).

**The proxy blind spot** — Squid access logs were reaching Elasticsearch but arriving as
un-decoded JSON in `message`, so a proxy query for outbound traffic returned nothing while
tens of thousands of records sat unread. Two different log shapes, both now promoted to ECS.
Written up in [`blog/content/posts/proxy-blind-spot.md`](blog/content/posts/proxy-blind-spot.md).

**PyArmor-obfuscated loader** — full detonation analysis: a double-extension executable unpacking a
PyArmor-protected PyInstaller payload, then adding Defender exclusions via WMIC.
See [`cases/`](cases/).

## Reproducing the tooling

`elastic_to_canvas.py` reads Elastic and writes a canvas JSON:

```bash
export ES_URL=https://your-cluster:9243 ES_USER=... ES_PASS=...
python3 tooling/elastic_to_canvas.py --host secdis --since 2026-08-17T10:00:00Z --mode host \
        > canvases/my-detonation.json
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
