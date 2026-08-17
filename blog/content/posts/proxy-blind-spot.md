---
title: "The C2 your endpoint agent never sees"
date: 2026-08-09
draft: false
tags: ["malware", "elastic", "detection", "squid"]
summary: "When a victim egresses through a proxy, host telemetry stops at the proxy. Here's what that looks like in Elastic — and how a broken log pipeline hid a C2 destination in plain sight."
---

Every endpoint agent on a proxied network shares a blind spot, and it is easy to miss
until you go looking for a C2 destination and find nothing.

## The setup

The detonation host sits on an isolated segment. All of its egress is forced through a
Squid proxy on the firewall — it has no route to the internet of its own.

```text
secdis                OPNsense (192.168.2.1)             Internet
  │                          │                              │
  ├── TCP :3128 ────────────►│                              │
  │   [Defend + Sysmon       ├── HTTP CONNECT ─────────────►│
  │    see this hop]         │   [only the proxy sees this] │
```

When malware on `secdis` beacons out, the endpoint agent faithfully records a network
connection. To `192.168.2.1:3128`. Every single time, regardless of where the traffic
is really going.

> The endpoint isn't wrong. It is reporting exactly what the host did — open a socket to
> the proxy. The destination it *wanted* only exists one hop further on.

## What each source can actually tell you

| Source | Victim → proxy | Proxy → C2 |
|---|---|---|
| Elastic Defend | yes | **no** |
| Sysmon | yes | **no** |
| Firewall filterlog | yes | **no** |
| **Squid access log** | yes | **yes** |

One source out of four holds the answer. If that source is broken, the destination is
gone — and nothing in the console tells you it's missing.

## Where it went wrong

Squid was shipping. The documents were arriving in Elasticsearch. They were simply
**unparsed**, because the integration's pipeline expected classic Squid text while
this proxy emits ECS-JSON:

```text
logformat opnsense {ECS-JSON...}
access_log syslog:local4.info opnsense
```

A `grok` processor met JSON, failed, and dropped the document into the index with its
fields unextracted. Present, but unqueryable — the worst failure mode, because volume
graphs look healthy.

### The fix

Decode the JSON instead of grokking it:

```json
{
  "json": {
    "field": "message",
    "add_to_root": true,
    "add_to_root_conflict_strategy": "replace",
    "ignore_failure": true,
    "tag": "json_decode_opnsense_squid_ecs"
  }
}
```

### Confirming it worked

```bash
curl -u "$ES_USER:$ES_PASS" \
  "$ES/logs-pfsense.log-*/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"exists":{"field":"squid.url.original"}}}'
```

From zero parsed records to thousands per day — with full HTTPS URLs, since `sslbump`
is decrypting.

## What to take from this

- **Ask which single source holds each fact.** If only one can answer "where did it
  connect to", that source is critical infrastructure, not a nice-to-have.
- **"Logs are arriving" is not "logs are usable".** Alert on parse success, not volume.
- **Proxies move evidence, they don't destroy it.** Architect your collection to follow
  where the evidence actually went.

The blind spot was never the proxy's fault. It was an assumption that endpoint
telemetry answers a question it structurally cannot.
