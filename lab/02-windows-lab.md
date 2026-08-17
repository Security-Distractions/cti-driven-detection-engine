# Windows Detonation Lab — `analysis-host`

Reconstructed from session transcripts on this host **[T]**; network reachability
re-checked 2026-08-09 **[V]**. Items marked **[?]** need your confirmation.

---

## 1. The detonation host

| Field | Value |
|---|---|
| Proxmox VMID | **101** |
| VM name | `analysis-vm` |
| OS hostname | **`analysis-host`** |
| OS | Windows 11 |
| RAM | 4 GB |
| LAN address | `<analysis-host-ip>` (detonation LAN) |
| Default gateway / resolver / proxy | `<firewall-detonation-if>` (OPNsense) |
| Internet egress | **Only** via Squid at `<firewall-detonation-if>:3128` |

**Reachability note [V]:** `<analysis-host-ip>` did **not** answer ICMP from collector on
2026-08-09. Expected if the host is powered off, mid-rollback, or blocking ICMP —
but confirm which, as it changes how you draw the trust boundary.

---

## 2. Endpoint telemetry on `analysis-host`

| Source | Elastic data stream | Notes |
|---|---|---|
| **Elastic Defend** (EDR) | `logs-endpoint.events.process`, `.network`, `.file`, `.registry`, `.library` | Primary detection source; also raises alerts |
| **Sysmon** | `logs-windows.sysmon_operational` | Deep process/network detail |
| **PowerShell operational** | `logs-windows.powershell_operational` | Script-block logging |
| **Windows Security** | `logs-system.security` | Account/logon events |

Both Sysmon and Elastic Defend ship via **Elastic Agent** enrolled in Fleet.

> **Snapshot rollbacks break telemetry silently.** After each rollback the agent must
> be re-verified — and the VM clock has repeatedly come back **wrong**, which both
> breaks TLS certificate validation (blocking installs such as OpenSSH) and lands
> events at the wrong timestamp so they never appear in the expected Kibana window.
> **Always verify time sync and agent health after a rollback, before detonating.** **[T]**

---

## 3. Sample workflow **[T]**

The established loop for each sample:

1. Roll `analysis-host` back to a clean snapshot
2. Verify Sysmon + Elastic Defend are shipping, and the **clock is correct**
3. Detonate the sample (labelled `Sample A`…`Sample E`)
4. Let it run ~5 minutes before analysis
5. Hunt across Elastic; correlate host, proxy, firewall and DNS telemetry
6. Link alerts into an **Elastic Case** for that sample

Sources are pulled from **MalwareBazaar** (`logs-ti_abusech.malwarebazaar` is enabled
as a threat-intel feed). One sample family referenced explicitly: **AgentTesla**;
one tool named: **silverfox**. **[T]**

Cases created during that work (Kibana → Security → Cases) **[T]**:
`26ce6f7b-8cae-4ff9-910f-9fea0e5ade4e`, `2747eaba-7963-4ca5-87dd-71c01a9f3c54`,
`3e635dd6-62fa-4f4f-869f-509a831800f1`, `74b26185-dcfc-4188-9cbc-e2065b0d75fc`

---

## 4. The proxy visibility lesson **[T]** — *gap now closed*

The most instructive finding in the lab. The gap it describes was **fixed on
2026-08-08**; it is kept here because the architecture point still stands.

Because `analysis-host` egresses through the Squid proxy, **host telemetry only ever sees the
connection to `<firewall-detonation-if>:3128`** — never the true C2 destination. The real
destination exists *only* in the proxy log.

```
analysis-host                OPNsense (<firewall-detonation-if>)             Internet
  │                          │                              │
  ├── TCP :3128 ────────────►│                              │
  │   [visible to Defend     ├── HTTP CONNECT ─────────────►│
  │    and Sysmon]           │   [visible ONLY in Squid log]│
```

| Telemetry source | Sees victim → proxy | Sees proxy → C2 |
|---|---|---|
| Elastic Defend / Sysmon | ✅ | ❌ |
| OPNsense filterlog | ✅ | ❌ |
| **Squid proxy log** | ✅ | ✅ |

**This gap is now CLOSED.** ✅ Squid access logs were fixed on 2026-08-08 and parse
into Elastic with full HTTPS URLs (sslbump decrypts). Query `logs-pfsense.log-*` with
`squid.url.original: *`. Root cause and fix are documented in
`03-elastic-logging.md` §4.

So the teaching point is now a *before/after* story rather than a live limitation:

| | Before 2026-08-08 | After |
|---|---|---|
| Host telemetry | sees only `<firewall-detonation-if>:3128` | unchanged — still only the proxy |
| Squid log | present but **unparsed** (grok expected text, Squid emits ECS-JSON) | parsed, queryable |
| Net effect | **true C2 destination invisible** | **C2 destination recoverable** |

That contrast is the most valuable thing in the lab for a workshop: it shows that
"we collect the log" and "we can query the log" are different claims, and that an
encrypted-proxy architecture moves the evidence rather than destroying it.

---

## 5. Previously-open questions — **now answered** **[V]**

| Question | Answer |
|---|---|
| Domain-joined or standalone? | **Standalone** — no `host.domain` on any of 577,679 Windows docs in 30d |
| Only Windows host? | **Yes** — `analysis-host` is the only one, ever |
| Clean baseline snapshot? | **`golden-baseline`** (2026-07-22 16:44). Also present: `migrated-working`, `ProxmoxReady` |
| Detonation LAN isolated? | **No** — NATs to the real internet via OPNsense `em0`. Only the home net (`10.0.0.0/8`) and other RFC1918 are blocked |
| Why no ping reply? | **The host is powered down between exercises** (owner-confirmed). pf permits utility→detonation, so the firewall is not the cause |
| Defender on or off? | **Disabled by Elastic Security** — Elastic Defend registers as the AV/EDR provider and Defender stands down **[owner-confirmed]** |
| Cause of clock drift? | **[?] Still open** — likely no NTP after snapshot restore |

**Why this matters for detonations:** with Defender disabled by Elastic Security,
**Elastic Defend is the only endpoint protection** on `analysis-host`. Detonation results
reflect Defend's detection surface alone — nothing is being caught or quarantined by
Defender first, so samples run further than they would on a stock Windows host. Good
for teaching detection engineering; worth stating explicitly to a workshop audience.

> **`analysis-host` is powered down between exercises** (owner-confirmed 2026-08-10). Proxmox
> reports VM 101 as `running` with uptime, but that is the hypervisor's view only — the
> guest OS is not up: the QEMU guest agent does not respond, there is no ARP entry on
> the detonation LAN, and telemetry stopped at 2026-08-08 19:44 UTC.
>
> **Do not read "running" in Proxmox as "the guest is alive."** The cheap check before
> each detonation is a guest-agent ping; if that fails, the OS is down regardless of
> what the VM state says.

---

## 6. Diagram brief — detonation flow

A **numbered sequence diagram** works better here than a topology map:

1. Analyst rolls back snapshot (Proxmox → VM 101)
2. Analyst verifies agent health + clock
3. Malware executes on `analysis-host`
4. Host telemetry (Defend, Sysmon, PowerShell, Security) → Elastic Agent → Elastic Cloud
5. Network egress → OPNsense: filterlog + Suricata + **Squid** + DNS
6. Detection rules fire → alerts → analyst links into an Elastic Case

Annotate the proxy hop with *"true C2 destination visible **only** in the Squid log"* —
it is the best teaching artefact in the lab. Draw it as **working** (solid, not dashed):
Squid parsing was fixed on 2026-08-08. If you want the diagram to carry the lesson,
produce a **before/after pair** using the table in §4.
