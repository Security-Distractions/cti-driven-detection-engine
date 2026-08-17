# Open Questions — status after the 2026-08-09 audit

Nearly all original questions were answered directly from OPNsense, Proxmox, and the
live Elastic cluster. Answers live in the relevant document; this is the index.

## ✅ Answered

| # | Question | Answer | Where |
|---|---|---|---|
| 1 | Is `192.168.3.1` OPNsense or another router? | OPNsense `em2` (OPT2) | `00` §3 |
| 2 | What is `10.0.0.33`? | OPNsense `em0` (LAN/uplink) — **not** a sinkhole | `00` §3 |
| 3 | Separate interfaces or VLANs? | Three separate NICs | `00` §3 |
| 4 | Which Proxmox bridge per segment? | `vmbr0`/`vmbr1`/`vmbr2` | `00` §2–3 |
| 5 | Detonation LAN egress-isolated? | **No** — NATs to the internet; home net blocked | `00` §3 |
| 6 | Why no ping reply from `secdis`? | VM running, pf permits it → Windows Firewall ICMP | `02` §5 |
| 7 | Domain-joined? | **Standalone** — no `host.domain` in 577,679 docs | `02` §5 |
| 8 | Only Windows host? | **Yes** | `02` §5 |
| 9 | Clean baseline snapshot? | **`golden-baseline`** (2026-07-22) | `00` §2 |
| 12 | Squid ingestion fixed? | **Yes** — 9,147 parsed docs/24h | `03` §4 |
| 13 | 286 rules installed? | Superseded — **1,790 installed, 620 enabled** | `03` §5 |
| 14 | ML v3 done? | 44 jobs: 6 open, 35 closed, **3 failed** | `03` §5 |
| 15 | ILM specifics? | `cti-*` policies; two are misnamed | `03` §6 |
| 16 | Cluster headroom? | **5% used**, ~678 GB free/node | `03` §6 |
| 17 | What does the OTel collector feed? | It **is** the OPNsense relay input | `03` §2 |
| 10 | Defender on `secdis`? | **Disabled by Elastic Security** — Defend is the sole EDR | `02` §5 |
| 18 | OPNsense GUI location? | **`http://192.168.2.1`** — plain HTTP, port 80 | `01` §1 |
| 19 | `<SSH-TUNNEL-HOST>` policy? | **Now a single operator** — second operator removed 2026-08-09 | `01` §3 |

## ❓ Still open — only you can answer

| # | Question | Why it matters |
|---|---|---|
| 11 | What causes the post-rollback clock drift — no NTP, or a paused-VM artifact? | Recurring cause of "missing" telemetry |
| 20 | When does the teaching session end? | So the CTI app Access bypass can be reverted |

## ⚠️ Action items surfaced by the audit

1. ~~`secdis` has not shipped telemetry~~ — **not a fault**: the host is powered down
   between exercises (owner-confirmed 2026-08-10). Note that Proxmox still reports the
   VM as `running`; use a guest-agent ping to tell the difference.
2. **Three ML jobs are failed** — all packetbeat models, probably starved of input.
3. **Two ILM policies are misnamed** — `cti-logs-90d` and `cti-network-logs-30d` both
   delete at **365 days**.
4. **OPNsense GUI is HTTP-only** — a TLS cert reference already exists; enabling HTTPS
   is a config toggle.
5. **The detonation LAN can reach the utility LAN** — a compromised `secdis` could
   reach util-debian, which runs the CTI app, the log relay, and the tunnel.
