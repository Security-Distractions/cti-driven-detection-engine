#!/usr/bin/env python3
"""
Elastic -> Compromise Canvas generator.

Reads process telemetry (Elastic Defend / Sysmon) for one host and time window,
reconstructs the on-host process tree, and emits a Compromise Canvas JSON file
that imports directly via "Import JSON".

Three output modes:

  --mode host       (default) One host node whose `actions` array is the ordered
                    on-host step chain. The canvas stays an infrastructure
                    diagram; double-clicking the host opens the step-by-step
                    path. Needs the on-host attack path feature in Compromise
                    Canvas (branch feat/on-host-attack-path).

  --mode technique  One node per MITRE technique, edges = real causality
                    (a process classified as A spawned one classified as B).
                    Works with upstream Compromise Canvas as-is.

  --mode process    One node per distinct process behaviour. Detailed, and
                    unreadable past ~30 nodes. Works with upstream as-is.

Usage:
  export ES_URL=https://...:9243 ES_USER=... ES_PASS=...
  ./elastic_to_canvas.py --host secdis \
      --from 2026-08-08T17:26:00Z --to 2026-08-08T17:40:00Z \
      --mode host \
      --title "Sample C — on-host attack path (secdis)" \
      --out sample-c-host.json
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime

# ---------------------------------------------------------------- config

# Processes that are almost always noise in a detonation window. Keep the list
# short and explicit: over-filtering hides the attack, under-filtering buries it.
NOISE = {
    "svchost.exe", "conhost.exe", "dllhost.exe", "sihost.exe", "taskhostw.exe",
    "RuntimeBroker.exe", "SearchProtocolHost.exe", "SearchFilterHost.exe",
    "backgroundTaskHost.exe", "ctfmon.exe", "explorer.exe", "MoUsoCoreWorker.exe",
    "SgrmBroker.exe", "audiodg.exe", "WmiPrvSE.exe", "smartscreen.exe",
    "SecurityHealthService.exe", "SecurityHealthSystray.exe", "TrustedInstaller.exe",
    "TiWorker.exe", "usocoreworker.exe", "wermgr.exe", "WerFault.exe",
}

# Interpreters / dual-use binaries — the living-off-the-land surface. Seeing one
# of these is usually the interesting part of a chain.
LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "installutil.exe", "msbuild.exe", "wmic.exe", "schtasks.exe",
    "reg.exe", "net.exe", "net1.exe", "sc.exe", "vssadmin.exe", "bcdedit.exe",
    "curl.exe", "wget.exe", "ftp.exe", "forfiles.exe", "pcalua.exe",
}

SUSPECT_DIRS = ("\\users\\public\\", "\\appdata\\local\\temp\\", "\\programdata\\",
                "\\windows\\temp\\", "\\downloads\\", "\\appdata\\roaming\\")

# Command-line substring -> (edge action type, MITRE id, MITRE name).
# Ordered: first match wins, so put the specific patterns first.
CMD_SIGNALS = [
    ("add-mppreference",       ("Defense Evasion",   "T1562.001", "Disable or Modify Tools")),
    ("set-mppreference",       ("Defense Evasion",   "T1562.001", "Disable or Modify Tools")),
    ("exclusionpath",          ("Defense Evasion",   "T1562.001", "Disable or Modify Tools")),
    ("enablelua",              ("Defense Evasion",   "T1548.002", "Bypass User Account Control")),
    ("schtasks",               ("Persistence",       "T1053.005", "Scheduled Task")),
    ("currentversion\\run",    ("Persistence",       "T1547.001", "Registry Run Keys")),
    ("-enc",                   ("Defense Evasion",   "T1027",     "Obfuscated Files or Information")),
    ("-encodedcommand",        ("Defense Evasion",   "T1027",     "Obfuscated Files or Information")),
    ("frombase64string",       ("Defense Evasion",   "T1140",     "Deobfuscate/Decode Files")),
    ("downloadstring",         ("Command & Control", "T1105",     "Ingress Tool Transfer")),
    ("invoke-webrequest",      ("Command & Control", "T1105",     "Ingress Tool Transfer")),
    ("certutil",               ("Command & Control", "T1105",     "Ingress Tool Transfer")),
    ("bitsadmin",              ("Command & Control", "T1105",     "Ingress Tool Transfer")),
    ("vssadmin",               ("Impact",            "T1490",     "Inhibit System Recovery")),
    ("bcdedit",                ("Impact",            "T1490",     "Inhibit System Recovery")),
    ("whoami",                 ("Discovery",         "T1033",     "System Owner/User Discovery")),
    ("systeminfo",             ("Discovery",         "T1082",     "System Information Discovery")),
    ("net view",               ("Discovery",         "T1135",     "Network Share Discovery")),
    ("net user",               ("Discovery",         "T1087",     "Account Discovery")),
    ("nltest",                 ("Discovery",         "T1482",     "Domain Trust Discovery")),
    ("ipconfig",               ("Discovery",         "T1016",     "System Network Configuration Discovery")),
    ("reg add",                ("Persistence",       "T1112",     "Modify Registry")),
    ("reg.exe add",            ("Persistence",       "T1112",     "Modify Registry")),
    ("rundll32",               ("Defense Evasion",   "T1218.011", "Rundll32")),
    ("mshta",                  ("Defense Evasion",   "T1218.005", "Mshta")),
    ("regsvr32",               ("Defense Evasion",   "T1218.010", "Regsvr32")),
]

DEFAULT_DISPLAY = {
    "showHostname": True, "showIpAddress": True, "showOs": True,
    "showServices": True, "showCriticality": True, "showActions": True,
    "showDescription": True, "showUsername": False, "showDomain": False,
    "showAccountType": False, "showAccountSource": False, "showAccountStatus": False,
}

EDGE_DISPLAY = {
    "showLabel": True, "showActionType": True, "showToolUsed": True,
    "showUserUsed": False, "showTimestamp": True, "showMitreAttack": True,
    "showDescription": False,
}

# ---------------------------------------------------------------- elastic


def es_search(url, user, password, index, body, timeout=60):
    req = urllib.request.Request(
        f"{url.rstrip('/')}/{index}/_search",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + base64.b64encode(
                f"{user}:{password}".encode()).decode(),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"Elasticsearch {e.code}: {e.read().decode()[:400]}")


def _os_label(os_obj):
    """Best available OS string. Elastic Defend process events often carry only
    host.os.type, so don't insist on host.os.full."""
    full = os_obj.get("full")
    if full:
        return full
    name = os_obj.get("name")
    if name:
        ver = os_obj.get("version")
        return f"{name} {ver}".strip() if ver else name
    return (os_obj.get("type") or "").capitalize()


def fetch_processes(cfg, host, t_from, t_to, limit):
    """Process-start events, oldest first."""
    body = {
        "size": limit,
        "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": [
            {"term": {"host.name": host}},
            {"term": {"event.action": "start"}},
            {"range": {"@timestamp": {"gte": t_from, "lte": t_to}}},
            {"exists": {"field": "process.entity_id"}},
        ]}},
        "_source": ["@timestamp", "process.name", "process.entity_id", "process.pid",
                    "process.executable", "process.command_line",
                    "process.parent.name", "process.parent.entity_id",
                    "user.name", "host.name",
                    "host.os.full", "host.os.name", "host.os.version", "host.os.type"],
    }
    hits = es_search(cfg["url"], cfg["user"], cfg["pass"],
                     "logs-endpoint.events.process-*", body)["hits"]["hits"]
    out = []
    for h in hits:
        s = h["_source"]
        p = s.get("process") or {}
        out.append({
            "ts": s.get("@timestamp"),
            "eid": p.get("entity_id"),
            "name": p.get("name") or "(unknown)",
            "pid": p.get("pid"),
            "exe": p.get("executable") or "",
            "cmd": p.get("command_line") or "",
            "parent_eid": (p.get("parent") or {}).get("entity_id"),
            "parent_name": (p.get("parent") or {}).get("name") or "",
            "user": (s.get("user") or {}).get("name") or "",
            "os": _os_label((s.get("host") or {}).get("os") or {}),
        })
    return out


def fetch_alerts(cfg, host, t_from, t_to, limit=200):
    """Detection alerts in the window — used for the incident log and to mark
    processes the SIEM actually flagged."""
    body = {
        "size": limit,
        "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": t_from, "lte": t_to}}},
        ], "should": [
            {"term": {"host.name": host}},
            {"term": {"kibana.alert.rule.parameters.index": host}},
        ], "minimum_should_match": 0}},
        "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity",
                    "process.name", "process.entity_id", "kibana.alert.reason"],
    }
    try:
        hits = es_search(cfg["url"], cfg["user"], cfg["pass"],
                         ".alerts-security.alerts-*", body)["hits"]["hits"]
    except SystemExit:
        return []
    def dig(src, dotted):
        """Alert _source mixes flat dotted keys and nested objects — try both."""
        if dotted in src:
            return src[dotted]
        cur = src
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur

    out = []
    for h in hits:
        s = h["_source"]
        out.append({
            "ts": s.get("@timestamp"),
            "rule": dig(s, "kibana.alert.rule.name"),
            "severity": dig(s, "kibana.alert.severity"),
            "proc": dig(s, "process.name"),
            "eid": dig(s, "process.entity_id"),
        })
    return out


# ---------------------------------------------------------------- analysis


def classify(proc):
    """Return (edge_action_type, mitre_id, mitre_name) for how this process
    came to exist, based on its command line and location."""
    cmd = (proc["cmd"] or "").lower()
    exe = (proc["exe"] or "").lower()
    for needle, mapped in CMD_SIGNALS:
        if needle in cmd:
            return mapped
    if any(d in exe for d in SUSPECT_DIRS):
        return ("Execution", "T1204.002", "Malicious File")
    if proc["name"].lower() in LOLBINS:
        return ("Execution", "T1059", "Command and Scripting Interpreter")
    return ("Execution", "", "")


def interesting(proc, flagged_eids):
    """Keep a process if it is plausibly attacker activity."""
    name = proc["name"].lower()
    exe = (proc["exe"] or "").lower()
    if proc["eid"] in flagged_eids:
        return True                            # the SIEM flagged it
    if any(d in exe for d in SUSPECT_DIRS):
        return True                            # running from a suspect directory
    if name in LOLBINS:
        return True                            # dual-use interpreter
    if name in NOISE:
        return False
    return False


def _cmd_signature(proc):
    """Normalise a command line so repeated instances of the same behaviour
    collapse together: strip random paths, GUIDs, digits and quoting."""
    import re
    s = (proc["cmd"] or proc["exe"] or proc["name"]).lower()
    s = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 'GUID', s)
    s = re.sub(r'[a-f0-9]{32,}', 'HASH', s)
    s = re.sub(r'\\users\\[^\\]+\\', r'\\users\\USER\\', s)
    s = re.sub(r'[0-9]{2,}', 'N', s)
    s = re.sub(r'["\']', '', s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s[:160]


def collapse_repeats(nodes, by_eid):
    """Malware often repeats one behaviour many times (30x schtasks, 33x cmd).
    Fold those into a single node carrying a repeat count, so the diagram shows
    the attack path rather than the loop count."""
    kept = {n["eid"] for n in nodes}
    # Key on the behaviour itself, not the parent instance: malware spawns a
    # fresh cmd.exe per action, so keying on the parent leaves the repeats
    # spread across dozens of near-identical nodes.
    groups = {}
    for n in nodes:
        key = (n["name"].lower(), _cmd_signature(n))
        groups.setdefault(key, []).append(n)

    representative = {}      # eid -> representative eid
    reps = []
    for key, members in groups.items():
        members.sort(key=lambda x: x["ts"] or "")
        rep = dict(members[0])
        rep["count"] = len(members)
        rep["last_ts"] = members[-1]["ts"]
        rep["pids"] = [m["pid"] for m in members if m.get("pid")][:6]
        reps.append(rep)
        for m in members:
            representative[m["eid"]] = rep["eid"]

    # re-point parents at representatives
    for r in reps:
        par = r.get("parent_eid")
        r["parent_eid"] = representative.get(par, par)

    reps.sort(key=lambda x: x["ts"] or "")
    rep_by_eid = {r["eid"]: r for r in reps}
    return reps, rep_by_eid


def build_tree(procs, flagged_eids, keep_ancestors=True):
    """Select interesting processes, then re-attach their ancestors so the chain
    is connected rather than a scatter of orphans."""
    by_eid = {p["eid"]: p for p in procs if p["eid"]}
    keep = {p["eid"] for p in procs if interesting(p, flagged_eids)}

    if keep_ancestors:
        for eid in list(keep):
            cur, guard = by_eid.get(eid), 0
            while cur and guard < 12:
                par = cur.get("parent_eid")
                if not par or par not in by_eid:
                    break
                keep.add(par)
                cur = by_eid[par]
                guard += 1

    nodes = [by_eid[e] for e in keep if e in by_eid]
    nodes.sort(key=lambda p: p["ts"] or "")
    return collapse_repeats(nodes, by_eid)


# ---------------------------------------------------------------- canvas


def layout(nodes, by_eid):
    """Depth = generation in the process tree, so the graph reads top-to-bottom
    as execution proceeds."""
    kept = {n["eid"] for n in nodes}
    depth = {}

    def d(eid, guard=0):
        if eid in depth:
            return depth[eid]
        if guard > 12:
            return 0
        p = by_eid.get(eid, {}).get("parent_eid")
        depth[eid] = (d(p, guard + 1) + 1) if (p in kept) else 0
        return depth[eid]

    for n in nodes:
        d(n["eid"])

    rows = {}
    pos = {}
    for n in sorted(nodes, key=lambda x: (depth[x["eid"]], x["ts"] or "")):
        lvl = depth[n["eid"]]
        col = rows.get(lvl, 0)
        rows[lvl] = col + 1
        pos[n["eid"]] = {"x": 80 + col * 330, "y": 90 + lvl * 200}
    return pos, depth


def to_canvas(host, os_name, nodes, by_eid, alerts, flagged_eids, title):
    pos, depth = layout(nodes, by_eid)
    width = max((p["x"] for p in pos.values()), default=400) + 320
    height = max((p["y"] for p in pos.values()), default=300) + 200

    cnodes = [{
        "id": f"host-{host}",
        "type": "labeledGroupNode",
        "position": {"x": 0, "y": 0},
        "zIndex": 0,
        "data": {
            "label": f"{host}  —  on-host execution chain",
            "type": "group",
            "criticality": "High",
            "services": [],
            "actions": [],
            "color": "red",
            "transparency": 0.12,
            "width": width,
            "height": height,
            "isCompromised": True,
            "investigationStatus": "Investigating",
            "displaySettings": dict(DEFAULT_DISPLAY),
        },
    }]

    for n in nodes:
        action, mid, mname = classify(n)
        flagged = n["eid"] in flagged_eids
        actions = []
        if mid:
            actions.append({
                "id": f"act-{n['eid'][:8]}",
                "type": "Execution" if action == "Execution" else action.replace(" & ", " and "),
                "technique": f"{mid} {mname}".strip(),
                "details": (n["cmd"] or n["exe"])[:300],
            })
        cnodes.append({
            "id": f"p-{n['eid']}",
            "type": "customNode",
            "position": pos[n["eid"]],
            "zIndex": 1,
            "data": {
                "label": (f"{n['name']}  x{n['count']}" if n.get("count", 1) > 1 else n["name"]),
                "type": "other",
                "hostname": f"pid {n['pid']}" if n["pid"] else "",
                "ipAddress": "",
                "os": (n["ts"] or "")[11:19] + " UTC" if n["ts"] else "",
                "criticality": "Critical" if flagged else "Medium",
                "services": [n["user"]] if n["user"] else [],
                "actions": actions,
                "description": ((n["exe"] or "")[:180] +
                                (f"  [repeated {n['count']}x until {(n.get('last_ts') or '')[11:19]} UTC]"
                                 if n.get("count", 1) > 1 else "")),
                "isCompromised": True,
                "investigationStatus": "Investigating" if flagged else "No Status",
                "displaySettings": dict(DEFAULT_DISPLAY),
            },
        })

    kept = {n["eid"] for n in nodes}
    cedges = []
    for n in nodes:
        par = n.get("parent_eid")
        if par not in kept or par == n["eid"]:
            continue        # collapsing can fold a parent into its own child
        action, mid, mname = classify(n)
        e = {
            "id": f"e-{par[:8]}-{n['eid'][:8]}",
            "source": f"p-{par}",
            "target": f"p-{n['eid']}",
            "type": "customEdge",
            "data": {
                "label": "spawned",
                "actionType": action,
                "toolUsed": n["name"],
                "userUsed": n["user"],
                "timestamp": n["ts"] or "",
                "description": (n["cmd"] or "")[:400],
                "displaySettings": dict(EDGE_DISPLAY),
            },
        }
        if mid:
            e["data"]["mitreAttackId"] = mid
            e["data"]["mitreAttackName"] = mname
            e["data"]["mitreAttackTechniques"] = [{"id": mid, "name": mname}]
        cedges.append(e)

    log = []
    seen = set()
    for a in alerts:
        key = a.get("rule")
        if not key or key in seen:
            continue
        seen.add(key)
        log.append({
            "id": f"inc-{len(log)+1}",
            "timestamp": a["ts"],
            "description": f"Detection: {key}" + (f" (process {a['proc']})" if a.get("proc") else ""),
            "category": "Observation",
        })

    return {
        "version": "1.0",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "canvasTitle": title,
        "incidentLog": log[:40],
        "diagram": {"nodes": cnodes, "edges": cedges,
                    "viewport": {"x": 0, "y": 0, "zoom": 0.7}},
    }



def aggregate_by_technique(nodes, by_eid):
    """Fold the process graph into a technique graph.

    One node per MITRE technique (or action type where no technique matched),
    and an edge A -> B whenever a process classified as A spawned a process
    classified as B. That keeps real causality rather than mere chronology,
    and produces a diagram a human can read in one glance.
    """
    kept = {n["eid"] for n in nodes}

    def tech_key(n):
        _a, mid, mname = classify(n)
        if mid:
            return (mid, f"{mid} {mname}")
        act, _, _ = classify(n)
        return (f"act:{act}", act)

    groups = {}
    eid_to_key = {}
    for n in nodes:
        k, label = tech_key(n)
        eid_to_key[n["eid"]] = k
        g = groups.setdefault(k, {"key": k, "label": label, "members": [],
                                  "first": n["ts"], "last": n["ts"]})
        g["members"].append(n)
        if (n["ts"] or "") < (g["first"] or ""):
            g["first"] = n["ts"]
        if (n["ts"] or "") > (g["last"] or ""):
            g["last"] = n["ts"]

    # causal edges between technique groups
    pairs = {}
    for n in nodes:
        par = n.get("parent_eid")
        if par not in kept:
            continue
        a, b = eid_to_key.get(par), eid_to_key.get(n["eid"])
        if not a or not b or a == b:
            continue
        pairs.setdefault((a, b), []).append(n)

    ordered = sorted(groups.values(), key=lambda g: g["first"] or "")
    return ordered, pairs


def technique_canvas(host, groups, pairs, alerts, flagged_eids, title):
    # Depth = chronological rank of first appearance. Causal loops are real here
    # (a payload spawns cmd.exe which spawns the payload again), so a longest-path
    # depth diverges. Time is the honest axis for an attack path, and the causal
    # edges still show which step led to which.
    ordered = sorted(groups, key=lambda x: x["first"] or "")
    depth = {g["key"]: i for i, g in enumerate(ordered)}

    pos = {}
    for g in ordered:
        lvl = depth[g["key"]]
        # slight horizontal stagger so long labels don't collide vertically
        pos[g["key"]] = {"x": 90 + (lvl % 2) * 90, "y": 100 + lvl * 190}

    width = max((p["x"] for p in pos.values()), default=400) + 340
    height = max((p["y"] for p in pos.values()), default=300) + 220

    cnodes = [{
        "id": f"host-{host}",
        "type": "labeledGroupNode",
        "position": {"x": 0, "y": 0},
        "zIndex": 0,
        "data": {
            "label": f"{host}  —  on-host attack path by technique",
            "type": "group", "criticality": "High", "services": [], "actions": [],
            "color": "red", "transparency": 0.12,
            "width": width, "height": height,
            "isCompromised": True, "investigationStatus": "Investigating",
            "displaySettings": dict(DEFAULT_DISPLAY),
        },
    }]

    for g in groups:
        members = g["members"]
        flagged = any(m["eid"] in flagged_eids for m in members)
        procs = sorted({m["name"] for m in members})
        samples = []
        seen = set()
        for m in members:
            sig = _cmd_signature(m)
            if sig in seen:
                continue
            seen.add(sig)
            samples.append((m["cmd"] or m["exe"])[:220])
            if len(samples) >= 4:
                break
        cnodes.append({
            "id": f"t-{g['key'].replace('.', '_').replace(':', '_')}",
            "type": "customNode",
            "position": pos[g["key"]],
            "zIndex": 1,
            "data": {
                "label": g["label"],
                "type": "other",
                "hostname": f"{len(members)} process event(s)",
                "ipAddress": "",
                "os": f"{(g['first'] or '')[11:19]} → {(g['last'] or '')[11:19]} UTC",
                "criticality": "Critical" if flagged else "Medium",
                "services": procs[:6],
                "actions": [{
                    "id": f"act-{i}",
                    "type": "Other",
                    "technique": g["label"],
                    "details": s,
                } for i, s in enumerate(samples)],
                "description": ", ".join(procs[:8]),
                "isCompromised": True,
                "investigationStatus": "Investigating" if flagged else "No Status",
                "displaySettings": dict(DEFAULT_DISPLAY),
            },
        })

    def nid(k):
        return f"t-{k.replace('.', '_').replace(':', '_')}"

    cedges = []
    for (a, b), members in pairs.items():
        first = min(members, key=lambda m: m["ts"] or "")
        act, mid, mname = classify(first)
        e = {
            "id": f"e-{nid(a)}-{nid(b)}",
            "source": nid(a), "target": nid(b),
            "type": "customEdge",
            "data": {
                "label": f"led to ({len(members)})",
                "actionType": act,
                "toolUsed": first["name"],
                "userUsed": first["user"],
                "timestamp": first["ts"] or "",
                "description": (first["cmd"] or "")[:300],
                "displaySettings": dict(EDGE_DISPLAY),
            },
        }
        if mid:
            e["data"]["mitreAttackId"] = mid
            e["data"]["mitreAttackName"] = mname
            e["data"]["mitreAttackTechniques"] = [{"id": mid, "name": mname}]
        cedges.append(e)

    log = []
    seen = set()
    for a in alerts:
        r = a.get("rule")
        if not r or r in seen:
            continue
        seen.add(r)
        log.append({"id": f"inc-{len(log)+1}", "timestamp": a["ts"],
                    "description": f"Detection: {r}" + (f" (process {a['proc']})" if a.get("proc") else ""),
                    "category": "Observation"})

    return {"version": "1.0",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "canvasTitle": title, "incidentLog": log[:40],
            "diagram": {"nodes": cnodes, "edges": cedges,
                        "viewport": {"x": 0, "y": 0, "zoom": 0.75}}}


# CompromiseCanvas node actions use tactic names; our edge action types are a
# slightly different vocabulary (and it has no Execution tactic).
NODE_ACTION_TYPE = {
    "Command & Control": "Command and Control",
    "Execution": "Other",
}


def host_canvas(host, os_name, groups, alerts, flagged_eids, title):
    """One host node whose `actions` are the ordered on-host step chain.

    This is the shape the drill-down reads: the canvas stays an infrastructure
    diagram (attacker -> host), and everything that happened *inside* the host
    lives in that host's action list, in time order. No abuse of hostname/os/
    services to smuggle in detail — those stay what they are.
    """
    ordered = sorted(groups, key=lambda g: g["first"] or "")

    actions = []
    for i, g in enumerate(ordered):
        first = min(g["members"], key=lambda m: m["ts"] or "")
        act, mid, mname = classify(first)
        # hash-named payloads have 64-char "names" — they'd swamp the step label
        procs = sorted({(m["name"][:20] + "…" if len(m["name"]) > 21 else m["name"])
                        for m in g["members"]})
        # one representative command per distinct behaviour, so a step reads as
        # "what was done" rather than a dump of every repeat
        samples, seen = [], set()
        for m in g["members"]:
            sig = _cmd_signature(m)
            if sig in seen:
                continue
            seen.add(sig)
            samples.append((m["cmd"] or m["exe"] or m["name"])[:220])
            if len(samples) >= 3:
                break
        detail = "\n".join(samples)
        if len(g["members"]) > len(samples):
            detail += f"\n(+{len(g['members']) - len(samples)} more event(s), " \
                      f"until {(g['last'] or '')[11:19]} UTC)"
        actions.append({
            "id": f"step-{i+1}",
            "type": NODE_ACTION_TYPE.get(act, act),
            "technique": g["label"] if not mid else f"{mname or g['label']} via {', '.join(procs[:3])}",
            "details": detail,
            "timestamp": g["first"] or "",
            **({"mitreAttackId": mid, "mitreAttackName": mname} if mid else {}),
        })

    display = dict(DEFAULT_DISPLAY)
    display["showActionPath"] = True        # render the chain, not a bullet list
    display["showHostname"] = False         # the label already is the hostname
    display["showIpAddress"] = False
    display["showServices"] = False
    display["showOs"] = bool(os_name)

    attacker = {
        "id": "attacker-infra",
        "type": "customNode",
        "position": {"x": 520, "y": 160},
        "zIndex": 1,
        "data": {
            "label": "Attacker infrastructure",
            "type": "server",
            "hostname": "", "ipAddress": "", "os": "",
            "criticality": "High",
            "services": [], "actions": [],
            "description": "Delivery / C2 endpoint(s) contacted from the host",
            "isCompromised": False,
            "investigationStatus": "No Status",
            "displaySettings": {**DEFAULT_DISPLAY, "showHostname": False,
                                "showIpAddress": False, "showOs": False},
        },
    }

    host_node = {
        "id": f"host-{host}",
        "type": "customNode",
        "position": {"x": 520, "y": 620},
        "zIndex": 1,
        "data": {
            "label": host,
            "type": "workstation",
            "hostname": "",
            "ipAddress": "",
            "os": os_name or "",
            "criticality": "Critical",
            "services": [],
            "actions": actions,
            "description": f"{len(actions)} on-host step(s) — double-click to drill into the path",
            "isCompromised": True,
            "investigationStatus": "Investigating",
            "displaySettings": display,
        },
    }

    first_act = actions[0] if actions else None
    edges = [{
        "id": "e-attacker-host",
        "source": "attacker-infra",
        "target": f"host-{host}",
        "type": "customEdge",
        "data": {
            "label": "initial access",
            "actionType": "Initial Access",
            "toolUsed": "",
            "userUsed": "",
            "timestamp": (first_act or {}).get("timestamp", ""),
            "description": "",
            "displaySettings": dict(EDGE_DISPLAY),
        },
    }]

    log, seen = [], set()
    for al in alerts:
        r = al.get("rule")
        if not r or r in seen:
            continue
        seen.add(r)
        log.append({"id": f"inc-{len(log)+1}", "timestamp": al["ts"],
                    "description": f"Detection: {r}" + (f" (process {al['proc']})" if al.get("proc") else ""),
                    "category": "Observation"})

    return {"version": "1.0",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "canvasTitle": title, "incidentLog": log[:40],
            "diagram": {"nodes": [attacker, host_node], "edges": edges,
                        "viewport": {"x": 0, "y": 0, "zoom": 1}}}


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description="Elastic -> Compromise Canvas")
    ap.add_argument("--host", required=True)
    ap.add_argument("--from", dest="t_from", required=True, help="ISO8601")
    ap.add_argument("--to", dest="t_to", required=True, help="ISO8601")
    ap.add_argument("--title", default=None)
    ap.add_argument("--out", default="canvas.json")
    ap.add_argument("--limit", type=int, default=4000, help="max process events")
    ap.add_argument("--mode", choices=["process", "technique", "host"], default="host",
                    help="host = one host node whose action list is the on-host "
                         "step chain (for the click-through drill-down); "
                         "technique = one node per MITRE technique; "
                         "process = one node per distinct process behaviour")
    ap.add_argument("--no-ancestors", action="store_true",
                    help="don't re-attach parents of interesting processes")
    a = ap.parse_args()

    cfg = {"url": os.environ.get("ES_URL", ""),
           "user": os.environ.get("ES_USER", ""),
           "pass": os.environ.get("ES_PASS", "")}
    if not all(cfg.values()):
        sys.exit("set ES_URL, ES_USER, ES_PASS")

    procs = fetch_processes(cfg, a.host, a.t_from, a.t_to, a.limit)
    if not procs:
        sys.exit("no process events in that window — widen it or check the host name")
    alerts = fetch_alerts(cfg, a.host, a.t_from, a.t_to)
    flagged = {al["eid"] for al in alerts if al.get("eid")}

    nodes, by_eid = build_tree(procs, flagged, keep_ancestors=not a.no_ancestors)
    if not nodes:
        sys.exit("nothing classified as interesting — try --no-ancestors off, or widen the window")

    title = a.title or f"{a.host} — on-host attack path {a.t_from[:16]}"
    if a.mode in ("technique", "host"):
        groups, pairs = aggregate_by_technique(nodes, by_eid)
        if a.mode == "host":
            # host.os.full isn't on every event — take the first one that has it
            os_name = next((p.get("os") for p in procs if p.get("os")), "")
            canvas = host_canvas(a.host, os_name, groups, alerts, flagged, title)
        else:
            canvas = technique_canvas(a.host, groups, pairs, alerts, flagged, title)
    else:
        canvas = to_canvas(a.host, procs[0].get("os", ""), nodes, by_eid,
                           alerts, flagged, title)

    with open(a.out, "w") as f:
        json.dump(canvas, f, indent=2)

    print(f"  process events fetched : {len(procs)}")
    print(f"  alerts in window       : {len(alerts)} ({len(flagged)} tied to a process)")
    print(f"  processes kept          : {len(nodes)}")
    print(f"  canvas nodes / edges    : {len(canvas['diagram']['nodes'])} / {len(canvas['diagram']['edges'])}")
    print(f"  incident log entries    : {len(canvas['incidentLog'])}")
    print(f"  written                 : {a.out}")


if __name__ == "__main__":
    main()
