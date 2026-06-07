#!/usr/bin/env python3
"""
extract_ground_truth.py
Build a normalized DFIR ground-truth manifest from a Caldera operation.

For each finished link in the operation, emits one event with:
  - host, agent paw, executor
  - decode timestamps (decide/finish, UTC)
  - ATT&CK technique id + tactic + ability metadata
  - decoded plaintext command
  - success flag + raw status
  - output preview (full output kept separately if requested)
  - facts/relationships discovered by the link
Plus operation-level metadata and summaries by technique/host.

Usage:
  ./extract_ground_truth.py <op_id> [-o /path/ground_truth.json]
  CALDERA_URL / CALDERA_API_KEY env overrides supported.

Output stays on host (answer-key isolation) — pass a path under
/home/zeus/dfir_answers/<run>/ for the canonical location.
"""
import argparse
import base64
import binascii
import collections
import json
import os
import sys
import urllib.error
import urllib.request

CALDERA = os.environ.get("CALDERA_URL", "http://192.168.56.10:8888").rstrip("/")
API_KEY = os.environ.get("CALDERA_API_KEY", "ADMIN123")
SCHEMA_VERSION = "1.0"
OUTPUT_PREVIEW_CHARS = 2000

# Sandcat reports every NIC's IP; on the hunt_lab VMs that means each VM's
# host-only IP AND a NAT IP from the host's real LAN. The NAT IPs don't matter
# for the benchmark and shouldn't ship in a public ground_truth.json.
# Default matches the lab's host-only network in Vagrantfile.
LAB_SUBNET_PREFIX = os.environ.get("HUNT_LAB_SUBNET_PREFIX", "192.168.56.")


def filter_lab_ips(ips):
    """Keep only IPs on the lab's host-only subnet; everything else is noise
    from the VM's secondary NIC on the host's home/work network."""
    return [ip for ip in (ips or []) if ip.startswith(LAB_SUBNET_PREFIX)]


def api_get(path):
    req = urllib.request.Request(CALDERA + path, method="GET")
    req.add_header("KEY", API_KEY)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def b64_decode_maybe(s):
    """Caldera double-stores command + plaintext_command as base64. Try to
    decode; if it's not valid base64 (e.g. already plaintext), return as-is."""
    if not s:
        return ""
    try:
        return base64.b64decode(s, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return s


def normalize_link(link, agent_ctx, seq):
    cmd = b64_decode_maybe(link.get("plaintext_command") or link.get("command"))
    output = link.get("output") or ""
    if isinstance(output, dict):
        output_repr = json.dumps(output)
    else:
        output_repr = str(output)
    output_truncated = len(output_repr) > OUTPUT_PREVIEW_CHARS
    ability = link.get("ability") or {}
    return {
        "seq": seq,
        "link_id": link.get("id"),
        "ts_decide_utc": link.get("decide"),
        "ts_finish_utc": link.get("finish"),
        "host": agent_ctx["host"],
        "agent_paw": agent_ctx["paw"],
        "executor": (link.get("executor") or {}).get("name"),
        "ability": {
            "ability_id": ability.get("ability_id"),
            "name": ability.get("name"),
            "description": ability.get("description"),
            "tactic": ability.get("tactic"),
            "technique_id": ability.get("technique_id"),
            "technique_name": ability.get("technique_name"),
            "plugin": ability.get("plugin"),
        },
        "command": cmd,
        "success": link.get("status") == 0,
        "status_code": link.get("status"),
        "output_preview": output_repr[:OUTPUT_PREVIEW_CHARS],
        "output_truncated": output_truncated,
        "output_full_chars": len(output_repr),
        "facts_discovered": link.get("facts") or [],
        "relationships": link.get("relationships") or [],
    }


def build_manifest(op, op_links):
    """Build the manifest from BOTH the operation object (for adversary +
    agent metadata) and the op-scoped /links endpoint (the only source of
    op-specific link history — host_group.links holds agent-lifetime data,
    NOT this op's links)."""
    agents_by_paw = {a.get("paw"): a for a in (op.get("host_group") or []) if a.get("paw")}
    hosts = []
    seen_paws = set()
    for agent in op.get("host_group") or []:
        if agent.get("paw") in seen_paws:
            continue
        seen_paws.add(agent.get("paw"))
        hosts.append({
            "hostname": agent.get("host"),
            "platform": agent.get("platform"),
            "ip_addresses": filter_lab_ips(agent.get("host_ip_addrs")),
            "agent_paw": agent.get("paw"),
            "agent_username": agent.get("username"),
            "agent_privilege": agent.get("privilege"),
            "agent_pid": agent.get("pid"),
            "agent_exe_name": agent.get("exe_name"),
            "agent_location": agent.get("location"),
        })
    events = []
    seq = 0
    for link in op_links:
        if not link.get("finish"):
            continue  # skip in-flight/cancelled
        paw = link.get("paw")
        agent = agents_by_paw.get(paw) or {}
        agent_ctx = {"host": agent.get("host"), "paw": paw}
        seq += 1
        events.append(normalize_link(link, agent_ctx, seq))

    events.sort(key=lambda e: (e.get("ts_finish_utc") or "", e["seq"]))
    for i, e in enumerate(events, start=1):
        e["seq"] = i

    # Caldera doesn't auto-populate the op-level finish field for finished
    # operations — derive from the latest link finish so the manifest has a
    # usable end time for scoring/timeline overlays.
    derived_finish = None
    if events:
        finish_times = [e["ts_finish_utc"] for e in events if e.get("ts_finish_utc")]
        if finish_times:
            derived_finish = max(finish_times)

    tech_summary = collections.defaultdict(lambda: {
        "count": 0,
        "successes": 0,
        "hosts": set(),
        "first_seen_utc": None,
        "technique_name": None,
        "tactic": None,
    })
    for e in events:
        tid = e["ability"]["technique_id"] or "UNMAPPED"
        agg = tech_summary[tid]
        agg["count"] += 1
        if e["success"]:
            agg["successes"] += 1
        agg["hosts"].add(e["host"])
        ts = e["ts_finish_utc"] or e["ts_decide_utc"]
        if ts and (agg["first_seen_utc"] is None or ts < agg["first_seen_utc"]):
            agg["first_seen_utc"] = ts
        agg["technique_name"] = e["ability"]["technique_name"] or agg["technique_name"]
        agg["tactic"] = e["ability"]["tactic"] or agg["tactic"]
    techniques_summary = {}
    for tid, agg in tech_summary.items():
        techniques_summary[tid] = {
            "technique_id": tid,
            "technique_name": agg["technique_name"],
            "tactic": agg["tactic"],
            "count": agg["count"],
            "successes": agg["successes"],
            "hosts": sorted(agg["hosts"]),
            "first_seen_utc": agg["first_seen_utc"],
        }

    facts = op.get("facts") or []
    facts_by_trait = collections.Counter(f.get("trait", "") for f in facts)
    discovered_facts_by_trait = collections.Counter()
    for e in events:
        for f in e["facts_discovered"]:
            discovered_facts_by_trait[f.get("trait", "")] += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "run_id": op.get("id"),
            "operation_name": op.get("name"),
            "scenario": {
                "name": (op.get("adversary") or {}).get("name"),
                "adversary_id": (op.get("adversary") or {}).get("adversary_id"),
                "planner": (op.get("planner") or {}).get("name"),
                "objective": (op.get("objective") or {}).get("name") if isinstance(op.get("objective"), dict) else None,
            },
            "state": op.get("state"),
            "started_utc": op.get("start"),
            "finished_utc": op.get("finish") or derived_finish,
            "extracted_by": "extract_ground_truth.py",
            "schema_version": SCHEMA_VERSION,
        },
        "hosts": hosts,
        "events": events,
        "techniques_summary": techniques_summary,
        "facts_summary": {
            "total_op_facts": len(facts),
            "op_facts_by_trait": dict(facts_by_trait),
            "discovered_facts_by_trait": dict(discovered_facts_by_trait),
        },
        "raw_op_facts": facts,
    }


def main():
    p = argparse.ArgumentParser(description="Extract ground-truth manifest from a Caldera operation.")
    p.add_argument("op_id", help="Caldera operation ID")
    p.add_argument("-o", "--output", help="Output path for ground_truth.json")
    p.add_argument("--print", action="store_true", help="Also print summary to stdout")
    args = p.parse_args()

    try:
        op = api_get(f"/api/v2/operations/{args.op_id}")
        op_links = api_get(f"/api/v2/operations/{args.op_id}/links")
    except urllib.error.HTTPError as e:
        print(f"ERR fetching op {args.op_id}: HTTP {e.code} {e.reason}", file=sys.stderr)
        sys.exit(2)

    manifest = build_manifest(op, op_links)
    # Default to op_id (not op_name) so a bare extract lands in the same
    # directory the bundle script uses — avoids a confusing fork where the
    # extractor's output and the bundle's output diverge.
    default_root = os.path.expanduser(
        os.environ.get("HUNT_LAB_BUNDLES_ROOT", "~/dfir_answers")
    )
    out_path = args.output or os.path.join(default_root, args.op_id, "ground_truth.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=False)
    print(f"wrote {out_path}")

    if args.print:
        run = manifest["run"]
        print(f"  scenario: {run['scenario']['name']}  state: {run['state']}")
        print(f"  events:   {len(manifest['events'])}")
        print(f"  hosts:    {[h['hostname'] for h in manifest['hosts']]}")
        print(f"  techniques: {len(manifest['techniques_summary'])} unique")


if __name__ == "__main__":
    main()
