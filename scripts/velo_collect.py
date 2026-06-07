#!/usr/bin/env python3
"""
velo_collect.py
Trigger Windows.KapeFiles.Targets (_SANS_Triage) collections on enrolled
Velociraptor clients, wait for completion, and download the result zips.

Hostnames are resolved from /velociraptor/client_info/snapshot.json inside
the container (the hostname is ASCII-visible in the protobuf-encoded `info`
field — we do a substring match rather than parse the protobuf).

Usage:
  ./velo_collect.py <hostname> [<hostname> ...] -o /path/output_dir
  ./velo_collect.py --all-windows -o /path/output_dir

All velociraptor binary access goes via:
  vagrant ssh docker-host -c 'docker exec -w /velociraptor velociraptor ...'

so this must be run on the host that has the hunt_lab Vagrantfile.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

# Derived from this script's location: scripts/ lives at <repo>/scripts/, so
# the repo root is its parent. Lets the script work for any clone, not just
# the original author's ~/Desktop/hunt_lab path.
HUNT_LAB = os.environ.get(
    "HUNT_LAB_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)
# Windows.KapeFiles.Targets is not loaded in Velo 0.76.3's stock artifact set
# on this build — we use Generic.Collectors.File with a SANS-style glob CSV
# that mirrors the essentials of KAPE's _SANS_Triage target list. Same intent,
# uses what's actually available.
TARGET_ARTIFACT = "Generic.Collectors.File"
POLL_SECONDS = 30
TIMEOUT_SECONDS = 60 * 60  # 1h per collection

# SANS-style triage globs. NO leading device (Generic.Collectors.File prepends
# Root). Use ntfs accessor so we can read locked SYSTEM/SAM/SECURITY hives and
# $MFT while Windows holds them open.
SANS_TRIAGE_CSV = """Glob
Windows/System32/winevt/Logs/*.evtx
Windows/System32/config/SAM
Windows/System32/config/SECURITY
Windows/System32/config/SYSTEM
Windows/System32/config/SOFTWARE
Windows/System32/config/DEFAULT
Windows/System32/config/RegBack/*
Windows/System32/config/TxR/*
Windows/System32/sru/SRUDB.dat
Windows/System32/Tasks/**
Windows/appcompat/Programs/Amcache.hve
Windows/Prefetch/*.pf
Windows/Tasks/**
$MFT
$LogFile
$Extend/$UsnJrnl:$J
Users/*/NTUSER.DAT
Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat
Users/*/AppData/Roaming/Microsoft/Windows/Recent/**
Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/*.txt
Users/*/AppData/Local/Microsoft/Windows/WebCache/*
Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History
Users/*/AppData/Local/Google/Chrome/User Data/Default/History
ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/**
$Recycle.Bin/**
"""


def vagrant_exec(cmd):
    """Run a shell command inside the velociraptor container via vagrant ssh."""
    full = f"docker exec -w /velociraptor velociraptor sh -c {shell_quote(cmd)}"
    res = subprocess.run(
        ["vagrant", "ssh", "docker-host", "-c", full],
        cwd=HUNT_LAB,
        capture_output=True,
        text=True,
    )
    return res.returncode, res.stdout, res.stderr


def shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


_API_CONFIG_READY = False


def ensure_api_config():
    """Idempotently create /velociraptor/api.config.yaml inside the container."""
    global _API_CONFIG_READY
    if _API_CONFIG_READY:
        return
    rc, out, _ = vagrant_exec(
        "test -s /velociraptor/api.config.yaml && echo ok || "
        "./velociraptor --config server.config.yaml config api_client "
        "--name admin --role administrator /velociraptor/api.config.yaml"
    )
    _API_CONFIG_READY = True


def velo_query(vql, fmt="jsonl"):
    """Run a VQL query inside the container via the gRPC API config.

    The --config (server) path can't write to the running server's task queue
    when invoked as a subprocess — collect_client() comes back null. The
    --api_config path connects via gRPC and works as expected. The config is
    auto-generated on first use."""
    ensure_api_config()
    cmd = (
        f"./velociraptor --api_config /velociraptor/api.config.yaml "
        f"query {shell_quote(vql)} --format {fmt} 2>/dev/null"
    )
    rc, out, err = vagrant_exec(cmd)
    if rc != 0:
        return None, f"<rc={rc}> {err}"
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows, out


def resolve_clients():
    """Read snapshot.json from the container and map hostnames -> client_ids.
    The `info` field is hex-encoded protobuf; hostnames are embedded as ASCII
    literals we can pull out with a regex over the hex-decoded bytes."""
    rc, out, err = vagrant_exec("cat /velociraptor/client_info/snapshot.json")
    if rc != 0:
        sys.exit(f"failed to read snapshot.json: {err}")
    mapping = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        cid = rec.get("client_id")
        hex_info = rec.get("info", "")
        try:
            decoded = bytes.fromhex(hex_info)
        except ValueError:
            continue
        # The hostname appears twice in the protobuf — once short, once FQDN.
        # Look for ascii strings of length >= 3 made of [A-Za-z0-9._-].
        hosts = re.findall(rb"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", decoded)
        for h in hosts:
            h = h.decode("ascii", errors="ignore").lower()
            if h and "." not in h and not h.startswith("c."):  # short hostname
                mapping.setdefault(h, cid)
                break
    return mapping


def trigger_collection(client_id):
    """Schedule Generic.Collectors.File with the SANS triage glob set.

    Returns the flow_id. Aborts (does NOT return None) if the server rejects
    the request — earlier versions silently polled a null flow_id forever."""
    # VQL string literal escaping: backslashes in the CSV need to survive
    # Python str → VQL string. VQL '' strings use '' as escape for a quote
    # and treat backslashes literally, so this is safe.
    csv_literal = SANS_TRIAGE_CSV.replace("'", "''")
    vql = (
        f'LET spec = \'{csv_literal}\' '
        f'SELECT collect_client(client_id="{client_id}", '
        f'artifacts="{TARGET_ARTIFACT}", '
        f'spec=dict(`{TARGET_ARTIFACT}`=dict('
        f'collectionSpec=spec, Root="C:", Accessor="ntfs"))'
        f').flow_id AS flow_id FROM scope()'
    )
    rows, raw = velo_query(vql)
    if not rows:
        sys.exit(f"trigger failed for {client_id}: no rows from server. raw={raw[:400]}")
    fid = rows[0].get("flow_id")
    if not fid:
        sys.exit(
            f"trigger failed for {client_id}: server returned null flow_id. "
            f"Likely artifact name unknown or spec malformed. raw={raw[:400]}"
        )
    return fid


def poll_flow(client_id, flow_id):
    """Block until the flow reaches a terminal state. Return final state dict.

    The flows() VQL function returns state/total_uploaded_* at top level —
    NOT nested under .context (which is null in jsonl output)."""
    vql = (
        f'SELECT state, total_uploaded_files AS files, '
        f'total_uploaded_bytes AS bytes, '
        f'total_collected_rows AS rows, '
        f'active_time '
        f'FROM flows(client_id="{client_id}", flow_id="{flow_id}")'
    )
    deadline = time.time() + TIMEOUT_SECONDS
    last_state = None
    while time.time() < deadline:
        rows, _ = velo_query(vql)
        if rows:
            r = rows[0]
            state = r.get("state")
            if state != last_state:
                print(f"  [{client_id}] state={state} files={r.get('files')} "
                      f"bytes={r.get('bytes')}")
                last_state = state
            if state in ("FINISHED", "ERROR", "CANCELLED"):
                return r
        time.sleep(POLL_SECONDS)
    return {"state": "TIMEOUT"}


def download_collection(client_id, flow_id, out_dir):
    """Copy the collection zip out of the container into out_dir.
    Velo stores per-collection artifacts under clients/<cid>/collections/<fid>/."""
    container_zip = f"/velociraptor/clients/{client_id}/collections/{flow_id}/uploads.zip"
    # Try common upload-zip locations; SANS_Triage uploads files individually
    # and the collection has a final results zip. The exact path depends on
    # the artifact, so we list and pick the largest zip.
    rc, out, _ = vagrant_exec(
        f"ls -la /velociraptor/clients/{client_id}/collections/{flow_id}/ 2>&1"
    )
    print(f"  [{client_id}] collection dir listing:\n{out}")
    # Try to download the whole collection dir via tar
    os.makedirs(out_dir, exist_ok=True)
    tar_path = os.path.join(out_dir, f"{client_id}_{flow_id}.tar")
    cmd = (
        f"docker exec velociraptor sh -c "
        f"'cd /velociraptor/clients/{client_id}/collections/{flow_id} && tar cf - .'"
    )
    res = subprocess.run(
        ["vagrant", "ssh", "docker-host", "-c", cmd],
        cwd=HUNT_LAB,
        capture_output=True,
    )
    if res.returncode == 0 and res.stdout:
        with open(tar_path, "wb") as f:
            f.write(res.stdout)
        print(f"  [{client_id}] wrote {tar_path} ({len(res.stdout)} bytes)")
        return tar_path
    print(f"  [{client_id}] download failed: rc={res.returncode}, "
          f"stderr={res.stderr.decode(errors='replace')[:300]}")
    return None


def main():
    p = argparse.ArgumentParser(description="Trigger Velo SANS_Triage collections.")
    p.add_argument("hostnames", nargs="*", help="Hostnames to collect from")
    p.add_argument("--all-windows", action="store_true",
                   help="Collect from all Windows clients (win-dc, win-server, win11-victim)")
    p.add_argument("-o", "--output", required=True, help="Output directory")
    args = p.parse_args()

    print("Resolving clients from snapshot.json...")
    mapping = resolve_clients()
    for h, cid in mapping.items():
        print(f"  {h} -> {cid}")

    if args.all_windows:
        targets = [h for h in ("win-dc", "win-server", "win11-victim") if h in mapping]
    else:
        targets = args.hostnames
    if not targets:
        sys.exit("no targets resolved")

    os.makedirs(args.output, exist_ok=True)

    flows = {}
    for h in targets:
        cid = mapping.get(h)
        if not cid:
            print(f"  no client for {h} — skipping")
            continue
        print(f"Triggering {TARGET_ARTIFACT}/_SANS_Triage on {h} ({cid})...")
        fid = trigger_collection(cid)
        print(f"  flow_id={fid}")
        flows[h] = (cid, fid)

    print(f"\nPolling {len(flows)} flows (this can take 10-30 min per host)...")
    results = {}
    for h, (cid, fid) in flows.items():
        state = poll_flow(cid, fid)
        results[h] = {"client_id": cid, "flow_id": fid, "state": state}

    print("\nDownloading collection artifacts...")
    for h, (cid, fid) in flows.items():
        path = download_collection(cid, fid, os.path.join(args.output, h))
        results[h]["download_path"] = path

    summary_path = os.path.join(args.output, "velo_collections.json")
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nWrote summary: {summary_path}")


if __name__ == "__main__":
    main()
