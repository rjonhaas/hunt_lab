#!/usr/bin/env python3
"""
make_benchmark_bundle.py
End-to-end bundle assembly for the hunt_lab DFIR benchmark harness (v1).

Given a finished Caldera operation ID, this:
  1. Extracts the ground-truth manifest (calls extract_ground_truth.py).
  2. Triggers Windows.KapeFiles.Targets (_SANS_Triage) on each Windows host
     in the op (calls velo_collect.py).
  3. Waits for collections to finish, downloads result tars.
  4. Assembles a postable bundle directory with README, evidence, metadata.

Layout produced (under <out_root>/<run_id>/):
  ground_truth/ground_truth.json    # STAYS ON HOST — answer key
  evidence/triage_<host>.tar         # SAFE TO DISTRIBUTE
  evidence/op_metadata.json          # scenario name, times, hosts — NO answers
  README.md                          # for analysts AND tool authors

Usage:
  ./make_benchmark_bundle.py <op_id>
  ./make_benchmark_bundle.py <op_id> --skip-triage   (skip Velo, just extract)
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
EXTRACT = os.path.join(SCRIPTS_DIR, "extract_ground_truth.py")
COLLECT = os.path.join(SCRIPTS_DIR, "velo_collect.py")
BUNDLES_ROOT = os.path.expanduser("~/dfir_answers")

def build_readme(manifest, op_id):
    run = manifest["run"]
    scenario = run["scenario"]
    hosts_list = ", ".join(
        sorted({h["hostname"] for h in manifest["hosts"] if h.get("hostname")})
    )
    technique_rows = []
    for tid, agg in sorted(manifest["techniques_summary"].items()):
        hosts = ", ".join(agg.get("hosts") or [])
        technique_rows.append(
            f"| `{tid}` | {agg.get('technique_name') or '—'} | "
            f"{agg.get('tactic') or '—'} | {agg.get('count', 0)} | {hosts} |"
        )
    technique_table = "\n".join(technique_rows) or "| — | — | — | — | — |"

    return f"""# hunt_lab DFIR Benchmark — {scenario['name']}

Generated from Caldera operation `{run['operation_name']}` ({op_id}).

## What this bundle is

A reproducible DFIR benchmark with **machine-readable ground truth**. A
known attack chain was executed against the hunt_lab Windows VMs, and a
SANS-style triage collection was pulled from each affected host *after*
the attack completed.

Use it two ways:

- **Analyst / Find Evil:** work only from `evidence/`. The triage tars
  contain Sysmon EVTX, all Windows event logs, registry hives, `$MFT`,
  `$UsnJrnl`, Prefetch, Amcache, PSReadline, browser history, scheduled
  tasks, Recycle Bin. Run your usual DFIR workflow against them.
- **Tool author / scoring:** `ground_truth/ground_truth.json` is the
  per-event answer key. Score your tool's findings against it (technique,
  host, time window). Don't load it into the same environment your DFIR
  tool reads — that would invalidate the benchmark.

## Scenario

| Field | Value |
|---|---|
| Adversary | {scenario['name']} |
| Adversary ID | {scenario['adversary_id']} |
| Planner | {scenario['planner']} |
| Started (UTC) | {run['started_utc'] or '—'} |
| Finished (UTC) | {run['finished_utc'] or '—'} |
| Hosts in scope | {hosts_list} |
| Total events | {len(manifest['events'])} |
| Unique techniques | {len(manifest['techniques_summary'])} |

## Techniques in this run

| MITRE ID | Name | Tactic | Events | Hosts |
|---|---|---|---|---|
{technique_table}

> ⚠️ **About `success` in the manifest:** for ART-driven abilities
> (anything where the command shells into `Invoke-AtomicTest`),
> `success=false` does NOT mean the attack didn't happen. Atomic Red
> Team's `Invoke-AtomicTest` often exits non-zero because individual
> sub-tests in the chain fail (missing payloads, prereqs not met), but
> the main technique still fires and leaves the expected artifacts on
> disk. Use `status_code` + `output_preview` for ground-truth on whether
> the attack actually executed. For scoring, every event with
> `ts_finish_utc` set was *attempted* (Caldera dispatched + agent ran it).

## What's in `evidence/<host>/*.tar`

Each tar is the Velociraptor on-disk collection directory for that host's
SANS-style triage flow (`Generic.Collectors.File` with a KAPE-equivalent
glob list, NTFS accessor). Files live under `uploads/ntfs/...`. Velo
URL-encodes special path characters — `%5C` is `\\`, `%3A` is `:`.

```
./uploads/ntfs/%5C%5C.%5CC%3A/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%254Operational.evtx
```

You should find:

- **Sysmon EVTX** (SwiftOnSecurity config — process create, network,
  registry, file create, image load) — single highest-value source.
- **Security / System / Application / PowerShell EVTX** plus every
  other Windows event log.
- **Registry hives:** SAM, SECURITY, SYSTEM, SOFTWARE, DEFAULT,
  NTUSER.DAT, UsrClass.dat.
- **NTFS metadata:** `$MFT`, `$LogFile`, `$UsnJrnl:$J`.
- **Forensic artifacts:** Prefetch, Amcache.hve, SRUDB.dat, scheduled tasks.
- **User activity:** PSReadLine history, Edge/Chrome history, Recent LNKs,
  Startup folders, Recycle Bin.

For each upload, Velo writes both `<file>` and `<file>.chunk` — use the
plain file; the `.chunk` is internal bookkeeping. `.idx` files are sparse
indexes for some artifacts.

### Suggested analysis tools

| Artifact | Tool |
|---|---|
| `*.evtx` | [`EvtxECmd`](https://github.com/EricZimmerman/evtx) (CSV/JSON), [`evtx_dump`](https://github.com/omerbenamram/evtx), or load into Elastic/Splunk |
| `$MFT` | [`MFTECmd`](https://github.com/EricZimmerman/MFTECmd) |
| `$UsnJrnl:$J` | [`MFTECmd`](https://github.com/EricZimmerman/MFTECmd) (UsnJrnl mode) |
| Registry hives | [`RegRipper`](https://github.com/keydet89/RegRipper3.0), [`Registry Explorer`](https://www.kroll.com/en/services/cyber/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) |
| Prefetch | [`PECmd`](https://github.com/EricZimmerman/PECmd) |
| Amcache.hve | [`AmcacheParser`](https://github.com/EricZimmerman/AmcacheParser) |
| Full timeline | [`plaso`/`log2timeline`](https://github.com/log2timeline/plaso) → Timesketch |

For a quick SIEM workflow, ingest the EVTX into Elastic with
`winlogbeat -e` (or Sysmon-specific filebeat module) and pivot in Kibana.

## Sysmon hints (for analysts hunting RansomHub-like chains)

The Sysmon-with-SwiftOnSecurity config will have captured:

- **EID 1** process create — `comsvcs.dll` LSASS dump, `reg save HKLM\\SAM`,
  `rclone.exe` download/execution, `vssadmin delete shadows`, `wevtutil cl`.
- **EID 3** network connect — rclone exfil traffic to LocalStack S3.
- **EID 10** process access — anything touching `lsass.exe`.
- **EID 11** file create — `nocmd.vbs`, `rcl.bat`, `include.txt`,
  simulated encryptor and ransom note dropped into `C:\\Users\\Public\\`.
- **EID 22** DNS query — rclone download URL resolution.

## Ground-truth manifest schema

`ground_truth.json` has these top-level keys:

- `schema_version` — currently `"1.0"`
- `run` — operation metadata (id, scenario, times, planner, state)
- `hosts` — array of host objects (hostname, IPs, agent context)
- `events` — chronologically ordered ability executions; one per Caldera
  link. Per-event fields: `seq`, `link_id`, `ts_decide_utc`, `ts_finish_utc`,
  `host`, `agent_paw`, `executor`, `ability` (id/name/tactic/technique),
  `command` (decoded plaintext), `success`, `status_code`, `output_preview`,
  `facts_discovered`, `relationships`.
- `techniques_summary` — per-technique aggregates (count, successes, hosts).
- `facts_summary` — fact graph statistics.

## How it was generated

1. `python3 scripts/extract_ground_truth.py <op_id>` → `ground_truth.json`
2. `python3 scripts/velo_collect.py --all-windows -o evidence/` → triage tars
3. `python3 scripts/make_benchmark_bundle.py <op_id>` ties them together
   (and writes this README).

All three scripts are in [hunt_lab/scripts/](https://github.com/rjonhaas/hunt_lab/tree/main/scripts).

## Reproducing

```bash
git clone https://github.com/rjonhaas/hunt_lab.git
cd hunt_lab
bash docker/setup.sh
vagrant up win-dc win-server win11-victim --no-parallel
# Then in the Caldera UI: Operations → New →
#   Adversary: {scenario['name']}, Group: red, Auto-run → Start
# When the op finishes, grab its id from the URL or:
#   curl -sS -H "KEY: ADMIN123" http://192.168.56.10:8888/api/v2/operations | jq
python3 scripts/make_benchmark_bundle.py <op_id>
```
"""


def run(cmd, **kwargs):
    """Run a shell command, streaming output."""
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, **kwargs)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("op_id", help="Caldera operation ID")
    p.add_argument("--skip-triage", action="store_true",
                   help="Skip Velo collections (just extract ground truth)")
    p.add_argument("--out-root", default=BUNDLES_ROOT,
                   help=f"Bundle root (default {BUNDLES_ROOT})")
    p.add_argument("--copy-evidence-to", metavar="DIR",
                   help="After the bundle is assembled, copy ONLY the evidence/ "
                        "subtree to this destination (e.g. a VMware shared folder "
                        "to a SIFT analysis VM). Ground truth never goes here.")
    args = p.parse_args()

    run_dir = os.path.join(args.out_root, args.op_id)
    gt_dir = os.path.join(run_dir, "ground_truth")
    ev_dir = os.path.join(run_dir, "evidence")
    os.makedirs(gt_dir, exist_ok=True)
    os.makedirs(ev_dir, exist_ok=True)

    # Step 1: extract ground truth
    gt_path = os.path.join(gt_dir, "ground_truth.json")
    res = run([sys.executable, EXTRACT, args.op_id, "--print", "-o", gt_path])
    if res.returncode != 0:
        sys.exit("extract_ground_truth failed")

    with open(gt_path) as f:
        manifest = json.load(f)

    # Write op_metadata.json — same data MINUS the events/facts that reveal answers
    op_meta = {
        "schema_version": manifest["schema_version"],
        "run": manifest["run"],
        "hosts": manifest["hosts"],
        "techniques_summary_keys": sorted(manifest["techniques_summary"].keys()),
        "events_count": len(manifest["events"]),
    }
    with open(os.path.join(ev_dir, "op_metadata.json"), "w") as f:
        json.dump(op_meta, f, indent=2)

    # Step 2: Velo triage (unless skipped)
    if not args.skip_triage:
        hostnames = sorted({h["hostname"] for h in manifest["hosts"] if h.get("hostname")})
        print(f"\n=== Triggering Velo SANS_Triage on: {hostnames} ===")
        cmd = [sys.executable, COLLECT, *hostnames, "-o", ev_dir]
        res = run(cmd)
        if res.returncode != 0:
            print("velo_collect returned non-zero — continuing with partial bundle",
                  file=sys.stderr)

    # Step 3: write README (built from the manifest so the technique table,
    # times, host list, etc. reflect the actual run rather than a static
    # template).
    with open(os.path.join(run_dir, "README.md"), "w") as f:
        f.write(build_readme(manifest, args.op_id))

    # Step 4: zip the evidence portion (excludes ground_truth dir)
    evidence_zip = os.path.join(run_dir, f"evidence_{args.op_id}.zip")
    shutil.make_archive(evidence_zip[:-4], "zip", ev_dir)

    # Step 5 (optional): copy evidence to a transfer destination — typically a
    # VMware shared folder mapped read-only into an analysis VM (SIFT). Ground
    # truth deliberately never goes here; the destination is for the analyst,
    # not the scorer.
    if args.copy_evidence_to:
        dest = os.path.expanduser(args.copy_evidence_to)
        os.makedirs(dest, exist_ok=True)
        for entry in os.listdir(ev_dir):
            src = os.path.join(ev_dir, entry)
            dst = os.path.join(dest, entry)
            if os.path.isdir(src):
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
        print(f"  copied evidence to: {dest}")

    print(f"\nBundle ready: {run_dir}/")
    print(f"  ground_truth.json:  {gt_path}")
    print(f"  evidence/:          {ev_dir}")
    print(f"  evidence zip:       {evidence_zip}")
    print(f"  README.md:          {os.path.join(run_dir, 'README.md')}")
    if args.copy_evidence_to:
        print(f"  evidence copy:      {os.path.expanduser(args.copy_evidence_to)}")


if __name__ == "__main__":
    main()
