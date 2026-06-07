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

README_TEMPLATE = """# hunt_lab DFIR Benchmark — {scenario_name}

Generated from Caldera operation `{op_name}` ({run_id}).

## What this bundle is

A reproducible DFIR benchmark with **machine-readable ground truth**. A
known attack chain was executed against the hunt_lab Windows VMs, and a
KAPE-style triage collection was pulled from each affected host *after*
the attack completed.

You can use this two ways:

- **Analyst / Find Evil:** work only from `evidence/`. The triage tars
  contain Sysmon/Security/Application event logs, registry hives, prefetch,
  $MFT, etc. Run your usual DFIR workflow against them.
- **Tool author / scoring:** `ground_truth/ground_truth.json` is the
  per-event answer key. Score your tool's findings against it (technique,
  host, time window). Don't load it into the same environment your DFIR
  tool reads — that would invalidate the benchmark.

## Scenario

| Field | Value |
|---|---|
| Adversary | {adversary_name} |
| Adversary ID | {adversary_id} |
| Planner | {planner} |
| Started (UTC) | {started_utc} |
| Finished (UTC) | {finished_utc} |
| Hosts in scope | {hosts_list} |
| Total events | {events_count} |
| Unique techniques | {techniques_count} |

## Ground-truth manifest schema

`ground_truth.json` has these top-level keys:

- `schema_version` — currently `"1.0"`
- `run` — operation metadata (id, scenario, times, planner, state)
- `hosts` — array of host objects (hostname, IPs, agent context)
- `events` — chronologically ordered ability executions; one per Caldera
  link. Each event has: `seq`, `link_id`, `ts_decide_utc`, `ts_finish_utc`,
  `host`, `agent_paw`, `executor`, `ability` (id/name/tactic/technique),
  `command` (decoded plaintext), `success`, `status_code`, `output_preview`,
  `facts_discovered`, `relationships`.
- `techniques_summary` — per-technique aggregates
- `facts_summary` — fact graph stats

## How it was generated

1. `python3 scripts/extract_ground_truth.py <op_id>` → `ground_truth.json`
2. `python3 scripts/velo_collect.py --all-windows -o evidence/` → triage tars
3. This script (`make_benchmark_bundle.py`) ties them together

All three scripts are in [hunt_lab/scripts/](https://github.com/rjonhaas/hunt_lab/tree/main/scripts).

## Reproducing

```bash
git clone https://github.com/rjonhaas/hunt_lab.git
cd hunt_lab
bash docker/setup.sh
vagrant up win-dc win-server win11-victim --no-parallel
# Then in Caldera UI: Operations → New → Adversary: DFIR-RansomHub-2025-Lab → Group: red → Start
# When op finishes:
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

    # Step 3: write README
    hosts_list = ", ".join(sorted({h["hostname"] for h in manifest["hosts"] if h.get("hostname")}))
    readme = README_TEMPLATE.format(
        scenario_name=manifest["run"]["scenario"]["name"],
        op_name=manifest["run"]["operation_name"],
        run_id=args.op_id,
        adversary_name=manifest["run"]["scenario"]["name"],
        adversary_id=manifest["run"]["scenario"]["adversary_id"],
        planner=manifest["run"]["scenario"]["planner"],
        started_utc=manifest["run"]["started_utc"] or "—",
        finished_utc=manifest["run"]["finished_utc"] or "—",
        hosts_list=hosts_list,
        events_count=len(manifest["events"]),
        techniques_count=len(manifest["techniques_summary"]),
    )
    with open(os.path.join(run_dir, "README.md"), "w") as f:
        f.write(readme)

    # Step 4: zip the evidence portion (excludes ground_truth dir)
    evidence_zip = os.path.join(run_dir, f"evidence_{args.op_id}.zip")
    shutil.make_archive(evidence_zip[:-4], "zip", ev_dir)
    print(f"\nBundle ready: {run_dir}/")
    print(f"  ground_truth.json:  {gt_path}")
    print(f"  evidence/:          {ev_dir}")
    print(f"  evidence zip:       {evidence_zip}")
    print(f"  README.md:          {os.path.join(run_dir, 'README.md')}")


if __name__ == "__main__":
    main()
