# WW-TRAIN-001 reference builder

Instructor/fallback material: students first translate the report themselves.
This builder generates four abilities and one profile for Caldera's v2 API.
It has no operation-start endpoint. Import is an explicit option, not execution.

Hosted evidence validation passed; see [rehearsal results and remaining gates](rehearsal.md).

## Required target preparation

The default SwiftOnSecurity rules do not collect arbitrary `.txt` files in the
exercise directory. Before running the scenario, run the included
`enable-file-telemetry.ps1` elevated on the selected Windows lab target. On the
local Vagrant target, the repository is normally available under `C:\vagrant`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\vagrant\workshops\war-wagon\scenario\enable-file-telemetry.ps1
```

For hosted targets, Joe installs this preparation once. If your existing Sysmon
configuration is elsewhere, pass `-ConfigPath` with that path. The script backs
up the XML, preserves existing rules, adds a narrow FileCreate include for
`C:\WarWagonTraining\`, and applies it through Sysmon. It does not disable
Defender or broaden logging to every file. Reapply after any provisioner that
replaces the Sysmon configuration. Validate actual events after configuration.

## Practice

From this directory, with Python 3.9+:

```sh
python3 build.py --config practice.json --out ~/war-wagon-private/practice-01.json
```

Review the commands in the output. To import during a separate build, set
`CALDERA_URL` and `CALDERA_API_KEY` privately in your environment and add `--import`.
Use a new output filename. The API key must never be added to configuration JSON.
Existing IDs cause a refusal; partial imports are retained for operator inspection.
The command does not delete or overwrite existing Caldera objects.

In Caldera, choose the generated profile, an explicitly isolated target group,
and the atomic planner. Review scope and commands before starting.
With a 30–60 second agent beacon interval, allow several minutes for all four
steps; do not launch duplicates just because a link is still pending. Do not select
all agents. Record the operation ID, indexed hostname, and UTC evidence window.

## Conference configuration

Copy practice.json outside Git, replace both practice markers with the private
workshop flags, and choose a unique run_label for each execution. Both hosted and
local students use the same flag values but different run labels. Output contains
flags, is created with mode 0600, and must stay outside public source/artifacts.
A run directory must not already exist: staging refuses to overwrite old evidence.

The discovery marker is deliberately visible in a child cmd.exe command line,
even when Caldera encodes its outer PowerShell command. Staging creates its own
synthetic source and copies it into a `staging` child directory. It verifies the
copy by comparing hashes. Neither ability collects existing user documents.

For manual student authoring, show command structure with the practice markers;
let students select/create abilities and use their private configuration values.
The generator is a reference/fallback, not mandatory for the student exercise.

## Cleanup after evidence capture

Delete only `C:\WarWagonTraining\<your-run-label>` after verifying the exact path.
Do not delete the whole training root or Elastic evidence. There is no automatic
cleanup attached to the abilities. Rehearsal records must establish file-create
collection and correlation before the exercise is released.

Caldera terminology and operation controls:
https://caldera.readthedocs.io/en/stable/index.html

## Verify indexed evidence

Set `ELASTICSEARCH_URL`, `ELASTIC_USER`, and `ELASTIC_PASSWORD` privately. Use the
actual indexed hostname and absolute UTC start/end times from the operation:

```sh
python3 verify.py --config ~/war-wagon-private/workshop-config.json \
  --host YOUR_INDEXED_HOST --start 2026-11-01T13:00:00Z --end 2026-11-01T14:00:00Z
```

Replace the example dates with your run. The verifier requires a discovery
marker in a Sysmon process-creation command line and the exact staged path in a
file-creation event, correlated to a process-creation event by `process.entity_id`.
It reports event references without printing the flags. Exit 0 means both checks
passed; exit 1 means evidence is missing. It rejects incomplete or oversized
searches. These checks target the lab's Elastic Sysmon mapping; inspect and adapt
for a different integration. Run with a read-only search account when available.

A verifier success does not grade the student's explanation, prove a malicious
intrusion, or validate every behavior in an intelligence report.
