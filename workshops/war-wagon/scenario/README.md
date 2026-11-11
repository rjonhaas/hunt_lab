# Workshop scenario — reference implementation

[Participant guide](../participant-guide.md) · [Instructor configuration](../instructor/README.md)

Setup automatically calls `preload.py` to generate and import four abilities and
one adversary profile. It verifies objects after import, reuses identical objects,
resumes partial imports and refuses conflicting objects. It never starts an operation.

Configuration comes from `.war-wagon/config.json` at the repo root when present;
otherwise it uses `practice.json`. Public practice markers are not conference flags.
All markers use `{flag}` format, including the literal braces. After changing
flags on an existing lab, use a fresh `run_label`, preload the new profile and
run that profile to generate new evidence; existing events do not change.

## Required target preparation

New Vagrant builds apply `enable-file-telemetry.ps1` automatically on all Windows
hosts before guest validation. It preserves existing Sysmon rules and adds a
FileCreate include for `C:\WarWagonTraining\`.

For an existing Windows lab target, run elevated:

```powershell
& C:\vagrant\workshops\war-wagon\scenario\enable-file-telemetry.ps1
```

If your Sysmon configuration is elsewhere, supply `-ConfigPath`. Reapply after
replacing the Sysmon configuration. Verify actual indexed file events afterward.

## Build a package for inspection

This is an optional reference, not an attendee setup step. From this directory
with Python 3.9+:

```sh
python3 build.py --config practice.json --out ~/war-wagon-private/practice-01.json
```

The output includes commands and markers. Keep generated packages outside Git.
The optional `--import` switch requires `CALDERA_URL` and `CALDERA_API_KEY` and
refuses existing IDs. Automatic setup uses the resumable `preload.py` path instead.
Neither command creates an operation.

## Verify evidence

Set `ELASTICSEARCH_URL`, `ELASTIC_USER` and `ELASTIC_PASSWORD` privately. Use the
same configuration, actual indexed hostname and UTC operation window:

```sh
python3 verify.py --config /path/to/private/config.json \
  --host YOUR_INDEXED_HOST --start 2026-11-11T13:00:00Z --end 2026-11-11T14:00:00Z
```

Replace the example dates. The verifier requires the discovery marker in a
Sysmon process event and the exact staged path in a file event, correlated to a
process event by `process.entity_id`. It reports event references without flags.
Exit 0 means those evidence checks passed; exit 1 means evidence is missing.
A pass does not grade the participant's explanation or verify learner permissions.

See [the earlier hosted rehearsal](rehearsal.md) for the logging gap that led to
the required Sysmon rule. The focused build still requires its own rehearsal.
