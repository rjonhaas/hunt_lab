> Updated teaching decision (November 1): WW-TRAIN-001 in [the shared report](training-report.md)
> is the core discovery + synthetic staging exercise. Students author abilities;
> Joe demonstrates authoring for hosted learners. Finished imports are fallback
> or post-workshop references. The earlier Atomic/RansomHub extraction below is
> a future packaging option, not the current exercise specification. Follow
> [the instructor guide](ctf-instructor.md) for the two shared flag contracts.

# Report-linked Caldera scenarios — implementation draft

Status: historical generic packaging proposal from October 25. The narrower
WW-TRAIN-001 reference builder/importer and evidence verifier are now implemented
and rehearsed on hosted ww-win11; see [results](scenario/rehearsal.md). Generic ZIP
validation, public release, and local-machine rehearsal remain pending.

## Experience and ownership

Read a Threat Reports training report, download its versioned scenario, validate
and import it into War Wagon, select the documented lab targets in Caldera, run
an operation, then hunt its evidence in Kibana. Importing must not start an
operation. In the hosted workshop, only the instructor imports, executes and
resets; participants use individual read-only Elastic accounts.

Author reports and scenario sources in hunt-ops. Publish the reviewed artifacts
to threat-reports, the public feed. Keep the reusable importer and compatibility
checks in hunt_lab. The local hunt-ops README describes this publication split;
a threat-reports checkout was not present at /Users/jon/git/threat-reports during
planning, so its exact publication structure still needs inspection.

## Proposed report package

```text
reports/<date>_war-wagon-discovery/
  report.md
  queries/elastic.kql
  mappings/                 # Existing report workflow
  stix/                     # Existing report workflow
  caldera/
    manifest.json
    adversary.yml
    abilities/
      discovery.yml
    README.md
    hunt-guide.md
```

Release a ZIP of the caldera directory alongside a SHA-256 checksum and link it
from the report. Preserve the unpacked source for review. These are proposed
paths, not existing artifacts.

Manifest fields: schema version, scenario ID/version, source report reference,
package file list and hashes, tested hunt_lab commit and Caldera version,
required plugins, required Atomic Red Team revision/tests, target OS/host role,
privileges, expected event sources, parameters, cleanup and known limitations.
Use stable unique IDs for abilities and profiles; never reuse an existing
scenario's IDs for different behavior. An adversary profile references abilities;
a profile alone is insufficient when its dependencies are absent.

## First scenario: discovery

Extract only the existing rh-01-recon-domain behavior from
scripts/caldera_ransomhub_setup.py, under package-owned IDs. It invokes Atomic
Red Team tests T1033, T1087.001, T1087.002, T1482 and T1016 (test 1 for each).
Document the actual tested Atomic revision, module path and required rights.
Do not import or execute the rest of the RansomHub-inspired chain.

Use the rehearsed DC target initially. Establish fresh expected evidence for
each action; do not claim all tests produced telemetry merely because the
Caldera link succeeded. Clearly label the report as a training simulation and
state which behaviors it represents and omits.

The hunt guide supplies hypotheses, host/time scoping, required log sources,
progressive hints and query starters. Preserve a completed evidence window for
an offline/replay fallback. Keep the instructor answer key outside the public
feed. The second package (dummy-file staging and correlation) follows only
after the discovery package passes its acceptance checks.

## Changes by repository

### hunt-ops

- Add a scenario section to the report template: behavior simulated, package
  link/version, prerequisites, expected telemetry, cleanup and limitations.
- Author the discovery report and caldera directory using that template.
- Add a packaging/validation tool checking schema, hashes, unique IDs and every
  referenced ability/dependency before producing the release ZIP/checksum.
- Extend publication instructions to include scenario source and release assets.

### threat-reports

- Publish the reviewed discovery report, scenario source and versioned package.
- Add a scenario-download column/link to its report index after inspecting the
  actual public repository structure.
- Document the read → import → run → hunt workflow and distinguish verified
  scenarios from reports that have no runnable scenario.

### hunt_lab

- Add a generic scenario importer, with offline validation/dry-run as the first
  step and explicit import as a separate step. Exact CLI is to be implemented.
- Accept a local package; validate archive paths, manifest, dependency references
  and checksums without executing package scripts during validation/import.
- Read the Caldera URL/key from local configuration; do not put secrets into
  packages, logs or Git. Use the supported API for the installed version.
- Import abilities before the profile. Detect existing IDs; unchanged entries
  are a no-op, differing definitions require an explicit update choice.
- Re-read imported objects to verify references. Report partial imports clearly
  and track newly created objects for recovery without deleting pre-existing ones.
- Leave operation creation, target selection and execution to the operator.
- Add participant documentation for home use and instructor-only hosted use.

## CTF flags

Publish simulation mechanics and query starters, not the conference answer.
Supply a run-specific marker privately at execution time and verify that it
appears in the intended telemetry. Exclude real markers from source, example
output, screenshots and public sample datasets. Use a separate practice marker
for public reproductions. Runtime parameter plumbing remains to be implemented.
Record the conference run ID, UTC window and answer privately for grading;
reruns must not silently invalidate the graded evidence window.

## Acceptance checks before publication

1. Validate a complete package offline; reject missing abilities, unsupported
   schemas, hash mismatches and unsafe archive paths.
2. Import into a clean instance of the recorded Caldera version; verify the
   profile and all abilities, and confirm no operation was created or started.
3. Import again without duplicates; test conflicting IDs and an interrupted
   import with clear recovery instructions.
4. Execute discovery against the selected lab agent. Check each command result
   and corresponding Sysmon events in Kibana, including hostname/time fields.
5. Complete the hunt using a learner account; confirm search works while data
   mutation, shared-object changes and administration are denied.
6. Verify the runtime marker/flag, evidence retention and cleanup; repeat from
   the documented starting state.
7. Test the same package against the hosted deployment before calling that path
   supported. Record actual results, versions, limitations and checksums.

Next implementation unit: discovery report + package schema and validator,
then importer, then a recorded lab rehearsal. No public release until those
artifacts have been verified.
