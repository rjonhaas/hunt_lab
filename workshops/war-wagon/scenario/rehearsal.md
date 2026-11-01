# WW-TRAIN-001 rehearsal — November 1, 2026

## Verified hosted result

Target: `ww-win11`, Windows 11 in the War Wagon Proxmox pool.
Elastic Agent/Stack: 8.19.14. Caldera image: `hunt-lab/caldera:local`,
image SHA-256 `3f8d5a2c4b3fb32e71cca2234ef7f0227e0415f372db18847f4a6682b7069c6f`.
The image lacks Git metadata; do not infer a release tag from this test.

Operation: `8cc2b4d8-a886-40b3-b647-c2036920b158`.
Evidence window: **2026-11-01 13:56:41–13:57:45 UTC**.
Profile: `WW-TRAIN-001 rehearsal-20261101-02`.

| Check | Result |
|---|---|
| Ability/profile import and read-back | Passed |
| Single-target scope | Only ww-win11; separate rehearsal group |
| Four abilities in atomic order | All finished with status 0 |
| Discovery marker in endpoint command line | Sysmon event 1, verified |
| Staged filename in endpoint telemetry | Sysmon event 11, verified |
| File event linked to creator | Matching `process.entity_id` in events 11 and 1 |
| Agent group/beacon restoration | Restored war-wagon and 30–60 seconds |
| Flags in repository source | None; private configuration outside Git |

The second run temporarily used a 5–10 second beacon interval. The first run
used 30–60 seconds and took several minutes. Allow for normal beacon latency.
No other Windows target was tasked. Synthetic staged files remain for inspection;
cleanup is intentionally manual after evidence capture.

## Logging gap found and corrected

The first operation completed all abilities, but the deployed SwiftOnSecurity
configuration did not include ordinary text-file creation under the exercise
root. The discovery check passed; the staging evidence check correctly failed.

Applied `enable-file-telemetry.ps1` to ww-win11: timestamped XML backup, preserved
existing rules, added FileCreate inclusion only for `C:\WarWagonTraining\`.
Sysmon accepted the configuration. Reran all four abilities with a fresh run
label and unchanged flag values; both evidence checks then passed.

This prerequisite must also be applied on the selected local student target.
It is a useful teaching example: successful execution does not guarantee logging.

## Joe's Kibana starting points

Use the absolute evidence window above and the `logs-*` data view. These filters
refer to fields observed in the verified event documents:

```text
host.name : "ww-win11" and data_stream.dataset : "windows.sysmon_operational" and event.code : "1"
```

Inspect `process.name`, `process.command_line`, `process.parent.name`,
`process.entity_id`, `process.parent.entity_id`, `user.name`, and `@timestamp`.
The discovery wrapper exposes its marker in a child cmd.exe command line even
when the outer PowerShell invocation is encoded.

```text
host.name : "ww-win11" and data_stream.dataset : "windows.sysmon_operational" and event.code : "11"
```

Inspect `file.path` and `process.entity_id`. Filter by the file event's entity ID
to find its creating process event. Do not use only PID or nearby time as proof.
The programmatic verifier passed against Elasticsearch; these KQL starting
points still need a learner-account UI walkthrough before release.

## Private artifacts and remaining gates

The private record contains both marker values, the exact package, operation
record, verifier results, and four retrieved endpoint documents. It is not a
public student download. Do not publish generated files or marked screenshots.

Still required before declaring the whole workshop release-ready:

- Repeat on a fresh local VMware/Vagrant student lab.
- Test Kibana access and both challenges with a restricted participant account.
- Have Joe rehearse authoring from the report, with hints hidden initially.
- Distribute private configuration to local participants and enter the same
  static flags in CTFd; evidence worksheets are reviewed separately.
- Test cleanup/recovery and any offline evidence bundle/tooling.

Source checks: four package validation/collision tests pass; Python modules
compile; Git diff whitespace checks pass. These are separate from live evidence
validation and do not substitute for the remaining gates above.
