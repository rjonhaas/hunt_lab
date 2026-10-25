# War Wagon — participant guide

## Before starting

Use your own completed lab or the instance assigned by the facilitator. The
shared instance details will be supplied before the workshop. Do not run setup
scripts on a shared instance. The lab's `lab.local` domain is separate from the
conference's `deathlab.net` environment.

Local setup allocates 22 GB of guest RAM across four VMs; allow room for the host.
The repository recommends a 32 GB host and 250 GB disk. Tracecat needs additional
resources. Apple Silicon local deployment is not validated by this workshop;
use a shared instance unless you have independently tested an alternative.

Build before the session using [the repository setup guide](../../README.md).
Allow hours for downloads and provisioning, rather than relying on the shorter
quick-start estimate. On Windows, run the existing health check from the repo:

```powershell
.\scripts\validate_lab.ps1
```

That check is an initial diagnostic, not proof that every scenario or detection
works. In Kibana confirm events for all three Windows hosts and a current time
window. Ask the facilitator for the completed run's UTC window and target host.

## 1. Form a hypothesis

Brief: an operator used native discovery tools, staged a file-copy utility, and
copied Finance-share documents to a destination represented by local S3 storage.
Some later behaviors simulate ransomware impact. The lab does not reproduce
the original intrusion's initial access or every stage of the source report.

Write your hypothesis in [the worksheet](hunt-worksheet.md) before opening the
prebuilt detection rules. Example: “A script-launched file-copy utility accessed
the Finance share and attempted a transfer to the lab S3 endpoint.”

Name the evidence that would support it and one legitimate activity that could
produce similar events. Distinguish a launched command from a successful copy.

## 2. Establish the evidence window

Open Kibana → Discover, select a `logs-*` data view, and set the absolute UTC
window supplied by the facilitator. Confirm the displayed timezone. Add columns
`@timestamp`, `host.name`, `event.dataset`, `event.code`, `process.name`,
`process.command_line`, and `process.parent.name` where available.

Start with:

```text
event.dataset : "windows.sysmon_operational" and event.code : "1"
```

Apply a host filter using the actual value in your events. Do not assume that
the short Vagrant name and the indexed hostname are identical. Save the query,
time window, and a document identifier for every finding. If ECS fields are
missing, inspect the event JSON and record its raw `winlog.event_data` fields.

## 3. Reconstruct the transfer

Find the file-copy process:

```text
event.dataset : "windows.sysmon_operational" and event.code : "1" and process.name : "rclone.exe"
```

Identify its command, parent, source path, destination endpoint, and bucket or
prefix. Pivot to nearby script and shell processes:

```text
event.dataset : "windows.sysmon_operational" and event.code : "1" and process.name : ("wscript.exe" or "cmd.exe" or "rclone.exe")
```

Use process entity IDs or Sysmon ProcessGuid/ParentProcessGuid to establish
ancestry where present. A nearby timestamp on the same host is a lead, not proof
that one process launched another. Submit a timeline with at least three events.

Now examine the cloud-side activity:

```text
event.dataset : "aws.cloudtrail" and eventSource : "s3.amazonaws.com" and eventName : "PutObject"
```

These are **lab-generated CloudTrail-shaped records**, derived from LocalStack
request logs. The adapter preserves API operation and error status, but uses
placeholder identity and source-IP values, empty request parameters, and an
emission-time timestamp. Do not use those placeholders to attribute the user,
source host, destination bucket, or an exact cross-system sequence.

For successful-copy evidence, request the facilitator's S3 object listing and
rclone log for this run. Correlate those with the endpoint command. Explain the
limits of each source and label conclusions as observed, inferred, or unknown.

## 4. Build and tune a detection

Start from the rclone process query above. Add context supported by actual data:
script/shell parent, unusual executable location, source share, or destination.
Explain what your added condition removes and what it could miss. Record the
match count before and after. Test a known legitimate file-transfer example if
the facilitator has supplied one; without a benign dataset, label false-positive
performance **untested**, not “zero false positives.”

Compare your result with the prebuilt `RansomHub: wscript → cmd → rclone exfil
chain` rule. Does it prove ancestry, or just sequence events on a host? What
happens if an administrator launches another transfer during the same window?

On a shared instance, submit your query to the facilitator rather than editing
the shared rule. On your own lab, create a separate disabled rule named with
your initials, preview it against the run, and record the preview result. Old
events outside a rule's lookback do not generate a fresh alert automatically.

## 5. Respond with evidence

For one finding, build a response record containing:

- Evidence IDs, UTC window, host, and detection condition.
- Parent/child process context and a finding confidence with justification.
- Transfer outcome: confirmed, attempted, failed, or unknown.
- Suggested next action and why it is justified.
- A check that would demonstrate the action worked.

The intended automated workflow is alert → collect context → create a response
record → analyst decision. The facilitator will demonstrate the verified
integration when available. Do not treat a running Tracecat UI as proof that a
workflow or alert connector is working. If the integration is unavailable,
complete this record manually; that is a fallback exercise, not an automation
success claim.

## 6. Finish

Submit your worksheet and attempt the two War Wagon CTF challenges supplied by
the facilitator. Keep the query, its limitations, and the evidence references
with your report. For an extension, repeat the method with the identity-chain
scenario after reading its host-targeting requirements.
