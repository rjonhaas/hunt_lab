# War Wagon — RansomHub lab worksheet

Use this worksheet for the **DFIR-RansomHub-2025-Lab** walkthrough. This is a lab emulation, not a record of a real intrusion. The earlier [Discovery Before Collection report](training-report.md) and [four-action participant guide](participant-guide.md) describe a separate introductory exercise.

**Goal:** follow an attack from endpoint activity into a local cloud sandbox, recover the exercise flag from Kibana, and explain what the evidence actually proves.

## 1. Join the lab and record your scope

**Hosted:** use the instructor-provided Kibana URL and learner account. The instructor runs Caldera; you do not need to install VMs or access Caldera.

**Local:** complete [local setup](../../docs/local-setup.md), then read the generated `lab-info.md` in your checkout for URLs and logins. Use the instructor-selected operation and targets. Do not start another operation just to populate this worksheet.

| Record | Your answer |
|---|---|
| Name / team | |
| Hosted or local | |
| Kibana URL / data view | |
| Operation name and ID, supplied by instructor | |
| Actual target host(s) | |
| Operation start / end in UTC | |
| Kibana displayed timezone | |

The lab includes a domain controller, a Windows server, a Windows 11 workstation, and a Docker host. Caldera/Sandcat runs the selected actions. Atomic Red Team supplies some behavior tests. Sysmon and Elastic Agent provide endpoint telemetry. LocalStack supplies local AWS-style services; Kibana is where you investigate.

**Before hunting:** predict one process event, one file event, and one cloud API event you expect to see. What observation would support each prediction?

Your predictions:

## 2. Set up Discover

1. Open **Discover → War Wagon logs** (or the instructor-assigned data view).
2. Use **KQL**, not ES|QL.
3. Select an **absolute time window** covering the operation, with a few extra minutes for ingestion. Confirm the timezone; do not copy timestamps from an old screenshot.
4. Add `@timestamp`, `host.name`, `event.code`, `process.name`, and `process.command_line` as columns. Sort time ascending.
5. Add `file.path`, `process.entity_id`, and `process.parent.entity_id` as needed.

Start with this endpoint timeline. Narrow the host list to the actual targets:

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : ("1" or "3" or "10" or "11" or "22")
```

Caldera group names such as `de&th` and `red` are not Kibana hostnames. The Caldera operation ID is not automatically attached to Sysmon events.

### Sysmon event reference

| Event code | Meaning | What it helps you investigate |
|---|---|---|
| **1** | Process Create | Program, command line, account, and parent process. |
| **3** | Network Connect | A connection and the process responsible. Not every failed probe is recorded. |
| **10** | Process Access | One process opening another; LSASS access alone does not establish a successful dump. |
| **11** | File Create | A file created or overwritten. It does not contain file contents or provide a general rename history. |
| **22** | DNS Query | A process querying a name. A lookup does not prove a download succeeded. |

These numbers apply to the Sysmon dataset. **Security event 1102** means the Security audit log was cleared; it is not a Sysmon event. Available events depend on collection rules.

## 3. Follow the operation

For each checkpoint, record an observation or a documented gap. A launched command is evidence of an attempt; it is not automatically evidence of success. Dwell steps are intentional pauses between phases.

| Checkpoint | What to look for | Your evidence / result |
|---|---|---|
| Domain and user discovery | `whoami`, `net`, `nltest`, `ipconfig`; event 1 | |
| Network sweep | Connections to multiple lab addresses and ports; event 3 | |
| Credential access attempts | ProcDump / LSASS activity; `reg.exe save`; events 1, 10 and output files if collected | |
| Finance share discovery | `win-server`, Finance share, mapped drive and directory listing; event 1 | |
| Symlink settings | `fsutil.exe` with `SymlinkEvaluation`; distinguish query from set | |
| Tool download and staging | rclone download/extraction, `nocmd.vbs`, `rcl.bat`; events 1, 11, 22 | |
| Copy to the cloud sandbox | rclone process, connection to LocalStack, S3 API result | |
| Shadow-copy deletion attempt | `vssadmin.exe delete shadows`; event 1 | |
| Simulated impact | `fake_amd64.ps1`, ransom-note artifacts; inspect operation output | |
| Log-clearing attempt | Atomic wrapper, possible `wevtutil.exe`; Security 1102 only if collected | |
| Cloud discovery / persistence | AWS CLI commands and LocalStack API outcomes | |

**Rehearsal limitations:** the full chain has not been verified end to end. Installed Atomic test versions matter: the LSASS step was labeled comsvcs but invoked ProcDump; one local-account test was Linux-only; the log-clearing Atomic was missing on the checked Windows 11 host. The rename simulator needs Finance decoys on its selected host, normally `win-server`. Missing results are something to investigate, not fill in from the ability name. The rename simulator does not encrypt files; the separate shadow-copy step makes an actual deletion attempt inside the lab.

### Hunt A — discovery and credential-access attempts

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
process.name : ("whoami.exe" or "net.exe" or "net1.exe" or "nltest.exe" or "ipconfig.exe" or "procdump.exe" or "procdump64.exe" or "reg.exe")
```

- Which account and host ran the commands?
- Which arguments reveal the purpose of each command?
- Can you distinguish the Atomic wrapper from the child process that performed the action?
- What additional evidence would establish that a credential dump succeeded?

Your findings:

### Hunt B — staged tools and the endpoint flag

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "11" and
file.path.text : "WarWagonTraining ransomhub"
```

Read the original **`file.path`** value. Find the exercise marker in the filename and submit it in **`{flag}` format, including the braces and excluding `.txt`**. The flag is intentionally placed in endpoint telemetry; it does not require reading an S3 object or finding file contents in Sysmon.

The `.text` subfields used here and below are mapped on the workshop lab. They perform analyzed searches; inspect the original field for exact spelling and punctuation. If your local mapping differs, start with the host/dataset/event-code filters and inspect the available fields.

| Evidence to capture | Your answer |
|---|---|
| Flag — submit privately | |
| Full file path | |
| Host and UTC timestamp | |
| Sysmon event code / Elasticsearch document `_id` | |
| Creating process entity ID | |
| Matching process command line | |

To pivot, replace the placeholder with the actual entity ID and retain your host and time scope:

```kql
process.entity_id : "PASTE_ENTITY_ID" or
process.parent.entity_id : "PASTE_ENTITY_ID"
```

This finds that process's events and its direct children, not a recursive tree. A PID can be reused; use process entity IDs for correlation.

### Hunt C — follow rclone to LocalStack

First find the endpoint processes:

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
(process.name : "rclone.exe" or
 process.command_line.text : ("nocmd.vbs" or "rcl.bat"))
```

Then look for connections to the lab endpoint. Replace the address if your lab uses a different subnet:

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "3" and
destination.ip : "192.168.56.10" and destination.port : 4566
```

**Switch to cloud evidence:** remove pinned Windows host and Sysmon filters. Keep the operation time window. Add `event.action`, `event.outcome`, `eventSource`, and `labels.simulated` as columns.

```kql
data_stream.dataset : "aws.cloudtrail" and
eventSource : "s3.amazonaws.com" and
event.action : ("PutObject" or "CreateMultipartUpload" or "UploadPart" or "CompleteMultipartUpload")
```

These are **simulated CloudTrail-shaped records derived from LocalStack request logs**, not native AWS CloudTrail. They record API operation/status, but do not identify the source host, object name, caller identity, or file contents. A nearby successful API event supports upload activity; time proximity alone does not prove which endpoint file was uploaded.

- Record the endpoint process, destination and UTC time:
- Record the cloud API action, outcome, UTC time and document ID:
- Which process relationships can you establish?
- What would you need from rclone output or the bucket to confirm the particular file arrived?

### Hunt D — cloud discovery and persistence attempts

```kql
data_stream.dataset : "aws.cloudtrail" and
event.action : ("GetCallerIdentity" or "ListUsers" or "ListBuckets" or "CreateAccessKey")
```

Check `event.outcome`, including failures. Correlate with endpoint `aws.exe` command lines in the same window. The cloud records do not contain the generated access key or its owner; access keys are not the exercise flag.

Your observed actions, outcomes and supporting event references:

## 4. Build an evidence-backed timeline

Use UTC. Separate the observation from your interpretation. Record `_id` from the expanded document where available; `event.code` is an event type, not a unique event identifier.

| UTC time | Host / source | Event code or API action | Command / path / result | Document ID | What this proves |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

## 5. If a query returns no results

Check the time window and timezone → remove unrelated pinned filters → confirm the indexed hostname → broaden to the endpoint timeline or `data_stream.dataset : "aws.cloudtrail"` → ask the instructor to compare the Caldera link status/output → confirm that the required event or Atomic test is available.

Do not treat missing telemetry as proof that an action did not happen. Do not rerun the whole operation without instructor direction.

Missing evidence and what you checked:

## 6. Turn the hunt into a defensive improvement

1. Summarize what happened in three sentences, citing your strongest evidence.
2. Propose a behavior-based detection that does not depend on the artificial flag or lab hostname.
3. Name a legitimate activity that could match and the context needed to distinguish it.
4. Identify one logging gap and how you would test that the fix works.
5. Explain one conclusion you cannot support with the available evidence.

Your response:

Preserve your evidence and submit the flag through the instructor's chosen channel. Leave cleanup and shared-lab resets to the instructor.
