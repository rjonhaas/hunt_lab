# RansomHub instructor KQL run sheet

For **DFIR-RansomHub-2025-Lab** on the `workshop/war-wagon` branch.
Matches the 16-entry adversary order: 13 actions and 3 dwell steps.
Prepared from the current ability commands and Zeus field mappings on November 11, 2026.

## Before the demonstration

1. Open **Discover → War Wagon logs** and select **KQL**, not ES|QL.
2. Set an **absolute time window** from the actual operation start through its end, with a small ingestion margin. Do not reuse the earlier four-action exercise's timestamps.
3. Sort `@timestamp` ascending. Record the operation ID separately; Caldera's operation ID is not automatically attached to Sysmon events.
4. The endpoint queries include all three lab hosts. Narrow the host list to the actual operation targets. `red` and `de&th` are Caldera groups, not Kibana host fields.
5. For cloud queries, remove any pinned Windows host or Sysmon filter. The cloud shipper is not win11-victim.

**Endpoint columns:** `@timestamp`, `host.name`, `event.code`, `process.name`, `process.command_line`, `process.entity_id`, `process.parent.entity_id`. Add `file.path` for file events and destination fields for connections.

**Cloud columns:** `@timestamp`, `event.action`, `event.outcome`, `eventSource`, `labels.simulated`.

These queries use `process.command_line.text` and `file.path.text`, verified as mapped text subfields on Zeus. Display the original `process.command_line` and `file.path` values. Text searches are analyzed; they identify candidates, not exact byte matches. No leading-wildcard setting change is required. [Elastic KQL reference](https://www.elastic.co/guide/en/kibana/8.19/kuery-query.html).

### Known gaps before recording

- `rh-03` is labeled comsvcs but currently invokes installed ART test 1, **ProcDump**.
- `rh-01` includes a Linux-only local-account test on this installation.
- `rh-12` references an Atomic YAML file absent on Zeus win11-victim.
- `rh-11` needs the Finance decoys on the selected host; the default local path is normally present on win-server, not Win11.
- The full RansomHub chain has not been validated end to end. The flag FileCreate and a separate LocalStack PutObject were verified in Elasticsearch. Empty results may mean a skipped/failed test, an unsuitable target, filtering, or missing telemetry.

## Sysmon event IDs — presenter quick reference

| Event ID | Name | What to say | Use in this operation |
|---|---|---|---|
| **1** | Process Create | “Sysmon event 1 tells us a process started, including its command line and parent.” | Discovery commands, tool execution and the flag-bearing PowerShell command. |
| **3** | Network Connect | “Sysmon event 3 links a network connection to the process that made it.” | Network sweep and connections to LocalStack on port 4566. |
| **10** | Process Access | “Sysmon event 10 shows one process opening another process.” | Investigate access to LSASS; access alone does not prove credentials were dumped. |
| **11** | File Create | “Sysmon event 11 records a file being created or overwritten.” | Flag file, staged tools and ransom notes. It does not include file contents or provide a general rename history. |
| **22** | DNS Query | “Sysmon event 22 records a process making a DNS query.” | Lookups for downloads.rclone.org. A lookup does not prove a download completed. |

In these queries, `event.code` is the event ID. Keep the Sysmon dataset filter so the number is interpreted in the right log source. Event collection depends on the active Sysmon rules. [Microsoft Sysmon event reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

**Separate log source:** Event **1102** means the Windows Security audit log was cleared; it is a **Security log event, not a Sysmon event**. The query later in this sheet uses `winlog.channel : "Security"`.

## Opening view — endpoint timeline

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : ("1" or "3" or "10" or "11" or "22")
```

## Walkthrough in operation order

### 01. Domain and user discovery — `rh-01-recon-domain`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
(process.name : ("whoami.exe" or "net.exe" or "net1.exe" or "nltest.exe" or "ipconfig.exe") or
 process.command_line.text : ("T1033" or "T1087.001" or "T1087.002" or "T1482" or "T1016"))
```

Inspect the native child processes and arguments. The Invoke-AtomicTest command establishes an attempt, not success. Installed T1087.001 test 1 is a Linux /etc/passwd test and may be skipped on Windows. T1087.002 test 1 runs net user /domain and net group /domain.

### 02. Network sweep — `rh-02-recon-network`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "3" and
destination.ip : "192.168.56.0/24" and
destination.port : (135 or 139 or 445 or 3389 or 5985)
```

Add destination.ip, destination.port, process.name and process.entity_id. Look for one process reaching many addresses/ports. This is not unique to the operation. Sysmon Event 3 is not a record of every ICMP probe or every unsuccessful TCP attempt.

### 03. Pause after reconnaissance — `rh-dwell-1-foothold`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
process.command_line.text : "Start-Sleep -Seconds 30" and
process.command_line.text : "dwell"
```

Default pause: 30 seconds. This is the command that asks for the pause; correlate the adjacent operation timestamps.

### 04. LSASS access / dump attempt — `rh-03-creds-lsass`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
(process.name : ("procdump.exe" or "procdump64.exe" or "rundll32.exe") or
 process.command_line.text : "T1003.001")
```

The profile label says comsvcs.dll, but the installed T1003.001 test 1 on Zeus is ProcDump. Inspect the actual command. A process launch alone does not prove that an LSASS dump succeeded.

### 05. Registry hive dump attempt — `rh-04-creds-sam`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
((process.name : "reg.exe" and process.command_line.text : "save") or
 process.command_line.text : "T1003.002")
```

Inspect HKLM\sam, HKLM\system and HKLM\security destinations. The installed test writes to %TEMP%; look for output-file evidence if collected. Do not infer success from the Invoke-AtomicTest wrapper.

### 06. Pause after credential access — `rh-dwell-2-creds`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
process.command_line.text : "Start-Sleep -Seconds 60" and
process.command_line.text : "dwell"
```

Default pause: 60 seconds. Change the number if RH_DWELL_CREDS was customized.

### 07. Finance share discovery — `rh-05-disc-fileshare`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
(process.command_line.text : "win-server" or
 process.command_line.text : "share-loot.txt")
```

Look for net view, net use Z:, the Finance share, and the PowerShell listing. Z: is mapped and then removed. Listing commands do not prove files were readable; inspect the Caldera output as well.

### 08. Symlink evaluation changes — `rh-06-evasion-symlink`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
process.name : "fsutil.exe" and
process.command_line.text : "SymlinkEvaluation"
```

Compare set versus query. The commands request R2L:1 and R2R:1; a query event alone is not a configuration change.

### 09. Download and stage rclone — `rh-07-tool-rclone-dl`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
(process.command_line.text : "downloads.rclone.org" or
 process.command_line.text : "rclone-extract")
```

Look for curl.exe, the ZIP and PowerShell extraction. If rclone already exists, this ability exits without downloading again; DNS/download evidence may therefore be absent.

### 10. Stage wrappers and the CTF flag — `rh-08-tool-stage-artifacts`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
(process.command_line.text : "nocmd.vbs" or
 process.command_line.text : "rcl.bat" or
 process.command_line.text : "RH_CLOUD_STAGING")
```

Look for Copy-Item of nocmd.vbs, rcl.bat, include.txt and ransom_note.txt. The flag is deliberately instrumented training evidence. Use the file query below to recover its literal braces.

### 11. Copy Finance data to the S3 sandbox — `rh-09-exfil-rclone`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
(process.name : "rclone.exe" or
 process.command_line.text : "nocmd.vbs" or
 process.command_line.text : "rcl.bat")
```

Reconstruct wscript.exe → cmd.exe → rclone.exe with process.entity_id and process.parent.entity_id. The actual copy command includes the source share and LocalStack endpoint. The wrapper sleeps 30 seconds and reads a log; it does not itself verify all files arrived.

### 12. Pause before simulated impact — `rh-dwell-3-pre-impact`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
process.command_line.text : "Start-Sleep -Seconds 120" and
process.command_line.text : "dwell"
```

Default pause: 120 seconds. Change the number if RH_DWELL_IMPACT was customized.

### 13. Delete shadow-copy attempt — `rh-10-impact-vss`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
((process.name : "vssadmin.exe" and process.command_line.text : "delete shadows") or
 process.command_line.text : "T1490")
```

The installed test requests vssadmin.exe delete shadows /all /quiet. This is an actual deletion attempt, not the benign rename simulator. A command line does not establish that snapshots existed or were deleted.

### 14. Benign rename-and-note simulation — `rh-11-impact-encrypt`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
process.command_line.text : "fake_amd64.ps1"
```

The simulator defaults to local C:\Shares\Finance, normally on win-server. On win11-victim without that directory it exits 2 with no-target. There is no real encryption. Sysmon Event 11 is not a general file-rename audit; inspect note creation and Caldera output to corroborate impact.

### 15. Log-clearing attempt — `rh-12-evasion-clearlogs`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
(process.name : "wevtutil.exe" or
 process.command_line.text : "T1070.001")
```

On Zeus win11-victim, T1070.001.yaml was absent during this run-sheet check. The wrapper may appear without any wevtutil child or log-clearing event. Verify the installed test before presenting this step as successful.

### 16. Cloud discovery and access-key creation — `rh-13-cloud-persist`

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "1" and
process.name : "aws.exe" and
process.command_line.text : ("get-caller-identity" or "list-users" or "list-buckets" or "create-access-key")
```

Look for AWS CLI children, then compare cloud events. The target IAM user is analyst-readonly. Repeated runs may reach the access-key limit; inspect event.outcome rather than assuming success.

## Supporting queries and pivots

### LSASS process access, when Event ID 10 is collected

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "10" and
winlog.event_data.TargetImage : "C:\\Windows\\System32\\lsass.exe"
```

Inspect `winlog.event_data.SourceImage`, `TargetImage` and `GrantedAccess`. Use the exact path/case shown in your indexed event if it differs. Event 10 coverage depends on the active Sysmon configuration.

### rclone DNS lookup

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "22" and dns.question.name : "downloads.rclone.org"
```

### Recover the endpoint flag — instructor answer

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "11" and file.path.text : "RH_CLOUD_STAGING"
```

Read the full `file.path`. Expected value:

```text
C:\WarWagonTraining\ransomhub\{RH_CLOUD_STAGING}.txt
```

Submit **`{RH_CLOUD_STAGING}`**, including braces and excluding `.txt`.
For a learner-friendly hunt that does not give away the answer, use:

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "11" and file.path.text : "WarWagonTraining ransomhub"
```

Verified rehearsal event: `2026-11-12T01:16:15.630Z` (November 11, 8:16:15 PM Eastern), win11-victim. This was a separate staging validation, not a complete RansomHub operation. Use the new operation window for the demonstration.

### Network connection to LocalStack

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "3" and
destination.ip : "192.168.56.10" and destination.port : 4566
```

A connection does not prove upload success. Correlate the process and cloud operation.

### LocalStack S3 upload events

```kql
data_stream.dataset : "aws.cloudtrail" and
eventSource : "s3.amazonaws.com" and
event.action : ("PutObject" or "CreateMultipartUpload" or "UploadPart" or "CompleteMultipartUpload")
```

Add `and event.outcome : "success"` to restrict to successful API calls.
The adapter reports API operation/status, not object names, caller identity, source IP or request parameters. These records are labeled simulations, not native AWS CloudTrail. A PutObject in the same window supports upload activity but cannot identify the source host or specific file by itself. Inspect the bucket/rclone output for that proof.

### Simulator output files, when file creation is collected

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
data_stream.dataset : "windows.sysmon_operational" and
event.code : "11" and
file.path.text : ("README_RANSOMHUB.txt" or "amd64-ran.flag")
```

The marker can also be written on a failed/no-target run. Its filename alone does not prove files were renamed. File content is not included in ordinary Sysmon FileCreate events.

### Security log cleared — only if that channel is ingested

```kql
host.name : ("win11-victim" or "win-server" or "win-dc") and
winlog.channel : "Security" and event.code : "1102"
```

Do not keep a Sysmon dataset filter on this query. No result does not establish that logs were not cleared: this branch may not collect Security events, and the referenced Atomic is absent on the checked Win11 host.

### Cloud discovery and persistence

```kql
data_stream.dataset : "aws.cloudtrail" and
event.action : ("GetCallerIdentity" or "ListUsers" or "ListBuckets" or "CreateAccessKey")
```

Narrow to the persistence attempt:

```kql
data_stream.dataset : "aws.cloudtrail" and
eventSource : "iam.amazonaws.com" and event.action : "CreateAccessKey"
```

Check `event.outcome`. These events do not contain the created key or its owning user; use endpoint arguments and the lab service state for those details. Access keys are not the CTF flag.

### Follow a process through multiple event types

Copy the exact entity ID from an event and replace the placeholder:

```kql
process.entity_id : "PASTE_ENTITY_ID" or
process.parent.entity_id : "PASTE_ENTITY_ID"
```

Keep the operation time window and target-host scope. This finds the process's events and direct children; it is not a recursive process-tree query. A PID alone is insufficient because Windows reuses PIDs.

## If a step returns nothing

Check time zone/window → remove unrelated pinned filters → confirm target host → inspect the Caldera link status/output → verify the Atomic test exists and supports Windows → check that the required event type is collected. Use the broad endpoint timeline to distinguish a too-specific query from missing telemetry.

Evidence checklist: host, UTC time, event/document ID, command or file path, process relationship, and what the event actually proves. Keep “command attempted,” “artifact created,” and “upload confirmed” separate.
