# War Wagon — from intelligence to evidence

## Goal

Read [Discovery Before Collection](training-report.md), translate its behaviors
into Caldera abilities, execute a controlled operation, and explain its evidence
in Kibana. Complete [the worksheet](hunt-worksheet.md) as you work.

## Choose your path

| Step | Hosted Proxmox | Local lab |
|---|---|---|
| Interpret report | Discuss behavior choices with Joe | Identify behaviors yourself |
| Build abilities | Joe demonstrates; explain your proposed commands | Create or adapt abilities yourself |
| Assemble profile | Follow Joe's ordering and reasoning | Build and review your own profile |
| Run operation | Joe executes once on the shared target | Execute on your own lab target |
| Hunt | Independently search shared Kibana data | Search your own Kibana data |
| Submit | Two flags plus evidence worksheet | Same flags plus your own evidence worksheet |

Local labs must be ready before class. Follow [repository setup](../../README.md)
and its VMware/Vagrant prerequisites. Hosted students do not run provisioning,
modify Caldera, reset VMs, or edit shared Elastic objects. The instructor supplies
access details and the indexed hostname; never assume local and hosted IPs match.

Before the live exercise, complete the [target telemetry preparation](scenario/README.md#required-target-preparation).
Joe handles this for hosted participants. This enables file-creation evidence for
the dedicated training directory while retaining the lab’s existing Sysmon rules.

## 1. Extract behaviors before choosing tools

For each of the report's four stages, write the intended outcome, a possible
Windows command, required privileges, side effects, expected logs, and cleanup.
Explain which details the report supports and which are your simulation choices.
Do not run a larger prebuilt attack chain just because it contains one useful step.

## 2. Translate into Caldera abilities

An ability describes an action, including its platform, executor, command, and
any prerequisites or cleanup. A profile collects an ordered selection of
abilities; an operation applies that selection to agents under a planner.

Inspect an existing Windows ability as a reference. For each report behavior,
select a suitable ability or create a separate workshop copy. Review its actual
command, not just its title or technique label. Choose an executor that supports
your command and verify required tools exist on the target.

Keep discovery and staging distinguishable in the operation results. Add the
instructor-provided marker instrumentation using the workshop instructions;
record how it changes the command without changing the intended behavior.
Do not use the marker itself as your proposed real-world detection.

## 3. Assemble and review

Create your own profile with discovery before staging. Give abilities and the
profile unique names/IDs so other content is not overwritten. Review every
command, input, dependency, expected output, and cleanup action.

Select only your assigned target. Verify the actual membership of any selected
agent group. Check the planner's behavior and operation options in your installed
version; a profile's visual order alone does not prove execution order. Keep
cleanup manual until all evidence is captured.

Predict the logs for each stage before execution. Record the operation ID and
UTC start time, run the operation, then examine every executed link and result.
A successful command status is not proof that its telemetry was collected.

## 4. Investigate in Kibana

Open Discover and the instructor-specified data view. Scope to the actual
hostname and an absolute time window around your run. Confirm the displayed
timezone. Start with process creation and then examine file creation.

Suggested columns, where present: timestamp, hostname, dataset, event ID,
process name, command line, parent process, user, and file path. Inspect raw
JSON if normalized fields are absent. Record the actual field names you use.

Use process identity and parent identity to establish relationships. A nearby
timestamp is a lead, not proof of ancestry. Separate commands that were launched
from file operations that completed. Different Caldera abilities may run in
separate processes; do not invent a single parent/child chain between them.

## 5. Two challenges

**Discovery flag:** Find the marker in a discovery-related process command line.
Submit it exactly, along with the host, timestamp, event/document ID, and command.

**Staging flag:** Find the marker in the final staged filename. Submit the marker
exactly, along with the full path, file-creation event, and creating process
evidence. Explain how the process identities connect those events.

Flags are identical across both paths; timestamps and process identifiers are
specific to each run and belong in the worksheet, not the fixed flag string.
Local operators can inspect their own commands/configuration. Knowing a marker
is not completion: demonstrate its independently collected endpoint evidence.

## 6. Explain and repeat

Write a short finding: observed behavior, supporting evidence, and limitations.
Propose one behavior-based hunt and a plausible false positive. After evidence
capture, change one harmless variable and predict its effect. Joe controls any
shared rerun and reset; local students control their own environment.

Use only reviewed cleanup scoped to the exercise's run directory. Preserve
Elastic evidence through grading. If your lab fails, request the rehearsed
fallback evidence window; label it as supplied evidence in your worksheet.
