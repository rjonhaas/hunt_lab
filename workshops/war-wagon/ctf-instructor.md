# War Wagon — Joe's instructor and CTF guide

**Hosted reference scenario rehearsed; local and learner-account checks pending.** Companion to [WW-TRAIN-001](training-report.md).
The [reference builder and verifier](scenario/README.md) now implement the marker
contract. Private workshop flags are stored outside Git. See [the rehearsal record](scenario/rehearsal.md)
for actual validation and remaining release gates.

## Teaching objective

Demonstrate the reasoning from report → behavior → command → Caldera ability →
profile/operation → predicted logs → observed evidence. Hosted learners suggest
choices and explain evidence; Joe controls execution. Local learners author and
run their own scenario. Do not start by handing out a finished profile.

## Suggested 60-minute exercise within the workshop

| Minutes | Activity |
|---|---|
| 0–10 | Read report; identify four behaviors and predict telemetry |
| 10–25 | Build/select abilities; explain executors, prerequisites, cleanup |
| 25–35 | Assemble profile, review scope/planner, execute and inspect results |
| 35–50 | Independently hunt both flags and record endpoint evidence |
| 50–60 | Compare interpretations, false positives, and evidence gaps |

Adjust after rehearsal; local setup happens before class.

## Build walkthrough and reference choices

These are instructor examples, not a claim that a particular Caldera release
already contains an ability with the required name or semantics.

| Behavior | Simple reference implementation | Evidence to predict |
|---|---|---|
| User discovery | `whoami.exe` | Process creation, executing identity and parent |
| Computer name | `hostname.exe` | Process creation and host context |
| Network configuration | `ipconfig.exe /all` | Process creation and full command line |
| Local staging | PowerShell creates a dedicated run directory and copies a prepared synthetic text file into it | PowerShell/process events and destination file creation |

For each, ask “What did the report actually say?” then show how you chose the
command. Inspect or create a separate ability, select Windows and a compatible
executor, and review the resulting command. Record actual IDs and tested versions
in a private rehearsal record. Use independent abilities for visible checkpoints.

Use a single assigned Windows endpoint for the first rehearsal; no domain or
lateral movement is needed. The hosted group has multiple agents, so explicitly
scope the operation to the chosen target. Verify planner behavior and prerequisites
rather than relying on profile order alone. Keep ability cleanup manual until
students finish collecting evidence. Never execute the full legacy RansomHub
profile for this exercise.

## Marker contract to implement

Use two fixed workshop flag values, held outside Git/public reports. Both paths
must receive the same values through separate workshop configuration. Public
practice releases use different values. The reference builder reads a private JSON configuration; generated abilities
contain the values. Give local learners that configuration through the workshop
channel, never the public feed. Distribution remains an instructor task.

1. Discovery: include marker A as a harmless literal in the command line of a
   discovery wrapper process that actually launches the discovery command.
   Do not merely print the marker to Caldera output: it must be captured in
   endpoint process telemetry.
2. Staging: use marker B in the destination filename, under a dedicated
   `C:\WarWagonTraining\<run-label>\` directory. Use a synthetic source text file.
   Verify the deployed Sysmon configuration records destination file creation
   and identifies the creating process.
3. Use a unique run label so repeated runs have distinct paths, while retaining
   the same graded marker values. Publish exact extraction/formatting rules once
   the marker format is chosen. Never make students submit run-specific GUIDs
   as part of a shared static CTF flag.

Local authors can read their own inputs; these flags are learning checkpoints,
not secret-resistant proof of investigation. Require the worksheet evidence for
workshop completion. CTFd can grade the static flags; Joe reviews the evidence
separately unless an evidence-validation workflow is explicitly implemented.
Do not claim that CTFd validates the worksheet automatically.

## Challenge 1 — Find discovery (easy)

Prompt: Find the discovery sequence from the training report. Recover the first
workshop marker from the command line of a discovery-related process event.
Submit the marker exactly. Document hostname, timestamp, command, user, and event
reference in your worksheet.

Hints, released progressively:
1. Scope to the supplied host and UTC window.
2. Look for native user/system/network discovery processes.
3. Inspect the process that launched them and its recorded command line.

Acceptance: marker A is present in actual indexed process telemetry; learner can
retrieve it using their account. Evidence must be an endpoint event, not a copy
of the Caldera command or report.

## Challenge 2 — Prove staging (hard)

Prompt: Locate the final staged synthetic file. Recover the second marker from
its filename. Document its full path and correlate its file-creation event to
the creating process. Explain its relationship to the operation.

Hints:
1. Search file-creation evidence on the same target and window.
2. Inspect the destination path and creating process identity.
3. Match that identity to process-creation evidence; inspect raw event JSON when
   normalized fields are absent. Timing alone does not establish ancestry.

Acceptance: marker B appears in file-creation telemetry; creator identity can be
matched to a process event. Record actual fields from the deployed integration.
Separate ability executions may share the agent as an ancestor without forming
one linear process tree. Accept accurate explanations of that distinction.

## Shared-lab operation procedure

1. Confirm all required services and target agents are healthy; verify learner
   accounts can search the intended data without changing shared configuration.
2. Announce target hostname, run label, timezone, and start time.
3. Demonstrate the build with participant input, then run once as instructor.
4. Check each link and verify both markers independently in Kibana.
5. Supply the final UTC evidence window and retain it through grading.
6. Announce reruns as separate windows; do not silently replace the graded run.

## Release gate and fallback

- Rehearse hosted and local paths using the same marker contract.
- Verify process and file events, their correlation fields, and both answers.
- Test progressive hints and queries with a learner account.
- Record versions, ability IDs, operation ID, target, times, and expected answers
  privately. Do not commit flags, credentials, or marked event exports publicly.
- Capture a sanitized, access-controlled fallback evidence bundle with equivalent
  fields. Do not promise offline completion until that bundle is verified.
- Create a completed Caldera reference package only after the authoring exercise
  works; release it as opt-in fallback or post-workshop material.
- Test cleanup against only the chosen run directory; preserve graded evidence.

Public report publication, CTFd submission, and live execution are separate
steps. This guide does not imply they have occurred.
