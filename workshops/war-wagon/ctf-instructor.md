# War Wagon — CTF drafts (instructor only)

These are challenge designs, not published challenges. Do not ship this file
with the participant bundle. Final flags must be derived from a captured,
verified run and tested before CTFd publication. Reading a source-code literal
must not be sufficient to solve either challenge.

## Easy: Find the transfer

**Participant prompt:** In the supplied War Wagon dataset, identify the
`rclone.exe` process that attempts to copy the Finance share to the lab S3
destination. Submit its Sysmon ProcessGuid (lowercase, without braces). Show
the command, host, UTC timestamp, and event/document reference in your notes.

**Skill:** Filter process telemetry and interpret an actual command line.

**Dataset requirement:** Exactly one intended matching process in the scoped
challenge window, with ProcessGuid retained in the evidence. Verify raw and ECS
representations. If multiple matches exist, narrow the prompt with the assigned
host and time window rather than choosing an undocumented answer.

**Hint 1:** Start with process creation events and the transfer utility name.
**Hint 2:** Inspect the source path and destination arguments before choosing a
process. A preparatory command is not the copy process.

**Flag:** Not set. Derive from the verified event. Configure normalization or
explain the exact format in CTFd. Do not invent a GUID.

## Hard: Prove the chain

**Participant prompt:** Reconstruct the script → shell → transfer process chain
for that event. Submit the three Sysmon ProcessGuids in ancestry order,
lowercase without braces, separated by underscores. Then explain whether the
transfer succeeded and cite independent evidence of its outcome.

**Skill:** Join parent/child evidence and distinguish execution from outcome.

**Dataset requirement:** All three process-creation events, their linking GUIDs,
and rclone result/object-list evidence from the same run. Verify ancestry first;
time proximity alone is insufficient. If Windows Script Host is unavailable or
the observed launch chain differs, correct the exercise to the captured chain
before publication rather than asserting that expected events occurred.

**Hint 1:** Match child ParentProcessGuid to parent ProcessGuid on the same host.
**Hint 2:** The LocalStack adapter cannot tell you the true user or bucket from
its placeholder identity and empty request parameters. Look at endpoint and
transfer-result evidence together.

**Flag:** Not set. Derive from the three verified events. CTFd can grade the
GUID chain automatically; assess the outcome explanation in the workshop.

## Instructor grading

| Criterion | Points |
|---|---:|
| Correct transfer process with evidence reference | 1 |
| Both parent-child links supported by GUIDs | 2 |
| Successful/failed/unknown outcome justified by independent evidence | 1 |
| Placeholder cloud fields and a detection blind spot identified | 1 |

Use workshop title “War Wagon: Tactical Telemetry Lab” in both CTF descriptions
so participants can find the associated teaching material.
