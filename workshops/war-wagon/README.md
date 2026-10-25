# War Wagon: Tactical Telemetry Lab

Working workshop draft for Jon Haas, DEATHCon 2026. **Not yet rehearsed or release-ready.**

Turn an adversary behavior into a hunt hypothesis, find its evidence, test a
detection, and document a response decision. Take the lab and the method home.

## Materials

- [Participant guide](participant-guide.md)
- [Hunt worksheet](hunt-worksheet.md)
- [Instructor runbook and release gates](instructor-runbook.md)
- [CTF challenge drafts and scoring rubric](ctf-instructor.md) — instructor only

The core uses hunt_lab's RansomHub-inspired endpoint-to-S3 scenario. The report
structure follows the threat overview → attack chain → mapping → detection
guidance approach used in Jon's hunt-ops authoring workspace. No private report
content is required for participants. The separate identity chain is an optional
extension, not a prerequisite for completing the core exercises.

## Proposed pacing — duration awaiting confirmation

| Module | Minutes | Participant output |
|---|---:|---|
| Orient and verify access | 10 | Correct instance, hosts, time window |
| Behavior → hypothesis | 10 | Falsifiable hypothesis and required telemetry |
| Observe emulation | 10 | Operation ID, target host, start/end time |
| Hunt and reconstruct | 30 | Three supported findings and a process chain |
| Engineer and tune | 20 | Query, positive result, benign explanation, limitation |
| Response workflow | 15 | Enrichment and response decision record |
| CTF practice | 20 | Easy and hard challenge evidence |
| Debrief | 5 | Take-home research plan |
| **Total** | **120** | |

Provisioning and a full 25–30 minute scenario run are pre-work. The observation
slot is a selected demonstration; participants hunt a completed, verified run.
If the slot is 90 minutes, assign CTF practice afterward and reduce the hunting
slot to 20 minutes. Do not remove the detection or response exercises.

## Delivery paths

1. **Local:** x86-64 Windows/Linux host with VMware Workstation and Vagrant;
   build and validate before the session. Follow the repository setup guide.
2. **Shared:** organizer-provided, prebuilt isolated instance; participants
   receive an assigned instance and access instructions. Availability and exact
   endpoints are still unverified.

An offline evidence bundle is a contingency only after it has been captured and
tested with documented analysis tools. The existence of a packaging script is
not proof that a usable workshop dataset has been published.
