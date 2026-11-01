# War Wagon: Tactical Telemetry Lab

Working workshop draft for Jon Haas, DEATHCon 2026. **Not yet rehearsed or release-ready.**

Build a repeatable lab with Vagrant, simulate adversary activity with MITRE
Caldera, and examine the resulting evidence in Elastic/Kibana. Participants
leave understanding how to repeat this cycle on their own machines.

## Materials

- [PowerPoint content scaffold](slide-scaffold.md)
- [Shared training intelligence report](training-report.md)
- [Participant guide](participant-guide.md)
- [Lab worksheet](hunt-worksheet.md)
- [Instructor runbook and release gates](instructor-runbook.md)
- [CTF challenge designs](ctf-instructor.md)
- [Reference scenario builder and evidence verifier](scenario/README.md)
- [Report-linked Caldera scenario packaging plan](scenario-packaging-plan.md)

The core exercise is **Discovery Before Collection (WW-TRAIN-001)**: translate
intelligence into Caldera abilities, predict telemetry, execute, and investigate.
Joe demonstrates authoring and controls hosted execution; local participants
author and run their own scenario. Both paths use the same two CTF challenges.
Vagrant teaches how to reproduce the environment at home. The previous
[RansomHub walkthrough](ransomhub-reference.md) remains optional reference.

## Proposed pacing, pending duration confirmation

| Module | Minutes | Participant output |
|---|---:|---|
| Architecture and participation paths | 10 | Assigned environment and component map |
| Vagrant configuration and provisioning walkthrough | 25 | Annotated VM definition and working-copy edit |
| Readiness checks | 10 | Services, agent, and telemetry evidence |
| Caldera concepts and operation setup | 20 | Targeted operation plan |
| Controlled execution | 15 | Ability results and UTC window |
| Elastic pipeline and Kibana investigation | 20 | An action matched to its telemetry |
| CTF practice | 15 | Evidence-backed challenge answers |
| Reset and take-home experiment | 5 | Recovery and next experiment plan |
| **Total** | **120** | |

Download and provision before the workshop. Teach the build using a prepared
recording and checkpoint inspection so download speed does not determine who
can finish. Demonstrate a rehearsed subset of the scenario in the execution
slot. If the workshop is 90 minutes, move CTF practice to follow-up and shorten
the provisioning walkthrough and execution demo by 10 and 5 minutes respectively.

## Delivery paths

1. **Local:** x86-64 Windows/Linux host with VMware Workstation and Vagrant.
   Participants build and validate before the workshop using the repository guide.
2. **Hosted:** assigned DEATHCon Proxmox instance. Participants still inspect and
   edit a local copy of the Vagrantfile, then use the prepared environment.
   Joe controls Caldera execution; participants hunt through learner Kibana accounts.
   Learner permissions and the new exercise still require validation.

The lab includes Elasticsearch and Kibana, with Elastic Agent/Fleet and Filebeat.
It does not use Logstash. Offline CTF exports must come from a captured, verified
run. The new scenario has a reference builder and endpoint-evidence verifier; see its
rehearsal record before using it. A published offline evidence bundle is still pending.
