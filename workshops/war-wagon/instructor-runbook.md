# War Wagon — instructor runbook

## Current status

Draft based on hunt_lab `84a6533` and the authoring structure in hunt-ops
`5f3dbc5`. Duration, lab availability, and successful end-to-end run are not yet
confirmed. No recording, shared instance, or CTF submission is claimed complete.

## Rehearsal sequence

1. Confirm duration and select a dedicated lab. Provision before recording;
   show architecture and setup checkpoints in the video, not hours of downloads.
2. Run `scripts/validate_lab.ps1` from an appropriate Windows host. Inspect
   actual events for each expected host, not just an overall PASS. The existing
   script does not fail when the CloudTrail index is absent; check it separately.
3. Verify the Finance share, the intended target agent, and a clean baseline.
   Default Caldera group `red` includes all three Windows agents. Do not start
   an operation against the whole group without deliberately selecting targets.
   Record the selected target(s); confirm their share access before the run.
4. Run the scenario only in the assigned disposable lab. Capture its operation
   ID, UTC window, agent hosts, completed/failed links, and rclone output. A
   successful Caldera link is not by itself evidence of successful transfer.
5. Capture a completed hunting window. Export endpoint events, the relevant
   cloud-shaped events, rclone logs, and an S3 object listing. Preserve originals
   and hashes. Keep the instructor answer key separate from participant data.
6. Work every participant query against this exact run. Check ECS mappings and
   document actual hostname values and timezone. Include a benign comparison
   or explicitly label noise testing incomplete.
7. Complete the response integration and record an actual successful run.
8. Test the guide with participant permissions and complete both CTF challenges.

## Evidence commands (lab operator)

From the repository on the host running Vagrant:

```bash
vagrant ssh docker-host -c 'sudo docker exec hl-localstack awslocal s3 ls s3://ransomhub-exfil-lab/finance/ --recursive'
```

Existing bundle tooling, after the completed operation:

```bash
python3 scripts/make_benchmark_bundle.py OPERATION_ID
```

Replace `OPERATION_ID` with the real run identifier. Check script dependencies
and access to Caldera and Velociraptor first. Review the exported evidence for
credentials and unrelated host data before distribution. Verify the resulting
archive actually supports the exercises; a triage archive alone does not create
a ready-to-query offline Kibana instance.

## Response integration acceptance criteria

The repo includes Tracecat infrastructure but no completed workshop workflow.
Before promising the automated module, verify all of the following:

- Tracecat resource allocation, pinned version, and service health.
- A real exported workflow available for repeatable import.
- An available Kibana action connector under the lab's actual license.
- A tested webhook URL and payload for that installed Tracecat version.
- One real detection triggering enrichment and an evidence/decision record.
- Failed enrichment visible to the analyst; no silent “success” for missing data.
- Repeated alert delivery handled without duplicate consequential actions.

Use a bounded enrichment/decision workflow for the core. If containment is
demonstrated, define its lab target and verification separately. A manual
worksheet fallback preserves the lesson but does not fulfill the automation
promise; keep that release gate open until tested.

## Shared lab handoff — fill from actual deployment

Jon selected the conference-hosted Proxmox path for War Wagon. In the workshop
leader channel, Randy's September 9 guidance says to connect through Tailscale
and use a conference exit node to reach the Proxmox admin interface; Proxmox is
not exposed to the public Internet. September 14 guidance specifies Tailscale's
Microsoft SSO option with the DEATHLab account provisioned by deathbot.

That server offer was addressed to another workshop leader, so it does not
establish which server or capacity is assigned to War Wagon. Confirm Jon's
assigned Proxmox endpoint and login instructions before provisioning. Do not
assume the Windows/Entra password also authenticates directly to Proxmox.
The existing Vagrant deployment targets VMware; a Proxmox deployment or image
import needs a tested adaptation, not an unchanged `vagrant up` command.

| Required item | Status |
|---|---|
| Organizer confirms instance count and capacity | Unconfirmed |
| Assigned instance identifiers / reachability | Unconfirmed |
| Participant login and permissions tested | Unconfirmed |
| Instructor controls scenario launches and reset | Unconfirmed |
| Completed run window and host map supplied | Not captured |
| Concurrent-user rehearsal | Not run |
| Download bundle and checksum | Not published |
| Recovery path if instance fails | Not tested |

Keep the hunt_lab domain separate from the conference domain unless an explicit
integration design is tested. Shared participants hunt the same completed run;
reserve scenario execution and resets for the facilitator to prevent collision.

## Known review findings

- CloudTrail adapter originally wrote multiline JSON without a final newline;
  Filebeat's line-oriented decoder requires newline-delimited complete objects.
  This branch fixes that file contract and enables JSON error visibility.
- Cloud identities and source addresses are placeholders. The exercise must not
  claim true AWS identity attribution or bucket attribution from these records.
- The network-sweep rule requires 15 distinct destination IPs, while this lab
  defines four VMs and only probes TCP after successful ping. It is unsuitable
  as a guaranteed positive exercise without further evidence and tuning.
- The existing exfil EQL rule correlates two events by host/time; it does not
  establish the full process ancestry advertised by its title.
- First-build runtime estimates conflict in the main README. Budget hours and
  complete setup before class.
- A 22 GB guest allocation and x86 Windows boxes make the shared path essential.
- No tracecat workflow export was found. No existing slide deck, participant
  guide, or CTF package was found in either repository.

## Release gates

- [ ] Duration and core scope confirmed by Jon.
- [ ] Fresh or known-good lab rehearsal completed with version manifest.
- [ ] Cloud events ingest and positive query results verified in Elasticsearch.
- [ ] Participant guide tested with a learner account.
- [ ] Shared instances and instructions confirmed with organizer.
- [ ] Response integration tested; workflow export included.
- [ ] Two CTF challenges tested and added to CTFd; answers kept separate.
- [ ] Recording completed and reviewed for audible instructions/readable text.
- [ ] Guides, recording, and downloads delivered by November 1.
- [ ] Workshop channel contains tested links and setup instructions.

Conference guidance: at least one easy and one hard practical CTF challenge per
workshop; CTF deadline November 10. Materials are online-first. Monitor the
workshop channel during convenient hours on both conference days.
