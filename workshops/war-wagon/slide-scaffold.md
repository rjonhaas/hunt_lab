# War Wagon slide scaffold

Content scaffold for a future PowerPoint. Screenshots, recorded demonstrations,
and observed results remain to be captured. Duration awaits confirmation.

**Takeaway:** Build a repeatable lab with Vagrant, simulate adversary activity
with MITRE Caldera, and examine the evidence in Elastic/Kibana.

| Slide | Title | Teaching point | Demonstration or participant checkpoint |
|---|---|---|---|
| 1 | War Wagon: Tactical Telemetry Lab | A lab participants can reproduce and use for experiments | Introduce the build, simulation, and evidence cycle |
| 2 | The complete lab cycle | Vagrant provisions machines, Caldera executes activity, Elastic collects events, Kibana exposes evidence | Follow one action through the cycle |
| 3 | Local and hosted participation | Local users build with Vagrant. Hosted users inspect the same configuration and use an assigned instance | Confirm each participant's path and access |
| 4 | Lab architecture | Ubuntu services host plus Windows DC, file server, and workstation | Architecture visual placeholder based on Vagrantfile |
| 5 | Anatomy of the Vagrantfile | Boxes, VM definitions, provider settings, private networks, and provisioners | Annotated repository excerpt placeholder |
| 6 | Configuration exercise | Explain a VM's role and resource settings before changing them | Edit a working copy's display name and identify related provisioning scripts. Hosted users do the same without applying it |
| 7 | Provisioning sequence | Services and enrollment material precede Windows provisioning | Show repository commands and prepared provisioning recording |
| 8 | Readiness checkpoints | Running VMs, reachable services, a live Caldera agent, and incoming endpoint events | Record health evidence. Shared users perform read-only checks |
| 9 | Caldera building blocks | An agent runs an ability. An adversary profile groups abilities. An operation executes a selected profile against selected agents | Caldera UI screenshot placeholder |
| 10 | Operation configuration | Inspect commands and expected effects, select the intended target, record the operation window | Participants prepare an operation plan. Facilitator executes on shared labs |
| 11 | Controlled adversary simulation | Execute a rehearsed subset of the RansomHub-inspired scenario | Capture target, ability, output, status, and UTC timestamps |
| 12 | Execution results | Command output and independent evidence establish outcomes | Compare one completed action with a failed or missing step |
| 13 | Elastic telemetry pipeline | Sysmon and Elastic Agent supply endpoint events. Filebeat ships the LocalStack adapter's cloud-shaped records | Show the actual event paths and field limitations |
| 14 | Evidence in Kibana | Scope by host and time, find the executed command, inspect process ancestry where available | Match a Caldera action to an event and retain its document ID |
| 15 | A repeatable experiment | Change one controlled variable and predict the observable difference | Compare two rehearsed runs or facilitator-provided exports |
| 16 | CTF practice | Easy: identify an executed ability. Hard: connect an operation to endpoint evidence and its marker | Use a verified fixed dataset for consistent grading |
| 17 | Reset and continued practice | Distinguish guest cleanup, snapshots, and full rebuilds | Document a tested recovery procedure and one take-home experiment |

## Demonstration placeholders

- Architecture and annotated Vagrantfile excerpt from this repository.
- Successful provisioning checkpoints and exact tested versions.
- Caldera agent, operation configuration, and execution-result screenshots.
- Kibana view of the same action, including UTC window and host filter.
- Verified paired-run comparison and recovery recording.
- Hosted access details from the organizer.

## Scope

Vagrant, Caldera, and Elastic/Kibana form the required workshop content.
Detection tuning, Velociraptor, and Tracecat response automation are optional
extensions. Long downloads happen before the workshop, while the workshop still
teaches the configuration and provisioning process through a prepared build.
The existing Vagrantfile targets VMware. Hosted Proxmox requires an adaptation
or image import that has not yet been validated.
