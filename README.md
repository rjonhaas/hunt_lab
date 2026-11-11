# War Wagon — DEATHCon workshop

Turn a threat report into a repeatable lab operation, then find its evidence in
Kibana. This is the focused `workshop/war-wagon` branch for Jon Haas and Joe
Morrissey's workshop. The broader lab remains on [main](https://github.com/rjonhaas/hunt_lab/tree/main).

## Start here

**[Follow the numbered workshop guide →](workshops/war-wagon/participant-guide.md)**

Install → find logins → read the report → understand the four abilities →
review the adversary → run the operation → hunt evidence.

| Your path | What you do |
|---|---|
| Hosted | Use the supplied Kibana login. Watch the instructor's Caldera demonstration and investigate the shared run. No local install needed. |
| Local | Build four VMs before class. Run the prepared profile on your own target and investigate in your own Kibana. |

Setup preloads **four abilities and one adversary profile**, including the flag
instrumentation. It does not execute them. Both paths find the flags in Kibana
and submit supporting events, not just a flag string.

## What is included

| VM | Purpose | Lab IP |
|---|---|---|
| `docker-host` | Ubuntu: Elasticsearch, Kibana, Fleet and Caldera | `192.168.56.10` |
| `win-dc` | Windows Server: Active Directory and DNS | `192.168.56.50` |
| `win-server` | Windows Server: domain member and synthetic Finance share | `192.168.56.51` |
| `win11-victim` | Windows 11: domain workstation and workshop target | `192.168.56.20` |

Windows hosts get Sysmon, Elastic Agent, Sandcat and **Atomic Red Team**. Setup
also enables file-creation logging for the exercise directory. Atomic Red Team
is included for discussion and further experiments; the four CTF abilities do
not depend on running its tests.

Local requirements: x64 Windows or x86-64 Linux, Git, VMware Workstation,
24 GB RAM minimum (32 GB recommended), 150 GB free disk minimum (250 GB
recommended). Allow several hours for the first build. See
[setup and recovery](docs/local-setup.md). Apple Silicon and Fusion are not supported.

## Materials

- [Numbered workshop guide](workshops/war-wagon/participant-guide.md)
- [Training report](workshops/war-wagon/training-report.md)
- [Evidence worksheet](workshops/war-wagon/hunt-worksheet.md)
- [Instructor setup and reference solutions](workshops/war-wagon/instructor/README.md)

The public configuration uses practice flags. Instructors supply the conference
configuration separately so local and hosted runs use the same flags. Local
operators can inspect their configuration; challenge completion requires the
matching Kibana events and an explanation.

This branch no longer deploys the cloud simulator, extra attack scenarios,
Velociraptor, SOAR or benchmark tools. Changing branches does not uninstall an
existing lab; see [existing labs](docs/local-setup.md#existing-labs).
The focused build needs a fresh end-to-end rehearsal; older full-lab results
are not proof that this revision is ready for attendees.
