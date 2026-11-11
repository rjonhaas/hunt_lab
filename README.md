# War Wagon — DEATHCon workshop

Turn a threat intelligence report into actions you can run in a lab, then find
and explain the resulting evidence in Kibana.

This is the `workshop/war-wagon` branch of Hunt Lab, used by Jon Haas and
Joe Morrissey for DEATHCon. Start here even if you are using the hosted lab.

## Choose your path

| | Hosted workshop | Build your own lab |
|---|---|---|
| What you need | Browser and the supplied Kibana login | x64 Windows or x86-64 Linux, Git and VMware Workstation |
| Who runs the actions | Instructor demonstrates Caldera and executes the shared operation | You build and run your own operation |
| Where you investigate | Supplied Kibana URL and evidence window | Kibana in your local lab |
| Start here | [Participant guide](workshops/war-wagon/participant-guide.md) | [Local setup](docs/local-setup.md), then the participant guide |

Hosted access is **Kibana only**. You do not need to install Vagrant or build VMs
to follow the hosted exercise. Access details come from the instructors.

## Workshop materials

1. Read [Discovery Before Collection](workshops/war-wagon/training-report.md).
2. Follow the [participant guide](workshops/war-wagon/participant-guide.md) to
   turn its four behaviors into abilities, a profile and an operation.
3. Use the [hunt worksheet](workshops/war-wagon/hunt-worksheet.md) to record
   predictions, searches and evidence for the two challenges.

The report is a synthetic training scenario: user, system and network discovery,
followed by staging a synthetic document. Finding a flag is only part of the
exercise; show the endpoint evidence that supports it.

## What the local setup builds

One [Vagrantfile](Vagrantfile) defines four VMware virtual machines:

| VM | Role | Lab address |
|---|---|---|
| `docker-host` | Ubuntu; Caldera, Elasticsearch, Kibana and Fleet | `192.168.56.10` |
| `win-dc` | Windows Server; `lab.local` domain and DNS | `192.168.56.50` |
| `win-server` | Windows Server; domain member and file share | `192.168.56.51` |
| `win11-victim` | Windows 11; domain workstation | `192.168.56.20` |

[setup.sh](setup.sh) and [setup.ps1](setup.ps1) install supported missing Vagrant
components, download the boxes, start the services, build the domain, join its
members, install endpoint tools and check readiness. Sysmon records activity,
Elastic Agent ships it to Elasticsearch, and Sandcat connects Windows to Caldera.

For a local build, allow several hours and use **24 GB RAM minimum, 32 GB
recommended; 150 GB free disk minimum, 250 GB recommended**. Install Git and
VMware Workstation first. See [local setup](docs/local-setup.md) for the exact
commands, supported hosts, disk/cache requirements and recovery instructions.
Docker Desktop is not needed. This build does not support Apple Silicon or Fusion.

The base lab also includes LocalStack, Velociraptor, Atomic Red Team and two
preloaded scenarios. These are additional capabilities, not prerequisites to
understanding the workshop exercise. [Additional lab reference](docs/lab-reference.md)
covers those scenarios, benchmark exports and the optional Tracecat overlay.

## Before the exercise

Local attendees should finish setup and run the readiness check before class.
Also complete the [target file-telemetry preparation](workshops/war-wagon/scenario/README.md#required-target-preparation)
on the chosen Windows target. The instructor does this for the hosted lab.
A successful command does not guarantee that the expected event was collected.

The hosted reference exercise has passed endpoint-evidence checks. Linux setup
has passed a local rehearsal; the fresh Windows-host build is still under test.
Restricted learner access and a complete local exercise still need verification.
See the [validation record](workshops/war-wagon/scenario/rehearsal.md) for scope and limitations.

## Finding your way around

| Location | Purpose |
|---|---|
| [docs/local-setup.md](docs/local-setup.md) | Install, access, readiness and resume instructions |
| [workshops/war-wagon/](workshops/war-wagon/README.md) | Report, participant guide and worksheet |
| [scripts/](scripts/) | Windows and Linux machine setup |
| [docker/](docker/) | Service definitions and first-run configuration |
| [Instructor materials](workshops/war-wagon/instructor/README.md) | Delivery notes, rehearsal and reference builder |
| [docs/lab-reference.md](docs/lab-reference.md) | Extra scenarios, tools and troubleshooting |

Practice markers are public examples. Instructors provide workshop flag
configuration separately; generated configurations, evidence and credentials
should stay outside Git. The lab uses known training credentials and weakened
guests; keep it on its intended lab network.
