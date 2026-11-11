# Build the local War Wagon lab

[Back to workshop](../README.md)

Hosted attendees use the supplied Kibana URL and do not need to run setup.
Local attendees build all four VMs before class. Commands below run on your host,
from the cloned repository. Allow several hours for a fresh download and build.

## Host requirements

| Resource | Minimum | Recommended |
|---|---|---|
| RAM | 24 GB | 32 GB or more |
| CPU | 6 cores | 8 or more |
| Free disk | 150 GB | 250 GB |
| Host OS | x64 Windows 10/11 or x86-64 Linux | VMware Workstation |

**Install Git and VMware Workstation before running setup.**

Missing VMware? Follow the [VMware installation walkthrough](install-vmware.md).
Setup prints these steps and stops if it cannot detect Workstation.

| Software                | Version | Where                                                                             |
|-------------------------|---------|-----------------------------------------------------------------------------------|
| VMware Workstation Pro  | 17+     | [vmware.com](https://www.vmware.com/products/workstation-pro.html) (free for personal, educational and commercial use) |
| Vagrant                 | 2.4.9 if missing | Setup installs it on Windows and Debian/Ubuntu-based Linux; [manual installation for other Linux distributions](https://developer.hashicorp.com/vagrant/install) |

The setup scripts install the `vagrant-vmware-utility` service and the
`vagrant-vmware-desktop` plugin when missing (see host compatibility below).

---

## Quick start

### Linux (x86-64, VMware Workstation)

```bash
git clone --branch workshop/war-wagon --single-branch https://github.com/rjonhaas/hunt_lab.git war-wagon
cd war-wagon
chmod +x setup.sh
./setup.sh
```

### Windows

Open an **elevated PowerShell** prompt:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
git clone --branch workshop/war-wagon --single-branch https://github.com/rjonhaas/hunt_lab.git war-wagon
cd war-wagon
.\setup.ps1
```

Both scripts do the same thing in the same order:

1. Verify VMware is installed; install missing Vagrant, the `vagrant-vmware-utility`
   service and `vagrant-vmware-desktop` plugin if missing.
2. Download Vagrant boxes (Ubuntu 22.04 ~700 MB, Windows 11 ~10 GB,
   Windows Server 2022 ~8 GB).
3. `vagrant up docker-host` — provisions Docker, runs `docker/setup.sh` inside
   the VM, which writes `fleet-enrollment-token.txt` and `elastic-credentials.txt`
   back to the repo root via the synced `/vagrant` folder.
4. `vagrant up win-dc` — promotes the DC, creates OUs/users, writes
   `domain-info.txt`, deploys agents.
5. `vagrant up win-server` — joins domain, deploys agents, prepares a synthetic
   `Finance` SMB share.
6. `vagrant up win11-victim` — joins domain, deploys agents.

**Build before the workshop. Allow several hours** for the first run, including
large box downloads, Docker images, Windows reboots and enrollment. Cached-image
rehearsals are not representative of a fresh participant download.

Both setup scripts retry explicit download failures up to three times and save logs
under `.setup-logs/`. WinRM connection failures trigger a bounded reload and retry of that VM.
Other provisioning failures stop dependent machines.
After fixing the reported cause, resume with `bash setup.sh --from win11-victim`
on Linux or `.\setup.ps1 -From win11-victim` on Windows
(or `docker-host`, `win-dc`, `win-server`). Earlier machines are not reprovisioned;
required enrollment/domain files must still exist.

Each machine has a three-hour limit, configurable with the positive integer
`LAB_STAGE_TIMEOUT_SECONDS`. A timeout stops Vagrant, not the VM; check guest
logs before retrying because a guest operation may still be finishing.
Setup then checks services, agents and telemetry, retrying readiness five times
before returning failure. It only reports success when those checks pass.
Logs may contain lab details and are excluded from Git.

Windows setup scripts run directly in the WinRM PowerShell session and propagate
failures to Vagrant. WinRM requests use a five-minute timeout; individual Windows
commands have a 30-minute execution limit. Each Windows VM finishes with checks
for domain membership, Sysmon, Elastic Agent, Sandcat and Atomic Red
Team. These guest checks also run when using the Windows host setup script.

If a step fails, fix the reported error and re-run that VM:
`vagrant up <name> --provider vmware_desktop --provision`. Then start the remaining
VMs in the order above. Running the whole setup script again reprovisions earlier
VMs too. For a known tool-install failure, use a named provisioner instead, e.g.
`vagrant provision win-server --provision-with install_atomic_red_team`.

**Check readiness before class.** Both setup scripts run this check automatically;
repeat it before the exercise. From the repository on either host, use Python
already in the Ubuntu services VM:

```text
vagrant status
vagrant ssh docker-host -c 'python3 /vagrant/scripts/validate_lab.py'
```

It checks Elasticsearch, Kibana, online Fleet enrollment, recently seen trusted
Caldera agents, and recent Sysmon events for **each** of `win-dc`, `win-server`,
and `win11-victim`, plus the preloaded workshop abilities/profile. Duplicate or stale agents cannot substitute for a missing
host. It exits nonzero when readiness is incomplete. Allow a few minutes after
provisioning for enrollment and ingestion, then retry. This does not run attacks
or prove that detections work. Rehearse the selected workshop operation next.

### Host compatibility and common setup blockers

- This Vagrantfile targets **x86-64 Linux or x64 Windows with VMware Workstation**.
  The workshop rehearsal used Linux Mint on an x86-64 host. A fresh Windows-host
  end-to-end installation is being tested and has not yet passed final readiness. macOS/Fusion and ARM hosts
  (including Apple Silicon) are not supported by this workshop build.
- Install Git and VMware before setup. Setup installs missing Vagrant on Windows
  and Debian/Ubuntu-based Linux (including Mint). Linux verifies the pinned
  HashiCorp package checksum before installation and preserves existing Vagrant.
  Other Linux distributions require manual Vagrant installation. Docker Desktop is **not** required:
  Docker runs inside `docker-host`.
- Linux automatic utility installation supports Debian/Ubuntu with systemd.
  Other Linux distributions need the VMware utility installed and running first.
- The guests allocate 22 GB RAM. Setup rejects hosts below 24 GB; 32 GB or more
  leaves better room for the host. Keep 150 GB free at minimum, preferably 250 GB.
  Vagrant caches boxes under `VAGRANT_HOME` (normally your user profile), which
  may be on a different disk from the repository and VM files. Check both disks.
- Enable hardware virtualization in firmware. Verify VMware can start an x64
  guest before downloading the lab. On managed computers, installation or driver
  restrictions may require using the conference-hosted lab.
- The private lab uses `192.168.56.0/24`. Check for overlap with a VPN, LAN or
  another hypervisor before starting. Changing this network requires updating
  the Vagrantfile and guest provisioning settings together.
- Keep the checkout in a local writable directory rather than OneDrive, a
  network share or a cloud-synced directory. Do not build as Linux root: use your
  normal account and let setup request sudo only for the utility installation.
- Dependencies still include remotely downloaded boxes, packages and scripts.
  Box versions are not pinned yet. For workshop release, record and verify a
  tested downloadable version set, including the Windows image's evaluation
  lifetime; disabling update checks alone does not pin fresh builds.

Generated credentials stay local: `docker/.env`, `elastic-credentials.txt`,
`fleet-enrollment-token.txt`, `domain-info.txt`, and `lab-info.md` are gitignored.
Do not include them in support reports. Share the failing VM/provisioner name,
exit code and redacted error text instead.

---

## Accessing the lab

| Service           | URL / Address              | Credentials                               |
|-------------------|----------------------------|-------------------------------------------|
| Kibana (SIEM)     | http://192.168.56.10:5601  | `elastic` / see `elastic-credentials.txt` |
| Caldera (C2)      | http://192.168.56.10:8888  | `admin` / `HuntLab2026!`                  |
| Fleet Server      | http://192.168.56.10:8220  | internal — used by Elastic Agent          |
| Elasticsearch API | http://192.168.56.10:9200  | same as Kibana                            |
| `win-dc` (RDP)    | 192.168.56.50              | `LAB\vagrant` / `vagrant`                 |
| `win-server` (RDP)| 192.168.56.51              | `LAB\vagrant` / `vagrant`                 |
| `win11-victim` (RDP) | 192.168.56.20           | `LAB\vagrant` / `vagrant`                 |

### Active Directory (`lab.local`, NetBIOS `LAB`)

| Account          | Type            | Group         | Password        |
|------------------|-----------------|---------------|-----------------|
| `LAB\vagrant`    | Domain Admin    | Domain Admins | `vagrant`       |
| `LAB\ajohnson`   | Domain Admin    | Domain Admins | `Lab!Password1` |
| `LAB\jsmith`     | Standard user   | —             | `Lab!Password1` |
| `LAB\bwilliams`  | Standard user   | —             | `Lab!Password1` |
| `LAB\cdavis`     | Standard user   | —             | `Lab!Password1` |
| `LAB\svc-backup` | Service account | —             | `Lab!Password1` |
| `LAB\svc-deploy` | Service account | —             | `Lab!Password1` |

DC safe-mode (DSRM) password: `Vagrant123!`

> VMs created by Vagrant don't automatically appear in the VMware Workstation
> GUI. To view one: **File → Open** → browse to
> `.vagrant/machines/<name>/vmware_desktop/<name>.vmx`.

---


When readiness passes, continue with the [participant guide](../workshops/war-wagon/participant-guide.md).

## Conference configuration

The default build preloads the public practice profile. For conference flags,
place the instructor-provided JSON at `.war-wagon/config.json` in the repo root
before running setup. Both hosted and local labs must use the same flag values.
See [instructor configuration](../workshops/war-wagon/instructor/README.md).

## Existing labs

Switching to this branch does not uninstall old containers, Windows tools or
Caldera objects. An existing full lab is not a clean workshop-only installation.
The setup scripts intentionally do not delete old data or unrelated scenarios.
Use a fresh checkout and lab for the focused build; preserve evidence before
retiring your old VMs. Do not run two labs using `192.168.56.0/24` simultaneously
on the same host. Stop the old lab first.

The focused build retains the previously tested VM resource allocations. Smaller
requirements have not been validated. A fresh focused build and learner-account
CTF rehearsal are still needed before declaring the workshop release-ready.
