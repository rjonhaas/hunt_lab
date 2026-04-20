# Threat Hunting Lab — Elastic SIEM + MITRE Caldera + Windows 11

A self-contained threat hunting lab provisioned automatically with a single script. Spins up three VMs: an Elastic SIEM stack, a MITRE Caldera C2 server, and a Windows 11 victim endpoint with Sysmon and an Elastic Agent pre-enrolled in Fleet.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                Host-Only Network: 192.168.56.0/24            │
│                                                              │
│  ┌──────────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  elastic-siem    │  │ win11-victim │  │   caldera     │  │
│  │  192.168.56.10   │◄─│192.168.56.20 │─►│192.168.56.30  │  │
│  │                  │  │              │  │               │  │
│  │  Elasticsearch   │  │  Windows 11  │  │  MITRE        │  │
│  │  Kibana          │  │  Sysmon      │  │  Caldera 5.x  │  │
│  │  Fleet Server    │  │  Elastic     │  │  (Docker)     │  │
│  │                  │  │  Agent       │  │               │  │
│  └──────────────────┘  └──────────────┘  └───────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### VM Inventory

| VM Name        | IP             | OS           | RAM  | CPUs | Role                              |
|----------------|----------------|--------------|------|------|-----------------------------------|
| `elastic-siem` | 192.168.56.10  | Ubuntu 22.04 | 8 GB | 4    | Elasticsearch + Kibana + Fleet    |
| `win11-victim` | 192.168.56.20  | Windows 11   | 4 GB | 2    | Monitored endpoint                |
| `caldera`      | 192.168.56.30  | Ubuntu 22.04 | 4 GB | 2    | MITRE Caldera C2 + sandcat agent  |

---

## Host Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM      | 20 GB free | 24 GB free |
| CPU      | 6 cores | 8+ cores |
| Disk     | 150 GB free | 200 GB free |
| OS       | Windows 10/11 or Linux | — |

**Required software (install manually before running the setup script):**

| Software | Version | Download |
|----------|---------|----------|
| VMware Workstation Pro | 17+ | [vmware.com](https://www.vmware.com/products/workstation-pro.html) — free for personal use |
| Vagrant | 2.3+ | [developer.hashicorp.com/vagrant/install](https://developer.hashicorp.com/vagrant/install) |

The setup script installs the `vagrant-vmware-utility` service and the `vagrant-vmware-desktop` Vagrant plugin automatically.

---

## Project Structure

```
hunt_lab/
├── setup.sh                       # Linux quick-start (run this first)
├── setup.ps1                      # Windows quick-start (run this first)
├── Vagrantfile                    # Defines all three VMs
└── scripts/
    ├── install_elastic.sh         # Guest: Elasticsearch 8.x + Kibana + Fleet Server
    ├── install_caldera.sh         # Guest: MITRE Caldera 5.x via Docker Compose
    ├── install_win_tools.ps1      # Guest: Sysmon + Elastic Agent enrollment + sandcat
    └── deploy_caldera_agent.ps1   # Standalone: re-deploy sandcat without full reprovision
```

**Generated at runtime (git-ignored):**
- `elastic-credentials.txt` — `elastic` superuser password, written by `install_elastic.sh`
- `fleet-enrollment-token.txt` — Fleet enrollment token consumed by `install_win_tools.ps1`

---

## Quick Start — Linux

```bash
git clone <repo-url> hunt_lab
cd hunt_lab

chmod +x setup.sh
bash setup.sh
```

`setup.sh` runs everything in the correct order:

1. Verifies VMware Workstation and Vagrant are installed
2. Downloads and installs `vagrant-vmware-utility` (`.deb`) and enables the systemd service
3. Installs the `vagrant-vmware-desktop` Vagrant plugin
4. Downloads the Windows 11 Vagrant box (~8–12 GB on first run)
5. Provisions `elastic-siem` → `caldera` → `win11-victim` in dependency order

**First-run time: 25–40 minutes** (mostly network downloads).

---

## Quick Start — Windows

Open an **elevated PowerShell prompt** (Run as Administrator), then:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd C:\path\to\hunt_lab
.\setup.ps1
```

`setup.ps1` does the same steps as `setup.sh` but uses Windows-native tooling:

1. Verifies VMware Workstation and Vagrant are installed
2. Downloads and installs `vagrant-vmware-utility` (`.msi`) silently
3. Installs the `vagrant-vmware-desktop` Vagrant plugin
4. Downloads the Windows 11 Vagrant box (~8–12 GB on first run)
5. Provisions `elastic-siem` → `caldera` → `win11-victim` in dependency order

---

## Accessing the Lab

Once the setup script completes:

| Service             | URL                           | Credentials                          |
|---------------------|-------------------------------|--------------------------------------|
| Kibana (SIEM)       | http://192.168.56.10:5601     | `elastic` / see `elastic-credentials.txt` |
| Caldera (C2)        | http://192.168.56.30:8888     | `admin` / `admin`                    |
| Elasticsearch API   | http://192.168.56.10:9200     | same as Kibana                       |
| Fleet Server        | http://192.168.56.10:8220     | internal — used by Elastic Agent     |

> **Note:** VMs created by Vagrant do not automatically appear in the VMware Workstation GUI.
> To view them: **File → Open** and browse to `.vagrant/machines/<name>/vmware_desktop/<name>.vmx`.

---

## Threat Hunting Workflow

```
Caldera (192.168.56.30)
    │
    │  executes ATT&CK TTPs via sandcat agent
    ▼
Windows 11 Victim (192.168.56.20)
    │  sandcat: beacons to Caldera, runs adversary commands
    │  Sysmon: logs process/network/file/registry events
    │  Elastic Agent: ships all telemetry via Fleet
    ▼
Elastic SIEM (192.168.56.10)
    │  Fleet ingests and indexes logs
    ▼
Kibana → Security → Alerts / Discover / Timeline
```

The sandcat agent is deployed automatically during provisioning and persists across reboots via a Windows Scheduled Task (`WindowsSecurityUpdate`). It beacons back to Caldera on port 8888 and joins the `red` agent group.

### Viewing data in Kibana

In **Analytics → Discover**, select the **`logs-*`** data view from the top-left dropdown. Filter by host to isolate the victim:

```kql
agent.hostname : "win11-victim"
```

Key indices written by the Windows agent:

| Index pattern | Content |
|---|---|
| `logs-windows.sysmon_operational-*` | Process, network, file, registry events |
| `logs-windows.powershell_operational-*` | PS script block logging (4103/4104) |
| `logs-windows.powershell-*` | PS classic pipeline events |
| `logs-windows.windows_defender-*` | AV detections and exclusions |
| `logs-system.security-*` | Windows Security Event Log |
| `logs-system.application-*` | Windows Application Event Log |

### Starter KQL queries

```kql
# All Sysmon process creation events from the victim
event.dataset : "windows.sysmon_operational" and event.code : "1"

# Suspicious PowerShell invocation (Sysmon or PS operational)
process.name : "powershell.exe" and process.command_line : (*-enc* or *bypass* or *EncodedCommand* or *IEX* or *DownloadString*)

# Caldera sandcat beaconing
destination.ip : "192.168.56.30" and destination.port : 8888

# LSASS memory access (credential dumping — Sysmon event 10)
event.dataset : "windows.sysmon_operational" and event.code : "10" and winlog.event_data.TargetImage : *lsass.exe

# Network connections by non-browser processes (Sysmon event 3)
event.dataset : "windows.sysmon_operational" and event.code : "3" and not process.name : ("chrome.exe" or "firefox.exe" or "msedge.exe")

# Scheduled task creation (persistence)
event.dataset : "windows.sysmon_operational" and event.code : "1" and process.name : "schtasks.exe"

# PowerShell script block logging — encoded/suspicious content
event.dataset : "windows.powershell_operational" and event.code : "4104" and winlog.event_data.ScriptBlockText : (*invoke* or *bypass* or *encoded* or *iex*)
```

---

## Lab Management

```bash
# SSH into a Linux VM
vagrant ssh elastic-siem
vagrant ssh caldera

# RDP into Windows 11
vagrant rdp win11-victim

# Suspend / resume all VMs
vagrant suspend
vagrant resume

# Tear down and rebuild everything
vagrant destroy -f
bash setup.sh          # or .\setup.ps1 on Windows

# Rebuild a single VM
vagrant destroy win11-victim -f
vagrant up win11-victim --provision

# Re-provision without destroying
vagrant provision elastic-siem
```

### Re-deploying the Caldera sandcat agent

If the agent stops beaconing (e.g., after the VM is rebuilt), re-deploy it without a full reprovision:

```bash
vagrant up win11-victim
vagrant provision win11-victim --provision-with deploy_caldera_agent
```

Or run the standalone script manually over WinRM:

```bash
vagrant winrm win11-victim -e -c "powershell -ExecutionPolicy Bypass -File C:\\vagrant\\scripts\\deploy_caldera_agent.ps1"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `curl: (22) 404` when downloading vagrant-vmware-utility | Old URL format tried a `.zip` that doesn't exist on Linux | `setup.sh` downloads the `.deb` directly — ensure you're running the current version |
| `sudo: a terminal is required` | Running `setup.sh` without a TTY (e.g., from a non-interactive shell) | Run from a proper terminal: `bash setup.sh` |
| `A Vagrant environment or target machine is required` | Vagrant can't find the Vagrantfile | Always run `setup.sh` from the `hunt_lab/` directory, or the script does `cd` automatically |
| `vmrun -T player snapshot … Error: not supported` | Plugin tries to create a linked clone; VMware Player mode doesn't support snapshots | Already fixed: `v.linked_clone = false` is set in all three provider blocks |
| `The provider 'vmware_desktop' could not be found` when running as root | Vagrant plugins are per-user; root has a separate plugin directory | Run `sudo vagrant plugin install vagrant-vmware-desktop` before re-running as root |
| `Permission denied @ rb_sysopen … .vmx (Errno::EACCES)` | A previous `sudo` run left `.vagrant/` owned by root | `sudo chown -R $USER:$USER .vagrant && vagrant destroy -f && vagrant up` |
| `Unable to create logs dir /usr/share/elasticsearch/logs` (exit 78) | `elasticsearch.yml` overwrite removed the default `path.logs` setting | Fixed in `install_elastic.sh`: explicit `path.data` and `path.logs` set |
| `gpg: cannot open '/dev/tty'` on re-provision | GPG prompts interactively to overwrite an existing keyring file | Fixed in `install_elastic.sh`: `gpg --batch --yes --dearmor` |
| `win11-victim` network adapter gets `169.254.x.x` (APIPA) | Vagrant cannot auto-configure the secondary VMware adapter on Windows | Fixed in `install_win_tools.ps1`: APIPA adapter is detected and statically assigned `192.168.56.20/24` |
| Fleet Server connection refused on port 8220 | Fleet Server bound to `localhost` only | Fixed in `install_elastic.sh`: `--fleet-server-host=0.0.0.0` |
| Caldera container restart-loops: `TypeError: encoding without a string argument` | `crypt_salt` and `encryption_key` missing from `local.yml` | Fixed in `install_caldera.sh`: both keys are written to the config template |
| Caldera login loops back to `/login` with correct credentials | Magma Vue UI built without `VITE_CALDERA_URL`; all API calls go to the user's localhost | Fixed in `install_caldera.sh`: build step sets `VITE_CALDERA_URL=http://192.168.56.30:8888` |
| Sandcat agent downloads but never beacons | Process launched with `Start-Process` inside WinRM session dies when session closes | Fixed in `install_win_tools.ps1`: agent registered as a Scheduled Task and started via `Start-ScheduledTask` |
| `vagrant provision` reports exit 1 even though script output shows "complete" | PS 5.1 `NativeCommandError` from native-EXE stderr (Sysmon, elastic-agent) propagates through the WinRM shell | Fixed in `install_win_tools.ps1`: `Start-Process -RedirectStandardOutput/-RedirectStandardError` runs Sysmon and elastic-agent with I/O redirected at OS level so PS never sees their stderr |
| `CloneFolderNotFolder` error during `vagrant up win11-victim` | VMware's background VM-discovery service deletes the clone directory while the 16 GB disk is still being copied by the plugin's full-copy loop | Already fixed in Vagrantfile: `v.force_vmware_license = "workstation"` + `v.linked_clone = true` forces `vmrun -T ws` linked clones instead of a file copy |
| `elastic-agent: Error: already installed` on re-provision | A prior partial run installed the agent; re-provisioning hits the guard and `$ErrorActionPreference = Stop` exits the script | Already fixed in `install_win_tools.ps1`: pre-install check skips the install if the service already exists |
| `Timed out while waiting for the machine to boot` on `vagrant reload win11-victim` | Windows 11 exceeds Vagrant's 300-second default WinRM boot timeout | Already fixed in Vagrantfile: `win.vm.boot_timeout = 600` |
| Elastic Agent shows `HEALTHY` in Fleet but zero documents appear in Discover | Fleet default output is `localhost:9200` — correct for the Fleet Server VM but wrong for remote agents; win11-victim has no Elasticsearch on its loopback | Already fixed in `install_elastic.sh`: output is patched to `http://192.168.56.10:9200` immediately after Fleet is ready |
| No Sysmon / PowerShell / Defender events in Kibana despite agent being online | `Windows Endpoint Policy` only had the `system` integration — the `windows` package (winlog inputs) was not configured | Already fixed in `install_elastic.sh`: `windows-1` package policy (Sysmon, PowerShell operational, Defender channels) is added to the policy via Fleet API on every provision |
| VMs don't appear in VMware Workstation GUI | Vagrant manages them outside the GUI's default library | Open them manually: **File → Open** → browse to `.vagrant/machines/<name>/vmware_desktop/<name>.vmx` |
| `setup.ps1` says VMware not installed, but it is (non-C: drive) | `Get-Command vmrun` only searches `%PATH%`; installer on non-default drives may not update PATH | Fixed in `setup.ps1`: falls back to registry `HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation\InstallPath` and adds the directory to PATH for the session |
