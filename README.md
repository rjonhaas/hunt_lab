# Hunt Lab — Elastic SIEM + MITRE Caldera + Active Directory + LocalStack + Tracecat SOAR

A self-contained threat hunting lab. One Linux VM runs the SIEM stack, C2
framework, and a simulated AWS environment as Docker containers; an optional
TraceCat SOAR overlay closes the detection-to-response loop via Kibana webhooks
and automated playbooks. Three Windows VMs (`win-dc`, `win-server`,
`win11-victim`) form an Active Directory domain preloaded with Sysmon, Elastic
Agent, MITRE Caldera sandcat, and Atomic Red Team — ready to hunt as soon as
`vagrant up` finishes.

The lab also ships with two fully wired-up Caldera scenarios that exercise
complementary detection surfaces:

- **DFIR-RansomHub-2025-Lab** — recreation of The DFIR Report's June 2025
  RansomHub case (endpoint-heavy: process / file / DNS / S3 exfil).
- **Identity-Chain-2025-Lab** — Kerberoasting → DCSync → Golden Ticket →
  Pass-the-Ticket (identity-side: 4769, 4662, Mimikatz patterns).

Both adversaries, all abilities, decoy data, and the S3 exfil target are
seeded automatically.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                  Host-Only Network: 192.168.56.0/24                     │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  docker-host          192.168.56.10        Ubuntu 22.04          │   │
│  │  ─────────────────────────────────────────────────────────────   │   │
│  │  Elasticsearch  Kibana  Fleet Server  Caldera  LocalStack        │   │
│  │  Filebeat       CloudTrail-gen        bootstrap (one-shot)       │   │
│  │  Tracecat (optional SOAR overlay — see docker-compose.tracecat)  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│         ▲                  ▲                  ▲                         │
│         │ Fleet            │ sandcat C2       │ S3 exfil target         │
│         │                  │                  │                         │
│  ┌──────┴───────┐  ┌───────┴──────┐  ┌────────┴─────────┐              │
│  │  win-dc      │  │  win-server  │  │  win11-victim    │              │
│  │ 192.168.56.50│  │192.168.56.51 │  │  192.168.56.20   │              │
│  │  WinSrv 2022 │  │  WinSrv 2022 │  │  Windows 11      │              │
│  │  AD DS / DNS │  │  Domain mbr  │  │  Domain member   │              │
│  │  lab.local   │  │  Finance SMB │  │                  │              │
│  └──────────────┘  └──────────────┘  └──────────────────┘              │
│                                                                         │
│  All Windows VMs ship with: Sysmon (SwiftOnSecurity) + Elastic Agent    │
│  + Caldera sandcat (group: red) + Atomic Red Team                       │
└─────────────────────────────────────────────────────────────────────────┘
```

### VM inventory

| VM            | IP             | OS                  | RAM   | CPUs | Role                                     |
|---------------|----------------|---------------------|-------|------|------------------------------------------|
| `docker-host` | 192.168.56.10  | Ubuntu 22.04        | 12 GB | 4    | SIEM + C2 + cloud-sim Docker stack       |
| `win11-victim`| 192.168.56.20  | Windows 11          | 4 GB  | 2    | Victim workstation (domain member)       |
| `win-dc`      | 192.168.56.50  | Windows Server 2022 | 4 GB  | 2    | Active Directory DC + DNS (`lab.local`)  |
| `win-server`  | 192.168.56.51  | Windows Server 2022 | 2 GB  | 2    | Domain member; hosts the SMB Finance share |

### Container inventory (running on `docker-host`)

| Container        | Port      | Role                                          |
|------------------|-----------|-----------------------------------------------|
| `elasticsearch`  | 9200      | Log/event store                               |
| `kibana`         | 5601      | SIEM UI                                       |
| `fleet-server`   | 8220      | Elastic Agent management                      |
| `caldera`        | 8888      | MITRE Caldera 5.x (C2 / adversary emulation)  |
| `localstack`     | 4566      | Simulated AWS (S3, IAM, CloudTrail, Lambda…)  |
| `velociraptor`   | 8889/8000 | DFIR endpoint visibility (GUI / client comms) |
| `filebeat`       | —         | Ships CloudTrail JSON to Elasticsearch        |
| `cloudtrail-gen` | —         | Tails LocalStack request logs and emits a CloudTrail event per real API call |
| `bootstrap`      | —         | One-shot init (writes Fleet token, seeds Caldera abilities, creates S3 bucket) |

**Optional SOAR overlay** (`docker-compose.tracecat.yml` — see [SOAR / Tracecat](#soar--tracecat-optional)):

| Container               | Port | Role                                        |
|-------------------------|------|---------------------------------------------|
| `tracecat-caddy`        | 8089 | Reverse proxy for Tracecat UI + API         |
| `tracecat-api`          | —    | Tracecat REST API + webhook receiver        |
| `tracecat-worker`       | —    | Temporal workflow worker                    |
| `tracecat-executor`     | —    | Action executor (HTTP, scripts, integrations) |
| `tracecat-ui`           | —    | Next.js SOAR frontend                       |
| `tracecat-temporal`     | —    | Temporal workflow engine                    |
| `tracecat-postgres`     | —    | Tracecat application database               |
| `tracecat-temporal-postgres` | — | Temporal history database              |
| `tracecat-redis`        | —    | Workflow queue / cache                      |
| `tracecat-minio`        | —    | Artifact / blob storage                     |
| `tracecat-migrations`   | —    | One-shot DB schema migration                |

---

## Host requirements

| Resource | Minimum   | Recommended | With Tracecat overlay |
|----------|-----------|-------------|----------------------|
| RAM      | 24 GB     | 32 GB       | 32 GB minimum         |
| CPU      | 6 cores   | 8+ cores    | 8+ cores              |
| Disk     | 150 GB    | 250 GB      | +10 GB                |
| OS       | Windows 10/11 or Linux | — |

**Required software (install manually before running setup):**

| Software                | Version | Where                                                                             |
|-------------------------|---------|-----------------------------------------------------------------------------------|
| VMware Workstation Pro  | 17+     | [vmware.com](https://www.vmware.com/products/workstation-pro.html) (free for personal use) |
| Vagrant                 | 2.3+    | [developer.hashicorp.com/vagrant/install](https://developer.hashicorp.com/vagrant/install) |

The setup script installs the `vagrant-vmware-utility` service and the
`vagrant-vmware-desktop` plugin automatically.

---

## Quick start

### Linux / macOS

```bash
git clone <repo-url> hunt_lab
cd hunt_lab
chmod +x setup.sh
./setup.sh
```

### Windows

Open an **elevated PowerShell** prompt:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd C:\path\to\hunt_lab
.\setup.ps1
```

Both scripts do the same thing in the same order:

1. Verify VMware and Vagrant are installed; install the `vagrant-vmware-utility`
   service and `vagrant-vmware-desktop` plugin if missing.
2. Download Vagrant boxes (Ubuntu 22.04 ~700 MB, Windows 11 ~10 GB,
   Windows Server 2022 ~8 GB).
3. `vagrant up docker-host` — provisions Docker, runs `docker/setup.sh` inside
   the VM, which writes `fleet-enrollment-token.txt` and `elastic-credentials.txt`
   back to the repo root via the synced `/vagrant` folder.
4. `vagrant up win-dc` — promotes the DC, creates OUs/users, writes
   `domain-info.txt`, deploys agents.
5. `vagrant up win-server` — joins domain, deploys agents, seeds the decoy
   `Finance` SMB share.
6. `vagrant up win11-victim` — joins domain, deploys agents.

**First-run time: 30–45 minutes** (mostly box downloads and Windows reboots).

If a step fails, re-run only that VM: `vagrant up <name> --provision`.

---

## Accessing the lab

| Service           | URL / Address              | Credentials                               |
|-------------------|----------------------------|-------------------------------------------|
| Kibana (SIEM)     | http://192.168.56.10:5601  | `elastic` / see `elastic-credentials.txt` |
| Caldera (C2)      | http://192.168.56.10:8888  | `admin` / `HuntLab2026!`                  |
| Velociraptor (DFIR)| https://192.168.56.10:8889 | `admin` / `HuntLab2026!` (set in `docker/.env`, self-signed TLS) |
| Fleet Server      | http://192.168.56.10:8220  | internal — used by Elastic Agent          |
| LocalStack API    | http://192.168.56.10:4566  | local test credentials (`test` / `test`)  |
| Elasticsearch API | http://192.168.56.10:9200  | same as Kibana                            |
| Tracecat (SOAR)   | http://192.168.56.10:8089  | email set in `.env.tracecat` / password on first login (optional overlay) |
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

## Built-in scenarios

### 1. DFIR-RansomHub-2025-Lab — endpoint chain

A faithful recreation of The DFIR Report's
[*"Hide Your RDP: Password Spray Leads to RansomHub Deployment"*](https://thedfirreport.com/reports/)
(2025-06). Twelve Caldera abilities + three dwell-time abilities chain through
recon → credential theft → discovery → defense evasion → exfil-to-S3 →
shadow-copy delete → benign "encryptor" → log clearing.

Run it: Caldera → **Operations → New Operation → Adversary
`DFIR-RansomHub-2025-Lab`, Group `red`, Start**.

- Scenario details, dwell-time tuning, hunt cheat-sheet:
  [`scripts/scenarios/ransomhub/README.md`](scripts/scenarios/ransomhub/README.md).
- ATT&CK Navigator layer:
  [`attack_navigator/ransomhub_layer.json`](attack_navigator/ransomhub_layer.json).

### 2. Identity-Chain-2025-Lab — Kerberos chain

Six attack abilities + two dwell abilities covering Kerberoasting → DCSync →
Golden Ticket → Pass-the-Ticket. Stresses Kerberos telemetry (4769 RC4 TGS,
4662 directory replication, Mimikatz command-line patterns) instead of the
RansomHub chain's process/file telemetry — useful for showing different
detection primitives off the same lab.

Run it: Caldera → **Operations → New Operation → Adversary
`Identity-Chain-2025-Lab`, Group `red`, Start** (manually pick agents per
ability — DCSync targets `win-dc`, the rest run on `win-server`; the scenario
README explains why).

- Scenario details, targeting matrix, hunt cheat-sheet:
  [`scripts/scenarios/identity_chain/README.md`](scripts/scenarios/identity_chain/README.md).
- ATT&CK Navigator layer:
  [`attack_navigator/identity_chain_layer.json`](attack_navigator/identity_chain_layer.json).

### What's seeded automatically

- **Bootstrap container** creates `s3://ransomhub-exfil-lab` in LocalStack
  and pushes both adversaries (RansomHub + Identity Chain) into Caldera.
- **`win-server` provisioner** stages 105 decoy files under `C:\Shares\Finance\`
  and publishes the SMB share.
- **`win-dc` provisioner** registers the kerberoastable SPN
  `HTTP/finance.lab.local` on `svc-deploy`.
- **Each Windows VM** registers a sandcat agent in Caldera group `red`.

---

## Threat hunting workflow

1. **Adversary emulation** — pick an operation in Caldera (the RansomHub
   chain, or run individual Atomic Red Team techniques via
   `Invoke-AtomicTest` on any Windows VM).
2. **Telemetry collection** — Sysmon (SwiftOnSecurity config) + Windows event
   channels are forwarded by Elastic Agent to Fleet → Elasticsearch.
   CloudTrail-style events from LocalStack flow in via Filebeat.
3. **Hunt in Kibana** — start in **Discover** with the `logs-*` data view, or
   open the prebuilt **HL - Threat Hunt Report Template** dashboard
   (auto-imported on Windows host runs; manual import steps in
   [`kibana/README.md`](kibana/README.md)).
4. **Watch for alerts** — 21 Elastic Security detection rules (13 RansomHub +
   8 Identity-Chain) are auto-imported by the bootstrap container. Find them
   in **Security → Rules**, and matching alerts in **Security → Alerts**.
   NDJSON sources: [`kibana/detection_rules/`](kibana/detection_rules/).

### Useful Kibana indices

| Index pattern                            | Content                                        |
|------------------------------------------|------------------------------------------------|
| `logs-windows.sysmon_operational-*`      | Process / network / file / registry events     |
| `logs-windows.powershell_operational-*`  | PS script-block logging (4103/4104)            |
| `logs-system.security-*`                 | Windows Security event log                     |
| `logs-system.system-*`                   | Windows System event log                       |
| `logs-aws.cloudtrail-*` (via filebeat)   | LocalStack CloudTrail-style events             |

### Starter KQL queries

```kql
# All Sysmon process creation from the victim
event.dataset : "windows.sysmon_operational" and event.code : "1"
  and agent.hostname : "win11-victim"

# LSASS memory access (credential dumping — Sysmon Event 10)
event.dataset : "windows.sysmon_operational" and event.code : "10"
  and winlog.event_data.TargetImage : *lsass.exe

# Suspicious PowerShell
process.name : "powershell.exe"
  and process.command_line : (*-enc* or *bypass* or *DownloadString* or *IEX*)

# AD: user added to Domain Admins (Security 4728)
event.dataset : "system.security" and event.code : "4728"

# AD: failed logon — brute force / password spray (4625)
event.dataset : "system.security" and event.code : "4625"

# Lateral movement: remote service creation (System 7045)
event.dataset : "system.system" and event.code : "7045"

# Caldera sandcat beaconing
destination.ip : "192.168.56.10" and destination.port : 8888

# CloudTrail S3 access in LocalStack
event.dataset : "aws.cloudtrail" and cloud.service.name : "s3.amazonaws.com"
```

---

## SOAR / Tracecat (optional)

Tracecat is a self-hosted SOAR platform (think open-source Tines) that closes
the detection-to-response loop: Kibana fires a webhook when a detection rule
hits, Tracecat receives it and executes a playbook.

### What it adds

- **Webhook receiver** — Kibana Connector → Webhook → `http://192.168.56.10:8089/api/webhooks/<id>`
- **Automated enrichment** — playbook steps can query Elasticsearch for full
  process trees, pull Caldera operation status, and call LocalStack IAM APIs
  directly (api/worker/executor containers share `hunt_net`).
- **Case management** — each triggered playbook creates a case pre-populated
  with alert context.
- **Scenario playbooks** (build after standing up the overlay):
  - *RansomHub*: S3 exfil alert → pull bucket objects from LocalStack → build
    incident timeline.
  - *Identity Chain*: Kerberoasting alert → correlate 4769 + DCSync events →
    assemble attack chain.

### Setup

```bash
# On docker-host, from /vagrant/docker:
cp .env.tracecat.example .env.tracecat

# Generate the four required secrets (run each command, paste output into .env.tracecat):
openssl rand -hex 32   # → TRACECAT__SERVICE_KEY
openssl rand -hex 32   # → TRACECAT__SIGNING_SECRET
openssl rand -hex 32   # → USER_AUTH_SECRET
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
                       # → TRACECAT__DB_ENCRYPTION_KEY

# Set your superadmin email, then start the overlay:
docker compose -f docker-compose.tracecat.yml --env-file .env.tracecat up -d

# Watch startup (Temporal takes ~30 s to initialize):
docker compose -f docker-compose.tracecat.yml --env-file .env.tracecat logs -f
```

Once healthy, open `http://192.168.56.10:8089`, sign in with the superadmin
email and a password of your choice (set on first login), and create your first
workflow.

### Connecting Kibana alerts to Tracecat

1. In Kibana → **Stack Management → Connectors → Create connector → Webhook**.
2. URL: `http://172.20.0.1:8089/api/webhooks/<tracecat-workflow-id>`  
   *(use the Docker bridge gateway IP `172.20.0.1` — Kibana is on `hunt_net`
   and Tracecat-caddy is exposed on the host; alternatively use the host's
   LAN IP `192.168.56.10:8089` if routing allows)*.
3. Edit a detection rule → **Actions → On each alert → your webhook connector**.

### Resource note

The overlay adds ~8 GB RAM at idle (Temporal + two Postgres instances + Redis +
MinIO + API/worker/executor). Ensure the `docker-host` VM has at least **20 GB
RAM** assigned (Vagrantfile default is 12 GB — increase `v.memory` in the
`docker-host` block before provisioning if you plan to run Tracecat).

---

## Project structure

```
hunt_lab/
├── setup.sh                                  # Linux/macOS quick-start
├── setup.ps1                                 # Windows quick-start
├── Vagrantfile                               # Defines the 4 lab VMs
├── docker/
│   ├── docker-compose.yml                    # SIEM + C2 + LocalStack stack
│   ├── docker-compose.tracecat.yml           # Optional SOAR overlay (Tracecat)
│   ├── setup.sh                              # Runs inside docker-host
│   ├── .env.example                          # Copy to .env (HOST_IP, passwords)
│   ├── .env.tracecat.example                 # Copy to .env.tracecat (Tracecat secrets)
│   ├── bootstrap/
│   │   ├── bootstrap.sh                      # One-shot init (Fleet, Caldera, S3)
│   │   └── generate_cloudtrail_activity.sh   # Synthetic AWS event emitter
│   ├── cloudtrail/                           # Filebeat input directory
│   └── config/
│       ├── caldera/local.yml                 # Caldera config (HOST_IP injected)
│       ├── filebeat/filebeat.yml             # Ships CloudTrail logs to ES
│       └── tracecat/Caddyfile                # Caddy reverse proxy for Tracecat
├── kibana/
│   ├── hunt_report_template.ndjson           # Saved-objects export
│   ├── create_all_objects.py                 # Programmatic object creation
│   ├── generate_template.py                  # Regenerate the NDJSON
│   └── README.md
└── scripts/
    ├── install_docker.sh                     # docker-host: Docker Engine + Compose
    ├── setup_dc.ps1                          # win-dc stage 1: AD DS + DC promotion
    ├── setup_dc_post_reboot.ps1              # win-dc stage 2: OUs/users + agents
    ├── setup_win_server.ps1                  # win-server stage 1: domain join
    ├── setup_win_server_tools.ps1            # win-server stage 2: agents
    ├── install_win_tools.ps1                 # win11-victim: Sysmon + Elastic Agent
    ├── join_domain.ps1                       # win11-victim: domain join
    ├── deploy_caldera_agent.ps1              # Standalone sandcat (re)deploy
    ├── install_atomic_red_team.ps1           # Invoke-AtomicRedTeam + atomics library
    ├── caldera_ransomhub_setup.py            # Pushes RansomHub abilities/adversary
    ├── caldera_identity_setup.py             # Pushes Identity-Chain abilities/adversary
    └── scenarios/
        ├── ransomhub/                        # DFIR-RansomHub-2025-Lab assets
        │   ├── README.md
        │   ├── seed_decoy_data.ps1           # Stages C:\Shares\Finance\
        │   ├── seed_localstack_bucket.sh     # Creates s3://ransomhub-exfil-lab
        │   ├── fake_amd64.ps1                # Benign rename-and-note simulator
        │   ├── nocmd.vbs / rcl.bat / include.txt  # Exfil wrapper artifacts
        │   └── ransom_note.txt
        └── identity_chain/                   # Identity-Chain-2025-Lab assets
            └── README.md                     # Targeting matrix + hunt cheat-sheet
```

**Files generated at runtime (git-ignored):**

| File                          | Written by                       | Consumed by                  |
|-------------------------------|----------------------------------|------------------------------|
| `elastic-credentials.txt`     | bootstrap container              | `setup.ps1`, you             |
| `fleet-enrollment-token.txt`  | bootstrap container              | All Windows agent installs   |
| `domain-info.txt`             | `setup_dc_post_reboot.ps1`       | `setup_win_server.ps1`, `join_domain.ps1` |

---

## Lab management

```bash
# Where to look
vagrant ssh docker-host -c 'cd /vagrant/docker && sudo docker compose logs -f'
vagrant rdp win-dc        # or win-server, win11-victim

# Re-run a single provisioner step
vagrant provision win-dc --provision-with setup_dc_post_reboot
vagrant provision win-server --provision-with seed_ransomhub_decoy

# Rebuild a single VM
vagrant destroy win11-victim -f
vagrant up win11-victim --provision

# Rebuild domain (destroy member before DC, otherwise the join guard fires)
vagrant destroy win-server win-dc -f
vagrant up win-dc --provision
vagrant up win-server --provision

# Re-deploy sandcat without full reprovision
vagrant provision <vm> --provision-with deploy_caldera_agent

# Tear it all down
vagrant destroy -f

# Restart just the container stack (data preserved)
vagrant ssh docker-host -c 'cd /vagrant/docker && sudo docker compose restart'

# Wipe container data and rebootstrap
vagrant ssh docker-host -c 'cd /vagrant/docker && sudo docker compose down -v && sudo bash setup.sh'
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `fleet-enrollment-token.txt not found` when bringing up a Windows VM | `docker-host` provisioning didn't finish | `vagrant up docker-host --provision` and wait for it to complete |
| `domain-info.txt not found` when bringing up `win-server` / `win11-victim` | `win-dc` stage 2 didn't finish | Check `C:\Windows\Temp\setup-dc-stage2.log` on `win-dc`; re-run `vagrant provision win-dc --provision-with setup_dc_post_reboot` |
| Elastic Agent shows `HEALTHY` in Fleet but Discover is empty | Fleet output still pointing at `localhost:9200` | The bootstrap container patches the output to `http://192.168.56.10:9200` — re-run `docker compose run --rm bootstrap` from `docker-host` |
| Caldera login loops back to `/login` | Magma UI built without `VITE_CALDERA_URL` | Already handled by the official 5.x image; ensure your `HOST_IP` in `docker/.env` is correct |
| Sandcat downloads but never beacons | Process started in a WinRM session and died on disconnect | Re-run `vagrant provision <vm> --provision-with deploy_caldera_agent` — the agent is registered as the `WindowsSecurityUpdate` scheduled task and started via `Start-ScheduledTask` |
| `vagrant up win-dc` hangs after promotion reboot | WinRM retries exhausted before AD finished coming online | `dc.winrm.retry_limit = 60` (15 min); if still hanging, re-run `vagrant provision win-dc --provision-with setup_dc_post_reboot` once the VM is back |
| `win11-victim` clone fails with `CloneFolderNotFolder` | VMware service interferes with the full-copy loop | Already handled in `Vagrantfile` — `force_vmware_license = "workstation"` + `linked_clone = true` forces `vmrun -T ws` linked clones |
| `setup.ps1` says VMware not installed (but it is) | VMware on a non-`C:` drive not on `%PATH%` | `setup.ps1` falls back to the registry `InstallPath` and adds it to `$env:PATH` for the session |
| `Permission denied` on `.vagrant/` after a `sudo` run | A prior `sudo vagrant` left `.vagrant/` owned by root | `sudo chown -R $USER:$USER .vagrant && vagrant destroy -f && vagrant up` |
| Elasticsearch OOMs / restart-loops | docker-host RAM too low | Increase `docker-host` `v.memory` in `Vagrantfile` (default 12 GB); Elastic alone wants ~4 GB |

---

## Notes

- This is a **lab environment**. Defender real-time protection is disabled on
  the victim, the domain has weak/known passwords, and HTTPS is off across the
  Elastic stack. Don't connect it to anything you care about.
- The RansomHub recreation runs a **benign** simulator (`fake_amd64.ps1` —
  rename-and-note only). No real encryption happens to the decoy share.
- LocalStack runs in Community mode by default. Drop a token into
  `localstack-auth-token.txt` at the repo root to enable Pro features.
