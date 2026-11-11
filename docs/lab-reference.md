# Additional Hunt Lab reference

[Back to War Wagon](../README.md) · [Local setup](local-setup.md)

These are additional lab capabilities, not the workshop exercise. The current
build still installs LocalStack, seeds the RansomHub and identity scenarios, and
includes Velociraptor and Atomic Red Team. Tracecat is an optional overlay.
Their presence does not mean attendees should execute them during the workshop.

The workshop starts with [Discovery Before Collection](../workshops/war-wagon/training-report.md).

## Built-in scenarios

### 1. DFIR-RansomHub-2025-Lab — endpoint chain

A faithful recreation of The DFIR Report's
[*"Hide Your RDP: Password Spray Leads to RansomHub Deployment"*](https://thedfirreport.com/reports/)
(2025-06). Thirteen Caldera abilities + three dwell-time abilities chain through
recon → credential theft → discovery → defense evasion → exfil-to-S3 →
shadow-copy delete → benign "encryptor" → log clearing → cloud-credential
persistence.

Run it: Caldera → **Operations → New Operation → Adversary
`DFIR-RansomHub-2025-Lab`, Group `red`, Start**.

- Scenario details, dwell-time tuning, hunt cheat-sheet:
  [`scripts/scenarios/ransomhub/README.md`](../scripts/scenarios/ransomhub/README.md).
- ATT&CK Navigator layer:
  [`attack_navigator/ransomhub_layer.json`](../attack_navigator/ransomhub_layer.json).

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
  [`scripts/scenarios/identity_chain/README.md`](../scripts/scenarios/identity_chain/README.md).
- ATT&CK Navigator layer:
  [`attack_navigator/identity_chain_layer.json`](../attack_navigator/identity_chain_layer.json).

### What's seeded automatically

- **Bootstrap container** creates `s3://ransomhub-exfil-lab` in LocalStack
  and pushes both adversaries (RansomHub + Identity Chain) into Caldera.
- **`win-server` provisioner** stages 105 decoy files under `C:\Shares\Finance\`
  and publishes the SMB share.
- **`win-dc` provisioner** registers the kerberoastable SPN
  `HTTP/finance.lab.local` on `svc-deploy`.
- **Each Windows VM** registers a sandcat agent in Caldera group `red`.

---

## DFIR benchmark bundles — Find Evil with a known answer key

Every Caldera operation that runs in this lab can be turned into a
distributable DFIR benchmark: a per-host triage collection plus a
machine-readable **ground-truth manifest** that records exactly which
ATT&CK techniques fired, on which host, at what time, and with what
command. Analysts can play "Find Evil" against the triage; tool authors
can score their findings against the manifest.

There are two ways to use this — pick one based on whether you want to
run the lab yourself.

### Path A — Just give me a dataset (no lab required)

Skip the lab entirely. Pre-built bundles are published as
[GitHub Releases](https://github.com/rjonhaas/hunt_lab/releases). Each
release has **two assets**:

- `evidence_<op_id>.zip` — Sysmon EVTX, all Windows event logs, registry
  hives, `$MFT`, `$UsnJrnl`, Prefetch, Amcache, PSReadline, browser
  history, scheduled tasks, Recycle Bin, for every host the operation
  touched. Plus an analyst-safe `op_metadata.json` (time window and host
  list — no scenario name, no technique list).
- `ground_truth_<op_id>.json` — per-event answer key for the benchmark.
  Used by scorers; downloading it before doing the analysis spoils the
  Find Evil challenge.

If you're playing analyst, download only the zip:

```bash
# Replace v1.0-rh-2026-06-06 with the latest release tag
curl -L -O https://github.com/rjonhaas/hunt_lab/releases/download/v1.0-rh-2026-06-06/evidence_<op_id>.zip
unzip evidence_<op_id>.zip -d find-evil-rh/
ls find-evil-rh/        # win-dc/  win-server/  win11-victim/  op_metadata.json
```

If you're scoring an AI / DFIR tool, download both — `ground_truth.json`
is the source of truth for precision/recall. The split is deliberate:
two separate downloads means "I want to be blind" vs "I want to score"
is a deliberate choice the participant makes, not something they
accidentally trip over.

### Path B — Run the lab and generate your own bundle

Use this if you want a fresh run, a different scenario, longer dwell
times to model real attacker tempo, or to experiment with the harness
itself. Total time end-to-end on a clean clone: roughly 4–6 hours
(mostly Windows VM provisioning on first bring-up — subsequent runs are
~30 min from "Caldera ready" to "bundle on disk").

```bash
# 1. Bring up the lab (skip if already running). docker/setup.sh is run
#    *inside* docker-host by its provisioner — you only invoke `vagrant up`.
vagrant up docker-host
vagrant up win-dc win-server win11-victim --no-parallel

# 2. Verify all three sandcat agents are healthy in Caldera group `red`
curl -sS -H "KEY: ADMIN123" http://192.168.56.10:8888/api/v2/agents \
  | jq '[.[] | select(.group=="red")] | map({host, trusted, last_seen})'

# 3. Launch a scenario in the Caldera UI (or via API) and note its operation id
#    UI: http://192.168.56.10:8888  (admin / HuntLab2026!)
#         Operations → New Operation → Adversary: DFIR-RansomHub-2025-Lab,
#         Group: red, Auto-run → Start
#    Op id is in the URL once the op is open, or:
curl -sS -H "KEY: ADMIN123" http://192.168.56.10:8888/api/v2/operations \
  | jq 'map({id, name, state})'

# 4. Wait for the op to finish (~26 min for the RansomHub chain at default dwell)

# 5. Generate the benchmark bundle
python3 scripts/make_benchmark_bundle.py <op_id>
```

The bundle lands at `~/dfir_answers/<op_id>/`:

```
~/dfir_answers/<op_id>/
├── README.md                          # scenario brief + analyst hints + manifest schema
├── ground_truth/
│   └── ground_truth.json              # answer key (per-event ts, host, technique, command, status, facts)
├── evidence/
│   ├── op_metadata.json               # scenario metadata, no answers — safe to share
│   ├── velo_collections.json          # which Velo flow_id produced each tar
│   └── <hostname>/C.<client>_F.<flow>.tar
└── evidence_<op_id>.zip               # zipped evidence/ — ready to upload to a GitHub Release
```

Under the hood, three scripts do the work:

| Script                              | What it does                                                     |
|-------------------------------------|------------------------------------------------------------------|
| `extract_ground_truth.py <op_id>`   | Pulls Caldera op + op-scoped links, emits normalized manifest.   |
| `velo_collect.py --all-windows -o…` | Triggers a SANS-style Velo triage on each Windows host.          |
| `make_benchmark_bundle.py <op_id>`  | Runs both, writes the bundle README, zips the evidence portion.  |

All three honor `CALDERA_URL` / `CALDERA_API_KEY` env overrides and have
`--help`.

### Getting the evidence onto your analysis VM

After `make_benchmark_bundle.py` finishes you have ~600 MB of triage tars
on the host. To analyze them you'll want to move just the **evidence**
portion (never the ground truth — that would invalidate your own
benchmark) onto whatever DFIR workstation you use.

The harness ships two transfer flags. **Use `--scp-evidence-to` if your
analysis VM is reachable over SSH** (cleanest, one command, no shared
folder plumbing); fall back to `--copy-evidence-to` for shared-folder
setups where SSH isn't an option.

```bash
# Preferred — scp the evidence/ subtree straight to a SIFT (or any) VM.
# Uses your ~/.ssh/config and ssh-agent; set up key auth first.
python3 scripts/make_benchmark_bundle.py <op_id> \
  --scp-evidence-to sansforensics@192.168.2.149:~/Desktop/cases/<op_id>

# Alternative — drop into a local dir (often a VMware host-only shared
# folder mounted into the analysis VM).
python3 scripts/make_benchmark_bundle.py <op_id> \
  --copy-evidence-to ~/Downloads/<op_id>
```

Both flags copy ONLY the `evidence/` subtree — `ground_truth.json` stays
under `~/dfir_answers/<op_id>/ground_truth/` no matter what. If you want
to score a tool, the ground-truth file is small enough to copy by hand
or grab from the GitHub Release.

Three common destination patterns:

- **SSH-reachable analysis VM (recommended for SIFT).** Set up
  passwordless key auth once, then `--scp-evidence-to` does the
  end-to-end transfer in one command. Standard SANS SIFT image uses
  `sansforensics@<sift-ip>`. The flag pre-creates the remote directory
  via `ssh mkdir -p`, so the destination doesn't need to exist.

- **VMware shared folder into a Linux analysis VM (fallback).** Add a
  *read-only* shared folder on the VM pointing at your transfer dir
  (e.g. host path `/home/<you>/Downloads`, guest name `case`). The guest
  sees it at `/mnt/hgfs/case/`. Read-only is intentional — it physically
  prevents the analysis VM from writing back into host paths that hold
  answer keys.
  ```bash
  # On host:
  python3 scripts/make_benchmark_bundle.py <op_id> --copy-evidence-to ~/Downloads/<op_id>
  # In the VM:
  cp -r /mnt/hgfs/case/<op_id> ~/cases/
  ```

- **Local analysis on the same host.** Just extract a tar wherever you
  want and point your DFIR tools at it (URL-encoded paths inside —
  `%5C` = `\`, `%3A` = `:`):
  ```bash
  mkdir -p analysis/win-dc && tar xf ~/dfir_answers/<op_id>/evidence/win-dc/C.*.tar -C analysis/win-dc
  ```

The triage tars come in Velociraptor's on-disk format: paths are
URL-encoded under `uploads/ntfs/...`. Most DFIR tooling (EvtxECmd,
MFTECmd, RegRipper, Plaso) doesn't care about path shape — point it at
the relevant files. For a fully rehydrated `C:\Windows\...` layout, use
Velociraptor's `Windows.KapeFiles.Extract` artifact against the original
collection (kept in the Velo container's datastore), or unpack and
rename by hand.

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
   [`kibana/README.md`](../kibana/README.md)).
4. **Watch for alerts** — 21 Elastic Security detection rules (13 RansomHub +
   8 Identity-Chain) are auto-imported by the bootstrap container. Find them
   in **Security → Rules**, and matching alerts in **Security → Alerts**.
   NDJSON sources: [`kibana/detection_rules/`](../kibana/detection_rules/).

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
