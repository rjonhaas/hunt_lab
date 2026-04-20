# Roadmap

## Current State (v1.0)

Three-VM threat hunting lab provisioned via `setup.sh`:

| VM | IP | Role |
|---|---|---|
| `elastic-siem` | 192.168.56.10 | Elasticsearch + Kibana + Fleet Server |
| `win11-victim` | 192.168.56.20 | Windows 11 + Sysmon + Elastic Agent |
| `caldera` | 192.168.56.30 | MITRE Caldera C2 + Sandcat |

---

## Phase 1 — Local Cloud Simulation VM

**Goal:** Add a 4th VM (`cloud-sim`) that emulates AWS infrastructure locally using LocalStack, so threat hunters can practice cloud security without incurring AWS costs.

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                 Host-Only Network: 192.168.56.0/24               │
│                                                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────┐ ┌────────────┐  │
│  │ elastic-siem │ │ win11-victim │ │ caldera  │ │ cloud-sim  │  │
│  │ .56.10       │ │ .56.20       │ │ .56.30   │ │ .56.40     │  │
│  │ Elastic+Fleet│◄│ Sysmon+Agent │►│ C2       │ │ LocalStack │  │
│  │              │◄─────────────────────────────│ Filebeat    │  │
│  └──────────────┘ └──────────────┘ └──────────┘ └────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### New VM: `cloud-sim` (192.168.56.40)

- **Box:** bento/ubuntu-22.04
- **RAM:** 4 GB / **CPUs:** 2
- **Services:**
  - LocalStack (Docker) — emulates S3, IAM, Lambda, STS, CloudTrail, CloudWatch, EC2
  - Filebeat — ships CloudTrail JSON logs to elastic-siem at 192.168.56.10:9200
  - Pre-loaded attack scenario logs bulk-ingested into Elastic on provisioning

### Updated host requirements

| Resource | Minimum | Recommended |
|---|---|---|
| RAM | 24 GB free | 28 GB free |
| Disk | 160 GB free | 200 GB free |

### Verification

1. `vagrant up cloud-sim` completes without errors
2. `awslocal s3 ls` from inside VM returns an empty bucket list (LocalStack is running)
3. Pre-loaded scenario logs visible in Kibana immediately after provisioning
4. KQL queries from README return expected matches against pre-loaded data

---

## Phase 2 — Interactive Cloud Attack Scripts

**Goal:** Provide standalone shell scripts a user can run inside `cloud-sim` to generate live CloudTrail events in real time against LocalStack, which flow into Elastic for immediate hunting.

### Scripts

- `run_s3_exfil.sh` — S3 data exfiltration (create bucket → upload PII → enumerate → download → delete evidence)
- `run_iam_privesc.sh` — IAM privilege escalation (low-priv user → discover overpermissive policy → attach admin → create backdoor user)
- `run_crypto_mining.sh` — Crypto mining (RunInstances with suspicious instance types and user-data)

### Verification

- Run `run_s3_exfil.sh` inside `cloud-sim` → within 60 seconds, events appear in Kibana under the `cloudtrail-*` index

---

## Phase 3 — Documentation

**Goal:** Update the README to cover the cloud simulation VM, new architecture diagram, updated requirements, cloud hunting workflow, and example CloudTrail KQL queries.

---

## Phase 4 — Caldera → Cloud Attack Automation

**Goal:** Create custom Caldera abilities and adversary profiles that launch ATT&CK-mapped cloud attacks against LocalStack autonomously. The user selects an adversary, clicks Start, and watches the full kill chain appear in Kibana — no manual CLI interaction required.

### How it works

```
Caldera C2 (192.168.56.30)
    │  deploys Sandcat agent + sends ability commands
    ▼
cloud-sim (192.168.56.40)
    │  Sandcat executes abilities via awslocal → LocalStack
    │  LocalStack generates CloudTrail events
    ▼
Filebeat → Elastic SIEM (192.168.56.10) → Kibana
    │
    ▼
Threat hunter sees the full ATT&CK kill chain in real time
```

### Adversary Profile 1: "Cloud Recon & Exfil"

Discovery → Collection → Exfiltration

| Step | Tactic | ATT&CK ID | Ability | Command |
|---|---|---|---|---|
| 1 | Discovery | T1526 | `cloud_service_discovery` | `awslocal sts get-caller-identity` + `awslocal s3 ls` |
| 2 | Discovery | T1580 | `cloud_infra_discovery` | `awslocal ec2 describe-instances` + `awslocal lambda list-functions` |
| 3 | Discovery | T1087.004 | `cloud_account_discovery` | `awslocal iam list-users` + `awslocal iam list-roles` |
| 4 | Collection | T1074 | `cloud_data_staging` | `awslocal s3 cp s3://target-bucket/secrets.csv /tmp/` |
| 5 | Exfiltration | T1537 | `cloud_exfil_s3` | `awslocal s3 sync /tmp/exfil s3://attacker-bucket/` |

### Adversary Profile 2: "IAM Privilege Escalation"

Discovery → Credential Access → Privilege Escalation → Persistence → Defense Evasion

| Step | Tactic | ATT&CK ID | Ability | Command |
|---|---|---|---|---|
| 1 | Discovery | T1526 | `cloud_service_discovery` | `awslocal sts get-caller-identity` |
| 2 | Credential Access | T1087.004 | `cloud_cred_enum` | `awslocal iam list-access-keys` + `list-attached-user-policies` |
| 3 | Privilege Escalation | T1078.004 | `iam_policy_attach` | `awslocal iam attach-user-policy --policy-arn ...AdministratorAccess` |
| 4 | Persistence | T1136.003 | `iam_create_user` | `awslocal iam create-user` + `create-access-key` |
| 5 | Defense Evasion | T1562.001 | `disable_cloudtrail` | `awslocal cloudtrail stop-logging` |

### Adversary Profile 3: "Crypto Mining via Cloud Compute"

Discovery → Execution → Defense Evasion

| Step | Tactic | ATT&CK ID | Ability | Command |
|---|---|---|---|---|
| 1 | Discovery | T1526 | `cloud_service_discovery` | `awslocal sts get-caller-identity` |
| 2 | Discovery | T1087.004 | `cloud_account_discovery` | `awslocal iam list-users` |
| 3 | Execution | T1496.001 | `cloud_run_instances` | `awslocal ec2 run-instances` (suspicious user-data) |
| 4 | Defense Evasion | T1070.004 | `delete_cloudtrail_logs` | `awslocal s3 rm s3://cloudtrail-logs/ --recursive` |

### Verification

1. Sandcat agent from `cloud-sim` appears in Caldera UI under group `cloud`
2. Running the "Cloud Recon & Exfil" operation completes all 5 steps
3. Corresponding CloudTrail events appear in Kibana `cloudtrail-*` index within 60 seconds

---

## Future Enhancements (Backlog)

- **Azure simulation** — add Azurite + Azure Activity Logs (pending Azure emulator maturity for audit logging)
- **Kubernetes attack scenarios** — add k3s to `cloud-sim` with Stratus Red Team integration for container-escape and RBAC bypass scenarios
- **Stratus Red Team integration** — run Stratus against LocalStack for additional ATT&CK techniques
- **Custom Elastic detection rules** — pre-loaded Elastic Security rules tuned for each cloud attack scenario, so alerts fire automatically during operations
- **Guided hunting notebooks** — Jupyter notebooks with step-by-step cloud threat hunting exercises using KQL
- **Multi-cloud adversary profiles** — Caldera adversaries that chain AWS + Windows endpoint attacks (e.g., credential theft on Windows → lateral movement to cloud)

---

## Scope Boundaries

**Included:** AWS simulation via LocalStack, CloudTrail log generation and ingest, pre-built attack scenario logs, interactive attack scripts, Caldera-to-cloud attack automation via custom abilities and adversary profiles, Elastic SIEM integration.

**Excluded (for now):** Azure/GCP emulation, Kubernetes attack scenarios, Stratus Red Team, real cloud account integration.
