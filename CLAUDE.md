# Hunt Lab - Project Context

## What This Is

A self-contained threat hunting lab. Docker containers provide the SIEM stack and C2 framework on the host. Vagrant spins up Windows VMs that act as attack targets and domain infrastructure.

## Vagrant VMs

| VM | Box | IP | RAM | Role |
|---|---|---|---|---|
| `win-dc` | Windows Server 2022 | 192.168.56.50 | 4GB | Active Directory Domain Controller (lab.local) |
| `win-server` | Windows Server 2022 | 192.168.56.51 | 2GB | Domain member server |
| `win11-victim` | Windows 11 | 192.168.56.20 | 4GB | Victim workstation (attack target) |

All three VMs get:
- Sysmon (SwiftOnSecurity config)
- Elastic Agent enrolled to Fleet Server
- Caldera sandcat C2 agent (hidden as scheduled task `WindowsSecurityUpdate`, group: `red`)
- Atomic Red Team (full atomics library)

## Docker Containers

Network: `172.20.0.0/24`

| Container | IP | Port | Role |
|---|---|---|---|
| Elasticsearch | 172.20.0.10 | 9200 | Log/event store |
| Kibana | 172.20.0.11 | 5601 | SIEM UI |
| Fleet Server | 172.20.0.12 | 8220 | Elastic Agent management |
| Caldera | 172.20.0.30 | 8888 | C2 framework (adversary emulation) |
| LocalStack | 172.20.0.40 | 4566 | Simulated AWS (S3, IAM, CloudTrail, Lambda, STS, CloudWatch, EC2) |
| Bootstrap | — | — | One-shot init: sets passwords, writes tokens, patches Caldera config |
| CloudTrail Generator | — | — | Emits synthetic AWS CloudTrail logs every 60s |
| Filebeat | — | — | Ships CloudTrail logs to Elasticsearch |

## Startup Order

1. `docker/setup.sh` — starts all containers; bootstrap writes `fleet-enrollment-token.txt` and `elastic-credentials.txt`
2. `win-dc` — promotes to DC, creates OUs/users, writes `domain-info.txt`
3. `win-server` + `win11-victim` — join domain, enroll agents (both require win-dc to be up first)

## Key Generated Files

| File | Location | Purpose |
|---|---|---|
| `fleet-enrollment-token.txt` | repo root | Windows Elastic Agent enrollment |
| `elastic-credentials.txt` | repo root | elastic user password |
| `domain-info.txt` | `C:\vagrant\` on win-dc | Domain join config consumed by member VMs |

## Domain

- Domain: `lab.local`
- NetBIOS: `LAB`
- DC IP: `192.168.56.50`
- Domain users: `jsmith`, `ajohnson`, `bwilliams`, `cdavis`, `svc-backup`, `svc-deploy`
- Default password: `Lab!Password1`

## Elastic Stack

- Version: `8.19.14` (set via `ELASTIC_VERSION` in `docker/.env`)
- Security enabled, no SSL (lab mode)
- Fleet integration enabled with auto-install of Fleet Server, System, Elastic Agent, Windows packages

## Current Branch

`feat/docker-single-server`
