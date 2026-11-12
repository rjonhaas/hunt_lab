# DFIR-RansomHub-2025-Lab

Hunt Lab recreation of The DFIR Report case
**"Hide Your RDP: Password Spray Leads to RansomHub Deployment"** (2025-06).

Source report: <https://thedfirreport.com/reports/>

## What's faithful, what's swapped

| Phase | Report | Lab |
|---|---|---|
| Initial access | RDP password spray from external IP | **Skipped** — start from a foothold on `win11-victim` |
| Persistence | Atera + Splashtop RMM install | **Skipped** |
| Recon | net / nltest / ipconfig, Advanced IP Scanner, SoftPerfect NetScan | Native PowerShell sweep + same `net`/`nltest` commands |
| Cred access | Mimikatz LSASS, NirSoft CredentialsFileView, DCSync | comsvcs.dll LSASS dump + reg-save SAM/SECURITY/SYSTEM (Atomic Red Team) |
| Discovery | Map file shares, walk Finance | `net view \\win-server` + recurse `\\win-server\Finance` |
| Defense evasion | `fsutil behavior set SymlinkEvaluation R2L:1 R2R:1` | Same |
| Tooling | rclone dropped at runtime | **Same** — downloaded by `rh-07` from `downloads.rclone.org` during the chain, not pre-installed |
| Exfiltration | `nocmd.vbs` → `rcl.bat` → rclone copy to remote SFTP | **Same wrapper, same filenames** — destination swapped to `s3://ransomhub-exfil-lab` on LocalStack |
| Impact | vssadmin Delete Shadows, then `amd64.exe` encryptor | vssadmin (Atomic) + benign rename-and-note simulator (`fake_amd64.ps1`) |
| Cleanup | `wevtutil cl` Security/Application/System | Same (Atomic Red Team T1070.001) |

## Workshop branch: optional scenario

This branch includes the original profile and supporting files for an optional
RansomHub walkthrough. It is separate from the four-action War Wagon CTF and
has its own brace-wrapped practice flag in endpoint telemetry.

Workshop setup starts LocalStack and its telemetry shippers. Load the optional
abilities and adversary without starting an operation:

```bash
CALDERA_URL=http://192.168.56.10:8888 python3 scripts/caldera_ransomhub_setup.py
```

LocalStack runs at `192.168.56.10:4566` with lab credentials `test` / `test`.
Setup creates the `ransomhub-exfil-lab` bucket and `analyst-readonly` IAM user.
To add these services to an existing lab without restarting Elastic or Caldera:

```bash
cd docker
docker compose build cloudtrail-gen
bash setup-localstack.sh
```

Before running the full chain, prepare the Finance decoys with
`seed_decoy_data.ps1` on win-server. Atomic Red Team must be installed on the
selected Windows hosts. Loading a profile does not start an operation.

### Cloud evidence in Kibana

Use `data_stream.dataset : "aws.cloudtrail"` in the War Wagon logs data view.
These are **simulated CloudTrail-shaped events derived from LocalStack API
operation/status logs**, not native AWS CloudTrail. They identify the service,
operation and result; they do not recover request parameters, object contents,
caller identity or the client's IP. `labels.simulated` marks this limitation.
A flag hidden only inside an S3 object will not appear in these events.
Endpoint command lines and file paths remain available through Sysmon.

In Caldera, select **DFIR-RansomHub-2025-Lab** and review the target group.
The original scenario targets the Windows lab machines in `red`; the workshop
walkthrough moves win11-victim into `de&th`, so inspect group membership first.
The profile includes real shadow-copy deletion and event-log clearing, plus a
rename-and-note simulation on the Finance decoys. It never deploys a real
RansomHub encryptor. Preserve the current CTF evidence before running it.

## Dwell time

The chain has three sleep abilities baked in so the operation models
attacker dwell instead of running 13 abilities back-to-back:

| Ability | When | Default | Env var | What real cases look like |
|---|---|---|---|---|
| `rh-dwell-1-foothold` | after recon, before credential theft | 30s | `RH_DWELL_FOOTHOLD` | 1–12h |
| `rh-dwell-2-creds` | after creds, before lateral / exfil | 60s | `RH_DWELL_CREDS` | overnight |
| `rh-dwell-3-pre-impact` | after exfil, before encryption | 120s | `RH_DWELL_IMPACT` | 24–72h |

Defaults are lab-friendly (≈3.5 min total). To make the timeline look like
the report's actual hours-to-days dwell, re-push the abilities with longer
sleeps:

```bash
RH_DWELL_FOOTHOLD=14400 RH_DWELL_CREDS=28800 RH_DWELL_IMPACT=86400 \
  python3 scripts/caldera_ransomhub_setup.py
```

(That's 4h / 8h / 24h — a typical end-to-end dwell of ~36 hours.)

The chain runs all 13 attack abilities in order. Total runtime ≈ 25-30
minutes end-to-end on the lab hardware at default dwell. The long pole
is `rh-02-recon-network` — a serial PowerShell ping sweep of the /24
that takes 8-10 minutes per host because `Test-Connection` has a 2-4s
timeout per unreachable IP and there are ~250 of them. Add `RH_DWELL_*`
seconds to that for the modelled attacker idle. Earlier docs claimed
"~10 minutes"; that was the optimistic-everything-quick-and-cached
estimate, not what an end-to-end run looks like in practice.

## What to look for in Kibana

| Step | Index / data view | Hint |
|---|---|---|
| `rh-01` domain recon | `logs-windows.*` | Sysmon Event 1 — `net.exe` parented by powershell |
| `rh-02` network sweep | `logs-windows.*` | Sysmon Event 3 — many TCP connect attempts to .56.0/24 |
| `rh-03` LSASS dump | `logs-windows.*` | Sysmon Event 10 with TargetImage `lsass.exe`; Event 11 minidump file write |
| `rh-04` SAM hive | `logs-windows.*` | `reg.exe save HKLM\SAM` command line |
| `rh-06` symlink toggle | `logs-windows.*` | `fsutil behavior set SymlinkEvaluation` literal match |
| `rh-07` rclone dl | `logs-windows.*` | Sysmon Event 22 DNS to `downloads.rclone.org`; Event 11 file create `rclone.exe` |
| `rh-09` exfil | `logs-windows.*` + LocalStack | Sysmon process tree `wscript.exe` → `cmd.exe` → `rclone.exe` with S3 args; bucket `ransomhub-exfil-lab` fills with `.docx`/`.xlsx`/`.pdf` |
| `rh-10` vssadmin | `logs-windows.*` | `vssadmin Delete Shadows /all /quiet` |
| `rh-11` "encrypt" | `logs-windows.*` | Burst of Sysmon Event 11 renames + `README_RANSOMHUB.txt` writes |
| `rh-12` log clear | `logs-windows.*` | Security log Event 1102 |

## Verifying exfil hit LocalStack

```bash
docker exec -it hl-localstack awslocal s3 ls s3://ransomhub-exfil-lab/finance/ --recursive | head
```

## Cleanup

```bash
# Reset the Finance share
vagrant winrm win-server -c "powershell -File C:\vagrant\scripts\scenarios\ransomhub\seed_decoy_data.ps1"

# Empty the bucket
docker exec -it hl-localstack awslocal s3 rm s3://ransomhub-exfil-lab/ --recursive

# Remove staged tooling on whichever red agent ran the op
# (rclone.exe, rclone.zip, nocmd.vbs, rcl.bat, include.txt, ransom_note.txt
#  all live in C:\Users\Public\)
```

## Endpoint CTF flag

The `rh-08-tool-stage-artifacts` ability records `{RH_CLOUD_STAGING}` in its
PowerShell command line and creates
`C:\WarWagonTraining\ransomhub\{RH_CLOUD_STAGING}.txt`.
The workshop Sysmon rule collects FileCreate events under that root. In Kibana,
filter the actual target and operation time, then inspect `process.command_line`
for Event ID 1 or `file.path` for Event ID 11. Submit the braces and inner value,
without `.txt`. A flag file is staging evidence, not proof that exfil succeeded.

Set `RH_CTF_FLAG='{your_conference_flag}'` when loading the profile to replace
the public practice value. Existing indexed events retain their previous values.
