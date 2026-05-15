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

## Setup (zero-touch)

After a fresh `git clone`, everything below is wired up automatically by
the existing provisioners — you do **not** need to run any of the seed
scripts by hand:

```bash
bash docker/setup.sh
vagrant up win-dc win-server win11-victim --no-parallel
```

What happens during that bring-up:

| Step | Where | Action |
|---|---|---|
| `docker/setup.sh` → bootstrap container | docker-host | Creates `s3://ransomhub-exfil-lab` in LocalStack and POSTs the 12 abilities + adversary into Caldera |
| `vagrant up win-server` → `seed_ransomhub_decoy` provisioner | win-server | Stages `C:\Shares\Finance\*.{docx,xlsx,pdf,txt,csv}` and publishes the SMB share |
| `vagrant up win-{dc,server,11-victim}` → `deploy_caldera_agent` | each Windows VM | Sandcat agents register in group `red` |

When all three Windows VMs are green in Caldera (group `red`), the lab is
ready. The seed scripts (`seed_decoy_data.ps1`, `seed_localstack_bucket.sh`,
`caldera_ransomhub_setup.py`) are still here for manual re-runs after a
wipe — they are idempotent.

## Running it

Log into Caldera at `http://<docker-host-ip>:8888` (admin / HuntLab2026!) and:

**Operations → New Operation**

- Adversary: `DFIR-RansomHub-2025-Lab`
- Group: `red`
- Auto-run, default obfuscation

## Dwell time

The chain has three sleep abilities baked in so the operation models
attacker dwell instead of running 12 abilities back-to-back:

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

The chain runs all 12 abilities in order. Total runtime ~10 minutes
end-to-end on the lab hardware.

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
