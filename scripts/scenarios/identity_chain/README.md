# Identity-Chain-2025-Lab

Hunt Lab identity-side scenario:
**Kerberoasting → DCSync → Golden Ticket → Pass-the-Ticket**.

Counterpart to `DFIR-RansomHub-2025-Lab`. Where RansomHub stresses
endpoint Sysmon telemetry (process create, file create, DNS), this chain
stresses Kerberos: 4769 RC4 TGS, 4662 directory replication, and
Mimikatz command-line patterns.

## What's in the chain

| ID                    | Technique  | Description                                                      |
|-----------------------|------------|------------------------------------------------------------------|
| `id-00-prep-spn`      | T1078.002  | Register `HTTP/finance.lab.local` SPN on `svc-deploy` (idempotent) |
| `id-01-kerberoast`    | T1558.003  | Atomic Test 2 — pure-PowerShell `KerberosRequestorSecurityToken` TGS request |
| `id-dwell-1-cracking` | T1029      | Models offline cracking time                                     |
| `id-02-dcsync`        | T1003.006  | Atomic Test 1 — Mimikatz `lsadump::dcsync /user:krbtgt`          |
| `id-dwell-2-target`   | T1029      | Models attacker pausing to pick a forge target                   |
| `id-03-golden-ticket` | T1558.001  | Atomic Test 1 — Mimikatz `kerberos::golden` (Administrator forge) |
| `id-04-pass-the-ticket` | T1550.003 | Atomic Test 1 — `kerberos::ptt` + access `\\win-dc\C$`         |
| `id-05-cleanup`       | T1070      | `klist purge` — leaves a tidy lab                                |

## Setup (zero-touch on a fresh clone)

After `bash docker/setup.sh && vagrant up win-dc win-server win11-victim --no-parallel`:

- The bootstrap container POSTs the `Identity-Chain-2025-Lab` adversary +
  abilities into Caldera.
- `setup_dc_post_reboot.ps1` registers the kerberoastable SPN on
  `svc-deploy` during DC provisioning.

If your lab was provisioned **before** the SPN line was added to
`setup_dc_post_reboot.ps1`, run the `id-00-prep-spn` ability once
(targeting the `win-dc` agent) — it's idempotent and self-heals existing labs.

## Running it

Caldera UI → **Operations → New Operation**:

- Adversary: `Identity-Chain-2025-Lab`
- Group: `red`
- **Manually pick agents per ability** in the operation UI:

| Ability                | Run on        | Why                                                            |
|------------------------|---------------|----------------------------------------------------------------|
| `id-00-prep-spn`       | `win-dc`      | `setspn` against AD; SYSTEM on a DC has rights                 |
| `id-01-kerberoast`     | `win-server`  | TGS request from a domain member (any account is fine)         |
| `id-02-dcsync`         | `win-dc`      | SYSTEM on the DC inherits Replicating Directory Changes rights |
| `id-03-golden-ticket`  | `win-server`  | Forge anywhere with the krbtgt hash; SYSTEM is fine            |
| `id-04-pass-the-ticket`| `win-server`  | Use the ticket; verify by listing `\\win-dc\C$`                |
| `id-05-cleanup`        | `win-server`  | `klist purge` on the host that imported the ticket             |

## Why this layout (privilege model)

This trips up first-timers: in this lab **all sandcat agents run as
NT AUTHORITY\\SYSTEM**. SYSTEM on a member machine has zero domain
privilege — it can request its *own* TGS but can't replicate AD or
modify SPNs. SYSTEM on a *Domain Controller* effectively maps to the
DC's machine account, which holds Replicating Directory Changes rights
inherited via the `Domain Controllers` group → DCSync runs cleanly.

That's why DCSync targets `win-dc` and everything else runs from
`win-server`. In a real intrusion the attacker would have stolen DA
credentials by this point and would run DCSync from anywhere; we shortcut
the credential-theft step so the chain is reproducible without password
spraying.

## Dwell time

Two sleep abilities model attacker idle time:

| Ability             | When                           | Default | Env var        | Real cases    |
|---------------------|--------------------------------|---------|----------------|---------------|
| `id-dwell-1-cracking` | After kerberoast, before DCSync | 60s   | `ID_DWELL_CRACK` | hours-days  |
| `id-dwell-2-target` | After DCSync, before forge     | 30s     | `ID_DWELL_LATER` | minutes-hours |

To stretch the demo timeline:

```bash
ID_DWELL_CRACK=14400 ID_DWELL_LATER=600 \
  python3 scripts/caldera_identity_setup.py
```

## What to look for in Kibana

Detection rules that fire on this chain (auto-imported by the bootstrap
container under `kibana/detection_rules/identity_chain.ndjson`):

| Step                      | Rule                                                          | Index               |
|---------------------------|---------------------------------------------------------------|---------------------|
| `id-00-prep-spn`          | Identity Chain: setspn -A registration                        | `logs-windows.*`    |
| `id-01-kerberoast` (DC)   | Identity Chain: Kerberoast TGS request (RC4 against SPN)      | Win event 4769      |
| `id-01-kerberoast` (host) | Identity Chain: PowerShell KerberosRequestorSecurityToken     | Sysmon Event 1      |
| `id-02-dcsync` (cmd)      | Identity Chain: Mimikatz lsadump::dcsync command line         | Sysmon Event 1      |
| `id-02-dcsync` (DC)       | Identity Chain: Directory Service replication GUIDs accessed  | Win event 4662      |
| `id-03-golden-ticket`     | Identity Chain: Mimikatz kerberos::golden command line        | Sysmon Event 1      |
| `id-04-pass-the-ticket`   | Identity Chain: Mimikatz kerberos::ptt                        | Sysmon Event 1      |
| Chain (cred-access)       | Identity Chain: DCSync followed by golden-ticket forge (EQL)  | Sysmon Event 1      |

The EQL chain rule is the highest-signal alert — DCSync alone has
plausible legitimate causes; golden-ticket forge alone is rare; the two
within 6 hours on the same fleet is essentially diagnostic.

## What this scenario *doesn't* do

- **No external entry vector**. The chain assumes a foothold.
- **No real password cracking**. The TGS dwell is symbolic — `svc-deploy`
  uses `Lab!Password1` by default, which `hashcat -a 0 -m 13100` would
  crack in milliseconds, but the detection of interest is the *request*
  not the *crack*.
- **No real privilege escalation off the forged ticket**. We list
  `\\win-dc\C$` as proof the impersonation works; we don't pivot
  further. Add lateral-movement abilities downstream if you want.

## Cleanup

```bash
# Remove the SPN from svc-deploy (re-running id-00 will re-add it)
vagrant winrm win-dc -c "powershell -Command \"Set-ADUser -Identity svc-deploy -ServicePrincipalNames @{Remove='HTTP/finance.lab.local'}\""

# Purge any leftover tickets on member hosts
vagrant winrm win-server -c "klist purge"

# Wipe Atomic Red Team artefact directory
vagrant winrm win-server -c "Remove-Item -Recurse -Force C:\\AtomicRedTeam\\atomics\\T1003.006,C:\\AtomicRedTeam\\atomics\\T1558.001,C:\\AtomicRedTeam\\atomics\\T1558.003,C:\\AtomicRedTeam\\atomics\\T1550.003 -ErrorAction SilentlyContinue"
```

## See also

- `attack_navigator/identity_chain_layer.json` — drop into
  <https://mitre-attack.github.io/attack-navigator/> for the visual matrix.
- `scripts/scenarios/ransomhub/README.md` — endpoint-heavy counterpart scenario.
