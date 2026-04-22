#!/usr/bin/env python3
"""
Creates Hunt Lab cloud-attack abilities and adversary in Caldera.
Run from host: python scripts/caldera_setup.py
"""
import json, sys, urllib.request, urllib.error

CALDERA = "http://192.168.56.30:8888"
API_KEY  = "ADMIN123"

# Fixed UUIDs so re-runs are idempotent
ABILITY_S3     = "hl-cloud-001-s3-exfil"
ABILITY_IAM    = "hl-cloud-002-iam-privesc"
ABILITY_CRYPTO = "hl-cloud-003-crypto-mining"
ADVERSARY_ID   = "hl-cloud-adversary-001"

SCRIPT_BASE = "/vagrant/scripts/scenarios"


def api(method, path, body=None):
    url = CALDERA + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("KEY", API_KEY)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode()[:300]
        return {"error": body_txt}, e.code


def upsert_ability(payload):
    name = payload["name"]
    aid  = payload["ability_id"]
    # Try PATCH first (update), fall back to POST (create)
    result, status = api("PUT", f"/api/v2/abilities/{aid}", payload)
    if status in (200, 201):
        print(f"  OK  ability: {name} ({aid})")
    else:
        result, status = api("POST", "/api/v2/abilities", payload)
        if status in (200, 201):
            print(f"  OK  ability: {name} ({aid})")
        else:
            print(f"  ERR ability: {name} — HTTP {status}: {result}", file=sys.stderr)
    return status in (200, 201)


def upsert_adversary(payload):
    name = payload["name"]
    adv_id = payload["adversary_id"]
    result, status = api("PUT", f"/api/v2/adversaries/{adv_id}", payload)
    if status in (200, 201):
        print(f"  OK  adversary: {name} ({adv_id})")
    else:
        result, status = api("POST", "/api/v2/adversaries", payload)
        if status in (200, 201):
            print(f"  OK  adversary: {name} ({adv_id})")
        else:
            print(f"  ERR adversary: {name} — HTTP {status}: {result}", file=sys.stderr)
    return status in (200, 201)


abilities = [
    {
        "ability_id": ABILITY_S3,
        "name": "HL: S3 Data Exfiltration",
        "description": (
            "Hunt Lab scenario: S3 bucket enumeration followed by data exfiltration "
            "to a staging bucket and cover-track cleanup. "
            "Simulates compromised analyst-readonly credential from Tor exit node (185.220.101.50). "
            "ATT&CK: T1526 (Cloud Service Discovery), T1537 (Transfer Data to Cloud Account)."
        ),
        "tactic": "exfiltration",
        "technique_name": "Transfer Data to Cloud Account",
        "technique_id": "T1537",
        "executors": [
            {
                "name": "sh",
                "platform": "linux",
                "command": f"export PATH=/usr/local/bin:$PATH && bash {SCRIPT_BASE}/run_s3_exfil.sh",
                "timeout": 180,
                "payloads": [],
                "uploads": [],
                "parsers": [],
                "cleanup": [],
                "variations": [],
            }
        ],
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "cloud", "aws", "s3"],
        "buckets": ["exfiltration"],
    },
    {
        "ability_id": ABILITY_IAM,
        "name": "HL: IAM Privilege Escalation",
        "description": (
            "Hunt Lab scenario: IAM privilege escalation chain — "
            "analyst-readonly recon → dev-ops creates backdoor admin user (svc-backup-restore) "
            "with AdministratorAccess → CloudTrail trail deleted to impair defenses. "
            "Attacker IP: 203.0.113.45. "
            "ATT&CK: T1087.004 (Account Discovery: Cloud Account), "
            "T1078.004 (Valid Accounts: Cloud Accounts), "
            "T1136.003 (Create Account: Cloud Account), "
            "T1562.001 (Impair Defenses: Disable or Modify Tools)."
        ),
        "tactic": "privilege-escalation",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "technique_id": "T1078.004",
        "executors": [
            {
                "name": "sh",
                "platform": "linux",
                "command": f"export PATH=/usr/local/bin:$PATH && bash {SCRIPT_BASE}/run_iam_privesc.sh",
                "timeout": 240,
                "payloads": [],
                "uploads": [],
                "parsers": [],
                "cleanup": [],
                "variations": [],
            }
        ],
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "cloud", "aws", "iam"],
        "buckets": ["privilege-escalation"],
    },
    {
        "ability_id": ABILITY_CRYPTO,
        "name": "HL: Crypto Mining / Compute Hijacking",
        "description": (
            "Hunt Lab scenario: dev-ops credential used to launch a compute mining fleet "
            "(t3.xlarge x1, c5.4xlarge x5, m5.8xlarge x10, spot x20) then disable CloudTrail "
            "and delete the S3 trail bucket to cover tracks. "
            "Attacker IP: 45.155.205.233. "
            "ATT&CK: T1496.001 (Resource Hijacking: Compute Hijacking), "
            "T1070.004 (Indicator Removal: File Deletion), "
            "T1562.001 (Impair Defenses: Disable or Modify Tools)."
        ),
        "tactic": "impact",
        "technique_name": "Resource Hijacking",
        "technique_id": "T1496",
        "executors": [
            {
                "name": "sh",
                "platform": "linux",
                "command": f"export PATH=/usr/local/bin:$PATH && bash {SCRIPT_BASE}/run_crypto_mining.sh",
                "timeout": 240,
                "payloads": [],
                "uploads": [],
                "parsers": [],
                "cleanup": [],
                "variations": [],
            }
        ],
        "requirements": [],
        "privilege": "",
        "repeatable": True,
        "singleton": False,
        "additional_info": {},
        "tags": ["hunt-lab", "cloud", "aws", "ec2"],
        "buckets": ["impact"],
    },
]

adversary = {
    "adversary_id": ADVERSARY_ID,
    "name": "HL: Cloud Attack Simulation",
    "description": (
        "Hunt Lab full cloud attack chain covering three realistic threat scenarios "
        "against LocalStack/AWS. Run against the 'cloud' agent group (cloud-sim VM). "
        "Phase 1 — S3 exfiltration (T1526, T1537): enumeration → data grab → staging → cover. "
        "Phase 2 — IAM privilege escalation (T1087.004, T1078.004, T1136.003, T1562.001): "
        "create backdoor admin, disable CloudTrail. "
        "Phase 3 — Crypto mining (T1496.001, T1070.004, T1562.001): "
        "launch 36+ compute instances, delete trail bucket."
    ),
    "atomic_ordering": [ABILITY_S3, ABILITY_IAM, ABILITY_CRYPTO],
    "tags": ["hunt-lab", "cloud", "aws"],
}


if __name__ == "__main__":
    print("=== Creating Hunt Lab Caldera abilities ===")
    ok = True
    for ab in abilities:
        ok &= upsert_ability(ab)

    print()
    print("=== Creating Hunt Lab adversary ===")
    ok &= upsert_adversary(adversary)

    print()
    if ok:
        print("Done. To run in Caldera:")
        print(f"  1. Ensure the cloud-sim Sandcat agent is registered (group: cloud)")
        print(f"     Run:  vagrant ssh cloud-sim -c 'sudo bash /vagrant/scripts/fix_cloud_sim_pipeline.sh'")
        print(f"     Then: vagrant ssh cloud-sim -c 'sudo systemctl start sandcat'")
        print(f"  2. Open Caldera: http://192.168.56.30:8888  (admin / admin)")
        print(f"  3. Operations -> New Operation")
        print(f"     Adversary: 'HL: Cloud Attack Simulation'")
        print(f"     Group:     cloud")
        print(f"  4. Click Start")
        print()
        print(f"  Or run individual abilities:")
        print(f"    {ABILITY_S3}     HL: S3 Data Exfiltration")
        print(f"    {ABILITY_IAM}    HL: IAM Privilege Escalation")
        print(f"    {ABILITY_CRYPTO} HL: Crypto Mining / Compute Hijacking")
    else:
        print("Some objects failed — check errors above.", file=sys.stderr)
        sys.exit(1)
