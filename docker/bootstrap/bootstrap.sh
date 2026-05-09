#!/usr/bin/env bash
# bootstrap/bootstrap.sh
# One-shot container that runs after Elasticsearch + Kibana are healthy.
# Performs all first-boot Elastic API work so fleet-server can start cleanly.
#
# Steps:
#   1. Set kibana_system password
#   2. Delete + recreate Fleet Server service token (idempotent)
#   3. Patch HOST_IP into caldera/local.yml
#   4. Configure Fleet default output (points at the real Elasticsearch IP)
#   5. Wait for Fleet API, fetch Windows enrollment token
#   6. Write fleet-enrollment-token.txt + patch FLEET_SERVER_SERVICE_TOKEN into .env
#   7. Seed LocalStack baseline resources (S3 buckets, IAM users)

set -euo pipefail

ES_URL="http://elasticsearch:9200"
KB_URL="http://kibana:5601"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD}"
KIBANA_SYSTEM_PASSWORD="${KIBANA_SYSTEM_PASSWORD}"
HOST_IP="${HOST_IP}"
CALDERA_CONFIG="/workspace/docker/config/caldera/local.yml"
ENV_FILE="/workspace/docker/.env"
TOKEN_FILE="/workspace/fleet-enrollment-token.txt"

log()  { echo "[bootstrap] $*"; }
die()  { echo "[bootstrap] ERROR: $*" >&2; exit 1; }

# ── helpers ───────────────────────────────────────────────────────────────────
es_api() {
  curl -sf -u "elastic:${ELASTIC_PASSWORD}" \
    -H "Content-Type: application/json" \
    "$@"
}

kb_api() {
  curl -sf -u "elastic:${ELASTIC_PASSWORD}" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    "$@"
}

wait_for_url() {
  local url=$1 label=$2 max=${3:-30}
  log "Waiting for $label..."
  for i in $(seq 1 "$max"); do
    if curl -sf --max-time 5 "$url" -u "elastic:${ELASTIC_PASSWORD}" -o /dev/null 2>/dev/null; then
      log "$label is ready."
      return 0
    fi
    sleep 5
  done
  die "$label did not become ready after $(( max * 5 ))s"
}

# ── 1. Confirm Elasticsearch is up ───────────────────────────────────────────
wait_for_url "${ES_URL}/_cluster/health" "Elasticsearch" 30

# ── 2. Set kibana_system password ────────────────────────────────────────────
log "Setting kibana_system password..."
es_api -X POST "${ES_URL}/_security/user/kibana_system/_password" \
  -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}" > /dev/null
log "kibana_system password set."

# ── 3. Confirm Kibana is up ───────────────────────────────────────────────────
wait_for_url "${KB_URL}/api/status" "Kibana" 36

# ── 4a. Ensure Fleet has been initialized + fleet-server policy exists ────────
# Fleet Server needs a policy with id "fleet-server-policy" to bootstrap.
# Calling /api/fleet/setup is idempotent and ensures Fleet's internal indices exist.
log "Initializing Fleet (POST /api/fleet/setup)..."
kb_api -X POST "${KB_URL}/api/fleet/setup" > /dev/null || true

EXISTING_FS_POLICY=$(curl -sf -u "elastic:${ELASTIC_PASSWORD}" \
  -H "kbn-xsrf: true" \
  -o /dev/null -w "%{http_code}" \
  "${KB_URL}/api/fleet/agent_policies/fleet-server-policy" 2>/dev/null || echo "404")

if [[ "${EXISTING_FS_POLICY}" != "200" ]]; then
  log "Creating fleet-server-policy (with has_fleet_server: true)..."
  kb_api -X POST "${KB_URL}/api/fleet/agent_policies?sys_monitoring=true" \
    -d '{
      "id": "fleet-server-policy",
      "name": "Fleet Server policy",
      "namespace": "default",
      "description": "Hunt Lab Fleet Server policy",
      "has_fleet_server": true,
      "monitoring_enabled": ["logs", "metrics"]
    }' > /dev/null
  log "fleet-server-policy created."
else
  log "fleet-server-policy already exists."
fi

# ── 4b. Create Fleet Server service token (idempotent) ────────────────────────
log "Creating Fleet Server service token..."
# Delete any pre-existing token so this script is safe to re-run
curl -sf -X DELETE -u "elastic:${ELASTIC_PASSWORD}" \
  "${ES_URL}/_security/service/elastic/fleet-server/credential/token/hunt-lab-fleet-token" \
  > /dev/null 2>&1 || true

TOKEN_RESPONSE=$(es_api -X POST \
  "${ES_URL}/_security/service/elastic/fleet-server/credential/token/hunt-lab-fleet-token")

SERVICE_TOKEN=$(echo "${TOKEN_RESPONSE}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'token' not in d:
    sys.stderr.write('[bootstrap] ERROR: token creation failed: ' + json.dumps(d) + '\n')
    sys.exit(1)
print(d['token']['value'])
")
log "Fleet Server service token created."

# Write token into .env so docker-compose can pass it to fleet-server on (re)start
if [[ -f "${ENV_FILE}" ]]; then
  # Replace existing line or append
  if grep -q "^FLEET_SERVER_SERVICE_TOKEN=" "${ENV_FILE}"; then
    sed -i "s|^FLEET_SERVER_SERVICE_TOKEN=.*|FLEET_SERVER_SERVICE_TOKEN=${SERVICE_TOKEN}|" "${ENV_FILE}"
  else
    echo "FLEET_SERVER_SERVICE_TOKEN=${SERVICE_TOKEN}" >> "${ENV_FILE}"
  fi
  log "FLEET_SERVER_SERVICE_TOKEN written to .env"
fi

# Also export for use in this process
export FLEET_SERVER_SERVICE_TOKEN="${SERVICE_TOKEN}"

# ── 5. Configure Fleet default output ────────────────────────────────────────
log "Configuring Fleet default Elasticsearch output..."
# Get ID of the default output
OUTPUT_ID=$(kb_api "${KB_URL}/api/fleet/outputs" \
  | python3 -c "
import sys, json
outputs = json.load(sys.stdin).get('items', [])
default = next((o for o in outputs if o.get('is_default')), None)
print(default['id'] if default else '')
")

if [[ -n "${OUTPUT_ID}" ]]; then
  kb_api -X PUT "${KB_URL}/api/fleet/outputs/${OUTPUT_ID}" \
    -d "{
      \"name\": \"Elasticsearch\",
      \"type\": \"elasticsearch\",
      \"hosts\": [\"http://${HOST_IP}:9200\"],
      \"is_default\": true,
      \"is_default_monitoring\": true
    }" > /dev/null
  log "Fleet default output updated to http://${HOST_IP}:9200"
else
  log "WARNING: could not find default Fleet output — agents may not be able to ship data."
fi

# ── 6. Patch HOST_IP into caldera/local.yml ───────────────────────────────────
if [[ -f "${CALDERA_CONFIG}" ]]; then
  sed -i "s|HOST_IP_PLACEHOLDER|${HOST_IP}|g" "${CALDERA_CONFIG}"
  log "Caldera local.yml patched with HOST_IP=${HOST_IP}"
fi

# ── 7. Wait for Fleet API + ensure an agent policy exists + fetch enrollment token ──
log "Waiting for Fleet enrollment API..."
FLEET_READY=0
for i in $(seq 1 24); do
  STATUS=$(kb_api "${KB_URL}/api/fleet/enrollment_api_keys" \
    -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
  if [[ "${STATUS}" == "200" ]]; then
    FLEET_READY=1; break
  fi
  sleep 5
done
[[ "${FLEET_READY}" -eq 1 ]] || die "Fleet enrollment API not ready after 120s"

# Trigger Fleet's first-run setup (idempotent — just initializes Fleet's internal state)
log "Initializing Fleet (POST /api/fleet/setup)..."
kb_api -X POST "${KB_URL}/api/fleet/setup" > /dev/null || true

# Ensure at least one agent policy exists. Creating a policy auto-generates
# an enrollment API key, which is what we ship to the Windows VMs.
EXISTING_POLICY_ID=$(kb_api "${KB_URL}/api/fleet/agent_policies" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('items', [])
hunt = next((p for p in items if p.get('name') == 'hunt-lab-windows'), None)
print(hunt['id'] if hunt else '')
")

if [[ -z "${EXISTING_POLICY_ID}" ]]; then
  log "Creating Hunt Lab Windows agent policy..."
  EXISTING_POLICY_ID=$(kb_api -X POST "${KB_URL}/api/fleet/agent_policies" \
    -d '{
      "name": "hunt-lab-windows",
      "namespace": "default",
      "description": "Hunt Lab default Windows policy",
      "monitoring_enabled": ["logs", "metrics"]
    }' | python3 -c "import sys,json; print(json.load(sys.stdin).get('item',{}).get('id',''))")
  log "Agent policy created (${EXISTING_POLICY_ID})."
else
  log "Agent policy 'hunt-lab-windows' already exists (${EXISTING_POLICY_ID})."
fi

# Attach the Windows integration to the policy so agents actually collect
# Sysmon, PowerShell, AppLocker, and Defender events. Without this, agents
# enroll and report "online" but no data shows up in Discover.
HAS_WINDOWS_INTEGRATION=$(kb_api "${KB_URL}/api/fleet/package_policies?perPage=100" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
pid = '${EXISTING_POLICY_ID}'
attached = [p for p in d.get('items', []) if p.get('policy_id') == pid and p.get('package',{}).get('name') == 'windows']
print('1' if attached else '')
")

if [[ -z "${HAS_WINDOWS_INTEGRATION}" ]]; then
  log "Attaching Windows integration to hunt-lab-windows policy..."
  EXISTING_POLICY_ID="${EXISTING_POLICY_ID}" KB_URL="${KB_URL}" ELASTIC_PASSWORD="${ELASTIC_PASSWORD}" python3 - <<'PY'
import os, json, urllib.request, base64, sys
KB = os.environ['KB_URL']
POLICY_ID = os.environ['EXISTING_POLICY_ID']
auth = base64.b64encode(f"elastic:{os.environ['ELASTIC_PASSWORD']}".encode()).decode()
HDRS = {'Authorization': f'Basic {auth}', 'kbn-xsrf':'true', 'Content-Type':'application/json'}

def req(method, path, body=None):
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(KB+path, data=data, method=method, headers=HDRS)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:400]

s, info = req('GET', '/api/fleet/epm/packages/windows')
pkg = info['item']; ver = pkg['version']
req('POST', f'/api/fleet/epm/packages/windows/{ver}', {'force': True})

# Build inputs from data_streams + policy_templates
templates = pkg.get('policy_templates', [])
inputs = []
for t in templates:
    for i in t.get('inputs', []):
        streams = []
        for ds in pkg.get('data_streams', []):
            for stream in ds.get('streams', []):
                if stream.get('input') == i['type']:
                    streams.append({
                        'enabled': True,
                        'data_stream': {'dataset': ds['dataset'], 'type': ds.get('type','logs')},
                    })
        inputs.append({'type': i['type'], 'policy_template': t['name'], 'enabled': True, 'streams': streams})

s, resp = req('POST', '/api/fleet/package_policies', {
    'name': 'windows-1', 'namespace': 'default', 'policy_id': POLICY_ID, 'enabled': True,
    'package': {'name': 'windows', 'version': ver, 'title': pkg.get('title','Windows')},
    'inputs': inputs,
})
print(f"  windows integration attach HTTP {s}", file=sys.stderr)
if s >= 300: print(f"  {resp}", file=sys.stderr)
PY
  log "Windows integration attached."
else
  log "Windows integration already attached."
fi

ENROLL_TOKEN=$(kb_api "${KB_URL}/api/fleet/enrollment_api_keys" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = d.get('items', d.get('list', []))
# Prefer keys tied to the hunt-lab-windows policy (resolved by policy_id below).
print(keys[0]['api_key'] if keys else '')
")

if [[ -z "${ENROLL_TOKEN}" ]]; then
  die "No Fleet enrollment key was generated. Check Kibana Fleet UI."
fi

echo "${ENROLL_TOKEN}" > "${TOKEN_FILE}"
chmod 600 "${TOKEN_FILE}"
log "Fleet enrollment token written to repo root: fleet-enrollment-token.txt"

# ── 8. Seed LocalStack baseline resources ────────────────────────────────────
# awslocal may not be installed in this container; skip if unavailable.
if command -v awslocal &>/dev/null || pip show awscli-local &>/dev/null 2>&1; then
  pip install -q awscli-local 2>/dev/null || true
  export AWS_ACCESS_KEY_ID=test
  export AWS_SECRET_ACCESS_KEY=test
  export AWS_DEFAULT_REGION=us-east-1

  LOCALSTACK_READY=0
  for i in $(seq 1 20); do
    if curl -sf "http://localstack:4566/_localstack/health" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('services',{}).get('s3')=='running' else 1)" 2>/dev/null; then
      LOCALSTACK_READY=1; break
    fi
    sleep 5
  done

  if [[ "${LOCALSTACK_READY}" -eq 1 ]]; then
    log "Seeding LocalStack baseline resources..."
    awslocal s3 mb s3://company-financials 2>/dev/null || true
    awslocal s3 mb s3://hr-data 2>/dev/null || true
    awslocal s3 mb s3://cloudtrail-logs 2>/dev/null || true
    # Exfil destination for the DFIR-RansomHub-2025-Lab scenario
    awslocal s3 mb s3://ransomhub-exfil-lab 2>/dev/null || true
    awslocal s3api put-bucket-tagging --bucket ransomhub-exfil-lab \
      --tagging 'TagSet=[{Key=hunt-lab,Value=ransomhub-recreation}]' 2>/dev/null || true
    echo '{"ssn":"123-45-6789","name":"John Doe","salary":150000}' \
      | awslocal s3 cp - s3://hr-data/employees/john_doe.json 2>/dev/null || true
    echo '{"q4_revenue":42000000,"projections":"confidential"}' \
      | awslocal s3 cp - s3://company-financials/2025-q4-report.json 2>/dev/null || true
    awslocal iam create-user --user-name analyst-readonly 2>/dev/null || true
    awslocal iam create-user --user-name dev-ops 2>/dev/null || true
    awslocal iam attach-user-policy --user-name analyst-readonly \
      --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null || true
    awslocal iam attach-user-policy --user-name dev-ops \
      --policy-arn arn:aws:iam::aws:policy/IAMFullAccess 2>/dev/null || true
    awslocal cloudtrail create-trail \
      --name hunt-lab-trail --s3-bucket-name cloudtrail-logs \
      --is-multi-region-trail 2>/dev/null || true
    awslocal cloudtrail start-logging --name hunt-lab-trail 2>/dev/null || true
    log "LocalStack baseline resources seeded."
  else
    log "WARNING: LocalStack not ready — skipping resource seeding. Re-run bootstrap to retry."
  fi
fi

# ── 9. Push RansomHub recreation into Caldera ────────────────────────────────
# Wait for Caldera's REST API, then upsert the abilities + adversary so a fresh
# clone arrives with the DFIR-RansomHub-2025-Lab adversary already in the UI.
# Idempotent — re-runs just refresh the existing objects.
log "Waiting for Caldera REST API (up to 180s)..."
CALDERA_READY=0
for i in $(seq 1 36); do
  if curl -sf --max-time 5 -H "KEY: ADMIN123" \
      "http://caldera:8888/api/v2/health" -o /dev/null 2>/dev/null; then
    CALDERA_READY=1; break
  fi
  sleep 5
done

if [[ "${CALDERA_READY}" -eq 1 ]]; then
  log "Pushing DFIR-RansomHub-2025-Lab abilities + adversary to Caldera..."
  if CALDERA_URL="http://caldera:8888" \
     python3 /workspace/scripts/caldera_ransomhub_setup.py; then
    log "RansomHub recreation seeded into Caldera."
  else
    log "WARNING: caldera_ransomhub_setup.py reported errors — check above."
  fi
else
  log "WARNING: Caldera REST API not ready — skipping ability seeding."
  log "  Re-run manually with: python3 scripts/caldera_ransomhub_setup.py"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
log ""
log "================================================================="
log "  Bootstrap complete!"
log "  Kibana:        http://${HOST_IP}:5601   (elastic / ${ELASTIC_PASSWORD})"
log "  Caldera:       http://${HOST_IP}:8888   (admin / admin)"
log "  Fleet Server:  http://${HOST_IP}:8220"
log "  LocalStack:    http://${HOST_IP}:4566"
log ""
log "  Windows VMs:    run 'vagrant up win-dc win-server win11-victim --no-parallel'"
log "  Enrollment token: fleet-enrollment-token.txt (repo root)"
log "================================================================="
