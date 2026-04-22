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
ENV_FILE="/workspace/.env"
TOKEN_FILE="/workspace/docker/fleet-enrollment-token.txt"

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

# ── 4. Create Fleet Server service token (idempotent) ────────────────────────
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

# ── 7. Wait for Fleet API + fetch Windows enrollment token ────────────────────
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

ENROLL_TOKEN=$(kb_api "${KB_URL}/api/fleet/enrollment_api_keys" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = d.get('items', d.get('list', []))
token = next((k['api_key'] for k in keys if 'windows' in k.get('name','').lower()), None)
if token is None and keys:
    token = keys[0]['api_key']
print(token or '')
")

echo "${ENROLL_TOKEN}" > "${TOKEN_FILE}"
chmod 600 "${TOKEN_FILE}"
log "Fleet enrollment token written to docker/fleet-enrollment-token.txt"

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

# ── Done ──────────────────────────────────────────────────────────────────────
log ""
log "================================================================="
log "  Bootstrap complete!"
log "  Kibana:        http://${HOST_IP}:5601   (elastic / ${ELASTIC_PASSWORD})"
log "  Caldera:       http://${HOST_IP}:8888   (admin / admin)"
log "  Fleet Server:  http://${HOST_IP}:8220"
log "  LocalStack:    http://${HOST_IP}:4566"
log ""
log "  Windows victim: run vagrant up win11-victim --provision"
log "  Enrollment token: docker/fleet-enrollment-token.txt"
log "================================================================="
