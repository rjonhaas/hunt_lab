#!/usr/bin/env bash
# bootstrap/generate_cloudtrail_activity.sh
# Writes CloudTrail-formatted JSON events to $CLOUDTRAIL_LOG_DIR.
# Runs inside the cloudtrail-gen container on a 60-second loop.
# Seeds baseline resources on first run (idempotent).
#
# Environment (set by docker-compose.yml):
#   LOCALSTACK_ENDPOINT  e.g. http://localstack:4566
#   CLOUDTRAIL_LOG_DIR   e.g. /cloudtrail

set -euo pipefail

EXPORT_DIR="${CLOUDTRAIL_LOG_DIR:-/cloudtrail}"
ENDPOINT="${LOCALSTACK_ENDPOINT:-http://localhost:4566}"
mkdir -p "${EXPORT_DIR}"

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ACCT="000000000000"
REGION="us-east-1"

# Portable UUID
uuid() {
  python3 -c "import uuid; print(str(uuid.uuid4()))" 2>/dev/null \
    || cat /proc/sys/kernel/random/uuid 2>/dev/null \
    || echo "$(date +%s%N)"
}

write_event() {
  local event_name=$1 service=$2 src_ip=$3 user=$4 body=$5
  local eid; eid=$(uuid)
  local fname="${EXPORT_DIR}/${event_name}-${eid}.json"
  cat > "${fname}" <<EOF
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAI${eid:0:16}",
    "arn": "arn:aws:iam::${ACCT}:user/${user}",
    "accountId": "${ACCT}",
    "userName": "${user}"
  },
  "eventTime": "${NOW}",
  "eventSource": "${service}",
  "eventName": "${event_name}",
  "awsRegion": "${REGION}",
  "sourceIPAddress": "${src_ip}",
  "userAgent": "aws-cli/2.x Python/3.11",
  "requestParameters": ${body},
  "responseElements": null,
  "eventID": "${eid}",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "${ACCT}"
}
EOF
}

# ── Seed baseline AWS resources (idempotent) ──────────────────────────────────
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION="${REGION}"
AWS_ENDPOINT_URL="${ENDPOINT}"
export AWS_ENDPOINT_URL

seed_resources() {
  aws s3 mb s3://company-financials --endpoint-url "${ENDPOINT}" 2>/dev/null || true
  aws s3 mb s3://hr-data              --endpoint-url "${ENDPOINT}" 2>/dev/null || true
  aws s3 mb s3://cloudtrail-logs      --endpoint-url "${ENDPOINT}" 2>/dev/null || true
  echo '{"name":"John Doe","salary":150000}' \
    | aws s3 cp - s3://hr-data/employees/john_doe.json \
        --endpoint-url "${ENDPOINT}" 2>/dev/null || true
  echo '{"q4_revenue":42000000}' \
    | aws s3 cp - s3://company-financials/2025-q4-report.json \
        --endpoint-url "${ENDPOINT}" 2>/dev/null || true
  aws iam create-user --user-name analyst-readonly \
    --endpoint-url "${ENDPOINT}" 2>/dev/null || true
  aws iam create-user --user-name dev-ops \
    --endpoint-url "${ENDPOINT}" 2>/dev/null || true
}

SEED_DONE_FILE="${EXPORT_DIR}/.seeded"
if [[ ! -f "${SEED_DONE_FILE}" ]]; then
  seed_resources
  touch "${SEED_DONE_FILE}"
fi

# ── Emit CloudTrail activity events ──────────────────────────────────────────

# 1. ListBuckets (baseline reconnaissance)
write_event "ListBuckets" "s3.amazonaws.com" "10.0.1.50" "analyst-readonly" \
  '{"Host":"s3.amazonaws.com"}'

# 2. GetObject — normal analyst read
write_event "GetObject" "s3.amazonaws.com" "10.0.1.50" "analyst-readonly" \
  '{"bucketName":"hr-data","key":"employees/john_doe.json"}'

# 3. ListUsers — IAM reconnaissance
write_event "ListUsers" "iam.amazonaws.com" "10.0.2.100" "dev-ops" \
  '{}'

# 4. GetObject — cross-account read on financial data (suspicious)
write_event "GetObject" "s3.amazonaws.com" "203.0.113.42" "dev-ops" \
  '{"bucketName":"company-financials","key":"2025-q4-report.json"}'

# 5. CreateAccessKey — potential credential theft
write_event "CreateAccessKey" "iam.amazonaws.com" "203.0.113.42" "dev-ops" \
  '{"userName":"analyst-readonly"}'

# 6. AttachUserPolicy — privilege escalation (dev-ops → AdministratorAccess)
write_event "AttachUserPolicy" "iam.amazonaws.com" "203.0.113.42" "dev-ops" \
  '{"userName":"analyst-readonly","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}'

# 7. PutObject — data staging / exfil
write_event "PutObject" "s3.amazonaws.com" "203.0.113.42" "dev-ops" \
  '{"bucketName":"cloudtrail-logs","key":"exfil/dump.tar.gz"}'

echo "[cloudtrail-gen] $(date -u) — wrote 7 events to ${EXPORT_DIR}"
