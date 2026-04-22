#!/usr/bin/env bash
# run_s3_exfil.sh
# Interactive S3 data exfiltration simulation for Hunt Lab.
# ATT&CK: T1526 (Cloud Service Discovery), T1537 (Transfer Data to Cloud Account)
#
# Run on cloud-sim: vagrant ssh cloud-sim -c "sudo bash /vagrant/scripts/scenarios/run_s3_exfil.sh"

set -euo pipefail

EXPORT_DIR="/var/log/localstack/cloudtrail"
ATTACKER_IP="185.220.101.50"   # Simulated Tor exit node
ACCT="000000000000"
REGION="us-east-1"

log()  { echo "[s3-exfil] $*"; }
warn() { echo "[s3-exfil] WARN: $*"; }

uuid() { python3 -c "import uuid; print(str(uuid.uuid4()))"; }

write_ct_event() {
  local ename="$1" esrc="$2" uname="$3" ronly="$4"
  local rparams="${5:-null}"
  local eid; eid=$(uuid)
  local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  mkdir -p "${EXPORT_DIR}"
  python3 - <<EOF
import json
obj = {
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::${ACCT}:user/${uname}",
    "accountId": "${ACCT}",
    "userName": "${uname}"
  },
  "eventTime": "${ts}", "@timestamp": "${ts}",
  "eventSource": "${esrc}",
  "eventName": "${ename}",
  "awsRegion": "${REGION}",
  "sourceIPAddress": "${ATTACKER_IP}",
  "userAgent": "Boto3/1.28.0 Python/3.10.12 botocore/1.31.0",
  "requestParameters": json.loads('${rparams}'),
  "responseElements": None,
  "requestID": "req-${eid}", "eventID": "${eid}",
  "readOnly": json.loads('${ronly}'),
  "eventType": "AwsApiCall", "managementEvent": True,
  "recipientAccountId": "${ACCT}"
}
with open("${EXPORT_DIR}/${eid}.json", "w") as f:
    json.dump(obj, f)
print("  [cloudtrail] ${ename}")
EOF
}

cat <<BANNER
=============================================================
  Hunt Lab — S3 Exfiltration Scenario
  ATT&CK: T1526, T1537
  Simulated attacker IP: ${ATTACKER_IP}  (Tor exit node)
=============================================================
BANNER

# Phase 1: Discovery
log "Phase 1: Cloud service discovery..."
awslocal s3api list-buckets &>/dev/null || true
write_ct_event "GetCallerIdentity" "sts.amazonaws.com"  "analyst-readonly" "true"
write_ct_event "ListBuckets"       "s3.amazonaws.com"   "analyst-readonly" "true"
write_ct_event "GetBucketAcl"      "s3.amazonaws.com"   "analyst-readonly" "true" \
  '{"bucketName":"company-financials"}'
write_ct_event "GetBucketAcl"      "s3.amazonaws.com"   "analyst-readonly" "true" \
  '{"bucketName":"hr-data"}'
write_ct_event "GetBucketLogging"  "s3.amazonaws.com"   "analyst-readonly" "true" \
  '{"bucketName":"hr-data"}'
sleep 2

# Phase 2: Data access
log "Phase 2: Accessing sensitive data..."
awslocal s3api list-objects-v2 --bucket hr-data &>/dev/null || true
write_ct_event "ListObjectsV2" "s3.amazonaws.com" "analyst-readonly" "true" \
  '{"bucketName":"hr-data","prefix":""}'
write_ct_event "ListObjectsV2" "s3.amazonaws.com" "analyst-readonly" "true" \
  '{"bucketName":"company-financials","prefix":""}'

awslocal s3 cp s3://hr-data/employees/john_doe.json /tmp/exfil_john.json &>/dev/null || true
write_ct_event "GetObject" "s3.amazonaws.com" "analyst-readonly" "true" \
  '{"bucketName":"hr-data","key":"employees/john_doe.json"}'
awslocal s3 cp s3://hr-data/employees/jane_smith.json /tmp/exfil_jane.json &>/dev/null || true
write_ct_event "GetObject" "s3.amazonaws.com" "analyst-readonly" "true" \
  '{"bucketName":"hr-data","key":"employees/jane_smith.json"}'
awslocal s3 cp s3://company-financials/2025-q4-report.json /tmp/exfil_q4.json &>/dev/null || true
write_ct_event "GetObject" "s3.amazonaws.com" "analyst-readonly" "true" \
  '{"bucketName":"company-financials","key":"2025-q4-report.json"}'
sleep 2

# Phase 3: Staging bucket + exfil
log "Phase 3: Creating staging bucket and exfiltrating..."
STAGING="exfil-staging-$(openssl rand -hex 4 2>/dev/null || echo '8f3a2b')"
awslocal s3 mb "s3://${STAGING}" &>/dev/null || true
write_ct_event "CreateBucket" "s3.amazonaws.com" "analyst-readonly" "false" \
  "{\"bucketName\":\"${STAGING}\"}"
write_ct_event "PutBucketAcl" "s3.amazonaws.com" "analyst-readonly" "false" \
  "{\"bucketName\":\"${STAGING}\",\"acl\":\"public-read\"}"

for f in /tmp/exfil_john.json /tmp/exfil_jane.json /tmp/exfil_q4.json; do
  [[ -f "${f}" ]] && awslocal s3 cp "${f}" "s3://${STAGING}/dump/$(basename ${f})" &>/dev/null || true
done
write_ct_event "PutObject" "s3.amazonaws.com" "analyst-readonly" "false" \
  "{\"bucketName\":\"${STAGING}\",\"key\":\"dump/hr_employees.json\"}"
write_ct_event "PutObject" "s3.amazonaws.com" "analyst-readonly" "false" \
  "{\"bucketName\":\"${STAGING}\",\"key\":\"dump/financials_q4.json\"}"
sleep 2

# Phase 4: Cover tracks
log "Phase 4: Covering tracks..."
awslocal s3 rm "s3://${STAGING}" --recursive &>/dev/null || true
write_ct_event "DeleteObject" "s3.amazonaws.com" "analyst-readonly" "false" \
  "{\"bucketName\":\"${STAGING}\",\"key\":\"dump/hr_employees.json\"}"
write_ct_event "DeleteObject" "s3.amazonaws.com" "analyst-readonly" "false" \
  "{\"bucketName\":\"${STAGING}\",\"key\":\"dump/financials_q4.json\"}"
awslocal s3 rb "s3://${STAGING}" &>/dev/null || true
write_ct_event "DeleteBucket" "s3.amazonaws.com" "analyst-readonly" "false" \
  "{\"bucketName\":\"${STAGING}\"}"

rm -f /tmp/exfil_john.json /tmp/exfil_jane.json /tmp/exfil_q4.json

log "Scenario complete. Events written to ${EXPORT_DIR}"
echo ""
echo "  Hunt in Kibana: http://192.168.56.10:5601"
echo "  Index: cloudtrail-*  |  Filter: sourceIPAddress: ${ATTACKER_IP}"
echo "  ATT&CK techniques: T1526, T1537"
