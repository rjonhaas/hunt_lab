#!/usr/bin/env bash
# fix_cloud_sim_pipeline.sh
# Applies the CloudTrail activity generator fix to the running cloud-sim VM.
# Run: vagrant ssh cloud-sim -c "sudo bash /vagrant/scripts/fix_cloud_sim_pipeline.sh"

set -euo pipefail
log() { echo "[fix-cloud-sim] $*"; }

EXPORT_DIR="/var/log/localstack/cloudtrail"
mkdir -p "${EXPORT_DIR}"

log "Installing CloudTrail activity generator..."
cat > /opt/localstack/generate_cloudtrail_activity.sh << 'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

EXPORT_DIR="/var/log/localstack/cloudtrail"
mkdir -p "${EXPORT_DIR}"
ACCT="000000000000"
REGION="us-east-1"
HOST_IP="192.168.56.40"

uuid() { python3 -c "import uuid; print(str(uuid.uuid4()))"; }

write_ct_event() {
  local ename="$1" esrc="$2" uname="$3" ronly="$4"
  local rparams="${5:-null}"
  local eid; eid=$(uuid)
  local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  python3 - <<EOF
import json
obj = {
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "arn": f"arn:aws:iam::${ACCT}:user/${uname}",
    "accountId": "${ACCT}", "userName": "${uname}"
  },
  "eventTime": "${ts}", "@timestamp": "${ts}",
  "eventSource": "${esrc}", "eventName": "${ename}",
  "awsRegion": "${REGION}", "sourceIPAddress": "${HOST_IP}",
  "userAgent": "aws-cli/2.13.0 Python/3.11.6",
  "requestParameters": json.loads('${rparams}'), "responseElements": None,
  "requestID": "req-${eid}", "eventID": "${eid}",
  "readOnly": json.loads('${ronly}'), "eventType": "AwsApiCall",
  "managementEvent": True, "recipientAccountId": "${ACCT}"
}
fname = "${EXPORT_DIR}/${eid}.json"
with open(fname, "w") as f:
    json.dump(obj, f)
EOF
}

awslocal s3api list-buckets &>/dev/null && \
  write_ct_event "ListBuckets" "s3.amazonaws.com" "analyst-readonly" "true"
awslocal iam list-users &>/dev/null && \
  write_ct_event "ListUsers" "iam.amazonaws.com" "dev-ops" "true"
awslocal sts get-caller-identity &>/dev/null && \
  write_ct_event "GetCallerIdentity" "sts.amazonaws.com" "analyst-readonly" "true"
awslocal ec2 describe-instances &>/dev/null && \
  write_ct_event "DescribeInstances" "ec2.amazonaws.com" "dev-ops" "true"
SCRIPT
chmod +x /opt/localstack/generate_cloudtrail_activity.sh

log "Installing cron job..."
cat > /etc/cron.d/cloudtrail-activity << 'CRON'
* * * * * root /opt/localstack/generate_cloudtrail_activity.sh >>/var/log/localstack/activity-gen.log 2>&1
CRON
chmod 644 /etc/cron.d/cloudtrail-activity

log "Running generator once immediately..."
/opt/localstack/generate_cloudtrail_activity.sh && log "Initial events written to ${EXPORT_DIR}"

# Count events now in watch dir
EVENT_COUNT=$(ls "${EXPORT_DIR}"/*.json 2>/dev/null | wc -l)
log "${EVENT_COUNT} event files now in ${EXPORT_DIR}"

log "Checking Filebeat status..."
systemctl is-active filebeat && log "Filebeat: running" || log "Filebeat: not running — restarting..."
systemctl restart filebeat || true

log "Pipeline fix complete."
log "  Watch dir: ${EXPORT_DIR}"
log "  Filebeat ships to: http://192.168.56.10:9200 (index: cloudtrail-*)"
log "  New events appear every 60s via cron."
