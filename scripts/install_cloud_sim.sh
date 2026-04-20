#!/usr/bin/env bash
# install_cloud_sim.sh
# Provisions the cloud-sim VM (192.168.56.40):
#   - Docker + LocalStack (AWS emulation)
#   - awscli-local (awslocal CLI wrapper)
#   - Filebeat → ships CloudTrail logs to elastic-siem
#   - Sandcat agent → registers with Caldera (group: cloud)
#   - Bulk-ingests pre-built attack scenario logs into Elastic

set -euo pipefail

LOCALSTACK_VERSION="3.4"
ELASTIC_HOST="192.168.56.10"
ES_PORT="9200"
CALDERA_HOST="192.168.56.30"
CALDERA_PORT="8888"
CLOUD_SIM_IP="192.168.56.40"
CLOUDTRAIL_LOG_DIR="/var/log/localstack/cloudtrail"
ELASTIC_VERSION="8.13.4"
LOCALSTACK_AUTH_TOKEN=""
LOCALSTACK_IMAGE="localstack/localstack:${LOCALSTACK_VERSION}"

log() { echo "[cloud-sim] $*"; }

# ── 1. System prep ────────────────────────────────────────────────────────────
log "Updating packages..."
export DEBIAN_FRONTEND=noninteractive
# Remove stale Elastic repo entries from previous failed runs.
# A bad key/repo state can break apt-get update before we reconfigure it later.
rm -f /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates lsb-release jq python3 python3-pip unzip

# ── 2. Install Docker ────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  log "Installing Docker..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
systemctl enable --now docker
usermod -aG docker vagrant || true

# ── 3. Install AWS CLI + awscli-local ─────────────────────────────────────────
log "Installing AWS CLI and awscli-local..."
if ! command -v aws &>/dev/null; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscli.zip
  unzip -qo /tmp/awscli.zip -d /tmp/awscli
  /tmp/awscli/aws/install --update
  rm -rf /tmp/awscli /tmp/awscli.zip
fi
pip3 install -q awscli-local

# Configure dummy AWS credentials for LocalStack
mkdir -p /home/vagrant/.aws
cat > /home/vagrant/.aws/credentials <<'EOF'
[default]
aws_access_key_id = test
aws_secret_access_key = test
EOF
cat > /home/vagrant/.aws/config <<'EOF'
[default]
region = us-east-1
output = json
EOF
chown -R vagrant:vagrant /home/vagrant/.aws

# ── 4. Create LocalStack directories ──────────────────────────────────────────
log "Setting up LocalStack directories..."
mkdir -p /opt/localstack/data
mkdir -p "${CLOUDTRAIL_LOG_DIR}"

# Optional: enable LocalStack Pro if a host token was shared via /vagrant.
# The token file should exist on the host as ./localstack-auth-token.txt.
if [[ -f /vagrant/localstack-auth-token.txt ]]; then
  LOCALSTACK_AUTH_TOKEN=$(tr -d '\r\n' < /vagrant/localstack-auth-token.txt)
fi
if [[ -n "${LOCALSTACK_AUTH_TOKEN}" ]]; then
  LOCALSTACK_IMAGE="localstack/localstack-pro:${LOCALSTACK_VERSION}"
  log "LocalStack Pro token detected. Using ${LOCALSTACK_IMAGE}."
else
  log "No LocalStack token detected. Using ${LOCALSTACK_IMAGE} (Community mode)."
fi

AUTH_TOKEN_ENV_LINE=""
if [[ -n "${LOCALSTACK_AUTH_TOKEN}" ]]; then
  AUTH_TOKEN_ENV_LINE="      - LOCALSTACK_AUTH_TOKEN=${LOCALSTACK_AUTH_TOKEN}"
fi

# ── 5. Deploy LocalStack via Docker Compose ───────────────────────────────────
log "Writing LocalStack docker-compose.yml..."
cat > /opt/localstack/docker-compose.yml <<EOF
version: "3.8"
services:
  localstack:
    image: ${LOCALSTACK_IMAGE}
    restart: unless-stopped
    ports:
      - "4566:4566"        # LocalStack Gateway
      - "4510-4559:4510-4559"  # Service-specific ports
    environment:
      - SERVICES=s3,iam,lambda,sts,cloudtrail,cloudwatch,ec2
      - DEFAULT_REGION=us-east-1
      - DEBUG=0
      - DATA_DIR=/var/lib/localstack/data
      - DOCKER_HOST=unix:///var/run/docker.sock
${AUTH_TOKEN_ENV_LINE}
    volumes:
      - localstack-data:/var/lib/localstack
      - /var/run/docker.sock:/var/run/docker.sock
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:4566/_localstack/health"]
      interval: 15s
      timeout: 5s
      retries: 10
      start_period: 30s

volumes:
  localstack-data:
EOF

log "Starting LocalStack..."
cd /opt/localstack
docker compose pull
docker compose up -d

# ── 6. Wait for LocalStack to be healthy ──────────────────────────────────────
log "Waiting for LocalStack to be ready..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:4566/_localstack/health | jq -e '.services.s3 == "running"' &>/dev/null; then
    log "LocalStack is healthy."
    break
  fi
  sleep 3
done

# ── 7. Bootstrap CloudTrail in LocalStack ─────────────────────────────────────
log "Setting up CloudTrail..."
# Create the CloudTrail log S3 bucket
awslocal s3 mb s3://cloudtrail-logs 2>/dev/null || true

# Put a bucket policy allowing CloudTrail to write
awslocal s3api put-bucket-policy --bucket cloudtrail-logs --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AWSCloudTrailAclCheck",
    "Effect": "Allow",
    "Principal": {"Service": "cloudtrail.amazonaws.com"},
    "Action": "s3:GetBucketAcl",
    "Resource": "arn:aws:s3:::cloudtrail-logs"
  },{
    "Sid": "AWSCloudTrailWrite",
    "Effect": "Allow",
    "Principal": {"Service": "cloudtrail.amazonaws.com"},
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::cloudtrail-logs/*",
    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
  }]
}' 2>/dev/null || true

# Create the trail
awslocal cloudtrail create-trail \
  --name hunt-lab-trail \
  --s3-bucket-name cloudtrail-logs \
  --is-multi-region-trail 2>/dev/null || true

awslocal cloudtrail start-logging --name hunt-lab-trail 2>/dev/null || true
log "CloudTrail trail 'hunt-lab-trail' enabled."

# Seed some baseline AWS resources for the attack scenarios to target
log "Seeding baseline AWS resources..."
awslocal s3 mb s3://company-financials 2>/dev/null || true
awslocal s3 mb s3://hr-data 2>/dev/null || true
echo '{"ssn":"123-45-6789","name":"John Doe","salary":150000}' | awslocal s3 cp - s3://hr-data/employees/john_doe.json 2>/dev/null || true
echo '{"ssn":"987-65-4321","name":"Jane Smith","salary":180000}' | awslocal s3 cp - s3://hr-data/employees/jane_smith.json 2>/dev/null || true
echo '{"q4_revenue":42000000,"projections":"confidential"}' | awslocal s3 cp - s3://company-financials/2025-q4-report.json 2>/dev/null || true

awslocal iam create-user --user-name analyst-readonly 2>/dev/null || true
awslocal iam create-user --user-name dev-ops 2>/dev/null || true
awslocal iam attach-user-policy --user-name analyst-readonly \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null || true
# Intentionally overpermissive — the IAM privesc scenario exploits this
awslocal iam attach-user-policy --user-name dev-ops \
  --policy-arn arn:aws:iam::aws:policy/IAMFullAccess 2>/dev/null || true

log "Baseline AWS resources seeded."

# ── 8. Set up CloudTrail log export cron ──────────────────────────────────────
# LocalStack stores CloudTrail events in S3. This script polls them and writes
# them to a flat JSON log directory that Filebeat monitors.
cat > /opt/localstack/export_cloudtrail.sh <<'SCRIPT'
#!/usr/bin/env bash
# Exports CloudTrail events from LocalStack S3 to flat JSON files for Filebeat.
set -euo pipefail
EXPORT_DIR="/var/log/localstack/cloudtrail"
MARKER_FILE="/var/log/localstack/.last_export"
mkdir -p "${EXPORT_DIR}"

# Method 1: Use CloudTrail lookup-events API
EVENTS=$(awslocal cloudtrail lookup-events \
  --max-results 50 \
  --output json 2>/dev/null || echo '{"Events":[]}')

echo "${EVENTS}" | jq -c '.Events[]' 2>/dev/null | while IFS= read -r event; do
  EVENT_ID=$(echo "${event}" | jq -r '.EventId // empty')
  if [[ -n "${EVENT_ID}" ]] && [[ ! -f "${EXPORT_DIR}/${EVENT_ID}.json" ]]; then
    # Parse CloudTrailEvent (it's a JSON string inside the event)
    CT_EVENT=$(echo "${event}" | jq -r '.CloudTrailEvent // empty')
    if [[ -n "${CT_EVENT}" ]]; then
      echo "${CT_EVENT}" > "${EXPORT_DIR}/${EVENT_ID}.json"
    else
      echo "${event}" | jq -c '.' > "${EXPORT_DIR}/${EVENT_ID}.json"
    fi
  fi
done

# Method 2: Also poll S3 for any trail-delivered logs
KEYS=$(awslocal s3api list-objects-v2 --bucket cloudtrail-logs --query 'Contents[].Key' --output text 2>/dev/null || echo "")
for key in ${KEYS}; do
  [[ "${key}" == "None" ]] && continue
  BASENAME=$(echo "${key}" | tr '/' '_')
  if [[ ! -f "${EXPORT_DIR}/s3_${BASENAME}" ]]; then
    awslocal s3 cp "s3://cloudtrail-logs/${key}" "/tmp/ct_tmp_${BASENAME}" 2>/dev/null || continue
    # CloudTrail delivers gzipped JSON; handle both cases
    if file "/tmp/ct_tmp_${BASENAME}" | grep -q gzip; then
      zcat "/tmp/ct_tmp_${BASENAME}" | jq -c '.Records[]' 2>/dev/null >> "${EXPORT_DIR}/s3_${BASENAME}" || true
    else
      jq -c '.Records[]' "/tmp/ct_tmp_${BASENAME}" 2>/dev/null >> "${EXPORT_DIR}/s3_${BASENAME}" || \
      cp "/tmp/ct_tmp_${BASENAME}" "${EXPORT_DIR}/s3_${BASENAME}"
    fi
    rm -f "/tmp/ct_tmp_${BASENAME}"
  fi
done
SCRIPT
chmod +x /opt/localstack/export_cloudtrail.sh

# Run every 30 seconds via cron
cat > /etc/cron.d/cloudtrail-export <<'CRON'
* * * * * root /opt/localstack/export_cloudtrail.sh >/dev/null 2>&1
* * * * * root sleep 30 && /opt/localstack/export_cloudtrail.sh >/dev/null 2>&1
CRON
chmod 644 /etc/cron.d/cloudtrail-export

# ── 9. Install and configure Filebeat ─────────────────────────────────────────
log "Installing Filebeat..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --batch --yes --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
  https://artifacts.elastic.co/packages/8.x/apt stable main" \
  > /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -qq
apt-get install -y -qq filebeat

# Read elastic credentials from the shared folder
ELASTIC_CREDS=""
if [[ -f /vagrant/elastic-credentials.txt ]]; then
  ELASTIC_CREDS=$(cat /vagrant/elastic-credentials.txt)
fi
ELASTIC_USER=$(echo "${ELASTIC_CREDS}" | cut -d: -f1)
ELASTIC_PASS=$(echo "${ELASTIC_CREDS}" | cut -d: -f2)

log "Configuring Filebeat..."
cat > /etc/filebeat/filebeat.yml <<EOF
filebeat.inputs:
  - type: log
    id: cloudtrail-json
    enabled: true
    paths:
      - ${CLOUDTRAIL_LOG_DIR}/*.json
    json.keys_under_root: true
    json.add_error_key: true
    json.overwrite_keys: true
    fields:
      event.dataset: aws.cloudtrail
      cloud.provider: aws
    fields_under_root: true
    # Re-read files as new events are appended
    close_eof: false
    scan_frequency: 10s

output.elasticsearch:
  hosts: ["http://${ELASTIC_HOST}:${ES_PORT}"]
  username: "${ELASTIC_USER}"
  password: "${ELASTIC_PASS}"
  index: "cloudtrail-%{+yyyy.MM.dd}"

setup.ilm.enabled: false
setup.template.name: "cloudtrail"
setup.template.pattern: "cloudtrail-*"
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0

processors:
  - timestamp:
      field: eventTime
      layouts:
        - '2006-01-02T15:04:05Z'
        - '2006-01-02T15:04:05.000Z'
      test:
        - '2024-01-15T10:30:00Z'
      ignore_missing: true
      ignore_failure: true
  - rename:
      fields:
        - {from: "eventName", to: "event.action"}
        - {from: "eventSource", to: "cloud.service.name"}
        - {from: "awsRegion", to: "cloud.region"}
        - {from: "sourceIPAddress", to: "source.ip"}
        - {from: "userAgent", to: "user_agent.original"}
        - {from: "errorCode", to: "error.code"}
        - {from: "errorMessage", to: "error.message"}
      ignore_missing: true
      fail_on_error: false
  - add_fields:
      target: ''
      fields:
        cloud.provider: aws
        event.dataset: aws.cloudtrail
        event.module: aws

logging.level: warning
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 3
EOF

systemctl enable --now filebeat
log "Filebeat configured and started."

# ── 10. Deploy Sandcat agent for Caldera ──────────────────────────────────────
log "Deploying Caldera Sandcat agent..."
# Wait a bit for Caldera to be ready (it may still be booting if started in parallel)
SANDCAT_DEPLOYED=false
for i in $(seq 1 10); do
  if curl -sf "http://${CALDERA_HOST}:${CALDERA_PORT}/api/v2/health" &>/dev/null; then
    curl -fsSL -o /tmp/sandcat \
      -H "file: sandcat.go-linux" \
      -H "KEY: ADMIN123" \
      "http://${CALDERA_HOST}:${CALDERA_PORT}/file/download" 2>/dev/null && {
      chmod +x /tmp/sandcat
      # Run as a background service via systemd
      cat > /etc/systemd/system/sandcat.service <<SVCEOF
[Unit]
Description=Caldera Sandcat Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/tmp/sandcat -server http://${CALDERA_HOST}:${CALDERA_PORT} -group cloud
Restart=always
RestartSec=30
User=root

[Install]
WantedBy=multi-user.target
SVCEOF
      systemctl daemon-reload
      systemctl enable --now sandcat
      SANDCAT_DEPLOYED=true
      log "Sandcat agent deployed (group: cloud)."
      break
    }
  fi
  log "Waiting for Caldera to be available (attempt ${i}/10)..."
  sleep 10
done

if [[ "${SANDCAT_DEPLOYED}" != "true" ]]; then
  log "WARNING: Could not deploy Sandcat agent. Caldera may not be ready."
  log "  Deploy manually: vagrant ssh cloud-sim -c 'sudo systemctl start sandcat'"
fi

# ── 11. Load pre-built scenarios into Elastic ─────────────────────────────────
log "Loading pre-built cloud attack scenarios..."
if [[ -f /vagrant/scripts/load_cloud_scenarios.sh ]]; then
  bash /vagrant/scripts/load_cloud_scenarios.sh
else
  log "WARNING: load_cloud_scenarios.sh not found. Skipping scenario ingest."
fi

# ── 12. Write helper script ───────────────────────────────────────────────────
cat > /usr/local/bin/cloud-hunt <<'HELPER'
#!/usr/bin/env bash
cat <<'BANNER'
╔══════════════════════════════════════════════════════════════╗
║              Cloud Threat Hunting — cloud-sim               ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  LocalStack endpoint:  http://localhost:4566                 ║
║  AWS CLI wrapper:      awslocal <command>                    ║
║                                                              ║
║  ── Interactive Attack Scenarios ──────────────────────────  ║
║                                                              ║
║  /vagrant/scripts/scenarios/run_s3_exfil.sh                  ║
║    → S3 bucket enum + data exfiltration                      ║
║    → ATT&CK: T1526, T1537                                   ║
║                                                              ║
║  /vagrant/scripts/scenarios/run_iam_privesc.sh               ║
║    → IAM privilege escalation chain                          ║
║    → ATT&CK: T1087.004, T1078.004, T1136.003, T1562.001     ║
║                                                              ║
║  /vagrant/scripts/scenarios/run_crypto_mining.sh             ║
║    → Crypto mining via cloud compute                         ║
║    → ATT&CK: T1496.001, T1070.004                           ║
║                                                              ║
║  ── Automated Attacks (via Caldera) ─────────────────────    ║
║                                                              ║
║  Sandcat agent registered with Caldera (group: cloud)        ║
║  Open http://192.168.56.30:8888 → Operations → Create        ║
║  Select a cloud adversary profile and click Start            ║
║                                                              ║
║  ── Useful Commands ──────────────────────────────────────   ║
║                                                              ║
║  awslocal s3 ls                   List all S3 buckets        ║
║  awslocal iam list-users          List IAM users             ║
║  awslocal cloudtrail lookup-events  View recent CT events    ║
║  awslocal sts get-caller-identity   Show current identity    ║
║                                                              ║
║  ── Where to Hunt ────────────────────────────────────────   ║
║                                                              ║
║  Kibana:  http://192.168.56.10:5601                          ║
║  Index:   cloudtrail-*                                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
BANNER
HELPER
chmod +x /usr/local/bin/cloud-hunt

# Add cloud-hunt to vagrant user's .bashrc
if ! grep -q 'cloud-hunt' /home/vagrant/.bashrc 2>/dev/null; then
  echo 'echo "Type cloud-hunt for available commands and scenarios."' >> /home/vagrant/.bashrc
fi

# ── 13. Open firewall ports ───────────────────────────────────────────────────
log "Opening firewall ports..."
if command -v ufw &>/dev/null; then
  ufw allow 4566/tcp comment "LocalStack Gateway"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
log ""
log "============================================================"
log "  cloud-sim provisioning complete!"
log "  LocalStack:       http://${CLOUD_SIM_IP}:4566"
log "  AWS CLI:          awslocal <command>"
log "  Attack scenarios: cloud-hunt"
log "  CloudTrail logs:  → Filebeat → http://${ELASTIC_HOST}:${ES_PORT}"
log "  Caldera agent:    Sandcat (group: cloud)"
log "============================================================"
