#!/usr/bin/env bash
# install_elastic.sh
# Provisions Elasticsearch 8.x, Kibana, and Fleet Server on elastic-siem (192.168.56.10)
# Writes credentials and Fleet enrollment token to /vagrant/ for other VMs to consume.

set -euo pipefail

ELASTIC_VERSION="8.19.14"
FLEET_SERVER_IP="192.168.56.10"
ES_PORT="9200"
KIBANA_PORT="5601"
FLEET_PORT="8220"

log() { echo "[elastic] $*"; }

# ── 1. System prep ────────────────────────────────────────────────────────────
log "Updating packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wget curl gnupg apt-transport-https python3

# ── 2. Add Elastic apt repository ────────────────────────────────────────────
log "Adding Elastic apt repo..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --batch --yes --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
  https://artifacts.elastic.co/packages/8.x/apt stable main" \
  > /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -qq

# ── 3. Install packages ───────────────────────────────────────────────────────
log "Installing Elasticsearch and Kibana ${ELASTIC_VERSION}..."
apt-get install -y -qq elasticsearch=${ELASTIC_VERSION} kibana=${ELASTIC_VERSION}

# ── 4. Configure Elasticsearch ───────────────────────────────────────────────
log "Configuring Elasticsearch..."
cat > /etc/elasticsearch/elasticsearch.yml <<EOF
cluster.name: hunt-lab
node.name: elastic-siem
network.host: 0.0.0.0
http.port: ${ES_PORT}

# Data and log paths (preserve Debian package defaults)
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# Transport binding (intra-cluster; single node, so local only)
transport.host: localhost

# Security: auth enabled, SSL disabled for lab convenience
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
EOF

systemctl daemon-reload
systemctl enable --now elasticsearch

# ── 5. Wait for Elasticsearch ─────────────────────────────────────────────────
log "Waiting for Elasticsearch to be ready (this may take ~60s)..."
ES_READY=0
for i in $(seq 1 30); do
  if curl -s -o /dev/null http://localhost:${ES_PORT}; then
    log "Elasticsearch is up."
    ES_READY=1
    break
  fi
  sleep 5
done
if [[ "${ES_READY}" -eq 0 ]]; then
  log "ERROR: Elasticsearch did not become ready after 150s. Check: journalctl -u elasticsearch -n 50"
  exit 1
fi

# ── 6. Set elastic user password ─────────────────────────────────────────────
log "Resetting elastic user password..."
ELASTIC_PASSWORD=$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null)
echo "elastic:${ELASTIC_PASSWORD}" > /vagrant/elastic-credentials.txt
chmod 600 /vagrant/elastic-credentials.txt
log "Credentials written to /vagrant/elastic-credentials.txt"

# ── 7. Set kibana_system password ────────────────────────────────────────────
log "Resetting kibana_system password..."
KIBANA_SYSTEM_PASSWORD=$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -s -b 2>/dev/null)

# ── 8. Configure Kibana ───────────────────────────────────────────────────────
log "Configuring Kibana..."
cat > /etc/kibana/kibana.yml <<EOF
server.host: "0.0.0.0"
server.port: ${KIBANA_PORT}
server.name: "hunt-lab-kibana"

elasticsearch.hosts: ["http://${FLEET_SERVER_IP}:${ES_PORT}"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "${KIBANA_SYSTEM_PASSWORD}"

# Fleet Server integration
xpack.fleet.enabled: true
xpack.fleet.packages:
  - name: system
    version: latest
  - name: elastic_agent
    version: latest
  - name: fleet_server
    version: latest
  - name: windows
    version: latest
xpack.fleet.agentPolicies:
  - name: Fleet Server Policy
    id: fleet-server-policy
    is_default_fleet_server: true
    package_policies:
      - name: fleet_server-1
        id: default-fleet-server
        package:
          name: fleet_server
  - name: Windows Endpoint Policy
    id: windows-endpoint-policy
    is_default: true
    package_policies:
      - name: system-1
        id: default-system
        package:
          name: system
EOF

systemctl enable --now kibana

# ── 9. Wait for Kibana ────────────────────────────────────────────────────────
log "Waiting for Kibana to be ready (this may take ~90s)..."
KIBANA_READY=0
for i in $(seq 1 36); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "elastic:${ELASTIC_PASSWORD}" \
    "http://localhost:${KIBANA_PORT}/api/status" 2>/dev/null || echo "000")
  if [[ "${STATUS}" == "200" ]]; then
    log "Kibana is up."
    KIBANA_READY=1
    break
  fi
  sleep 5
done
if [[ "${KIBANA_READY}" -eq 0 ]]; then
  log "ERROR: Kibana did not become ready after 180s. Check: journalctl -u kibana -n 50"
  exit 1
fi

# ── 10. Install Elastic Agent as Fleet Server ─────────────────────────────────
log "Installing elastic-agent ${ELASTIC_VERSION}..."
apt-get install -y -qq elastic-agent=${ELASTIC_VERSION}

log "Creating Fleet Server service token..."
SERVICE_TOKEN=$(curl -s -X POST \
  -u "elastic:${ELASTIC_PASSWORD}" \
  "http://localhost:${ES_PORT}/_security/service/elastic/fleet-server/credential/token/fleet-server-token-1" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['token']['value'])")

log "Enrolling elastic-agent as Fleet Server..."
/usr/share/elastic-agent/bin/elastic-agent enroll \
  --path.home=/var/lib/elastic-agent \
  --path.config=/etc/elastic-agent \
  --path.logs=/var/log/elastic-agent \
  --fleet-server-es="http://${FLEET_SERVER_IP}:${ES_PORT}" \
  --fleet-server-service-token="${SERVICE_TOKEN}" \
  --fleet-server-host=0.0.0.0 \
  --fleet-server-port=${FLEET_PORT} \
  --fleet-server-insecure-http \
  --insecure \
  --force 2>&1 | tail -3
systemctl restart elastic-agent
sleep 10

# ── 11. Generate Fleet enrollment token for Windows agent ─────────────────────
log "Waiting for Fleet API to be ready..."
sleep 15

log "Fetching Fleet enrollment token..."
ENROLL_TOKEN=$(curl -s \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -H "kbn-xsrf: true" \
  "http://localhost:${KIBANA_PORT}/api/fleet/enrollment_api_keys" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = d.get('items', d.get('list', []))
# Prefer the default 'Managed by Fleet' policy key
token = next((k['api_key'] for k in keys if 'windows' in k.get('name','').lower()), None)
if token is None and keys:
    token = keys[0]['api_key']
print(token or '')
" 2>/dev/null)

echo "${ENROLL_TOKEN}" > /vagrant/fleet-enrollment-token.txt
chmod 600 /vagrant/fleet-enrollment-token.txt
log "Fleet enrollment token written to /vagrant/fleet-enrollment-token.txt"

# ── 12. Fix Fleet default output — localhost:9200 is correct for the Fleet
#        Server agent but wrong for any remote agent (e.g. win11-victim).
#        Update it to the real Elasticsearch IP so remote agents can ship data.
log "Fixing Fleet default output host (localhost → ${FLEET_SERVER_IP})..."
curl -s -X PUT \
  -u "elastic:${ELASTIC_PASSWORD}" \
  "http://localhost:${KIBANA_PORT}/api/fleet/outputs/fleet-default-output" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"default\",\"type\":\"elasticsearch\",\"hosts\":[\"http://${FLEET_SERVER_IP}:${ES_PORT}\"],\"is_default\":true,\"is_default_monitoring\":true}" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('[elastic] Fleet output updated to http://${FLEET_SERVER_IP}:${ES_PORT}') if 'item' in d else print('[elastic] WARNING: could not update Fleet output:', d)" \
  2>/dev/null

# ── 13. Add Windows integration to Windows Endpoint Policy ──────────────────
log "Waiting for Windows package to be available in Fleet..."
for i in $(seq 1 12); do
  PKG_VER=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
    "http://localhost:${KIBANA_PORT}/api/fleet/epm/packages/windows" \
    -H "kbn-xsrf: true" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('item',d).get('version',''))" 2>/dev/null || true)
  [[ -n "${PKG_VER}" ]] && break
  sleep 5
done

if [[ -n "${PKG_VER}" ]]; then
  log "Windows package ${PKG_VER} available. Adding integration to Windows Endpoint Policy..."
  curl -s -X POST \
    -u "elastic:${ELASTIC_PASSWORD}" \
    "http://localhost:${KIBANA_PORT}/api/fleet/package_policies" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"windows-1\",
      \"description\": \"Windows Event Logs - Sysmon, PowerShell, Defender\",
      \"namespace\": \"default\",
      \"policy_id\": \"windows-endpoint-policy\",
      \"enabled\": true,
      \"package\": {\"name\": \"windows\", \"version\": \"${PKG_VER}\"},
      \"inputs\": [{
        \"type\": \"winlog\",
        \"enabled\": true,
        \"streams\": [
          {
            \"id\": \"winlog-windows.sysmon_operational\",
            \"enabled\": true,
            \"data_stream\": {\"type\": \"logs\", \"dataset\": \"windows.sysmon_operational\"},
            \"vars\": {
              \"preserve_original_event\": {\"value\": false},
              \"event_id\":   {\"value\": \"\"},
              \"ignore_older\":{\"value\": \"72h\"},
              \"language\":   {\"value\": 0},
              \"tags\":       {\"value\": []},
              \"processors\": {\"value\": \"\"},
              \"custom\":     {\"value\": \"\"}
            }
          },
          {
            \"id\": \"winlog-windows.powershell_operational\",
            \"enabled\": true,
            \"data_stream\": {\"type\": \"logs\", \"dataset\": \"windows.powershell_operational\"},
            \"vars\": {
              \"preserve_original_event\": {\"value\": false},
              \"event_id\":   {\"value\": \"4103, 4104, 4105, 4106\"},
              \"ignore_older\":{\"value\": \"72h\"},
              \"language\":   {\"value\": 0},
              \"tags\":       {\"value\": []},
              \"processors\": {\"value\": \"\"},
              \"custom\":     {\"value\": \"\"}
            }
          },
          {
            \"id\": \"winlog-windows.powershell\",
            \"enabled\": true,
            \"data_stream\": {\"type\": \"logs\", \"dataset\": \"windows.powershell\"},
            \"vars\": {
              \"preserve_original_event\": {\"value\": false},
              \"event_id\":   {\"value\": \"400, 403, 600, 800\"},
              \"ignore_older\":{\"value\": \"72h\"},
              \"language\":   {\"value\": 0},
              \"tags\":       {\"value\": []},
              \"processors\": {\"value\": \"\"},
              \"custom\":     {\"value\": \"\"}
            }
          },
          {
            \"id\": \"winlog-windows.windows_defender\",
            \"enabled\": true,
            \"data_stream\": {\"type\": \"logs\", \"dataset\": \"windows.windows_defender\"},
            \"vars\": {
              \"preserve_original_event\": {\"value\": false},
              \"event_id\":   {\"value\": \"\"},
              \"ignore_older\":{\"value\": \"72h\"},
              \"language\":   {\"value\": 0},
              \"tags\":       {\"value\": []},
              \"processors\": {\"value\": \"\"},
              \"custom\":     {\"value\": \"\"}
            }
          }
        ]
      }]
    }" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print('[elastic] Windows integration added: id=' + d['item']['id']) if 'item' in d else print('[elastic] WARNING: Windows integration add failed:', d)" \
    2>/dev/null
else
  log "WARNING: Windows package not available after 60s — skipping integration setup."
  log "         Run manually: vagrant provision elastic-siem"
fi

# ── 14. Open firewall ports ───────────────────────────────────────────────────
log "Opening firewall ports..."
if command -v ufw &>/dev/null; then
  ufw allow ${ES_PORT}/tcp    comment "Elasticsearch"
  ufw allow ${KIBANA_PORT}/tcp comment "Kibana"
  ufw allow ${FLEET_PORT}/tcp  comment "Fleet Server"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
log ""
log "============================================================"
log "  Elastic SIEM provisioning complete!"
log "  Kibana:          http://${FLEET_SERVER_IP}:${KIBANA_PORT}"
log "  Elasticsearch:   http://${FLEET_SERVER_IP}:${ES_PORT}"
log "  Fleet Server:    https://${FLEET_SERVER_IP}:${FLEET_PORT}"
log "  Credentials:     /vagrant/elastic-credentials.txt"
log "============================================================"
