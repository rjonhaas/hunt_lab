#!/usr/bin/env bash
# deploy_cloud_agent.sh
# (Re)deploys the Caldera Sandcat agent on the cloud-sim VM.
# Run from host: vagrant ssh cloud-sim -c "sudo bash /vagrant/scripts/deploy_cloud_agent.sh"
# Or applied automatically at end of install_cloud_sim.sh provisioning.

set -euo pipefail

CALDERA_HOST="192.168.56.30"
CALDERA_PORT="8888"
SANDCAT_PATH="/opt/sandcat/sandcat"
SERVICE_FILE="/etc/systemd/system/sandcat-cloud.service"

log()  { echo "[cloud-agent] $*"; }
die()  { echo "[cloud-agent] ERROR: $*" >&2; exit 1; }

# Wait for Caldera to be reachable
log "Checking Caldera availability at ${CALDERA_HOST}:${CALDERA_PORT}..."
for i in $(seq 1 20); do
  if curl -sf -H "KEY: ADMIN123" "http://${CALDERA_HOST}:${CALDERA_PORT}/api/v2/health" &>/dev/null; then
    log "Caldera is reachable."
    break
  fi
  [[ $i -eq 20 ]] && die "Caldera not reachable after 100s. Is caldera VM up?"
  log "  waiting... (${i}/20)"
  sleep 5
done

# Stop any existing sandcat service/process
systemctl stop sandcat-cloud 2>/dev/null || true
systemctl stop sandcat      2>/dev/null || true
pkill -f sandcat            2>/dev/null || true
sleep 1

# Download fresh sandcat binary
mkdir -p /opt/sandcat
log "Downloading sandcat (linux) from Caldera..."
curl -fsSL \
  -H "file: sandcat.go-linux" \
  -H "KEY: ADMIN123" \
  "http://${CALDERA_HOST}:${CALDERA_PORT}/file/download" \
  -o "${SANDCAT_PATH}" || die "sandcat download failed"
chmod +x "${SANDCAT_PATH}"
log "sandcat binary downloaded to ${SANDCAT_PATH}"

# Write systemd unit
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Caldera Sandcat Agent (cloud group)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SANDCAT_PATH} -server http://${CALDERA_HOST}:${CALDERA_PORT} -group cloud -v
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sandcat-cloud
systemctl start  sandcat-cloud

# Confirm it started
sleep 3
if systemctl is-active --quiet sandcat-cloud; then
  log "sandcat-cloud service is running."
else
  journalctl -u sandcat-cloud --no-pager -n 20
  die "sandcat-cloud failed to start — see logs above."
fi

# Wait up to 30s for the agent to appear in Caldera
log "Waiting for agent to register in Caldera (group: cloud)..."
for i in $(seq 1 10); do
  COUNT=$(curl -sf --max-time 5 -H "KEY: ADMIN123" \
    "http://${CALDERA_HOST}:${CALDERA_PORT}/api/v2/agents" 2>/dev/null \
    | python3 -c "import sys,json; agents=json.load(sys.stdin); print(sum(1 for a in agents if a.get('group')=='cloud'))" 2>/dev/null || echo 0)
  if [[ "${COUNT}" -gt 0 ]]; then
    log "Agent registered in Caldera (cloud group). Count: ${COUNT}"
    break
  fi
  sleep 3
done

log "Done. cloud-sim sandcat agent is deployed."
log "  Group: cloud | Server: http://${CALDERA_HOST}:${CALDERA_PORT}"
log "  Abilities available: HL: S3 Exfil, IAM Privesc, Crypto Mining"
