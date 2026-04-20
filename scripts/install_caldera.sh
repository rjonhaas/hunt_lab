#!/usr/bin/env bash
# install_caldera.sh
# Provisions MITRE Caldera 5.x on caldera (192.168.56.30)
# Uses Docker Compose for a self-contained, restartable deployment.

set -euo pipefail

CALDERA_IP="192.168.56.30"
CALDERA_PORT="8888"
CALDERA_DIR="/opt/caldera"
CALDERA_TAG="5.0.0"
CALDERA_IMAGE="ghcr.io/mitre/caldera:${CALDERA_TAG}"

log() { echo "[caldera] $*"; }

# ── 1. System prep ────────────────────────────────────────────────────────────
log "Updating packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates lsb-release git

# ── 2. Install Docker ────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  log "Installing Docker..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

systemctl enable --now docker

# Add vagrant user to docker group so they can manage containers without sudo
usermod -aG docker vagrant || true

# ── 3. Create Caldera directory ───────────────────────────────────────────────
log "Setting up Caldera directory at ${CALDERA_DIR}..."
mkdir -p "${CALDERA_DIR}/data/configurations"
mkdir -p "${CALDERA_DIR}/data/results"
mkdir -p "${CALDERA_DIR}/data/payloads"

# ── 4. Write custom Caldera server config ─────────────────────────────────────
# This sets the contact address so agents beacon back to 192.168.56.30
cat > "${CALDERA_DIR}/data/configurations/local.yml" <<EOF
host: 0.0.0.0
port: ${CALDERA_PORT}

plugins:
  - access
  - atomic
  - compass
  - debrief
  - emu
  - fieldmanual
  - manx
  - response
  - sandcat
  - stockpile
  - training

# app.contact.http is the URL agents beacon back to (external address)
# app.contact.tcp/udp/websocket are SERVER BIND addresses inside the container — must be 0.0.0.0
app.contact.http: http://${CALDERA_IP}:${CALDERA_PORT}
app.contact.dns.domain: caldera.lab
app.contact.tcp: 0.0.0.0:7010
app.contact.udp: 0.0.0.0:7011
app.contact.websocket: 0.0.0.0:7012

# Default admin credentials — CHANGE if exposing beyond host-only network
users:
  red:
    admin: admin
    red: admin
  blue:
    blue: admin
api_key_red: ADMIN123
api_key_blue: BLUEADMIN123

# Required by Caldera 5.x file service
crypt_salt: hunt-lab-salt-6ddf9d464e5eb723
encryption_key: hunt-lab-enc-key-2026
EOF

# ── 5. Write docker-compose.yml ───────────────────────────────────────────────
log "Writing docker-compose.yml..."
cat > "${CALDERA_DIR}/docker-compose.yml" <<EOF
version: "3.8"
services:
  caldera:
    image: ${CALDERA_IMAGE}
    restart: unless-stopped
    ports:
      - "${CALDERA_PORT}:${CALDERA_PORT}"
      - "7010:7010"   # TCP contact
      - "7011:7011/udp"  # UDP contact
      - "7012:7012"   # WebSocket contact
    volumes:
      - ./data/configurations/local.yml:/usr/src/app/conf/local.yml:ro
      - ./data/magma-dist:/usr/src/app/plugins/magma/dist:ro
      - caldera-data:/usr/src/app/data
    environment:
      - CALDERA_PORT=${CALDERA_PORT}
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:${CALDERA_PORT}/api/v2/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s

volumes:
  caldera-data:
EOF

# ── 6. Build magma Vue UI ─────────────────────────────────────────────────────
# The 5.0.0 image ships magma source without a pre-built dist/assets directory.
# We extract the plugin sources, build them with Node.js, and mount the result
# into the container so the REST API can serve the UI.
log "Building Caldera magma UI (requires Node.js)..."
if ! command -v node &>/dev/null; then
  log "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y -qq nodejs
fi

BUILD_DIR="/tmp/caldera-plugins-build"
rm -rf "${BUILD_DIR}"

# Pull the image first so we can extract plugin sources
docker pull "${CALDERA_IMAGE}"
TEMP_CID=$(docker create "${CALDERA_IMAGE}")
docker cp "${TEMP_CID}:/usr/src/app/plugins" "${BUILD_DIR}"
docker rm "${TEMP_CID}"

cd "${BUILD_DIR}/magma"
npm install --silent
node prebundle.js
VITE_CALDERA_URL="http://${CALDERA_IP}:${CALDERA_PORT}" npx vite build --logLevel warn

mkdir -p "${CALDERA_DIR}/data/magma-dist"
cp -r "${BUILD_DIR}/magma/dist/." "${CALDERA_DIR}/data/magma-dist/"
log "Magma UI built and copied to ${CALDERA_DIR}/data/magma-dist/"

# ── 7. Start Caldera ──────────────────────────────────────────────────────────
log "Starting Caldera container..."
cd "${CALDERA_DIR}"
docker compose pull
docker compose up -d

# ── 8. Open firewall ports ────────────────────────────────────────────────────
log "Opening firewall ports..."
if command -v ufw &>/dev/null; then
  ufw allow ${CALDERA_PORT}/tcp comment "Caldera HTTP"
  ufw allow 7010/tcp             comment "Caldera TCP contact"
  ufw allow 7011/udp             comment "Caldera UDP contact"
  ufw allow 7012/tcp             comment "Caldera WebSocket"
fi

# ── 9. Create a helper script for operators ────────────────────────────────────
cat > /usr/local/bin/caldera-logs <<'SCRIPT'
#!/usr/bin/env bash
cd /opt/caldera && docker compose logs -f
SCRIPT
chmod +x /usr/local/bin/caldera-logs

# ── Done ──────────────────────────────────────────────────────────────────────
log ""
log "============================================================"
log "  Caldera provisioning complete!"
log "  URL:           http://${CALDERA_IP}:${CALDERA_PORT}"
log "  Admin creds:   admin / admin"
log "  Red team key:  ADMIN123"
log "  Logs:          vagrant ssh caldera -c 'caldera-logs'"
log "============================================================"
