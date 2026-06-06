#!/usr/bin/env bash
# docker/setup.sh
# Sets up the single-server Docker deployment of the Threat Hunting Lab.
#
# Usage:
#   cd hunt_lab/docker
#   chmod +x setup.sh && bash setup.sh
#
# Prerequisites (install manually first):
#   - Docker Engine 24+    https://docs.docker.com/engine/install/ubuntu/
#   - Docker Compose v2    (included with Docker Engine 24+ as `docker compose`)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

RED="\033[0;31m"; YELLOW="\033[1;33m"; GREEN="\033[0;32m"; NC="\033[0m"
log()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn() { echo -e "${YELLOW}[setup]${NC} WARNING: $*"; }
die()  { echo -e "${RED}[setup] ERROR:${NC} $*" >&2; exit 1; }

# ── 1. Prerequisite checks ────────────────────────────────────────────────────
log "Checking prerequisites..."

command -v docker &>/dev/null || die "Docker is not installed.\n  See: https://docs.docker.com/engine/install/ubuntu/"
docker compose version &>/dev/null 2>&1 || die "Docker Compose v2 plugin not found.\n  Update Docker Engine to 24+ or install the compose plugin."

TOTAL_RAM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
if (( TOTAL_RAM_MB < 14000 )); then
  warn "Only ${TOTAL_RAM_MB} MB RAM detected. Recommended: 16 GB+. Elasticsearch may OOM."
fi
log "RAM: ${TOTAL_RAM_MB} MB"

# ── 2. .env setup ─────────────────────────────────────────────────────────────
if [[ ! -f ".env" ]]; then
  cp .env.example .env
  warn ".env file created from .env.example"
  warn "Edit docker/.env — set HOST_IP to this machine's LAN IP, then re-run setup.sh"
  warn "  nano .env"
  exit 1
fi

# Validate HOST_IP is set and is not the placeholder
HOST_IP=$(grep "^HOST_IP=" .env | cut -d= -f2 | tr -d '[:space:]' || true)
if [[ -z "${HOST_IP}" || "${HOST_IP}" == "192.168.1.100" ]]; then
  warn "HOST_IP in docker/.env is still the placeholder value."
  warn "Set it to this machine's actual LAN IP so agents can reach Caldera and Fleet."
  warn "  ip -4 addr show  # to find your IP"
  read -r -p "[setup] Continue anyway? (y/N) " confirm
  [[ "${confirm}" =~ ^[Yy]$ ]] || exit 1
fi
log "HOST_IP: ${HOST_IP}"

# ── 3. Pull images ────────────────────────────────────────────────────────────
log "Pulling Docker images (this may take a few minutes on first run)..."
# caldera is built locally (image hunt-lab/caldera:local) and has no registry
# source, so it cannot be pulled. Compose v2.15+ errors on buildable services
# during `pull`, so skip them here and build caldera explicitly afterward.
docker compose pull --ignore-buildable
log "Building local images (caldera)..."
docker compose build caldera

# ── 4. Start core services (Elastic + Caldera + LocalStack) ───────────────────
log "Starting Elasticsearch, Kibana, Caldera, and LocalStack..."
docker compose up -d elasticsearch kibana caldera localstack

# ── 4b. Start Velociraptor (DFIR) ─────────────────────────────────────────────
# Independent of Elastic. Started early so it has time to generate its config
# and repack the platform clients before the Windows VMs provision.
log "Starting Velociraptor server (generates config + repacks clients on first run)..."
docker compose up -d velociraptor

# Stage the repacked Windows client onto the synced folder so the Windows VMs
# can install it. The datastore is a named volume (HGFS can't host a Docker
# bind mount), so copy the client out with docker cp once the repack finishes.
log "Waiting for Velociraptor to repack the Windows client..."
VELO_CLIENT_IN="/velociraptor/clients/windows/velociraptor_client_repacked.exe"
VELO_CLIENT_OUT="${SCRIPT_DIR}/velociraptor/clients/windows"
for _ in $(seq 1 60); do
  docker exec velociraptor test -f "${VELO_CLIENT_IN}" 2>/dev/null && break
  sleep 5
done
if docker exec velociraptor test -f "${VELO_CLIENT_IN}" 2>/dev/null; then
  mkdir -p "${VELO_CLIENT_OUT}"
  docker cp "velociraptor:${VELO_CLIENT_IN}" /tmp/velociraptor_client_repacked.exe
  cp -f /tmp/velociraptor_client_repacked.exe "${VELO_CLIENT_OUT}/velociraptor_client_repacked.exe"
  rm -f /tmp/velociraptor_client_repacked.exe
  log "Velociraptor Windows client staged to docker/velociraptor/clients/windows/."
else
  warn "Velociraptor Windows client not repacked within 5 min — the Windows VMs' install_velociraptor_client.ps1 will wait/retry."
fi

# ── 5. Run bootstrap ──────────────────────────────────────────────────────────
log "Running bootstrap (sets passwords, Fleet token, LocalStack baseline)..."
log "  Follow logs with: docker compose logs -f bootstrap"
docker compose run --rm bootstrap

# ── 6. Start Fleet Server (needs service token set by bootstrap) ───────────────
log "Starting Fleet Server..."
docker compose up -d fleet-server

# ── 7. Start Filebeat + CloudTrail activity generator ─────────────────────────
# Pre-create the cloudtrail bind-mount dir. Docker can't create+chown a bind
# source on the VMware HGFS shared folder ("operation not permitted"), but it
# mounts an already-existing dir fine.
mkdir -p "${SCRIPT_DIR}/cloudtrail"
log "Starting Filebeat and CloudTrail activity generator..."
docker compose up -d filebeat cloudtrail-gen

# ── 8. Health summary ─────────────────────────────────────────────────────────
log ""
log "Waiting for all services to stabilise (30s)..."
sleep 30

ELASTIC_PASS=$(grep "^ELASTIC_PASSWORD=" .env | cut -d= -f2 | tr -d '[:space:]' || echo "<see .env>")

# Write elastic-credentials.txt to the repo root so setup.ps1 can read it
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
echo "elastic:${ELASTIC_PASS}" > "${REPO_ROOT}/elastic-credentials.txt"
chmod 600 "${REPO_ROOT}/elastic-credentials.txt"
log "elastic-credentials.txt written to repo root."

log ""
log "================================================================="
log "  Docker lab is up!"
log ""
log "  Kibana (SIEM):   http://${HOST_IP}:5601   elastic / ${ELASTIC_PASS}"
log "  Caldera (C2):    http://${HOST_IP}:8888   admin / HuntLab2026!"
log "  Fleet Server:    http://${HOST_IP}:8220"
log "  LocalStack API:  http://${HOST_IP}:4566"
log "  Velociraptor:    https://${HOST_IP}:8889  (creds in docker/.env: VELOX_USER/VELOX_PASSWORD)"
log ""
log "  Enrollment token: fleet-enrollment-token.txt  (repo root)"
log "  Windows VMs:     vagrant up win-dc win-server win11-victim --no-parallel"
log "                   (from the repo root)"
log ""
log "  View logs:       docker compose logs -f"
log "  Stop lab:        docker compose down"
log "  Wipe data:       docker compose down -v"
log "================================================================="
