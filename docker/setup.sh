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
docker compose pull

# ── 4. Start core services (Elastic + Caldera + LocalStack) ───────────────────
log "Starting Elasticsearch, Kibana, Caldera, and LocalStack..."
docker compose up -d elasticsearch kibana caldera localstack

# ── 5. Run bootstrap ──────────────────────────────────────────────────────────
log "Running bootstrap (sets passwords, Fleet token, LocalStack baseline)..."
log "  Follow logs with: docker compose logs -f bootstrap"
docker compose run --rm bootstrap

# ── 6. Start Fleet Server (needs service token set by bootstrap) ───────────────
log "Starting Fleet Server..."
docker compose up -d fleet-server

# ── 7. Start Filebeat + CloudTrail activity generator ─────────────────────────
log "Starting Filebeat and CloudTrail activity generator..."
docker compose up -d filebeat cloudtrail-gen

# ── 8. Health summary ─────────────────────────────────────────────────────────
log ""
log "Waiting for all services to stabilise (30s)..."
sleep 30

ELASTIC_PASS=$(grep "^ELASTIC_PASSWORD=" .env | cut -d= -f2 | tr -d '[:space:]' || echo "<see .env>")

log ""
log "================================================================="
log "  Docker lab is up!"
log ""
log "  Kibana (SIEM):   http://${HOST_IP}:5601   elastic / ${ELASTIC_PASS}"
log "  Caldera (C2):    http://${HOST_IP}:8888   admin / admin"
log "  Fleet Server:    http://${HOST_IP}:8220"
log "  LocalStack API:  http://${HOST_IP}:4566"
log ""
log "  Enrollment token: docker/fleet-enrollment-token.txt"
log "  Windows victim:  vagrant up win11-victim --provision"
log "                   (from the repo root — uses fleet-enrollment-token.txt)"
log ""
log "  View logs:       docker compose logs -f"
log "  Stop lab:        docker compose down"
log "  Wipe data:       docker compose down -v"
log "================================================================="
