#!/usr/bin/env bash
# install_docker.sh
# Provisions Docker Engine + Compose v2 on the docker-host VM.
# Supports Vagrant guests and standalone Ubuntu hosts (including 26.04).
# Re-running reconciles Docker service and Elasticsearch kernel settings.

set -euo pipefail

log() { echo "[install-docker] $*"; }

if (( EUID != 0 )); then
  log "Run this script as root (sudo bash scripts/install_docker.sh)."
  exit 1
fi

. /etc/os-release
if [[ "${ID:-}" != ubuntu || -z "${VERSION_CODENAME:-}" ]]; then
  log "Expected Ubuntu with VERSION_CODENAME in /etc/os-release."
  exit 1
fi

# Only grant Docker access when explicitly requested, or to the existing
# Vagrant account for compatibility with the local workshop provisioner.
DOCKER_USER="${DOCKER_USER:-}"
if [[ -z "$DOCKER_USER" ]] && id vagrant &>/dev/null; then
  DOCKER_USER=vagrant
fi
if [[ -n "$DOCKER_USER" ]] && ! id "$DOCKER_USER" &>/dev/null; then
  log "DOCKER_USER does not exist: $DOCKER_USER"
  exit 1
fi

if command -v docker &>/dev/null && docker compose version &>/dev/null; then
  log "Docker already installed: $(docker --version)"
  log "Compose: $(docker compose version | head -1)"
else

log "Installing Docker Engine + Compose v2..."
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -qq -y ca-certificates curl gnupg lsb-release

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -qq
apt-get install -qq -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

fi

if [[ -n "$DOCKER_USER" ]]; then
  usermod -aG docker "$DOCKER_USER"
else
  log "No Docker group access added; use sudo for Docker commands."
fi

# Elasticsearch requires a high vm.max_map_count; set persistently.
sysctl -w vm.max_map_count=262144 >/dev/null
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf

systemctl enable --now docker

log "Docker installed: $(docker --version)"
log "Compose: $(docker compose version | head -1)"
