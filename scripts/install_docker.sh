#!/usr/bin/env bash
# install_docker.sh
# Provisions Docker Engine + Compose v2 on the docker-host VM.
# Idempotent: re-running this is a no-op once Docker is installed.

set -euo pipefail

log() { echo "[install-docker] $*"; }

if command -v docker &>/dev/null && docker compose version &>/dev/null; then
  log "Docker already installed: $(docker --version)"
  log "Compose: $(docker compose version | head -1)"
  exit 0
fi

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

usermod -aG docker vagrant

# Elasticsearch requires a high vm.max_map_count; set persistently.
sysctl -w vm.max_map_count=262144 >/dev/null
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf

systemctl enable --now docker

log "Docker installed: $(docker --version)"
log "Compose: $(docker compose version | head -1)"
