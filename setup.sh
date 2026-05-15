#!/usr/bin/env bash
# setup.sh
# Bootstrap script for the Threat Hunting Lab (Linux / macOS host).
# Brings up the docker-host Linux VM (which runs the Docker stack inside)
# and the three Windows VMs.
#
# Prerequisites (must be manually installed before running this script):
#   - VMware Workstation Pro (Linux) or VMware Fusion Pro (macOS)
#   - Vagrant                             https://developer.hashicorp.com/vagrant/install
#   - vagrant-vmware-desktop plugin       (installed automatically below)
#
# Usage:
#   chmod +x setup.sh && ./setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

UTILITY_VERSION="1.0.22"
PLUGIN_NAME="vagrant-vmware-desktop"

RED="\033[0;31m"; YELLOW="\033[1;33m"; GREEN="\033[0;32m"; NC="\033[0m"
log()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn() { echo -e "${YELLOW}[setup]${NC} WARNING: $*"; }
die()  { echo -e "${RED}[setup] ERROR:${NC} $*" >&2; exit 1; }

# ── 1. Check VMware ───────────────────────────────────────────────────────────
log "Checking VMware..."
if ! command -v vmrun &>/dev/null; then
  die "VMware Workstation / Fusion does not appear to be installed or vmrun is not on PATH."
fi
log "VMware found."

# ── 2. Check Vagrant ──────────────────────────────────────────────────────────
log "Checking Vagrant..."
command -v vagrant &>/dev/null || die "Vagrant is not installed.\n  Install: https://developer.hashicorp.com/vagrant/install"
VAGRANT_VERSION=$(vagrant --version | grep -oP '\d+\.\d+\.\d+')
log "Vagrant ${VAGRANT_VERSION} found."

# ── 3. Install vagrant-vmware-utility service (Linux only) ────────────────────
if [[ "$(uname)" == "Linux" ]]; then
  if ! systemctl is-active --quiet vagrant-vmware-utility 2>/dev/null; then
    warn "vagrant-vmware-utility is not running. Attempting installation..."
    ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    DEB_FILE="/tmp/vagrant-vmware-utility_${UTILITY_VERSION}-1_${ARCH}.deb"
    if [[ ! -f "${DEB_FILE}" ]]; then
      log "Downloading vagrant-vmware-utility v${UTILITY_VERSION}..."
      curl -fL --progress-bar \
        "https://releases.hashicorp.com/vagrant-vmware-utility/${UTILITY_VERSION}/vagrant-vmware-utility_${UTILITY_VERSION}-1_${ARCH}.deb" \
        -o "${DEB_FILE}"
    fi
    sudo dpkg -i "${DEB_FILE}"
    sudo systemctl enable --now vagrant-vmware-utility
    log "vagrant-vmware-utility installed and started."
  else
    log "vagrant-vmware-utility is already running."
  fi
fi

# ── 4. Install vagrant-vmware-desktop plugin ─────────────────────────────────
log "Checking Vagrant plugin: ${PLUGIN_NAME}..."
if ! vagrant plugin list 2>/dev/null | grep -q "${PLUGIN_NAME}"; then
  log "Installing ${PLUGIN_NAME}..."
  vagrant plugin install "${PLUGIN_NAME}"
  log "Plugin installed."
else
  log "Plugin ${PLUGIN_NAME} already installed."
fi

# ── 5. Add Vagrant boxes ─────────────────────────────────────────────────────
log "Checking for Vagrant boxes..."
if ! vagrant box list 2>/dev/null | grep -q "bento/ubuntu-22.04"; then
  log "Downloading Ubuntu 22.04 box (~700 MB) for the docker-host VM..."
  vagrant box add bento/ubuntu-22.04 --provider vmware_desktop
fi
if ! vagrant box list 2>/dev/null | grep -q "gusztavvargadr/windows-11"; then
  log "Downloading Windows 11 box (~8-12 GB, slowest step)..."
  vagrant box add gusztavvargadr/windows-11 --provider vmware_desktop
fi
if ! vagrant box list 2>/dev/null | grep -q "gusztavvargadr/windows-server-2022-standard"; then
  log "Downloading Windows Server 2022 box (~7-10 GB)..."
  vagrant box add gusztavvargadr/windows-server-2022-standard --provider vmware_desktop
fi

# ── 6. Bring up the lab ───────────────────────────────────────────────────────
log ""
log "================================================================="
log "  All prerequisites satisfied. Starting the lab..."
log "  Estimated time: 25-40 minutes on first run"
log "================================================================="
log ""

HOST_IP="192.168.56.10"

log "Step 1/4 - docker-host (Elasticsearch + Kibana + Fleet + Caldera + LocalStack)..."
vagrant up docker-host --provision
log "docker-host is up."

log "Step 2/4 - win-dc (Active Directory DC, includes reboot after promotion)..."
vagrant up win-dc --provision
log "win-dc is up."

log "Step 3/4 - win-server (domain member server, includes reboot after domain join)..."
vagrant up win-server --provision
log "win-server is up."

log "Step 4/4 - win11-victim (Windows 11 + Sysmon + Elastic Agent)..."
vagrant up win11-victim --provision
log "win11-victim is up."

# ── 7. Print access info ──────────────────────────────────────────────────────
ELASTIC_PASS=$(grep "^ELASTIC_PASSWORD=" "${SCRIPT_DIR}/docker/.env" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo "<see docker/.env on docker-host>")

log ""
log "================================================================="
log "  Lab is up!"
log ""
log "  Kibana (SIEM):   http://${HOST_IP}:5601   elastic / ${ELASTIC_PASS}"
log "  Caldera (C2):    http://${HOST_IP}:8888   (admin / HuntLab2026!)"
log "  Fleet Server:    http://${HOST_IP}:8220"
log "  LocalStack API:  http://${HOST_IP}:4566"
log ""
log "  AD Domain:       lab.local  (NetBIOS: LAB)"
log "  DC:              192.168.56.50  (win-dc)"
log "  Member server:   192.168.56.51  (win-server)"
log "  Victim:          192.168.56.20  (win11-victim)"
log ""
log "  Domain admin:    LAB\\vagrant  or  LAB\\ajohnson"
log "  Domain user pass: Lab!Password1"
log ""
log "  RDP into victim: vagrant rdp win11-victim"
log "  RDP into DC:     vagrant rdp win-dc"
log "  Docker logs:     vagrant ssh docker-host -c 'cd /vagrant/docker && sudo docker compose logs -f'"
log "  Tear down all:   vagrant destroy -f"
log "================================================================="

# ── 8. Write env details to lab-info.md at repo root ──────────────────────────
LAB_INFO_FILE="${SCRIPT_DIR}/lab-info.md"
DOMAIN_INFO_FILE="${SCRIPT_DIR}/domain-info.txt"
GENERATED_AT=$(date '+%Y-%m-%d %H:%M:%S %z')

if [[ -f "$DOMAIN_INFO_FILE" ]]; then
  # shellcheck disable=SC1090
  source <(grep -E '^(DOMAIN|NETBIOS|DC_IP|JOIN_USER|JOIN_PASS)=' "$DOMAIN_INFO_FILE")
  DOMAIN_SECTION=$(cat <<EOF
- **Domain:** ${DOMAIN:-lab.local}
- **NetBIOS:** ${NETBIOS:-LAB}
- **DC IP:** ${DC_IP:-192.168.56.50}
- **Join user / pass:** \`${JOIN_USER:-vagrant}\` / \`${JOIN_PASS:-vagrant}\`
- **Lab domain users:** \`jsmith\`, \`ajohnson\`, \`bwilliams\`, \`cdavis\`, \`svc-backup\`, \`svc-deploy\` (default password: \`Lab!Password1\`)
EOF
)
else
  DOMAIN_SECTION="_domain-info.txt not present — win-dc may not have finished provisioning._"
fi

cat > "$LAB_INFO_FILE" <<EOF
# Hunt Lab — Environment Details

_Generated by \`setup.sh\` on ${GENERATED_AT}._
_This file contains credentials and is gitignored. Regenerated on every \`setup.sh\` run._

## Service endpoints (host: \`${HOST_IP}\`)

| Service | URL | Credentials |
|---|---|---|
| Kibana (SIEM) | http://${HOST_IP}:5601 | \`elastic\` / \`${ELASTIC_PASS}\` |
| Elasticsearch | http://${HOST_IP}:9200 | \`elastic\` / \`${ELASTIC_PASS}\` |
| Fleet Server | http://${HOST_IP}:8220 | — |
| Caldera (C2) | http://${HOST_IP}:8888 | \`admin\` / \`admin\` (red API key: \`ADMIN123\`) |
| LocalStack | http://${HOST_IP}:4566 | \`test\` / \`test\` (any region) |

## Active Directory

${DOMAIN_SECTION}

## Vagrant VMs

| VM | IP | Role |
|---|---|---|
| \`docker-host\` | 192.168.56.10 | Ubuntu — Docker stack (Elastic, Caldera, LocalStack, Filebeat) |
| \`win-dc\` | 192.168.56.50 | Windows Server 2022 — AD DC for \`lab.local\` |
| \`win-server\` | 192.168.56.51 | Windows Server 2022 — domain member |
| \`win11-victim\` | 192.168.56.20 | Windows 11 — victim workstation |

All Windows VMs have: Sysmon (SwiftOnSecurity config), Elastic Agent (enrolled to Fleet), Caldera sandcat (scheduled task \`WindowsSecurityUpdate\`, group \`red\`), Atomic Red Team.

## Useful commands

\`\`\`bash
# RDP into the Windows VMs
vagrant rdp win11-victim
vagrant rdp win-dc
vagrant rdp win-server

# Tail the docker stack logs
vagrant ssh docker-host -c 'cd /vagrant/docker && sudo docker compose logs -f'

# Run the validation suite
powershell -ExecutionPolicy Bypass -File ./scripts/validate_lab.ps1

# Tear the whole lab down
vagrant destroy -f
\`\`\`

## Generated files at repo root

| File | Purpose |
|---|---|
| \`elastic-credentials.txt\` | \`elastic\` user password (used by validate_lab.ps1) |
| \`fleet-enrollment-token.txt\` | Fleet enrollment token consumed by Windows VMs |
| \`domain-info.txt\` | Domain join config consumed by win-server / win11-victim |
| \`lab-info.md\` | This file |
EOF
log "Wrote environment details to $LAB_INFO_FILE"
