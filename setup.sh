#!/usr/bin/env bash
# setup.sh
# Bootstrap script for the Threat Hunting Lab.
# Checks prerequisites and brings up all VMs in the correct order.
#
# Prerequisites (must be manually installed before running this script):
#   - VMware Workstation Pro (https://www.vmware.com/products/workstation-pro.html)
#   - Vagrant (https://developer.hashicorp.com/vagrant/install)
#
# Usage:
#   chmod +x setup.sh && ./setup.sh

set -euo pipefail

# Always run from the directory containing this script (where the Vagrantfile lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

UTILITY_VERSION="1.0.22"   # Update to latest: https://releases.hashicorp.com/vagrant-vmware-utility/
PLUGIN_NAME="vagrant-vmware-desktop"

RED="\033[0;31m"; YELLOW="\033[1;33m"; GREEN="\033[0;32m"; NC="\033[0m"
log()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn() { echo -e "${YELLOW}[setup]${NC} $*"; }
die()  { echo -e "${RED}[setup] ERROR:${NC} $*" >&2; exit 1; }

# ── 1. Check VMware Workstation ───────────────────────────────────────────────
log "Checking VMware Workstation..."
if ! command -v vmware &>/dev/null && ! command -v vmrun &>/dev/null; then
  die "VMware Workstation Pro does not appear to be installed.\n  Install it from: https://www.vmware.com/products/workstation-pro.html\n  Then re-run this script."
fi
log "VMware Workstation found."

# ── 2. Check Vagrant ──────────────────────────────────────────────────────────
log "Checking Vagrant..."
if ! command -v vagrant &>/dev/null; then
  die "Vagrant is not installed.\n  Install it from: https://developer.hashicorp.com/vagrant/install\n  Then re-run this script."
fi
VAGRANT_VERSION=$(vagrant --version | grep -oP '\d+\.\d+\.\d+')
log "Vagrant ${VAGRANT_VERSION} found."

# ── 3. Install vagrant-vmware-utility service ────────────────────────────────
log "Checking vagrant-vmware-utility service..."
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

  log "Installing vagrant-vmware-utility..."
  sudo dpkg -i "${DEB_FILE}"
  sudo systemctl enable --now vagrant-vmware-utility
  log "vagrant-vmware-utility installed and started."
else
  log "vagrant-vmware-utility is already running."
fi

# ── 4. Install vagrant-vmware-desktop plugin ─────────────────────────────────
log "Checking Vagrant plugin: ${PLUGIN_NAME}..."
if ! vagrant plugin list 2>/dev/null | grep -q "${PLUGIN_NAME}"; then
  log "Installing Vagrant plugin: ${PLUGIN_NAME}..."
  vagrant plugin install "${PLUGIN_NAME}"
  log "Plugin installed."
else
  log "Plugin ${PLUGIN_NAME} is already installed."
fi

# ── 5. Add the Windows 11 box (pre-fetch to give user early progress signal) ──
log "Checking for gusztavvargadr/windows-11 box..."
if ! vagrant box list 2>/dev/null | grep -q "gusztavvargadr/windows-11"; then
  log "Downloading Windows 11 Vagrant box (~8-12 GB, this is the slowest step)..."
  vagrant box add gusztavvargadr/windows-11 --provider vmware_desktop
else
  log "Windows 11 box already present."
fi

# ── 6. Bring up the lab in the correct order ──────────────────────────────────
log ""
log "================================================================="
log "  Starting the Threat Hunting Lab..."
log "  Total estimated time: 25–40 minutes on first run"
log "================================================================="
log ""

log "Step 1/3 — Provisioning elastic-siem (Elasticsearch + Kibana + Fleet)..."
vagrant up elastic-siem --provision

log "Step 2/3 — Provisioning caldera (MITRE Caldera C2)..."
vagrant up caldera --provision

log "Step 3/3 — Provisioning win11-victim (Windows 11 + Sysmon + Elastic Agent)..."
vagrant up win11-victim --provision

# ── 7. Print access info ──────────────────────────────────────────────────────
ELASTIC_CREDS=""
if [[ -f "elastic-credentials.txt" ]]; then
  ELASTIC_CREDS=$(cat elastic-credentials.txt)
fi

log ""
log "================================================================="
log "  Lab is up!"
log ""
log "  Kibana (SIEM):   http://192.168.56.10:5601"
log "  Caldera (C2):    http://192.168.56.30:8888   (admin / admin)"
log ""
if [[ -n "${ELASTIC_CREDS}" ]]; then
log "  Elastic creds:   ${ELASTIC_CREDS}"
else
log "  Elastic creds:   see elastic-credentials.txt"
fi
log ""
log "  RDP into victim: vagrant rdp win11-victim"
log "  Tear it down:    vagrant destroy -f"
log "================================================================="
