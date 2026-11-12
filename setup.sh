#!/usr/bin/env bash
# setup.sh
# Bootstrap script for the Threat Hunting Lab (x86-64 Linux host).
# Brings up the docker-host Linux VM (which runs the Docker stack inside)
# and the three Windows VMs.
#
# Prerequisites (must be manually installed before running this script):
#   - VMware Workstation Pro (x86-64 Linux)
#   - Git (to clone this repository)
# Vagrant is installed automatically on Debian/Ubuntu-based Linux when missing.
#   - vagrant-vmware-desktop plugin       (installed automatically below)
#
# Usage:
#   chmod +x setup.sh && ./setup.sh

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Resume explicitly at a failed machine; never silently skip failed provisioning.
START_AT="${2:-docker-host}"
if [[ $# -gt 0 && ( $# -ne 2 || "$1" != --from ) ]]; then
  echo "Usage: bash setup.sh [--from docker-host|win-dc|win-server|win11-victim]" >&2
  exit 2
fi
case "$START_AT" in docker-host|win-dc|win-server|win11-victim) ;; *) echo "Invalid resume machine: $START_AT" >&2; exit 2;; esac
STAGE_TIMEOUT="${LAB_STAGE_TIMEOUT_SECONDS:-10800}"
[[ "$STAGE_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { echo "LAB_STAGE_TIMEOUT_SECONDS must be a positive integer" >&2; exit 2; }
CURRENT_STAGE="prerequisites"
trap 'rc=$?; echo "[setup] FAILED during $CURRENT_STAGE (exit $rc). Fix the error above, then rerun setup." >&2; exit "$rc"' ERR

UTILITY_VERSION="1.0.22"
VAGRANT_VERSION_TO_INSTALL="2.4.9"
VAGRANT_DEB_SHA256="42d830d05e6e9e647f8a5c854d9f5295e319dac74edd37d54b97b4f29cbbd70d"
PLUGIN_NAME="vagrant-vmware-desktop"

RED="\033[0;31m"; YELLOW="\033[1;33m"; GREEN="\033[0;32m"; NC="\033[0m"
log()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn() { echo -e "${YELLOW}[setup]${NC} WARNING: $*"; }
die()  { echo -e "${RED}[setup] ERROR:${NC} $*" >&2; exit 1; }

# Fail before downloading multi-GB boxes on unsupported hosts.
[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || die "This build targets x86-64 Linux with Workstation or x64 Windows. macOS/Fusion and ARM hosts are not validated; use the hosted workshop lab."
for tool in curl awk df timeout tee; do
  command -v "$tool" >/dev/null || die "Required command missing: $tool"
done
TOTAL_RAM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
(( TOTAL_RAM_MB >= 24000 )) || die "At least 24 GB host RAM is required (22 GB allocated to guests); 32 GB or more is recommended. Detected ${TOTAL_RAM_MB} MB."
check_disk() {
  local target="$1" free_kb
  while [[ ! -d "$target" ]]; do target=$(dirname "$target"); done
  free_kb=$(df -Pk "$target" | awk 'END {print $4}')
  (( free_kb >= 150 * 1024 * 1024 )) || die "Less than 150 GiB free at $target. Allow 250 GB for boxes, VMs and logs."
}
check_disk "$SCRIPT_DIR"
check_disk "${VAGRANT_HOME:-$HOME/.vagrant.d}"
command -v systemctl >/dev/null || die "Automatic utility setup requires systemd. See the prerequisite guide."

# ── 1. Check VMware ───────────────────────────────────────────────────────────
log "Checking VMware..."
if ! command -v vmrun &>/dev/null; then
  die "VMware Workstation was not detected (vmrun is not on PATH).\n  1. Open https://support.broadcom.com/ and sign in or register.\n  2. Under Free Software Downloads, choose VMware Workstation Pro for Linux (x86-64).\n  3. Install the downloaded .bundle using Broadcom's instructions; complete any kernel-module setup.\n  4. Open Workstation once and finish its first-run prompts. Reboot if requested.\n  5. Open a new terminal, return to this repository, and run ./setup.sh again.\n  Already installed? Add the directory containing vmrun to PATH, then retry.\n  Illustrated download guide: https://knowledge.broadcom.com/external/article/368734/download-desktop-hypervisor-workstation.html\n  Local walkthrough: docs/install-vmware.md"
fi
log "VMware found."

# ── 2. Check Vagrant ──────────────────────────────────────────────────────────
log "Checking Vagrant..."
if ! command -v vagrant &>/dev/null; then
  command -v apt-get >/dev/null && command -v dpkg >/dev/null ||
    die "Automatic Vagrant installation supports Debian/Ubuntu-based Linux. Install Vagrant from https://developer.hashicorp.com/vagrant/install and rerun setup."
  command -v sha256sum >/dev/null || die "Install coreutils (sha256sum) and rerun setup."
  log "Installing Vagrant ${VAGRANT_VERSION_TO_INSTALL} from HashiCorp..."
  VAGRANT_DOWNLOAD_DIR=$(mktemp -d)
  trap 'rm -rf -- "$VAGRANT_DOWNLOAD_DIR"' EXIT
  VAGRANT_DEB_FILE="${VAGRANT_DOWNLOAD_DIR}/vagrant_${VAGRANT_VERSION_TO_INSTALL}-1_amd64.deb"
  curl -fL --retry 3 --progress-bar \
    "https://releases.hashicorp.com/vagrant/${VAGRANT_VERSION_TO_INSTALL}/vagrant_${VAGRANT_VERSION_TO_INSTALL}-1_amd64.deb" \
    -o "$VAGRANT_DEB_FILE"
  printf '%s  %s\n' "$VAGRANT_DEB_SHA256" "$VAGRANT_DEB_FILE" | sha256sum --check --status ||
    die "Vagrant download failed checksum verification; nothing was installed."
  sudo apt-get install -y "$VAGRANT_DEB_FILE"
  hash -r
  command -v vagrant >/dev/null || die "Vagrant installation finished but vagrant is not on PATH. Open a new terminal and rerun setup."
  rm -rf -- "$VAGRANT_DOWNLOAD_DIR"
  trap - EXIT
fi
VAGRANT_VERSION=$(vagrant --version)
log "${VAGRANT_VERSION} found."

# ── 3. Install vagrant-vmware-utility service (Linux only) ────────────────────
if [[ "$(uname)" == "Linux" ]]; then
  if ! systemctl is-active --quiet vagrant-vmware-utility 2>/dev/null; then
    warn "vagrant-vmware-utility is not running. Attempting installation..."
    command -v dpkg >/dev/null || die "Install and start vagrant-vmware-utility manually on this distribution, then rerun setup. Automatic installation supports Debian/Ubuntu."
    ARCH=amd64
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

# Let Vagrant resolve each machine's exact box/provider from the Vagrantfile.
# This avoids treating a similarly named or VirtualBox-only cached box as usable.
vagrant validate

# ── 6. Bring up the lab ───────────────────────────────────────────────────────
log ""
log "================================================================="
log "  All prerequisites satisfied. Starting the lab..."
log "  Allow several hours for first-run downloads and provisioning"
log "================================================================="
log ""

HOST_IP="192.168.56.10"

umask 077
LOG_DIR="$SCRIPT_DIR/.setup-logs/$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$LOG_DIR"
run_machine() {
  local machine="$1" mode="${2:---provision}" attempt rc logfile
  CURRENT_STAGE="$machine"
  for attempt in 1 2 3; do
    logfile="$LOG_DIR/$machine-attempt-$attempt.log"
    log "Building $machine (attempt $attempt/3); log: $logfile"
    if timeout --kill-after=30 "$STAGE_TIMEOUT" vagrant up "$machine" --provider vmware_desktop "$mode" --no-destroy-on-error 2>&1 | tee "$logfile"; then
      return 0
    else
      rc=${PIPESTATUS[0]}
      [[ "$rc" -ne 0 ]] || rc=1
    fi
    # Retry only an explicit download failure. Do not mask guest script errors.
    if [[ "$attempt" -lt 3 ]] && ! grep -Eqi 'URL returned error: (401|403|404)' "$logfile" && grep -Eqi 'error occurred while downloading|error while downloading the metadata|Could not resolve host|Failed to connect|SSL connect error' "$logfile"; then
      warn "Download interrupted; retrying $machine in 10 seconds (cached progress is retained)."
      sleep 10
    elif [[ "$attempt" -lt 3 ]] && { grep -Eqi 'timed out while attempting to connect via WinRM|WinRM.*connection refused' "$logfile" || { [[ "$machine" == win11-victim ]] && grep -Fqi 'Timed out while waiting for the machine to boot' "$logfile"; } || { grep -q 'Timeout::Error' "$logfile" && grep -q 'plugins/communicators/winrm/' "$logfile"; }; }; then
      # A timed-out boot can leave shared folders and private networking
      # unconfigured. Reload completes those provider steps before provisioning.
      warn "Windows connection failed; reloading $machine to finish networking and shared folders before retrying."
      if ! timeout --kill-after=30 1500 vagrant reload "$machine" 2>&1 | tee "$LOG_DIR/$machine-reload-$attempt.log"; then
        die "Could not recover $machine. See $LOG_DIR. Resume after fixing connectivity: bash setup.sh --from $machine"
      fi
    else
      die "$machine failed (exit $rc; 124/137 indicates timeout). Log: $logfile\n  Fix the reported error, then resume: bash setup.sh --from $machine"
    fi
  done
}
started=false
for machine in docker-host win-dc win-server win11-victim; do
  [[ "$machine" != "$START_AT" ]] || started=true
  if [[ "$machine" != docker-host ]]; then
    for artifact in elastic-credentials.txt fleet-enrollment-token.txt; do
      [[ -s "$artifact" ]] || die "docker-host did not produce $artifact. Resume with: bash setup.sh --from docker-host"
    done
  fi
  if [[ "$machine" == win-server || "$machine" == win11-victim ]]; then
    [[ -s domain-info.txt ]] || die "win-dc did not produce domain-info.txt. Resume with: bash setup.sh --from win-dc"
  fi
  if $started; then
    run_machine "$machine"
    log "$machine provisioning completed."
  else
    state_log="$LOG_DIR/$machine-resume-state.log"
    if ! timeout --kill-after=30 60 vagrant status "$machine" --machine-readable >"$state_log" 2>&1; then
      die "Cannot inspect prerequisite $machine. Log: $state_log. Resume: bash setup.sh --from $machine"
    fi
    machine_state=$(awk -F, -v machine="$machine" '$2 == machine && $3 == "state" {print $4}' "$state_log")
    case "$machine_state" in
      ""|not_created|unknown) die "Prerequisite $machine is missing or its state is unknown. Resume: bash setup.sh --from $machine" ;;
    esac
    log "Starting prerequisite $machine without provisioning (resume from $START_AT)."
    run_machine "$machine" --no-provision
  fi
done

CURRENT_STAGE="readiness validation"
ready=false
for attempt in 1 2 3 4 5; do
  if timeout --kill-after=30 180 vagrant ssh docker-host -c 'python3 /vagrant/scripts/validate_lab.py' 2>&1 | tee "$LOG_DIR/readiness-$attempt.log"; then
    ready=true
    break
  fi
  [[ "$attempt" -eq 5 ]] || sleep 15
done
$ready || die "Provisioning finished but readiness failed. Logs: $LOG_DIR\n  Retry the check: vagrant ssh docker-host -c 'python3 /vagrant/scripts/validate_lab.py'"

# ── 7. Print access info ──────────────────────────────────────────────────────
ELASTIC_PASS=$(grep "^ELASTIC_PASSWORD=" "${SCRIPT_DIR}/docker/.env" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo "<see docker/.env on docker-host>")

log ""
log "================================================================="
log "  VM provisioning and core readiness checks passed."
log ""
log "  Kibana (SIEM):   http://${HOST_IP}:5601   elastic / ${ELASTIC_PASS}"
log "  Caldera (C2):    http://${HOST_IP}:8888   (admin / HuntLab2026!)"
log "  Fleet Server:    http://${HOST_IP}:8220"
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
log "  Readiness: vagrant ssh docker-host -c 'python3 /vagrant/scripts/validate_lab.py'"
log "  Tear down all (deletes guest data): vagrant destroy"
log "================================================================="

# ── 8. Write env details to lab-info.md at repo root ──────────────────────────
umask 077
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
| Caldera (C2) | http://${HOST_IP}:8888 | \`admin\` / \`HuntLab2026!\` (red API key: \`ADMIN123\`) |
| LocalStack | http://${HOST_IP}:4566 | test / test (lab AWS credentials) |

## Active Directory

${DOMAIN_SECTION}

## Vagrant VMs

| VM | IP | Role |
|---|---|---|
| \`docker-host\` | 192.168.56.10 | Ubuntu — Docker stack (Elastic, Caldera) |
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
