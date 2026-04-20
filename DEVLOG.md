# hunt_lab Setup DEVLOG

## Environment
- Host OS: Linux Mint 22.2 (Ubuntu Noble base)
- Vagrant: 2.4.9
- VMware Workstation: installed (`/usr/bin/vmware`, `/usr/bin/vmrun`)
- Host RAM: 62 GB | Disk: 645 GB free | CPUs: 20
- VM RAM budget: 16 GB (elastic-siem 8 GB + caldera 4 GB + win11-victim 4 GB)

---

## Issues Log

### Issue 1 — `vagrant-vmware-utility` download 404
**Date:** 2026-04-15
**Symptom:** `curl: (22) The requested URL returned error: 404`
**Root cause:** `setup.sh` was trying to download a `.zip` archive
(`vagrant-vmware-utility_1.0.22_linux_amd64.zip`) that does not exist.
HashiCorp ships the Linux release as a direct `.deb`, not a zip.
**Fix:** Updated `setup.sh` to download the `.deb` directly:
```
https://releases.hashicorp.com/vagrant-vmware-utility/1.0.22/vagrant-vmware-utility_1.0.22-1_amd64.deb
```
**Status:** Fixed

### Issue 2 — `sudo` blocked (no TTY)
**Date:** 2026-04-15
**Symptom:** `sudo: a terminal is required to read the password`
**Root cause:** Claude Code's Bash tool runs as user `zeus` (uid=1000) without
a TTY, so `sudo` inside `setup.sh` cannot prompt for a password.
**Fix:** Script must be launched from a root terminal:
```bash
bash /home/zeus/Desktop/hunt_lab/setup.sh > /tmp/hunt_lab.log 2>&1 &
```
**Status:** Workaround applied — user launching from root terminal

---

### Issue 3 — `vagrant up` fails: no Vagrantfile found
**Date:** 2026-04-15
**Symptom:** `A Vagrant environment or target machine is required to run this command`
**Root cause:** `setup.sh` does not `cd` to its own directory before calling `vagrant up`.
When launched from any directory other than `hunt_lab/`, Vagrant can't locate the `Vagrantfile`.
**Fix:** Added at the top of `setup.sh` (after `set -euo pipefail`):
```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
```
**Status:** Fixed

---

### Issue 4 — `vmrun -T player snapshot` not supported on Workstation
**Date:** 2026-04-15
**Symptom:** `An error occurred while executing vmrun ... Stdout: Error: The operation is not supported`
**Root cause:** The vagrant-vmware-desktop plugin calls `vmrun -T player snapshot` to create a
linked clone base snapshot. VMware Player mode does not support snapshots; Workstation does.
The VMware kernel modules (vmmon, vmnet) were also not loaded — fixed by running
`sudo vmware-modconfig --console --install-all`.
**Fix:** Added `v.linked_clone = false` to all three VM provider blocks in the Vagrantfile.
This skips the snapshot step entirely and uses a full copy of the base box instead.
**Status:** Fixed

---

## Pending / In Progress

- [ ] vagrant-vmware-desktop plugin install
- [ ] Windows 11 box download (~8-12 GB)
### Issue 5 — Elastic apt repo GPG key not dearmored
**Date:** 2026-04-15
**Symptom:** `W: GPG error: NO_PUBKEY D27D666CD88E42B4` inside elastic-siem VM
**Root cause:** `install_elastic.sh` saved the ASCII-armored key directly as `.gpg` without
dearmoring it. apt expects a binary dearmored key in `/usr/share/keyrings/`.
**Fix:** Changed key download in `install_elastic.sh` to pipe through `gpg --dearmor`:
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```
**Status:** Fixed

---

## Pending / In Progress

- [ ] elastic-siem provisioning (Elasticsearch + Kibana + Fleet)
### Issue 6 — `mitre/caldera:5.0.0` not found on Docker Hub
**Date:** 2026-04-15
**Symptom:** `failed to resolve reference "docker.io/mitre/caldera:5.0.0": not found`
**Root cause:** MITRE publishes Caldera images to GitHub Container Registry, not Docker Hub.
**Fix:** Updated `install_caldera.sh` to use `ghcr.io/mitre/caldera:5.0.0`
**Status:** Fixed

---

## Pending / In Progress

### Issue 7 — vagrant-vmware-desktop plugin not available for root
**Date:** 2026-04-16
**Symptom:** `The provider 'vmware_desktop' could not be found` when running vagrant as root
**Root cause:** Vagrant plugins are per-user. The plugin was installed as `zeus` but
`sudo bash setup.sh` runs vagrant as `root`, which has a separate plugin directory.
**Fix:** Install the plugin explicitly as root before running setup:
```bash
sudo vagrant plugin install vagrant-vmware-desktop
```
**Status:** Fixed (manual step)

---

### Issue 8 — `.vagrant` directory owned by root after previous sudo run
**Date:** 2026-04-16
**Symptom:** `Permission denied @ rb_sysopen - .../ubuntu-22.04-amd64.vmx (Errno::EACCES)`
**Root cause:** Previous `sudo bash setup.sh` runs created `.vagrant/machines/` with root ownership.
When re-run as `zeus` (NOPASSWD sudoers), the plugin couldn't read/write the vmx file.
**Fix:**
```bash
sudo chown -R zeus:zeus /home/zeus/Desktop/hunt_lab/.vagrant
vagrant destroy -f  # clean stale state
vagrant global-status --prune
bash setup.sh       # re-run as zeus
```
**Status:** Fixed

---

### Issue 9 — Elasticsearch fails to start: cannot create logs dir
**Date:** 2026-04-16
**Symptom:** `ERROR: Unable to create logs dir [/usr/share/elasticsearch/logs], with exit code 78`
**Root cause:** `install_elastic.sh` overwrites the entire `elasticsearch.yml`, losing the
Debian package defaults for `path.data` and `path.logs`. Elasticsearch fell back to
`/usr/share/elasticsearch/logs` which the `elasticsearch` user cannot create.
**Fix:** Added explicit paths to the config block in `install_elastic.sh`:
```yaml
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
```
**Status:** Fixed

---

### Issue 10 — `gpg: cannot open '/dev/tty'` on re-provision
**Date:** 2026-04-16
**Symptom:** `gpg: cannot open '/dev/tty': No such device or address` during apt key import
**Root cause:** On re-provision the keyring file already exists; gpg prompts interactively
to confirm overwrite but no TTY is available in the Vagrant shell provisioner.
**Fix:** Added `--batch --yes` to the gpg command in `install_elastic.sh`:
```bash
gpg --batch --yes --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```
**Status:** Fixed

---

### Issue 11 — `elasticsearch-reset-password` not on PATH in provisioner
**Date:** 2026-04-16
**Symptom:** `sudo: elasticsearch-reset-password: command not found`
**Root cause:** Elasticsearch 8.x installs its CLI tools to `/usr/share/elasticsearch/bin/`
which is not in the provisioner's `$PATH`.
**Fix:** Use full paths in `install_elastic.sh`:
```bash
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -s -b
```
**Status:** Fixed

---

### Issue 12 — `win11-victim` missing `linked_clone = false`
**Date:** 2026-04-16
**Symptom:** `vmrun -T player snapshot ... Error: The operation is not supported`
**Root cause:** Same as Issue 4 — `linked_clone = false` was added to elastic-siem and
caldera but was omitted from the win11-victim provider block in the Vagrantfile.
**Fix:** Added `v.linked_clone = false` to the win11-victim vmware_desktop provider block.
**Status:** Fixed

---

### Issue 13 — `privileged: true` shell provisioner uploads 0-byte script via WinRM
**Date:** 2026-04-16
**Symptom:** Script runs but produces no output; `C:\tmp\vagrant-shell.ps1` is 0 bytes
**Root cause:** vagrant-vmware-desktop's WinRM file upload silently fails when
`privileged: true` is set (uses scheduled-task elevation path that drops the payload).
**Fix:** Changed provisioner to `privileged: false` with an inline call that runs the
script from the already-mounted `/vagrant` shared folder:
```ruby
win.vm.provision "shell", privileged: false, inline: <<~POWERSHELL
  powershell -ExecutionPolicy Bypass -File "C:\\vagrant\\scripts\\install_win_tools.ps1"
POWERSHELL
```
**Status:** Fixed

### Issue 14 — `#Requires -RunAsAdministrator` silently exits WinRM session
**Date:** 2026-04-16
**Symptom:** Script exits immediately even after privileged fix; no transcript created
**Root cause:** `#Requires -RunAsAdministrator` exits the script before any code runs when
PowerShell's WinRM session token doesn't satisfy the elevated-token check, even though
`IsInRole(Administrator)` returns True.
**Fix:** Removed the `#Requires` directive; admin access confirmed via `IsInRole` check.
**Status:** Fixed

### Issue 15 — `Invoke-WebRequest` drops on large file download over WinRM
**Date:** 2026-04-16
**Symptom:** `Unable to read data from transport connection: An existing connection was forcibly closed`
**Root cause:** `Invoke-WebRequest` cannot reliably download large files through the WinRM
streaming pipe. Also: Elastic Agent version was 8.13.4, mismatched with elastic-siem's 8.19.14.
**Fix:** Replaced all `Invoke-WebRequest` calls with `curl.exe` (native Win10/11).
Updated `$AgentVersion` to `8.19.14` to match elastic-siem.
**Status:** Fixed — re-provisioning

---

### Issue 16 — Fleet Server bound to localhost only
**Date:** 2026-04-16
**Symptom:** win11-victim agent gets "connection refused" to 192.168.56.10:8220
**Root cause:** `elastic-agent install` (for downloaded binary) vs apt-installed agent uses
different install path. The apt service started with default config before `install` could
set Fleet Server mode. Used `elastic-agent enroll` with explicit path flags instead, but
omitted `--fleet-server-host=0.0.0.0`, so Fleet Server bound to localhost only.
**Fix:**
- Use `elastic-agent enroll` (not `install`) in install_elastic.sh with all path flags
- Add `--fleet-server-host=0.0.0.0` and `--fleet-server-insecure-http`

### Issue 17 — Windows secondary network adapter not configured
**Date:** 2026-04-16
**Symptom:** win11-victim Ethernet1 gets APIPA (169.254.x.x), cannot reach 192.168.56.10
**Root cause:** "Configuring secondary network adapters through VMware on Windows is not
yet supported" — Vagrant leaves Ethernet1 unconfigured.
**Fix:** Added PowerShell in install_win_tools.ps1 to find the APIPA adapter and set
192.168.56.20/24 statically before enrolling Elastic Agent.

### Issue 18 — Em dash in ps1 file causes PowerShell parser error
**Date:** 2026-04-16
**Symptom:** `Missing closing '}' in statement block` at else clause
**Root cause:** Em dash character (U+2014) in PowerShell string parsed over VMware shared
folder causes PS 5.1 lexer to miscount braces.
**Fix:** Replaced em dash with ASCII hyphen; used `Where-Object IPAddress -like` (no
script block) to eliminate nested brace ambiguity.

### Issue 19 — elastic-agent stderr JSON logs trigger WinRM non-zero exit
**Date:** 2026-04-16
**Symptom:** Vagrant reports "non-zero exit status" after successful enrollment
**Root cause:** elastic-agent prints daemon-restart JSON to stderr; WinRM treats any stderr
as failure.
**Fix:** Added `2>$null` to the elastic-agent install invocation.
**Status:** Fixed

---

### Issue 20 — Caldera 5.0.0 Docker image missing required config keys
**Date:** 2026-04-16
**Symptom:** Container restart-loops: `TypeError: encoding without a string argument` in `file_svc.py`
**Root cause:** `crypt_salt` and `encryption_key` are required by Caldera 5.x's file service
encryption but were not in `local.yml`. `get_config()` returns `None`, which cannot be passed
to `bytes()`.
**Fix:** Added both keys to `install_caldera.sh`'s local.yml template:
```yaml
crypt_salt: hunt-lab-salt-6ddf9d464e5eb723
encryption_key: hunt-lab-enc-key-2026
```
**Status:** Fixed

---

### Issue 21 — Caldera contact bind addresses must be 0.0.0.0 inside Docker
**Date:** 2026-04-16
**Symptom:** `OSError: [Errno 99] error while attempting to bind on address ('192.168.56.30', 7010)`
**Root cause:** `app.contact.tcp`, `app.contact.udp`, `app.contact.websocket` are SERVER BIND
addresses, not advertised addresses. Inside the Docker container, `192.168.56.30` is not
assigned to any interface. Docker port-forwards handle external routing.
**Fix:** Changed in `local.yml`:
```yaml
app.contact.tcp: 0.0.0.0:7010
app.contact.udp: 0.0.0.0:7011
app.contact.websocket: 0.0.0.0:7012
```
Only `app.contact.http` uses the external IP (agents need it to beacon back).
**Status:** Fixed

---

### Issue 22 — Caldera 5.0.0 image ships magma Vue UI unbuilt
**Date:** 2026-04-16
**Symptom:** `ValueError: No directory exists at '/usr/src/app/plugins/magma/dist/assets'`
**Root cause:** `ghcr.io/mitre/caldera:5.0.0` includes the magma Vue.js source but did not
pre-compile the frontend. Node.js is not present in the container image, so the build cannot
run at startup. `server.py` always registers the magma static asset route, causing a fatal crash.
**Fix:**
1. Install Node.js 20 on the caldera VM
2. Extract all plugin sources from the container with `docker cp`
3. `npm install && node prebundle.js && npx vite build` in `plugins/magma/`
4. Copy `dist/` to `/opt/caldera/data/magma-dist/`
5. Mount it read-only into the container:
   `./data/magma-dist:/usr/src/app/plugins/magma/dist:ro`
Added full build step to `install_caldera.sh` so re-provisioning is automatic.
**Status:** Fixed

---

### Issue 23 — Caldera magma login loop (VITE_CALDERA_URL not set at build time)
**Date:** 2026-04-17
**Symptom:** Login with correct credentials (admin/admin) loops back to the login page
**Root cause:** The magma Vue router (`router.js`) creates its own axios instance with
`baseURL: import.meta.env.VITE_CALDERA_URL || "http://localhost:8888"`. The build-time
env var was not set, so all API requests from the nav guard went to `http://localhost:8888`
(the user's machine, not the VM). `getAuthStatus` (`HEAD /api/v2/config/main`) always
failed → nav guard always redirected to `/login`.
**Fix:** Rebuild magma dist with the correct env var:
```bash
VITE_CALDERA_URL=http://192.168.56.30:8888 npx vite build
```
Updated `install_caldera.sh` to pass `VITE_CALDERA_URL` during the build step.
**Status:** Fixed

---

### Issue 24 — Sandcat agent killed when WinRM session closes
**Date:** 2026-04-17
**Symptom:** Agent starts but never beacons; Caldera shows no agents
**Root cause:** Processes launched with `Start-Process` inside a WinRM session are children of
the WinRM session process and are killed when the session closes (Vagrant closes it after the
provisioner finishes).
**Fix:** Register the scheduled task first, then start it via `Start-ScheduledTask -TaskName`.
The task runs in a separate session (Task Scheduler service), not the WinRM tree, so it
survives session close.
**Status:** Fixed

---

### Issue 25 — win11-victim auto-suspends between vagrant calls
**Date:** 2026-04-17
**Symptom:** "VM must be running" error on successive `vagrant provision` calls; Windows
default power plan sleeps the headless VM after ~10 minutes of no UI input.
**Fix:** Added `powercfg /change standby-timeout-ac 0` and `hibernate-timeout-ac 0` to both
`install_win_tools.ps1` and the `deploy_caldera_agent` provisioner block in the Vagrantfile.
**Status:** Fixed

---

### Issue 26 — curl.exe progress output to stderr causes WinRM false failure
**Date:** 2026-04-17
**Symptom:** `vagrant provision` reports exit code 1 even when all steps succeed; curl's
transfer progress bar goes to stderr and WinRM treats any stderr as failure.
**Fix:** Added `2>$null` to all `curl.exe` calls in the deploy_caldera_agent provisioner and
`deploy_caldera_agent.ps1`.
**Status:** Fixed

---

---

### Issue 27 — `CloneFolderNotFolder` error during win11-victim import
**Date:** 2026-04-18
**Symptom:** `The clone directory given is not a directory` — vagrant-vmware-desktop fails to
clone the Windows 11 box. Error fires after copying `disk-cl1.vmdk` (the 16 GB base disk).
**Root cause:** The plugin's full-copy path iterates box files with `FileUtils.cp_r` and checks
`destination.directory?` after each file. VMware Workstation's background VM-discovery service
watches directories via inotify; when the `.vmx` file appears in the UUID clone directory,
VMware detects the new VM and attempts to validate it. Finding the 16 GB disk still being
written, it deletes the clone directory, so the post-copy check fails.
**Fix (two parts):**
1. `v.force_vmware_license = "workstation"` in the win11-victim provider block.
   The utility reports license as `"standard"`, which the plugin maps to `-T player` mode
   (no snapshot support). Forcing `"workstation"` makes `@pro_license = true`, switching
   vmrun to `-T ws` and enabling native linked clones.
2. `v.linked_clone = true` — uses `vmrun -T ws snapshot` + `vmrun -T ws clone ... linked`
   instead of the file-copy loop, so VMware never sees a half-written disk.
**Status:** Fixed

---

### Issue 28 — `elastic-agent.exe: Error: already installed` on re-provision
**Date:** 2026-04-18
**Symptom:** `vagrant provision win11-victim --provision-with install_win_tools` exits 1 on
re-run because Elastic Agent is already installed and the script hits `$ErrorActionPreference = "Stop"`.
**Root cause:** A prior partial `vagrant up` (killed via SIGPIPE from `| head -30`) successfully
installed the agent before the pipe broke. Re-provisioning hits the already-installed guard in
the agent binary and exits non-zero.
**Fix:** Added a pre-install check in `install_win_tools.ps1`:
```powershell
$ExistingAgent = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
if ($ExistingAgent) {
    Write-Log "Elastic Agent already installed — skipping."
} else {
    & elastic-agent.exe install ...
}
```
**Status:** Fixed

---

### Issue 29 — PS 5.1 `NativeCommandError` terminates `install_win_tools.ps1` via WinRM
**Date:** 2026-04-18
**Symptom:** `vagrant provision win11-victim` exits 1 even when the script runs to completion.
Multiple root causes across the same session:

1. **Em dash in string literal** (Issue 18 pattern) — `—` inside `Write-Log "... already installed — skipping ..."` caused `MissingEndCurlyBrace` parse error at the `$($ExistingAgent.Status)` expansion. **Fixed:** replaced `—` with `-`.

2. **curl.exe progress bar on stderr** — `--progress-bar` flag writes `##...` to stderr. In PS 5.1 with `$ErrorActionPreference = "Stop"`, any native-EXE stderr write generates a terminating `NativeCommandError`. **Fixed:** switched all `curl.exe` calls to `-fsSL` (silent) + `2>$null`.

3. **Sandcat binary locked** — On re-provision, `svhost.exe` was still running (from the previous provision), so `curl.exe` failed with `error 23: client returned ERROR on write` when trying to overwrite the running EXE. **Fixed:** added `Stop-ScheduledTask` + `Stop-Process` before re-downloading.

4. **Sysmon stderr via console handle** — `Sysmon64.exe` writes to the Windows console via `WriteConsoleW`, which PS cannot intercept with `2>$null`. Any invocation of `& $SysmonExe` generates a `NativeCommandError` in the inner PS's error stream. That error record is written to the inner PS process's stderr, which the outer WinRM shell (`EAP=Stop`) terminates on. `EAP=Continue` fence made it non-terminating WITHIN the script but still wrote to process stderr. **Fixed:** replaced `& $SysmonExe` with `Start-Process -RedirectStandardOutput/-RedirectStandardError` so Sysmon's I/O is redirected at the OS level before PS ever sees it. Same fix applied to `elastic-agent.exe` install.

5. **Exit code propagation** — Non-terminating error records in `$Error` cause `powershell.exe` to exit with code 1 in PS 5.1 `-File` mode. `exit 0` at the end of the script was added as a belt-and-suspenders measure.

**Status:** Fixed — `vagrant provision win11-victim --provision-with install_win_tools` now exits 0 cleanly with full provisioning output.

---

### Issue 30 — `vagrant reload win11-victim` times out waiting for WinRM
**Date:** 2026-04-19
**Symptom:** `Timed out while waiting for the machine to boot` after `vagrant reload`. Windows 11 exceeds Vagrant's default 300-second boot timeout.
**Root cause:** Vagrant's default `config.vm.boot_timeout` is 300 seconds. Windows 11 with VMware Tools initialising can take 5–8 minutes to get WinRM ready.
**Fix:** Added `win.vm.boot_timeout = 600` to the win11-victim block in `Vagrantfile`.
**Status:** Fixed

---

### Issue 31 — Fleet default output set to `localhost:9200` — remote agents cannot ship data
**Date:** 2026-04-19
**Symptom:** Elastic Agent on win11-victim shows `HEALTHY / Connected` in Fleet, but zero documents appear in Kibana Discover. Agent logs show 70+ reconnect attempts: `Failed to connect to elasticsearch(http://localhost:9200)`.
**Root cause:** When Fleet Server enrols itself during `install_elastic.sh`, it writes the default Elasticsearch output as `http://localhost:9200`. This is correct for the Fleet Server agent (Elasticsearch runs on the same host), but the same output config is pushed to all other enrolled agents. win11-victim has no Elasticsearch on its loopback — it can connect to Fleet (port 8220) to receive policy but cannot ship collected events anywhere.
**Fix:**
1. **Immediate:** `PUT /api/fleet/outputs/fleet-default-output` with `hosts: ["http://192.168.56.10:9200"]` — agents picked up the change within 30 seconds and the queued event backlog (3,200+ events) flushed immediately.
2. **Permanent:** Added a step to `install_elastic.sh` after Fleet is ready to patch the output to `http://${FLEET_SERVER_IP}:${ES_PORT}` so it is correct from first provision.
**Status:** Fixed

---

### Issue 32 — Windows integration not configured in Fleet — no Sysmon/PowerShell/Defender events
**Date:** 2026-04-19
**Symptom:** Even after fixing the output host (Issue 31), only `system.*` events appeared. No `logs-windows.sysmon_operational-*`, `logs-windows.powershell_operational-*`, or `logs-windows.windows_defender-*` indices existed.
**Root cause:** The `Windows Endpoint Policy` in `kibana.yml` only pre-installs the `system` package. The `windows` package (which adds winlog inputs for Sysmon, PowerShell, and Defender channels) was not configured. Kibana's `xpack.fleet.agentPolicies` YAML only supports simple package references — it cannot set the required per-stream vars (e.g. `preserve_original_event`, `event_id`, `ignore_older`) that the `windows` package demands via the Fleet API.
**Fix:**
1. Added `windows: latest` to `xpack.fleet.packages` in `kibana.yml` so the package is pre-installed on Kibana startup.
2. Added a post-Fleet-ready step in `install_elastic.sh` that `POST`s a fully-configured `package_policy` (windows-1) to the `windows-endpoint-policy` via the Fleet API, enabling:
   - `windows.sysmon_operational` — Sysmon event log
   - `windows.powershell_operational` — PS script block logging (4103/4104/4105/4106)
   - `windows.powershell` — PS classic pipeline events (400/403/600/800)
   - `windows.windows_defender` — AV detections/exclusions
**Status:** Fixed — all four channels flowing on fresh provision

---

### Issue 33 — `setup.ps1` VMware detection fails when installed on non-C: drive
**Date:** 2026-04-18
**Symptom:** On a Windows host where VMware Workstation is installed to a non-C: drive (e.g. `A:\Program Files (x86)\VMware\VMware Workstation\`), `setup.ps1` reports "VMware Workstation Pro does not appear to be installed" and exits.
**Root cause:** The detection relied solely on `Get-Command vmrun` / `Get-Command vmware`, which searches `$env:PATH`. Installers on non-default drives often don't update the system PATH (or the PATH update isn't reflected in the current elevated session), so both commands return `$null` even though VMware is present on disk.
**Fix:** Added a registry-based fallback. VMware always writes its install path to:
```
HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation  (64-bit OS)
HKLM:\SOFTWARE\VMware, Inc.\VMware Workstation               (32-bit OS)
```
If `Get-Command` fails, the script reads `InstallPath` from whichever key exists, verifies that `vmrun.exe` is present there, and prepends the directory to `$env:PATH` for the current session. This ensures both the detection check and all subsequent `vagrant` calls (which also shell out to `vmrun`) work correctly without requiring the user to fix their PATH.
**Status:** Fixed in `setup.ps1`

---

## Completed

- [x] elastic-siem — Elasticsearch 8.19.14 + Kibana + Fleet Server on 192.168.56.10
- [x] caldera — MITRE Caldera 5.0.0 via Docker on 192.168.56.30 — login working
- [x] win11-victim — Windows 11 + Sysmon + Elastic Agent enrolled with Fleet
- [x] Caldera sandcat agent — beaconing from win11-victim (paw: dlkrqv, group: red)
- [x] Automated agent deploy: `vagrant provision win11-victim --provision-with deploy_caldera_agent`
- [x] Full destroy/rebuild verified: all three VMs up, Kibana 200, Caldera 200, data flowing
- [x] `install_win_tools.ps1` fully idempotent — clean exit 0 on first run and re-provision
- [x] Windows telemetry pipeline verified: Sysmon, PowerShell, Defender, System events in Kibana
- [x] `setup.ps1` VMware detection works on any drive (registry fallback + session PATH patch)
