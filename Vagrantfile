# Vagrantfile
# Threat Hunting Lab: Elastic SIEM + Windows Domain + MITRE Caldera
#
# Architecture:
#   All services run inside Vagrant VMs. The docker-host Linux VM runs the
#   Elastic + Caldera Docker stack; the three Windows VMs are
#   the attack targets / domain.
#
# VM inventory:
#   192.168.56.10  docker-host    Ubuntu 22.04  — Docker Compose stack
#                                                 (Elasticsearch, Kibana,
#                                                  Fleet Server, Caldera)
#   192.168.56.20  win11-victim   Windows 11    — Victim workstation
#   192.168.56.50  win-dc         WinSrv 2022   — Active Directory DC (lab.local)
#   192.168.56.51  win-server     WinSrv 2022   — Domain member server
#
# Service endpoints (reachable at docker-host = 192.168.56.10):
#   :9200 / :5601 / :8220  — Elasticsearch + Kibana + Fleet Server
#   :8888                  — MITRE Caldera C2
#
# Provisioning order:
#   1. docker-host    — installs Docker, runs docker/setup.sh inside the VM,
#                       writes fleet-enrollment-token.txt + elastic-credentials.txt
#                       to the repo root via the /vagrant synced folder
#   2. win-dc         — promotes DC, writes domain-info.txt, installs Sysmon +
#                       Elastic Agent, deploys sandcat
#   3. win-server     — joins domain, installs Sysmon + Elastic Agent, deploys sandcat
#   4. win11-victim   — installs Sysmon + Elastic Agent, deploys sandcat
#
# Manual launch:
#   vagrant up docker-host
#   vagrant up win-dc win-server win11-victim --no-parallel

Vagrant.configure("2") do |config|

  # Refresh stalled WinRM requests promptly after Windows reboots. The default
  # operation timeout is 30 minutes, which can look like frozen provisioning.
  config.winrm.timeout = 300
  config.winrm.execution_time_limit = "PT30M"

  # Disable automatic box update checks for reproducibility
  config.vm.box_check_update = false
  # Bound stalled downloads on either host OS without limiting healthy large transfers.
  config.vm.box_download_options = { "connect-timeout" => "30", "speed-time" => "120", "speed-limit" => "1024" }

  # On Windows hosts, vmrun can return the host-only lab IP after provisioning.
  # VMware NAT port forwards then target the wrong subnet and WinRM reconnects
  # fail. Look up the NAT adapter's DHCP lease by MAC instead.
  if Vagrant::Util::Platform.windows?
    config.vm.provider "vmware_desktop" do |v|
      v.enable_vmrun_ip_lookup = false
    end
  end

  # ── Docker Host (Linux VM running the SIEM/Caldera stack) ────────────────────
  # Provisioned first. The /vagrant synced folder maps the repo root, so
  # docker/setup.sh inside the VM writes fleet-enrollment-token.txt and
  # elastic-credentials.txt back to the host's repo root for the Windows VMs.
  config.vm.define "docker-host" do |dh|
    dh.vm.box          = "bento/ubuntu-22.04"
    dh.vm.hostname     = "docker-host"
    dh.vm.network       "private_network", ip: "192.168.56.10"
    dh.vm.boot_timeout = 600

    dh.vm.provider "vmware_desktop" do |v|
      v.memory = 12288
      v.cpus   = 4
      v.vmx["displayname"]             = "docker-host"
      v.vmx["uefi.secureBoot.enabled"] = "FALSE"
      v.gui                = false
      v.force_vmware_license = "workstation"
      v.linked_clone       = true
    end

    # Step 1: Install Docker Engine + Compose v2 (idempotent)
    dh.vm.provision "shell", name: "install_docker",
      privileged: true,
      path: "scripts/install_docker.sh"

    # Step 2: Seed docker/.env with HOST_IP set to this VM's private IP
    dh.vm.provision "shell", name: "seed_env",
      privileged: false, inline: <<~SHELL
        set -euo pipefail
        # vagrant-vmware-desktop 3.0.5 sometimes finishes booting before the
        # HGFS shared folder is mounted, so inline provisioners that touch
        # /vagrant race the mount. Wait up to 2 minutes for it to appear.
        for i in $(seq 1 60); do
          [[ -d /vagrant/docker ]] && break
          echo "[seed_env] /vagrant not mounted yet (attempt $i)..."
          sleep 2
        done
        [[ -d /vagrant/docker ]] || { echo "[seed_env] FATAL: /vagrant/docker still not mounted after 120s"; exit 1; }
        cd /vagrant/docker
        if [[ ! -f .env ]]; then
          cp .env.example .env
        fi
        # Force HOST_IP to the docker-host private IP so agents can reach this VM
        if grep -q '^HOST_IP=' .env; then
          sed -i 's|^HOST_IP=.*|HOST_IP=192.168.56.10|' .env
        else
          echo 'HOST_IP=192.168.56.10' >> .env
        fi
        echo "[seed_env] HOST_IP=192.168.56.10 in docker/.env"
      SHELL

    # Step 3: Run docker/setup.sh — pulls images, starts the stack, runs
    # bootstrap, writes tokens/credentials to the repo root.
    # Use sudo so the fresh shell session has docker group membership.
    dh.vm.provision "shell", name: "docker_stack_up",
      privileged: false, inline: <<~SHELL
        set -e
        for i in $(seq 1 60); do
          [[ -f /vagrant/docker/setup.sh ]] && break
          echo "[docker_stack_up] /vagrant/docker/setup.sh not visible yet (attempt $i)..."
          sleep 2
        done
        [[ -f /vagrant/docker/setup.sh ]] || { echo "[docker_stack_up] FATAL: /vagrant/docker/setup.sh missing after 120s"; exit 1; }
        sudo bash /vagrant/docker/setup.sh
      SHELL
  end

  # ── Windows Domain Controller ──────────────────────────────────────────────────
    # Provision AFTER docker/setup.sh has written fleet-enrollment-token.txt.
    # Two-stage provisioning: setup_dc.ps1 promotes the DC, Vagrant reboots,
    # then setup_dc_post_reboot.ps1 creates users/OUs, installs Sysmon + Elastic Agent,
    # and deploys the Caldera sandcat agent.
  config.vm.define "win-dc" do |dc|
    dc.vm.box          = "gusztavvargadr/windows-server-2022-standard"
    dc.vm.hostname     = "win-dc"
    dc.vm.communicator = "winrm"
    dc.vm.network       "private_network", ip: "192.168.56.50"
    dc.vm.boot_timeout = 600

    # Give WinRM extra retries — DC promotion reboot takes longer than a normal reboot
    dc.winrm.retry_limit = 60
    dc.winrm.retry_delay = 15
    # After DC promotion, local 'vagrant' becomes 'LAB\vagrant'. NTLM negotiate over
    # port-forwarding fails to resolve the domain account. Basic auth sends credentials
    # directly and the DC resolves 'vagrant' as 'LAB\vagrant' successfully.
    dc.winrm.transport     = :plaintext
    dc.winrm.basic_auth_only = true

    dc.vm.provider "vmware_desktop" do |v|
      v.memory = 4096
      v.cpus   = 2
      v.vmx["displayname"]             = "win-dc"
      v.vmx["uefi.secureBoot.enabled"] = "FALSE"
      v.gui                = false
      v.force_vmware_license = "workstation"
      v.linked_clone       = true
    end

    # Guard: docker/setup.sh must have run first
    dc.vm.provision "shell", privileged: false, inline: <<~POWERSHELL
      if (-not (Test-Path "C:\\vagrant\\fleet-enrollment-token.txt")) {
        Write-Error "fleet-enrollment-token.txt not found. Run 'bash docker/setup.sh' first."
        exit 1
      }
    POWERSHELL

    # Stage 1: Install AD DS role and promote to DC; Vagrant reboots after
    dc.vm.provision "shell", name: "setup_dc", reboot: true, privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\setup_dc.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    # Stage 2: Post-reboot — create OUs/users, write domain-info.txt, install Sysmon + Elastic Agent
    dc.vm.provision "shell", name: "setup_dc_post_reboot", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\setup_dc_post_reboot.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    # Deploy Caldera sandcat agent automatically during provisioning
    dc.vm.provision "shell", name: "deploy_caldera_agent", privileged: false, inline: <<~POWERSHELL
      powercfg /change standby-timeout-ac 0 | Out-Null
      powercfg /change hibernate-timeout-ac 0 | Out-Null
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\deploy_caldera_agent.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL


    # Install Atomic Red Team (Invoke-AtomicRedTeam + all atomics)
    dc.vm.provision "shell", name: "install_atomic_red_team", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\install_atomic_red_team.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    # Prepare the workshop evidence directory and Sysmon file-creation rule.
    dc.vm.provision "shell", name: "prepare_workshop", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\prepare_workshop.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    dc.vm.provision "shell", name: "verify_windows", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\validate_windows.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL
  end

  # ── Windows Member Server ──────────────────────────────────────────────────────
  # Provision AFTER docker/setup.sh (Fleet token) AND win-dc (domain-info.txt).
  # Two-stage provisioning: setup_win_server.ps1 joins the domain, Vagrant reboots,
  # then setup_win_server_tools.ps1 installs Sysmon and Elastic Agent.
  config.vm.define "win-server" do |srv|
    srv.vm.box          = "gusztavvargadr/windows-server-2022-standard"
    srv.vm.hostname     = "win-server"
    srv.vm.communicator = "winrm"
    srv.vm.network       "private_network", ip: "192.168.56.51"
    srv.vm.boot_timeout = 600

    srv.winrm.retry_limit = 30
    srv.winrm.retry_delay = 10

    srv.vm.provider "vmware_desktop" do |v|
      v.memory = 2048
      v.cpus   = 2
      v.vmx["displayname"]             = "win-server"
      v.vmx["uefi.secureBoot.enabled"] = "FALSE"
      v.gui                = false
      v.force_vmware_license = "workstation"
      v.linked_clone       = true
    end

    # Guard: docker/setup.sh and win-dc must have run first
    srv.vm.provision "shell", privileged: false, inline: <<~POWERSHELL
      if (-not (Test-Path "C:\\vagrant\\fleet-enrollment-token.txt")) {
        Write-Error "fleet-enrollment-token.txt not found. Run 'bash docker/setup.sh' first."
        exit 1
      }
      if (-not (Test-Path "C:\\vagrant\\domain-info.txt")) {
        Write-Error "domain-info.txt not found. Run 'vagrant up win-dc' first."
        exit 1
      }
    POWERSHELL

    # Stage 1: Configure network and join domain; Vagrant reboots after
    srv.vm.provision "shell", name: "setup_win_server", reboot: true, privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\setup_win_server.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    # Stage 2: Post-reboot — install Sysmon and Elastic Agent
    srv.vm.provision "shell", name: "setup_win_server_tools", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\setup_win_server_tools.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    # Idempotent — re-running just refreshes the contents.

    # Deploy Caldera sandcat agent automatically during provisioning
    srv.vm.provision "shell", name: "deploy_caldera_agent", privileged: false, inline: <<~POWERSHELL
      powercfg /change standby-timeout-ac 0 | Out-Null
      powercfg /change hibernate-timeout-ac 0 | Out-Null
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\deploy_caldera_agent.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL


    # Install Atomic Red Team (Invoke-AtomicRedTeam + all atomics)
    srv.vm.provision "shell", name: "install_atomic_red_team", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\install_atomic_red_team.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    # Prepare the workshop evidence directory and Sysmon file-creation rule.
    srv.vm.provision "shell", name: "prepare_workshop", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\prepare_workshop.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    srv.vm.provision "shell", name: "verify_windows", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\validate_windows.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL
  end
  # ── Windows 11 Victim ─────────────────────────────────────────────────────
  # Must be provisioned AFTER docker/setup.sh writes fleet-enrollment-token.txt
  config.vm.define "win11-victim" do |win|
    win.vm.box              = "gusztavvargadr/windows-11"
    win.vm.hostname         = "win11-victim"
    win.vm.communicator     = "winrm"
    win.vm.network          "private_network", ip: "192.168.56.20"
    win.vm.boot_timeout     = 1200  # Fresh Windows 11 boots can exceed 10 minutes on a busy host

    win.vm.provider "vmware_desktop" do |v|
      v.memory = 4096
      v.cpus   = 2
      v.vmx["displayname"]              = "win11-victim"
      v.vmx["uefi.secureBoot.enabled"]  = "FALSE"
      v.gui = false
      # Force Workstation product type so vmrun uses -T ws (not -T player).
      # The utility reports "standard" license, which the plugin maps to "player"
      # mode (disabling snapshots). "workstation" forces @pro_license = true,
      # enabling vmrun -T ws + linked clone (Issues 4 and 27).
      v.force_vmware_license = "workstation"
      v.linked_clone = true
    end

    # Abort early with a clear message if docker/setup.sh hasn't run yet
    win.vm.provision "shell", inline: <<~POWERSHELL, privileged: false
      if (-not (Test-Path "C:\\vagrant\\fleet-enrollment-token.txt")) {
        Write-Error "fleet-enrollment-token.txt not found. Run 'bash docker/setup.sh' first."
        exit 1
      }
      if (-not (Test-Path "C:\\vagrant\\domain-info.txt")) {
        Write-Error "domain-info.txt not found. Run 'vagrant up win-dc' first."
        exit 1
      }
    POWERSHELL

    # Elastic Agent can exceed SCM's default 30-second startup limit on a busy
    # Windows 11 guest. Apply the guest-only timeout before the required reboot.
    win.vm.provision "shell", name: "prepare_win11", reboot: true, privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      & "C:\\vagrant\\scripts\\prepare_win11.ps1"
      if (-not $?) { exit 1 }
    POWERSHELL

    # Run script from shared folder — avoids WinRM file-upload bug in vagrant-vmware-desktop
    win.vm.provision "shell", name: "install_win_tools", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\install_win_tools.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    # Domain-join win11-victim to lab.local (requires win-dc to be fully provisioned)
    win.vm.provision "shell", name: "join_domain", reboot: true, privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\join_domain.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    # Deploy Caldera sandcat agent automatically during provisioning
    win.vm.provision "shell", name: "deploy_caldera_agent", privileged: false, inline: <<~POWERSHELL
      powercfg /change standby-timeout-ac 0 | Out-Null
      powercfg /change hibernate-timeout-ac 0 | Out-Null
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\deploy_caldera_agent.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL


    # Install Atomic Red Team (Invoke-AtomicRedTeam + all atomics)
    win.vm.provision "shell", name: "install_atomic_red_team", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\install_atomic_red_team.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    # Prepare the workshop evidence directory and Sysmon file-creation rule.
    win.vm.provision "shell", name: "prepare_workshop", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\prepare_workshop.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL

    win.vm.provision "shell", name: "verify_windows", privileged: false, inline: <<~POWERSHELL
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"
      $LASTEXITCODE = 0
      & "C:\\vagrant\\scripts\\validate_windows.ps1"
      if (-not $?) { exit 1 }
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    POWERSHELL
  end

end
