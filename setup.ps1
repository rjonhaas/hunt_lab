#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Bootstrap script for the Threat Hunting Lab (Windows host).
.DESCRIPTION
    Installs all prerequisites (Vagrant, vagrant-vmware-utility, vagrant-vmware-desktop
    plugin) if missing, then provisions three VMs in the correct order:
      1. elastic-siem  (Elasticsearch + Kibana + Fleet Server)
      2. caldera       (MITRE Caldera C2)
      3. win11-victim  (Windows 11 + Sysmon + Elastic Agent)

    Only prerequisite requiring manual install beforehand:
      VMware Workstation Pro 17+
      https://www.vmware.com/products/workstation-pro.html
.EXAMPLE
    # From an elevated PowerShell prompt in the hunt_lab directory:
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\setup.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Set-Location $PSScriptRoot

$VagrantVersion = "2.4.9"
$UtilityVersion = "1.0.22"
$PluginName     = "vagrant-vmware-desktop"

# Minimum requirements
$MinRamGB   = 20
$MinDiskGB  = 150

function Write-Log  { param([string]$Msg) Write-Host "[setup] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "[setup] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "[setup] WARNING: $Msg" -ForegroundColor Yellow }
function Write-Die  {
    param([string]$Msg)
    Write-Host ""
    Write-Host "[setup] ERROR: $Msg" -ForegroundColor Red
    Write-Host ""
    exit 1
}

function Invoke-Download {
    param([string]$Url, [string]$OutFile, [string]$Label)
    Write-Log "Downloading $Label..."
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    } catch {
        Write-Die "Failed to download $Label from $Url`n  $_`n  Check your internet connection and try again."
    }
}

# Detect CPU architecture for MSI download URLs
$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "ARM64"  { "arm64" }
    "x86"    { "386"   }
    default  { "amd64" }
}

Write-Log "================================================================="
Write-Log "  Threat Hunting Lab - Setup"
Write-Log "  Host arch: $Arch  |  PowerShell: $($PSVersionTable.PSVersion)"
Write-Log "================================================================="
Write-Log ""

# --- 1. System requirements check ---
Write-Log "Checking system requirements..."

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os) {
    $totalRamGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    if ($totalRamGB -lt $MinRamGB) {
        Write-Warn "Only ${totalRamGB} GB RAM detected. Lab requires ${MinRamGB} GB minimum."
        Write-Warn "Provisioning will likely fail. Consider adding RAM before continuing."
    } else {
        Write-Ok "RAM: ${totalRamGB} GB (OK)"
    }
}

$drive = Split-Path $PSScriptRoot -Qualifier
$disk  = Get-PSDrive ($drive.TrimEnd(":")) -ErrorAction SilentlyContinue
if ($disk) {
    $freeGB = [math]::Round($disk.Free / 1GB, 1)
    if ($freeGB -lt $MinDiskGB) {
        Write-Warn "Only ${freeGB} GB free on ${drive}. Lab requires ${MinDiskGB} GB minimum."
        Write-Warn "Provisioning may fail. Free up disk space before continuing."
    } else {
        Write-Ok "Disk free on ${drive}: ${freeGB} GB (OK)"
    }
}

# --- 2. Check VMware Workstation ---
Write-Log "Checking VMware Workstation..."

$vmwareInstallPath = $null

# Check PATH first
if (Get-Command vmrun -ErrorAction SilentlyContinue) {
    $vmwareInstallPath = Split-Path (Get-Command vmrun).Source -Parent
}

# Fall back to registry (works regardless of which drive VMware is on)
if (-not $vmwareInstallPath) {
    $regPaths = @(
        "HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation",
        "HKLM:\SOFTWARE\VMware, Inc.\VMware Workstation"
    )
    foreach ($rp in $regPaths) {
        $key = Get-ItemProperty $rp -ErrorAction SilentlyContinue
        if ($key -and $key.InstallPath) {
            $candidate = $key.InstallPath.TrimEnd("\")
            if (Test-Path (Join-Path $candidate "vmrun.exe")) {
                $vmwareInstallPath = $candidate
                break
            }
        }
    }
}

if (-not $vmwareInstallPath) {
    Write-Die ("VMware Workstation Pro does not appear to be installed.`n" +
               "  Download from: https://www.vmware.com/products/workstation-pro.html`n" +
               "  Version 17 or later required. Re-run this script after installing.")
}

# Ensure vmrun is reachable in this session and in child processes
if ($env:PATH -notlike "*$vmwareInstallPath*") {
    $env:PATH = "$vmwareInstallPath;$env:PATH"
    $machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($machinePath -notlike "*$vmwareInstallPath*") {
        [Environment]::SetEnvironmentVariable("PATH", "$vmwareInstallPath;$machinePath", "Machine")
        Write-Warn "VMware was not on PATH - added permanently. A new terminal will pick it up automatically."
    }
}

# Version check
$vmwareExe = Join-Path $vmwareInstallPath "vmware.exe"
if (Test-Path $vmwareExe) {
    $ver = (Get-Item $vmwareExe).VersionInfo.ProductVersion
    $major = [int]($ver -split "\.")[0]
    if ($major -lt 17) {
        Write-Warn "VMware Workstation $ver detected. Version 17+ is recommended for best compatibility."
    } else {
        Write-Ok "VMware Workstation $ver found."
    }
} else {
    Write-Ok "VMware Workstation found at $vmwareInstallPath"
}

# --- 3. Install Vagrant if missing ---
Write-Log "Checking Vagrant..."

function Find-VagrantExe {
    # 1. Already on session PATH
    $cmd = Get-Command vagrant -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # 2. Known install locations
    $knownDirs = @(
        "C:\Program Files\Vagrant\bin",
        "C:\HashiCorp\Vagrant\bin",
        "C:\Program Files (x86)\Vagrant\bin"
    )
    foreach ($d in $knownDirs) {
        $exe = Join-Path $d "vagrant.exe"
        if (Test-Path $exe) { return $exe }
    }
    # 3. System PATH (updated by MSI but not yet visible in this session's $env:PATH)
    foreach ($d in ([Environment]::GetEnvironmentVariable("PATH", "Machine") -split ";")) {
        $exe = Join-Path $d.Trim() "vagrant.exe"
        if ($d -and (Test-Path $exe)) { return $exe }
    }
    return $null
}

$vagrantExe = Find-VagrantExe

if (-not $vagrantExe) {
    Write-Log "Vagrant not found. Installing v$VagrantVersion automatically..."
    $msiName = "vagrant_${VagrantVersion}_windows_${Arch}.msi"
    $msiPath = "$env:TEMP\$msiName"
    $msiUrl  = "https://releases.hashicorp.com/vagrant/${VagrantVersion}/${msiName}"

    if (-not (Test-Path $msiPath)) {
        Invoke-Download -Url $msiUrl -OutFile $msiPath -Label "Vagrant v$VagrantVersion ($Arch)"
    } else {
        Write-Log "MSI already cached at $msiPath, skipping download."
    }

    Write-Log "Installing Vagrant (this takes ~30 seconds)..."
    $proc = Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait -PassThru
    # 0 = clean success; 3010 = success, reboot recommended (all files are in place)
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Write-Die "Vagrant MSI installer returned exit code $($proc.ExitCode).`n  Try running the installer manually: $msiPath"
    }

    $vagrantExe = Find-VagrantExe
    if (-not $vagrantExe) {
        Write-Die ("Vagrant was installed but vagrant.exe could not be located.`n" +
                   "  Close this window, open a new elevated PowerShell, and re-run setup.ps1.")
    }
    Write-Ok "Vagrant installed."
}

# Ensure vagrant's bin dir is in this session's PATH for all child processes
$vagrantBin = Split-Path $vagrantExe -Parent
if ($env:PATH -notlike "*$vagrantBin*") { $env:PATH = "$vagrantBin;$env:PATH" }

$vagrantVersion = (& $vagrantExe --version) -replace "[^\d\.]", ""
Write-Ok "Vagrant $vagrantVersion found at $vagrantExe"

# --- 4. Install vagrant-vmware-utility service ---
Write-Log "Checking vagrant-vmware-utility service..."
$svc = Get-Service -Name "vagrant-vmware-utility" -ErrorAction SilentlyContinue

if (-not $svc -or $svc.Status -ne "Running") {
    Write-Log "vagrant-vmware-utility not running. Installing v$UtilityVersion..."
    $utilMsiName = "vagrant-vmware-utility_${UtilityVersion}_windows_amd64.msi"
    $utilMsiPath = "$env:TEMP\$utilMsiName"
    $utilMsiUrl  = "https://releases.hashicorp.com/vagrant-vmware-utility/${UtilityVersion}/${utilMsiName}"

    if (-not (Test-Path $utilMsiPath)) {
        Invoke-Download -Url $utilMsiUrl -OutFile $utilMsiPath -Label "vagrant-vmware-utility v$UtilityVersion"
    }

    Write-Log "Installing vagrant-vmware-utility..."
    $proc = Start-Process msiexec.exe -ArgumentList "/i `"$utilMsiPath`" /qn /norestart" -Wait -PassThru
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Write-Die "vagrant-vmware-utility installer returned exit code $($proc.ExitCode)."
    }

    # Wait for SCM to commit the service registration (MSI may return before SCM is ready)
    Write-Log "Waiting for service registration..."
    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Seconds 2
        $svc = Get-Service -Name "vagrant-vmware-utility" -ErrorAction SilentlyContinue
    } while ((-not $svc) -and ((Get-Date) -lt $deadline))

    if ($svc) {
        try { Set-Service -Name "vagrant-vmware-utility" -StartupType Automatic -ErrorAction SilentlyContinue } catch {}
        try {
            $svc.Refresh()
            if ($svc.Status -ne "Running") { Start-Service -Name "vagrant-vmware-utility" -ErrorAction SilentlyContinue }
        } catch {}
    }
    Write-Ok "vagrant-vmware-utility installed."
} else {
    Write-Ok "vagrant-vmware-utility is running."
}

# --- 5. Install vagrant-vmware-desktop plugin ---
Write-Log "Checking Vagrant plugin: $PluginName..."
$pluginList = & $vagrantExe plugin list 2>$null
if ($pluginList -notmatch [regex]::Escape($PluginName)) {
    Write-Log "Installing $PluginName plugin (requires internet)..."
    & $vagrantExe plugin install $PluginName
    if ($LASTEXITCODE -ne 0) { Write-Die "Plugin install failed (exit $LASTEXITCODE)." }
    Write-Ok "Plugin $PluginName installed."
} else {
    Write-Ok "Plugin $PluginName already installed."
}

# --- 6. Add the Windows 11 Vagrant box ---
Write-Log "Checking for gusztavvargadr/windows-11 box..."
$boxList = (& $vagrantExe box list 2>$null) -join "`n"
if ($boxList -notmatch "gusztavvargadr/windows-11") {
    Write-Log "Downloading Windows 11 box (~8-12 GB). This is the slowest step..."
    & $vagrantExe box add gusztavvargadr/windows-11 --provider vmware_desktop
    if ($LASTEXITCODE -ne 0) { Write-Die "Box download failed (exit $LASTEXITCODE)." }
    Write-Ok "Windows 11 box downloaded."
} else {
    Write-Ok "Windows 11 box already present."
}

# --- 7. Bring up the lab ---
Write-Log ""
Write-Log "================================================================="
Write-Log "  All prerequisites satisfied. Starting the lab..."
Write-Log "  Estimated time: 25-40 minutes on first run"
Write-Log "================================================================="
Write-Log ""

Write-Log "Step 1/3 - elastic-siem (Elasticsearch + Kibana + Fleet)..."
& $vagrantExe up elastic-siem --provision
if ($LASTEXITCODE -ne 0) { Write-Die "elastic-siem provisioning failed. Check the output above for details." }
Write-Ok "elastic-siem is up."

Write-Log "Step 2/3 - caldera (MITRE Caldera C2)..."
& $vagrantExe up caldera --provision
if ($LASTEXITCODE -ne 0) { Write-Die "caldera provisioning failed. Check the output above for details." }
Write-Ok "caldera is up."

Write-Log "Step 3/3 - win11-victim (Windows 11 + Sysmon + Elastic Agent)..."
& $vagrantExe up win11-victim --provision
if ($LASTEXITCODE -ne 0) { Write-Die "win11-victim provisioning failed. Check the output above for details." }
Write-Ok "win11-victim is up."

# --- 8. Print access info ---
$credsFile = Join-Path $PSScriptRoot "elastic-credentials.txt"
$elasticCreds = if (Test-Path $credsFile) { (Get-Content $credsFile -Raw).Trim() } else { "see elastic-credentials.txt" }

Write-Log ""
Write-Log "================================================================="
Write-Ok  "  Lab is up and ready!"
Write-Log ""
Write-Log "  Kibana (SIEM):   http://192.168.56.10:5601"
Write-Log "  Caldera (C2):    http://192.168.56.30:8888   (admin / admin)"
Write-Log "  Elastic creds:   $elasticCreds"
Write-Log ""
Write-Log "  RDP into victim: vagrant rdp win11-victim"
Write-Log "  SSH into VMs:    vagrant ssh elastic-siem"
Write-Log "  Tear it down:    vagrant destroy -f"
Write-Log "================================================================="
