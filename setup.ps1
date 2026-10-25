#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Bootstrap script for the Threat Hunting Lab (Windows host).
.DESCRIPTION
    Installs all prerequisites (Vagrant, vagrant-vmware-utility, vagrant-vmware-desktop
        plugin) if missing, then brings up the lab in this order:
      1. Docker stack  (Elasticsearch + Kibana + Fleet Server + Caldera + LocalStack)
      2. win-dc        (Windows Server 2022 — Active Directory DC)
      3. win-server    (Windows Server 2022 — Domain member)
      4. win11-victim  (Windows 11 + Sysmon + Elastic Agent)

    Prerequisites requiring manual install beforehand:
      VMware Workstation Pro 17+   https://www.vmware.com/products/workstation-pro.html
      Docker runs inside docker-host; Docker Desktop is not required.
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
$MinRamGB   = 24
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

# Guest boxes and VMware settings in this build target x64 Workstation.
$hostArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
if ($hostArch -ne "AMD64") {
    Write-Die "This lab requires an x64 Windows host. ARM and 32-bit hosts are not supported by this build."
}
$Arch = "amd64"

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
        Write-Die "22 GB is allocated to guests. Use a host with at least 24 GB RAM (32 GB recommended)."
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
        Write-Die "Free up disk space before continuing; 250 GB is recommended."
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
    Write-Die ("VMware Workstation was not detected in PATH or the installation registry.`n" +
               "  1. Open https://support.broadcom.com/ and sign in or register.`n" +
               "  2. Under Free Software Downloads, choose VMware Workstation Pro for Windows (x64).`n" +
               "  3. Run the downloaded installer as administrator and finish installation.`n" +
               "  4. Open Workstation once and finish its first-run prompts. Reboot if requested.`n" +
               "  5. Open a new elevated PowerShell, return to this repository, and run .\setup.ps1 again.`n" +
               "  Already installed? Repair the installation or add its vmrun.exe directory to PATH.`n" +
               "  Illustrated download guide: https://knowledge.broadcom.com/external/article/368734/download-desktop-hypervisor-workstation.html`n" +
               "  Local walkthrough: docs/install-vmware.md")
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
    # 2. Known install locations (use env vars so this works on any system drive)
    $knownDirs = @(
        "$env:ProgramFiles\Vagrant\bin",
        "$env:ProgramFiles\HashiCorp\Vagrant\bin",
        "${env:ProgramFiles(x86)}\Vagrant\bin"
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
    if (-not $svc -or $svc.Status -ne "Running") { Write-Die "VMware utility did not start. Inspect its Windows service before retrying." }
    Write-Ok "vagrant-vmware-utility installed."
} else {
    Write-Ok "vagrant-vmware-utility is running."
}

# --- 5. Install vagrant-vmware-desktop plugin ---
Write-Log "Checking Vagrant plugin: $PluginName..."
$pluginList = (& $vagrantExe plugin list 2>$null) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Die "Cannot list Vagrant plugins. Repair Vagrant before continuing." }
if ($pluginList -notmatch ("(?m)^" + [regex]::Escape($PluginName) + "\s")) {
    Write-Log "Installing $PluginName plugin (requires internet)..."
    & $vagrantExe plugin install $PluginName
    if ($LASTEXITCODE -ne 0) { Write-Die "Plugin install failed (exit $LASTEXITCODE)." }
    Write-Ok "Plugin $PluginName installed."
} else {
    Write-Ok "Plugin $PluginName already installed."
}

# Resolve box names, versions and provider from the Vagrantfile at creation time.
& $vagrantExe validate
if ($LASTEXITCODE -ne 0) { Write-Die "Vagrantfile validation failed." }

# --- 7. Bring up docker-host (Linux VM running the Docker Compose stack) ---
Write-Log ""
Write-Log "================================================================="
Write-Log "  All prerequisites satisfied. Starting the lab..."
Write-Log "  Allow several hours for first-run downloads and provisioning"
Write-Log "================================================================="
Write-Log ""

Write-Log "Step 1/4 - docker-host (Elasticsearch + Kibana + Fleet + Caldera + LocalStack)..."
& $vagrantExe up docker-host --provider vmware_desktop --provision
if ($LASTEXITCODE -ne 0) { Write-Die "docker-host provisioning failed. Run 'vagrant ssh docker-host' and check 'docker compose logs' inside the VM." }
foreach ($artifact in @("elastic-credentials.txt", "fleet-enrollment-token.txt")) {
    $path = Join-Path $PSScriptRoot $artifact
    if (-not (Test-Path $path) -or (Get-Item $path).Length -eq 0) {
        Write-Die "docker-host did not produce $artifact. Check bootstrap and /vagrant shared-folder access."
    }
}
Write-Ok "docker-host is up."

$HostIP = "192.168.56.10"

# --- Import Kibana threat hunt report template ---
$KibanaUrl      = "http://${HostIP}:5601"
$CredsFile      = Join-Path $PSScriptRoot "elastic-credentials.txt"
$TemplateNdjson = Join-Path $PSScriptRoot "kibana\hunt_report_template.ndjson"

if (Test-Path $TemplateNdjson) {
    Write-Log "Importing Kibana Threat Hunt Report Template..."
    if (-not (Test-Path $CredsFile)) {
        Write-Warn "elastic-credentials.txt not found — skipping Kibana template import."
    } else {
        $RawCreds = (Get-Content $CredsFile -Raw).Trim()
        $ColonIdx = $RawCreds.IndexOf(":")
        if ($ColonIdx -le 0) {
            Write-Warn "elastic-credentials.txt does not contain a valid 'user:password' entry — skipping import."
        } else {
            $KibUser  = $RawCreds.Substring(0, $ColonIdx)
            $KibPass  = $RawCreds.Substring($ColonIdx + 1)
            $B64Creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${KibUser}:${KibPass}"))

            $KibReady = $false
            $Deadline = (Get-Date).AddMinutes(5)
            Write-Log "  Waiting for Kibana API to become available..."
            while ((Get-Date) -lt $Deadline) {
                try {
                    $resp = Invoke-WebRequest -Uri "$KibanaUrl/api/status" `
                        -Headers @{Authorization = "Basic $B64Creds"} `
                        -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                    if ($resp.StatusCode -eq 200) { $KibReady = $true; break }
                } catch { }
                Start-Sleep -Seconds 5
            }

            if (-not $KibReady) {
                Write-Warn "Kibana did not become available within 5 minutes. Skipping template import."
            } else {
                $result = & curl.exe -s --max-time 30 `
                    -u "${KibUser}:${KibPass}" `
                    -X POST "$KibanaUrl/api/saved_objects/_import?overwrite=true" `
                    -H "kbn-xsrf: true" `
                    -F "file=@`"$TemplateNdjson`"" 2>&1
                $parsed = $result | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($parsed -and $parsed.success -eq $true) {
                    Write-Ok "  Threat Hunt Report Template imported ($($parsed.successCount) objects)."
                } else {
                    Write-Warn "  Template import returned unexpected response: $result"
                }
            }
        }
    }
} else {
    Write-Warn "Template file not found at $TemplateNdjson — skipping import."
}

# Caldera abilities are loaded by the bootstrap container during
# docker/setup.sh (see docker/bootstrap/bootstrap.sh) — nothing to do here.

# --- 8. Bring up Windows VMs ---
Write-Log "Step 2/4 - win-dc (Active Directory DC)..."
& $vagrantExe up win-dc --provider vmware_desktop --provision
if ($LASTEXITCODE -ne 0) { Write-Die "win-dc provisioning failed. Check the output above for details." }
$domainInfoPath = Join-Path $PSScriptRoot "domain-info.txt"
if (-not (Test-Path $domainInfoPath) -or (Get-Item $domainInfoPath).Length -eq 0) {
    Write-Die "win-dc did not produce domain-info.txt. Fix DC post-reboot provisioning before starting members."
}
Write-Ok "win-dc is up."

Write-Log "Step 3/4 - win-server (Domain member server)..."
& $vagrantExe up win-server --provider vmware_desktop --provision
if ($LASTEXITCODE -ne 0) { Write-Die "win-server provisioning failed. Check the output above for details." }
Write-Ok "win-server is up."

Write-Log "Step 4/4 - win11-victim (Windows 11)..."
& $vagrantExe up win11-victim --provider vmware_desktop --provision
if ($LASTEXITCODE -ne 0) { Write-Die "win11-victim provisioning failed. Check the output above for details." }
Write-Ok "win11-victim is up."

# --- 9. Print access info ---
$credsFile    = Join-Path $PSScriptRoot "elastic-credentials.txt"
$elasticCreds = if (Test-Path $credsFile) { (Get-Content $credsFile -Raw).Trim() } else { "see elastic-credentials.txt" }

Write-Log ""
Write-Log "================================================================="
Write-Ok  "  VM provisioning finished. Run the readiness check before class."
Write-Log ""
Write-Log "  Kibana (SIEM):   http://${HostIP}:5601"
Write-Log "  Caldera (C2):    http://${HostIP}:8888   (admin / HuntLab2026!)"
Write-Log "  LocalStack API:  http://${HostIP}:4566"
Write-Log "  Elastic creds:   $elasticCreds"
Write-Log ""
Write-Log "  RDP into victim: vagrant rdp win11-victim"
Write-Log "  RDP into DC:     vagrant rdp win-dc"
Write-Log "  Docker logs:     vagrant ssh docker-host -c 'cd /vagrant/docker && sudo docker compose logs -f'"
Write-Log "  Readiness: vagrant ssh docker-host -c 'python3 /vagrant/scripts/validate_lab.py'"
Write-Log "  Tear down all (deletes guest data): vagrant destroy"
Write-Log "================================================================="

# --- 10. Write env details to lab-info.md at repo root ---
$labInfoFile = Join-Path $PSScriptRoot "lab-info.md"

# Pull domain info from domain-info.txt (written by win-dc provisioning).
$domainInfoFile = Join-Path $PSScriptRoot "domain-info.txt"
$domainSection = "_domain-info.txt not present — win-dc may not have finished provisioning._"
if (Test-Path $domainInfoFile) {
    $kv = @{}
    foreach ($line in Get-Content $domainInfoFile) {
        if ($line -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') { $kv[$matches[1]] = $matches[2] }
    }
    $domainSection = @"
- **Domain:** $($kv['DOMAIN'])
- **NetBIOS:** $($kv['NETBIOS'])
- **DC IP:** $($kv['DC_IP'])
- **Join user / pass:** ``$($kv['JOIN_USER'])`` / ``$($kv['JOIN_PASS'])``
- **Lab domain users:** ``jsmith``, ``ajohnson``, ``bwilliams``, ``cdavis``, ``svc-backup``, ``svc-deploy`` (default password: ``Lab!Password1``)
"@
}

# Split elastic creds into user / pass for cleaner formatting.
$esUser = "elastic"
$esPass = $elasticCreds
if ($elasticCreds -match '^([^:]+):(.+)$') { $esUser = $matches[1]; $esPass = $matches[2] }

$generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")

$labInfoContent = @"
# Hunt Lab — Environment Details

_Generated by ``setup.ps1`` on $generatedAt._
_This file contains credentials and is gitignored. Regenerated on every ``setup.ps1`` run._

## Service endpoints (host: ``$HostIP``)

| Service | URL | Credentials |
|---|---|---|
| Kibana (SIEM) | http://${HostIP}:5601 | ``$esUser`` / ``$esPass`` |
| Elasticsearch | http://${HostIP}:9200 | ``$esUser`` / ``$esPass`` |
| Fleet Server | http://${HostIP}:8220 | — |
| Caldera (C2) | http://${HostIP}:8888 | ``admin`` / ``HuntLab2026!`` (red API key: ``ADMIN123``) |
| LocalStack | http://${HostIP}:4566 | ``test`` / ``test`` (any region) |

## Active Directory

$domainSection

## Vagrant VMs

| VM | IP | Role |
|---|---|---|
| ``docker-host`` | 192.168.56.10 | Ubuntu — Docker stack (Elastic, Caldera, LocalStack, Filebeat) |
| ``win-dc`` | 192.168.56.50 | Windows Server 2022 — AD DC for ``lab.local`` |
| ``win-server`` | 192.168.56.51 | Windows Server 2022 — domain member |
| ``win11-victim`` | 192.168.56.20 | Windows 11 — victim workstation |

All Windows VMs have: Sysmon (SwiftOnSecurity config), Elastic Agent (enrolled to Fleet), Caldera sandcat (scheduled task ``WindowsSecurityUpdate``, group ``red``), Atomic Red Team.

## Useful commands

``````powershell
# RDP into the Windows VMs
vagrant rdp win11-victim
vagrant rdp win-dc
vagrant rdp win-server

# Tail the docker stack logs
vagrant ssh docker-host -c 'cd /vagrant/docker && sudo docker compose logs -f'

# Run the validation suite
powershell -ExecutionPolicy Bypass -File .\scripts\validate_lab.ps1

# Tear the whole lab down
vagrant destroy -f
``````

## Generated files at repo root

| File | Purpose |
|---|---|
| ``elastic-credentials.txt`` | ``elastic`` user password (used by validate_lab.ps1) |
| ``fleet-enrollment-token.txt`` | Fleet enrollment token consumed by Windows VMs |
| ``domain-info.txt`` | Domain join config consumed by win-server / win11-victim |
| ``lab-info.md`` | This file |
"@

Set-Content -Path $labInfoFile -Value $labInfoContent -Encoding UTF8
Write-Ok "Wrote environment details to $labInfoFile"
