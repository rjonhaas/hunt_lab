# install_atomic_red_team.ps1
# Installs Invoke-AtomicRedTeam + all atomic test definitions.
# Enables running ATT&CK techniques directly and via Caldera sandcat.
#
# Installs to: C:\AtomicRedTeam\
#   invoke-atomicredteam\  -- PowerShell module
#   atomics\               -- ATT&CK technique YAML definitions + payloads

param()

$LogFile = "C:\Windows\Temp\install-art.log"
Start-Transcript -Path $LogFile -Force

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    Write-Host "[art] $Message"
}

# Exclude ART directory from Defender so payloads are not quarantined
Write-Log "Adding Defender exclusion for C:\AtomicRedTeam..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "C:\AtomicRedTeam" -ErrorAction SilentlyContinue
    Write-Log "Exclusion added."
} catch {
    Write-Log "WARNING: Could not configure Defender exclusion: $_"
}

# Skip if already installed
if (Test-Path "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1") {
    Write-Log "Invoke-AtomicRedTeam already installed - skipping."
    Stop-Transcript
    exit 0
}

Write-Log "Downloading Invoke-AtomicRedTeam installer..."
$installerUrl = "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1"
$installerContent = (Invoke-WebRequest -Uri $installerUrl -UseBasicParsing).Content
Invoke-Expression $installerContent

Write-Log "Installing Invoke-AtomicRedTeam with all atomics (this takes 2-5 minutes)..."
Install-AtomicRedTeam -getAtomics -Force -NoPayloads

# Verify
if (-not (Test-Path "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1")) {
    Write-Error "Installation failed - module file not found after install."
    exit 1
}

$atomicCount = (Get-ChildItem "C:\AtomicRedTeam\atomics" -Directory -ErrorAction SilentlyContinue).Count
Write-Log ""
Write-Log "============================================================"
Write-Log "  Atomic Red Team installed!"
Write-Log "  Module:   C:\AtomicRedTeam\invoke-atomicredteam"
Write-Log "  Atomics:  C:\AtomicRedTeam\atomics  ($atomicCount techniques)"
Write-Log ""
Write-Log "  Usage:"
Write-Log "  Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
Write-Log "  Invoke-AtomicTest T1059.001 -ShowDetailsBrief"
Write-Log "  Invoke-AtomicTest T1059.001 -TestNumbers 1"
Write-Log "============================================================"

Stop-Transcript
exit 0
