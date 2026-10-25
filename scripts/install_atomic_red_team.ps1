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

function Publish-YamlDependency {
    # The upstream installer uses the provisioning user's module directory.
    # Sandcat runs as SYSTEM and cannot discover modules in that user profile.
    $yaml = Get-Module -ListAvailable powershell-yaml |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $yaml) {
        throw "powershell-yaml was not installed; Invoke-AtomicRedTeam cannot run."
    }
    $shared = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\powershell-yaml\$($yaml.Version)"
    if ($yaml.ModuleBase.TrimEnd('\') -ne $shared.TrimEnd('\')) {
        New-Item -ItemType Directory -Path $shared -Force | Out-Null
        Copy-Item -Path (Join-Path $yaml.ModuleBase '*') -Destination $shared -Recurse -Force
    }
    # Verify in a clean process. The upstream installer has already loaded its
    # user-scoped YAML module; forcing a second copy into that session collides
    # with its exported cfy/cty aliases.
    $manifest = Join-Path $shared 'powershell-yaml.psd1'
    $verify = "`$ErrorActionPreference = 'Stop'; Import-Module '$manifest' -ErrorAction Stop; Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -ErrorAction Stop; Get-Command Invoke-AtomicTest -ErrorAction Stop | Out-Null"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($verify))
    & "$PSHOME\powershell.exe" -NoProfile -NonInteractive -EncodedCommand $encoded
    if ($LASTEXITCODE -ne 0) {
        throw "Atomic Red Team dependency verification failed in a clean PowerShell process."
    }
    Write-Log "Verified ART import; powershell-yaml is available in the all-users module directory."
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
    Write-Log "Invoke-AtomicRedTeam already installed - verifying shared dependency."
    Publish-YamlDependency
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

Publish-YamlDependency

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
