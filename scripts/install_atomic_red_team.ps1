# install_atomic_red_team.ps1
# Installs Invoke-AtomicRedTeam + all atomic test definitions.
# Enables running ATT&CK techniques directly and via Caldera sandcat.
#
# Installs to: C:\AtomicRedTeam\
#   invoke-atomicredteam\  -- PowerShell module
#   atomics\               -- ATT&CK technique YAML definitions (no payload download)

param()

$LogFile = "C:\Windows\Temp\install-art.log"
Start-Transcript -Path $LogFile -Force

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    Write-Host "[art] $Message"
}

function Invoke-InstallRetry {
    param([string]$Step, [scriptblock]$Action)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Write-Log "$Step (attempt $attempt/3)..."
            & $Action
            return
        } catch {
            Write-Log "$Step failed: $($_.Exception.Message)"
            if ($attempt -eq 3) { throw }
            Start-Sleep -Seconds (10 * $attempt)
        }
    }
}

function Test-AtomicInstallation {
    # A previous installer failure can leave just the module behind.
    $module = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
    $definition = 'C:\AtomicRedTeam\atomics\T1059.001\T1059.001.yaml'
    return ((Test-Path $module -PathType Leaf) -and (Test-Path $definition -PathType Leaf))
}

function Install-YamlDependency {
    if (Get-Module -ListAvailable powershell-yaml) { return }
    Invoke-InstallRetry 'Installing powershell-yaml dependency' {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
            Register-PSRepository -Default -ErrorAction Stop
        }
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
                Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        }
        Install-Module -Name powershell-yaml -Repository PSGallery -Scope AllUsers -Force -ErrorAction Stop
        if (-not (Get-Module -ListAvailable powershell-yaml)) {
            throw 'powershell-yaml is still unavailable after installation.'
        }
    }
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

try {
    # Exclude ART directory from Defender so payloads are not quarantined
    Write-Log "Adding Defender exclusion for C:\AtomicRedTeam..."
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionPath "C:\AtomicRedTeam" -ErrorAction SilentlyContinue
        Write-Log "Exclusion added."
    } catch {
        Write-Log "WARNING: Could not configure Defender exclusion: $_"
    }

    Install-YamlDependency

    # Skip only a complete installation; repair partial installs left by a failed download.
    if (Test-AtomicInstallation) {
        Write-Log "Invoke-AtomicRedTeam already installed - verifying shared dependency."
        try {
            Publish-YamlDependency
            exit 0
        } catch {
            Write-Log "Existing ART installation failed validation; repairing it. $($_.Exception.Message)"
        }
    }

    $installerUrl = "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1"
    $script:installerContent = $null
    Invoke-InstallRetry 'Downloading Invoke-AtomicRedTeam installer' {
        $script:installerContent = (Invoke-WebRequest -Uri $installerUrl -UseBasicParsing -TimeoutSec 120).Content
    }
    Invoke-Expression $script:installerContent

    Write-Log "Installing Invoke-AtomicRedTeam with all atomics (this takes 2-5 minutes)..."
    Invoke-InstallRetry 'Installing module and atomic definitions' {
        Install-AtomicRedTeam -getAtomics -Force -NoPayloads
        if (-not (Test-AtomicInstallation)) {
            throw 'Atomic Red Team installation is incomplete: module or T1059.001 definition missing.'
        }
        Publish-YamlDependency
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

} catch {
    Write-Log "ERROR: Atomic Red Team provisioning failed. See $LogFile. $($_.Exception.Message)"
    throw
} finally {
    Stop-Transcript
}
exit 0
