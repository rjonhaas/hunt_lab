# setup_win_server_tools.ps1
# Stage 2 of 2: Post-domain-join tooling for win-server.
# Installs Sysmon (SwiftOnSecurity config) and Elastic Agent enrolled with Fleet.
#
# Reads:
#   C:\vagrant\fleet-enrollment-token.txt   — written by install_elastic.sh

param()

$LogFile = "C:\Windows\Temp\setup-win-server-stage2.log"
Start-Transcript -Path $LogFile -Force

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    Write-Host "[win-server] $Message"
}

$FleetServer   = "http://192.168.56.10:8220"
$CalderaServer = "http://192.168.56.30:8888"
$TokenFile     = "C:\vagrant\fleet-enrollment-token.txt"

$TempDir   = "C:\Windows\Temp\lab-setup"
$SysmonDir = "$TempDir\Sysmon"
$AgentDir  = "$TempDir\ElasticAgent"
New-Item -ItemType Directory -Force -Path $SysmonDir | Out-Null
New-Item -ItemType Directory -Force -Path $AgentDir  | Out-Null

# ── 1. Install Sysmon ─────────────────────────────────────────────────────────
Write-Log "Downloading Sysmon..."
$SysmonZip    = "$SysmonDir\Sysmon.zip"
$SysmonConfig = "$SysmonDir\sysmonconfig.xml"

& curl.exe -fsSL -o $SysmonZip "https://download.sysinternals.com/files/Sysmon.zip" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to download Sysmon (exit $LASTEXITCODE)"; exit 1 }

Write-Log "Extracting Sysmon..."
Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force

Write-Log "Downloading SwiftOnSecurity Sysmon config..."
& curl.exe -fsSL -o $SysmonConfig `
    "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to download Sysmon config (exit $LASTEXITCODE)"; exit 1 }

Write-Log "Installing Sysmon..."
$SysmonExe = if (Test-Path "$SysmonDir\Sysmon64.exe") { "$SysmonDir\Sysmon64.exe" } else { "$SysmonDir\Sysmon.exe" }
$SysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
$sysArgs   = if ($SysmonSvc) {
    Write-Log "Sysmon already installed - updating config only..."
    @("-c", $SysmonConfig)
} else {
    @("-accepteula", "-i", $SysmonConfig)
}
# Use Start-Process to redirect I/O at the OS level — prevents WinRM EAP=Stop
# from treating Sysmon's stderr output as a fatal NativeCommandError.
$sysmonOut = "$env:TEMP\sysmon-stdout.tmp"
$sysmonErr = "$env:TEMP\sysmon-stderr.tmp"
$p = Start-Process -FilePath $SysmonExe -ArgumentList $sysArgs `
    -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $sysmonOut `
    -RedirectStandardError  $sysmonErr
if ($p.ExitCode -ne 0) {
    $errText = Get-Content $sysmonErr -ErrorAction SilentlyContinue
    Write-Error "Sysmon install failed (exit $($p.ExitCode)): $errText"
    exit 1
}
Write-Log "Sysmon installed."

# ── 2. Read Fleet enrollment token ────────────────────────────────────────────
Write-Log "Reading Fleet enrollment token..."
if (-not (Test-Path $TokenFile)) {
    Write-Error "fleet-enrollment-token.txt not found at $TokenFile."
    exit 1
}
$EnrollToken = (Get-Content $TokenFile -Raw).Trim()
if ([string]::IsNullOrEmpty($EnrollToken)) {
    Write-Error "Fleet enrollment token is empty. Check elastic-siem provisioning logs."
    exit 1
}
Write-Log "Token found."

# ── 3. Install Elastic Agent ──────────────────────────────────────────────────
Write-Log "Downloading Elastic Agent..."
$AgentVersion = "8.19.14"   # Must match elastic-siem version
$AgentZip     = "$AgentDir\elastic-agent.zip"
$AgentUrl     = "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${AgentVersion}-windows-x86_64.zip"

& curl.exe -fsSL -o $AgentZip $AgentUrl 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to download Elastic Agent (exit $LASTEXITCODE)"; exit 1 }

Write-Log "Extracting Elastic Agent..."
Expand-Archive -Path $AgentZip -DestinationPath $AgentDir -Force

$AgentExtracted = (Get-ChildItem -Path $AgentDir -Directory | Select-Object -First 1).FullName
if (-not $AgentExtracted) { Write-Error "Could not find extracted Elastic Agent directory."; exit 1 }

$ExistingAgent = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
if ($ExistingAgent) {
    Write-Log "Elastic Agent already installed - skipping (service: $($ExistingAgent.Status))."
} else {
    Write-Log "Installing and enrolling Elastic Agent..."
    # Use Start-Process (same pattern as Sysmon) to redirect elastic-agent's I/O
    # at OS level — prevents WinRM from terminating on stderr writes.
    $agentOut = "$env:TEMP\elastic-agent-out.tmp"
    $agentErr = "$env:TEMP\elastic-agent-err.tmp"
    $p = Start-Process -FilePath "$AgentExtracted\elastic-agent.exe" `
        -ArgumentList @("install",
            "--url=$FleetServer",
            "--enrollment-token=$EnrollToken",
            "--insecure",
            "--non-interactive") `
        -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $agentOut `
        -RedirectStandardError  $agentErr
    if ($p.ExitCode -ne 0) {
        $errText = Get-Content $agentErr -ErrorAction SilentlyContinue
        Write-Error "Elastic Agent install failed (exit $($p.ExitCode)): $errText"
        exit 1
    }
    Write-Log "Elastic Agent installed and enrolled."
}

# ── 4. Verify Elastic Agent service ───────────────────────────────────────────
$AgentService = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
if ($AgentService -and $AgentService.Status -eq "Running") {
    Write-Log "Elastic Agent service is running."
} else {
    Write-Log "WARNING: Elastic Agent service may not be running. Check 'sc query ElasticEndpoint'."
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Log ""
Write-Log "============================================================"
Write-Log "  Windows member server provisioning complete!"
Write-Log "  IP:            192.168.56.51"
Write-Log "  Domain:        lab.local"
Write-Log "  Sysmon:        running as a service"
Write-Log "  Elastic Agent: enrolled with Fleet at $FleetServer"
Write-Log "  Caldera C2:    $CalderaServer"
Write-Log "  Sandcat:       deploy with vagrant provision win-server --provision-with deploy_caldera_agent"
Write-Log "============================================================"

Stop-Transcript
exit 0
