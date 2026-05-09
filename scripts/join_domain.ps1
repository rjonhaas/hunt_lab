# join_domain.ps1
# Optional: domain-join win11-victim to lab.local.
# Run after win-dc is fully provisioned:
#   vagrant provision win11-victim --provision-with join_domain
#
# Vagrant will reboot win11-victim automatically after this script exits
# (reboot: true on the join_domain provision block in the Vagrantfile).
#
# Reads C:\vagrant\domain-info.txt written by setup_dc_post_reboot.ps1.

param()

$LogFile = "C:\Windows\Temp\join-domain.log"
Start-Transcript -Path $LogFile -Force

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    Write-Host "[join-domain] $Message"
}

$DCIP           = "192.168.56.50"
$DomainInfoFile = "C:\vagrant\domain-info.txt"

# ── Guard ─────────────────────────────────────────────────────────────────────
if (-not (Test-Path $DomainInfoFile)) {
    Write-Error "domain-info.txt not found at $DomainInfoFile. Run 'vagrant up win-dc' first."
    exit 1
}

# Parse domain-info.txt (KEY=VALUE format)
$domainInfo = @{}
Get-Content $DomainInfoFile | ForEach-Object {
    if ($_ -match "^(\w[\w-]*)=(.+)$") { $domainInfo[$Matches[1]] = $Matches[2].Trim() }
}
$DomainName = $domainInfo["DOMAIN"]
$JoinUser   = "$($domainInfo['NETBIOS'])\$($domainInfo['JOIN_USER'])"
$JoinPass   = ConvertTo-SecureString $domainInfo["JOIN_PASS"] -AsPlainText -Force
$JoinCred   = New-Object System.Management.Automation.PSCredential($JoinUser, $JoinPass)

# ── Check current domain membership ──────────────────────────────────────────
Write-Log "Checking current domain membership..."
$currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($currentDomain -ieq $DomainName) {
    Write-Log "Already a member of $DomainName - nothing to do."
    Stop-Transcript
    exit 0
}

# ── Update DNS to point at the DC ─────────────────────────────────────────────
# The private adapter already has a static IP (set by install_win_tools.ps1).
# We only need to update its DNS server address to point at win-dc.
Write-Log "Pointing DNS at DC ($DCIP)..."
$privateAdapter = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -like "192.168.56.*" } |
    Select-Object -First 1
if ($privateAdapter) {
    Set-DnsClientServerAddress -InterfaceIndex $privateAdapter.InterfaceIndex -ServerAddresses $DCIP
    Write-Log "DNS set to $DCIP on adapter index $($privateAdapter.InterfaceIndex)."
} else {
    Write-Log "WARNING: Could not find 192.168.56.x adapter. Verify network config."
}

# ── Join the domain ────────────────────────────────────────────────────────────
Write-Log "Joining domain '$DomainName' as $JoinUser ..."
Add-Computer -DomainName $DomainName -Credential $JoinCred -Force -ErrorAction Stop
Write-Log "Domain join successful. Vagrant will now reboot win11-victim."

Stop-Transcript
exit 0
