# join_domain.ps1
# Domain-join win11-victim to lab.local.
# Runs automatically during provisioning after install_win_tools.ps1.
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

# Both the private and NAT adapters must use AD DNS. Leaving NAT pointed at
# VMware's resolver can make Windows send domain-discovery queries there.
Write-Log "Pointing private and default-route adapters at AD DNS ($DCIP)..."
$privateAdapter = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -like "192.168.56.*" } |
    Select-Object -First 1
if (-not $privateAdapter) { throw "Private 192.168.56.x adapter is missing; cannot join the domain." }
$dnsInterfaces = @($privateAdapter.InterfaceIndex)
$dnsInterfaces += @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
    Select-Object -ExpandProperty InterfaceIndex)
foreach ($index in ($dnsInterfaces | Sort-Object -Unique)) {
    Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $DCIP -ErrorAction Stop
    Write-Log "AD DNS configured on adapter index $index."
}
Clear-DnsClientCache
$dcReady = $false
for ($attempt = 1; $attempt -le 12; $attempt++) {
    & nltest.exe "/dsgetdc:$DomainName" /force | Out-Host
    if ($LASTEXITCODE -eq 0) { $dcReady = $true; break }
    if ($attempt -lt 12) { Start-Sleep -Seconds 5 }
}
if (-not $dcReady) { throw "Domain-controller discovery failed after configuring AD DNS. Check DC DNS and network connectivity." }

# ── Join the domain ────────────────────────────────────────────────────────────
Write-Log "Joining domain '$DomainName' as $JoinUser ..."
Add-Computer -DomainName $DomainName -Credential $JoinCred -Force -ErrorAction Stop
Write-Log "Domain join successful. Vagrant will now reboot win11-victim."

Stop-Transcript
exit 0
