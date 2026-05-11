#Requires -Version 5.1
<#
.SYNOPSIS
    Post-setup health check for the Hunt Lab.
.DESCRIPTION
    Runs ~10 checks against the running lab and prints PASS/FAIL for each.
    Use after setup.ps1 completes to confirm every piece (Elastic, Kibana,
    Fleet, Caldera, three Windows agents, both adversaries, detection rules,
    log shipping) is actually wired up. Exits 0 on full pass, 1 otherwise.

    Reads elastic password from elastic-credentials.txt at the repo root.
.EXAMPLE
    PS> powershell -ExecutionPolicy Bypass -File .\scripts\validate_lab.ps1
    PS> .\scripts\validate_lab.ps1 -HostIP 192.168.56.10
#>
[CmdletBinding()]
param(
    [string]$HostIP = "192.168.56.10",
    [string]$CalderaKey = "ADMIN123",
    [int]$RecentEventWindowMinutes = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CredsFile = Join-Path $RepoRoot "elastic-credentials.txt"

$Script:Pass = 0
$Script:Fail = 0
$Script:Failures = @()

# URL roots (use ${var} form so the colon doesn't get parsed as a scope qualifier)
$EsRoot = "http://${HostIP}:9200"
$KbRoot = "http://${HostIP}:5601"
$FsRoot = "http://${HostIP}:8220"
$CdRoot = "http://${HostIP}:8888"

function Pass([string]$Name, [string]$Detail) {
    Write-Host "[ OK ] " -ForegroundColor Green -NoNewline
    Write-Host "$Name" -NoNewline
    if ($Detail) { Write-Host "  $Detail" -ForegroundColor DarkGray } else { Write-Host "" }
    $Script:Pass++
}
function Fail([string]$Name, [string]$Detail, [string]$Hint = "") {
    Write-Host "[FAIL] " -ForegroundColor Red -NoNewline
    Write-Host "$Name" -NoNewline
    if ($Detail) { Write-Host "  $Detail" -ForegroundColor Yellow } else { Write-Host "" }
    if ($Hint) { Write-Host "       hint: $Hint" -ForegroundColor DarkYellow }
    $Script:Fail++
    $Script:Failures += ("{0}: {1}" -f $Name, $Detail)
}
function Info([string]$Msg) { Write-Host "[ -- ] $Msg" -ForegroundColor DarkCyan }

if (-not (Test-Path $CredsFile)) {
    Write-Host "[FAIL] elastic-credentials.txt not found at $CredsFile" -ForegroundColor Red
    Write-Host "       The bootstrap container writes it. Has docker-host finished provisioning?" -ForegroundColor DarkYellow
    exit 1
}
$credsLine = (Get-Content $CredsFile -Raw).Trim()
if (-not $credsLine) { Write-Host "[FAIL] elastic-credentials.txt is empty" -ForegroundColor Red; exit 1 }
# File format is "elastic:<password>"; tolerate either "user:pass" or just "<password>"
if ($credsLine -match '^([^:]+):(.+)$') {
    $ElasticUser = $matches[1]
    $ElasticPass = $matches[2]
} else {
    $ElasticUser = "elastic"
    $ElasticPass = $credsLine
}

$EsAuth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${ElasticUser}:${ElasticPass}"))
$BasicHdr   = @{ Authorization = "Basic $EsAuth" }
$KbHdr      = @{ Authorization = "Basic $EsAuth"; "kbn-xsrf" = "true" }
$CalderaHdr = @{ KEY = $CalderaKey }

function Try-Get([string]$Url, [hashtable]$Headers, [int]$TimeoutSec = 10) {
    try {
        return Invoke-RestMethod -Uri $Url -Headers $Headers -TimeoutSec $TimeoutSec -ErrorAction Stop
    } catch {
        return $null
    }
}

Write-Host ""
Write-Host "=== Hunt Lab validation against $HostIP ===" -ForegroundColor Cyan
Write-Host ""

# 1. Elasticsearch cluster health
$health = Try-Get "$EsRoot/_cluster/health" $BasicHdr
if ($null -eq $health) {
    Fail "Elasticsearch /_cluster/health" "no response from $EsRoot" "is docker-host up? Run: vagrant ssh docker-host -c 'docker ps'"
} elseif ($health.status -in "green", "yellow") {
    Pass "Elasticsearch cluster health" "status=$($health.status) nodes=$($health.number_of_nodes)"
} else {
    Fail "Elasticsearch cluster health" "status=$($health.status)" "check docker logs hl-elasticsearch"
}

# 2. Kibana availability
$kbStatus = Try-Get "$KbRoot/api/status" $KbHdr 15
if ($null -eq $kbStatus) {
    Fail "Kibana /api/status" "no response" "Kibana takes ~60s after Elasticsearch is up"
} elseif ($kbStatus.status.overall.level -eq "available") {
    Pass "Kibana availability" "level=available"
} else {
    Fail "Kibana availability" "level=$($kbStatus.status.overall.level)" "check docker logs hl-kibana"
}

# 3. Fleet Server reachable
try {
    $fs = Invoke-WebRequest -Uri "$FsRoot/api/status" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
    if ($fs.StatusCode -eq 200) { Pass "Fleet Server /api/status" "HTTP 200" }
    else { Fail "Fleet Server /api/status" "HTTP $($fs.StatusCode)" }
} catch {
    Fail "Fleet Server /api/status" "no response from $FsRoot" "check docker logs hl-fleet-server"
}

# 4. Fleet enrolled agents
$agents = Try-Get "$KbRoot/api/fleet/agents?perPage=100" $KbHdr 15
if ($null -eq $agents) {
    Fail "Fleet agent inventory" "/api/fleet/agents not reachable"
} else {
    $items = @($agents.items)
    $online  = @($items | Where-Object { $_.status -eq "online" })
    $offline = @($items | Where-Object { $_.status -ne "online" })
    Info ("Fleet sees {0} total agents ({1} online, {2} other)" -f $items.Count, $online.Count, $offline.Count)
    foreach ($a in $items) {
        $hn = $a.local_metadata.host.hostname
        Info ("    hostname={0}  status={1}  last_checkin={2}" -f $hn, $a.status, $a.last_checkin)
    }
    if ($online.Count -ge 4) {
        Pass "Fleet enrolled agents" "$($online.Count) online (expect 4: fleet-server + 3 Windows)"
    } elseif ($online.Count -ge 1) {
        Fail "Fleet enrolled agents" "only $($online.Count) online; expect 4 (fleet-server + win-dc + win-server + win11-victim)" "Elastic Agent likely failed to enroll on win-dc/win-server. Check Get-Service 'Elastic Agent' on each VM"
    } else {
        Fail "Fleet enrolled agents" "0 agents online" "Fleet output may be misconfigured. Re-run docker bootstrap"
    }
}

# 5. Per-host log coverage in last N minutes
$since = (Get-Date).ToUniversalTime().AddMinutes(-$RecentEventWindowMinutes).ToString("o")
$aggBody = @{
    size = 0
    query = @{ range = @{ "@timestamp" = @{ gte = $since } } }
    aggs  = @{ hosts = @{ terms = @{ field = "agent.name"; size = 20 } } }
} | ConvertTo-Json -Depth 10

try {
    $aggResp = Invoke-RestMethod -Uri "$EsRoot/logs-windows.*/_search" `
        -Method POST -Body $aggBody -ContentType "application/json" `
        -Headers $BasicHdr -TimeoutSec 15 -ErrorAction Stop
    $hostBuckets = @($aggResp.aggregations.hosts.buckets)
    Info ("Windows log shipping (last {0}m): {1} hostnames" -f $RecentEventWindowMinutes, $hostBuckets.Count)
    foreach ($b in $hostBuckets) { Info ("    {0}: {1} events" -f $b.key, $b.doc_count) }
    $windowsHostnames = @($hostBuckets | Where-Object { $_.key -match "^(win-dc|win-server|win11-victim|WIN-|DESKTOP-)" })
    if ($windowsHostnames.Count -ge 3) {
        Pass "Windows log shipping" "$($windowsHostnames.Count) Windows hosts shipping logs"
    } else {
        Fail "Windows log shipping" "only $($windowsHostnames.Count) Windows hosts shipping (expect 3)" "missing hosts haven't enrolled Elastic Agent - check C:\Windows\Temp\setup-*.log on that VM"
    }
} catch {
    Fail "Windows log shipping" "ES query failed: $($_.Exception.Message)" "logs-windows.* index may not exist yet"
}

# 6. Caldera reachable
$cald = Try-Get "$CdRoot/api/v2/health" $CalderaHdr 10
if ($null -eq $cald) {
    Fail "Caldera /api/v2/health" "no response from $CdRoot" "check docker logs hl-caldera"
} else {
    Pass "Caldera REST API" "responding"
}

# 7. Caldera sandcat agents
$calderaAgents = Try-Get "$CdRoot/api/v2/agents" $CalderaHdr 10
if ($null -eq $calderaAgents) {
    Fail "Caldera agent inventory" "/api/v2/agents not reachable"
} else {
    $agentArr = @($calderaAgents)
    $red = @($agentArr | Where-Object { $_.group -eq "red" })
    Info ("Caldera sees {0} sandcat agents ({1} in group red)" -f $agentArr.Count, $red.Count)
    foreach ($a in $agentArr) {
        Info ("    host={0} group={1} trusted={2} last_seen={3}" -f $a.host, $a.group, $a.trusted, $a.last_seen)
    }
    if ($red.Count -ge 3) {
        Pass "Caldera sandcat agents (group red)" "$($red.Count) registered"
    } else {
        Fail "Caldera sandcat agents (group red)" "only $($red.Count) in group red (expect 3)" "agents likely failed to deploy. On the missing VM run: Start-ScheduledTask -TaskName WindowsSecurityUpdate"
    }
}

# 8. Both adversaries seeded
$advs = Try-Get "$CdRoot/api/v2/adversaries" $CalderaHdr 10
if ($null -eq $advs) {
    Fail "Caldera adversaries" "/api/v2/adversaries not reachable"
} else {
    $advArr = @($advs)
    $rh = $advArr | Where-Object { $_.adversary_id -eq "rh-adversary-dfir-ransomhub-2025-lab" }
    $id = $advArr | Where-Object { $_.adversary_id -eq "id-adversary-identity-chain-2025-lab" }
    if ($rh -and $id) {
        Pass "Caldera adversaries seeded" "DFIR-RansomHub-2025-Lab + Identity-Chain-2025-Lab present"
    } else {
        $missing = @()
        if (-not $rh) { $missing += "DFIR-RansomHub-2025-Lab" }
        if (-not $id) { $missing += "Identity-Chain-2025-Lab" }
        Fail "Caldera adversaries seeded" ("missing: " + ($missing -join ", ")) "re-run inside docker-host: docker compose run --rm bootstrap"
    }
}

# 9. Detection rules imported
$rulesUrl = "$KbRoot/api/detection_engine/rules/_find?per_page=200&filter=alert.attributes.tags:%22hunt-lab%22"
$rules = Try-Get $rulesUrl $KbHdr 15
if ($null -eq $rules) {
    Fail "Detection rules import" "/api/detection_engine/rules/_find not reachable"
} else {
    $ruleCount = $rules.total
    if ($ruleCount -ge 21) {
        Pass "Detection rules imported" "$ruleCount hunt-lab tagged rules present (expect >=21)"
    } else {
        Fail "Detection rules imported" "only $ruleCount hunt-lab tagged rules (expect 21)" "re-run inside docker-host: docker compose run --rm bootstrap"
    }
}

# 10. CloudTrail events flowing
$ctBody = @{
    size  = 0
    query = @{ range = @{ "@timestamp" = @{ gte = $since } } }
} | ConvertTo-Json -Depth 10
try {
    $ctResp = Invoke-RestMethod -Uri "$EsRoot/logs-aws.cloudtrail-*/_count" `
        -Method POST -Body $ctBody -ContentType "application/json" `
        -Headers $BasicHdr -TimeoutSec 10 -ErrorAction Stop
    if ($ctResp.count -gt 0) {
        Pass "CloudTrail log shipping" ("{0} events in last {1}m" -f $ctResp.count, $RecentEventWindowMinutes)
    } else {
        Fail "CloudTrail log shipping" "0 events in last ${RecentEventWindowMinutes}m" "the cloudtrail-tailer needs LocalStack to handle a real AWS API call. Trigger one: docker exec hl-localstack awslocal s3 ls"
    }
} catch {
    Info "CloudTrail index logs-aws.cloudtrail-* not yet created (expected if no AWS activity yet)"
}

# Summary
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host ("  passed: {0}" -f $Script:Pass) -ForegroundColor Green
if ($Script:Fail -gt 0) {
    Write-Host ("  failed: {0}" -f $Script:Fail) -ForegroundColor Red
    Write-Host ""
    Write-Host "Failures:" -ForegroundColor Red
    foreach ($f in $Script:Failures) { Write-Host "  - $f" -ForegroundColor Yellow }
    exit 1
} else {
    Write-Host "  failed: 0" -ForegroundColor Green
    Write-Host ""
    Write-Host "Lab is healthy." -ForegroundColor Green
    exit 0
}
