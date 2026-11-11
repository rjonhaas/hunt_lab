# seed_decoy_data.ps1
# Hunt Lab: pre-stage decoy "Finance" documents on win-server so the
# RansomHub recreation has something to enumerate, exfil, and "encrypt".
# Idempotent: re-running just refreshes the contents.

param(
    [string]$Root      = "C:\Shares\Finance",
    [string]$ShareName = "Finance"
)

$ErrorActionPreference = "Stop"
Start-Transcript -Path "C:\Windows\Temp\seed-decoy-data.log" -Force

function Write-Log { param([string]$m) Write-Host "[seed-decoy] $m" }

$subdirs = @("Q1", "Q2", "Q3", "Q4", "Payroll", "Contracts", "Audit")
$exts    = @("docx", "xlsx", "pdf", "txt", "csv")

Write-Log "Creating $Root and subdirs..."
New-Item -ItemType Directory -Force -Path $Root | Out-Null
foreach ($d in $subdirs) {
    New-Item -ItemType Directory -Force -Path (Join-Path $Root $d) | Out-Null
}

# Body text reused for every file. The strings here are deliberately the
# kind of canary content a defender might key on (SSN-shaped, dollar amounts,
# "CONFIDENTIAL" header).
$body = @"
CONFIDENTIAL - Hunt Lab Decoy
=============================
This document is a synthetic file used by the Hunt Lab RansomHub
recreation. It contains no real personal or financial data.

Sample row:  EMPID=00$(Get-Random -Minimum 100 -Maximum 999)  SSN=$(Get-Random -Minimum 100 -Maximum 999)-$(Get-Random -Minimum 10 -Maximum 99)-$(Get-Random -Minimum 1000 -Maximum 9999)  AMOUNT=`$$(Get-Random -Minimum 10000 -Maximum 999999).00
Generated: $(Get-Date -Format o)
"@

$count = 0
foreach ($d in $subdirs) {
    foreach ($ext in $exts) {
        for ($i = 1; $i -le 3; $i++) {
            $name = "{0}_{1:D2}.{2}" -f $d, $i, $ext
            $path = Join-Path (Join-Path $Root $d) $name
            Set-Content -Path $path -Value $body -Encoding ascii -Force
            $count++
        }
    }
}

Write-Log "Seeded $count files under $Root."

# Publish as an SMB share so \\win-server\Finance is reachable from win11-victim.
$existing = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Log "Share '$ShareName' already exists - leaving in place."
} else {
    Write-Log "Publishing SMB share '$ShareName' -> $Root..."
    New-SmbShare -Name $ShareName -Path $Root -FullAccess "Everyone" | Out-Null
    Write-Log "Share published."
}

Stop-Transcript
exit 0
