# Configure evidence collection on every lab target. No attack is executed.
$ErrorActionPreference = 'Stop'
& 'C:\vagrant\workshops\war-wagon\scenario\enable-file-telemetry.ps1'
if (-not $?) { throw 'Workshop telemetry preparation failed.' }

# Keep a simple member-server share without the unrelated attack scenario assets.
if ($env:COMPUTERNAME -ieq 'win-server') {
    $path = 'C:\Shares\Finance'
    New-Item -ItemType Directory -Force -Path $path | Out-Null
    $sample = Join-Path $path 'training.txt'
    if (-not (Test-Path $sample)) {
        Set-Content $sample 'Synthetic War Wagon lab share. No real data.'
    }
    if (-not (Get-SmbShare -Name 'Finance' -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name 'Finance' -Path $path -ReadAccess 'LAB\Domain Users' -FullAccess 'LAB\Domain Admins' | Out-Null
    }
}
Write-Host '[workshop] File-creation telemetry prepared. No operation started.'
