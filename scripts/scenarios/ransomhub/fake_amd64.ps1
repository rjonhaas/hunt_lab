# fake_amd64.ps1
# Hunt Lab recreation of the RansomHub encryptor stage.
# In the DFIR Report the binary 'amd64.exe' was the Linux/ESXi-targeted
# RansomHub payload. We do NOT detonate real ransomware. Instead this script:
#   1. Walks C:\Shares\Finance (the seeded decoy)
#   2. Renames each file to <name>.<ext>.locked  (no encryption, just rename)
#   3. Drops a ransom note in every directory it touches
#   4. Writes a marker file C:\Users\Public\amd64-ran.flag
#
# The combination of mass file rename + note drop is what most behavioral
# detection rules key on (Sigma "Mass File Rename", Elastic prebuilt rules,
# Windows ransomware canaries), so the telemetry it generates is what
# matters - not the cryptography.

param(
    [string]$Target  = "C:\Shares\Finance",
    [string]$NoteSrc = "C:\Users\Public\ransom_note.txt",
    [string]$Marker  = "C:\Users\Public\amd64-ran.flag"
)

$ErrorActionPreference = "Continue"

if (-not (Test-Path $Target)) {
    Write-Host "[fake-amd64] target $Target not found - nothing to encrypt"
    "no-target" | Out-File -FilePath $Marker -Encoding ascii -Force
    exit 0
}

if (-not (Test-Path $NoteSrc)) {
    Write-Host "[fake-amd64] WARN: ransom note source $NoteSrc missing; using inline copy"
    @"
!!! HUNT LAB SIMULATED RANSOMWARE NOTE !!!
This is a lab artifact, not real ransomware.
"@ | Out-File -FilePath $NoteSrc -Encoding ascii -Force
}

$noteText = Get-Content $NoteSrc -Raw

$renamed = 0
$dirsTouched = New-Object 'System.Collections.Generic.HashSet[string]'

Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $f = $_
    if ($f.Extension -eq ".locked") { return }
    try {
        Rename-Item -LiteralPath $f.FullName -NewName ($f.Name + ".locked") -ErrorAction Stop
        $renamed++
        [void]$dirsTouched.Add($f.DirectoryName)
    } catch {
        Write-Host "[fake-amd64] could not rename $($f.FullName): $_"
    }
}

foreach ($d in $dirsTouched) {
    $notePath = Join-Path $d "README_RANSOMHUB.txt"
    Set-Content -Path $notePath -Value $noteText -Encoding ascii -Force
}

"$(Get-Date -Format o)`nrenamed=$renamed`ndirs=$($dirsTouched.Count)" |
    Out-File -FilePath $Marker -Encoding ascii -Force

Write-Host "[fake-amd64] simulated encryption: renamed=$renamed files across $($dirsTouched.Count) dirs"
exit 0
