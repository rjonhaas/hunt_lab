# install_velociraptor_client.ps1
# Installs the Velociraptor client - repacked with the embedded server config by
# the velociraptor container on docker-host - as a Windows service, so this
# endpoint auto-enrolls to the Velociraptor server at https://192.168.56.10:8000/.
# Run from C:\vagrant\scripts\ on win-dc, win-server, and win11-victim.

$RepackedExe = "C:\vagrant\docker\velociraptor\clients\windows\velociraptor_client_repacked.exe"
$InstallDir  = "C:\Program Files\Velociraptor"
$LocalExe    = Join-Path $InstallDir "Velociraptor.exe"
$ServiceName = "Velociraptor"

Start-Transcript -Path "C:\Windows\Temp\install-velociraptor-client.log" -Force

# The velociraptor container repacks the Windows client at startup. If docker-host
# is still bringing the stack up, the file may not exist yet - wait for it.
Write-Host "[velociraptor] Waiting for repacked client at $RepackedExe ..."
$deadline = (Get-Date).AddMinutes(10)
while (-not (Test-Path $RepackedExe)) {
    if ((Get-Date) -gt $deadline) {
        Write-Host "[velociraptor] ERROR: repacked client not found after 10 min."
        Write-Host "[velociraptor] Is docker-host up and the 'velociraptor' container running?"
        Stop-Transcript; exit 1
    }
    Start-Sleep -Seconds 10
}
Write-Host "[velociraptor] Found repacked client."

# Idempotent: remove any prior install before reinstalling.
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[velociraptor] Existing service found - removing before reinstall..."
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (Test-Path $LocalExe) {
        & $LocalExe service remove 2>$null
    } else {
        & sc.exe delete $ServiceName | Out-Null
    }
    Start-Sleep -Seconds 2
}

# Copy the binary to a local path. Never run a service off C:\vagrant - the
# synced folder isn't mounted at boot, which would break the service.
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path $RepackedExe -Destination $LocalExe -Force

Write-Host "[velociraptor] Installing Velociraptor client service..."
& $LocalExe service install
if ($LASTEXITCODE -ne 0) {
    Write-Host "[velociraptor] ERROR: 'service install' failed (exit $LASTEXITCODE)"
    Stop-Transcript; exit 1
}

# service install usually starts it; make sure it's running.
Start-Sleep -Seconds 3
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Running') {
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

Write-Host "[velociraptor] Done. Client installed and enrolling to https://192.168.56.10:8000/"
Write-Host "[velociraptor] It should appear under 'Clients' in the Velociraptor GUI shortly."
Stop-Transcript
exit 0
