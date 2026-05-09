' nocmd.vbs
' Hunt Lab recreation of the artifact observed in The DFIR Report
' "Hide Your RDP: Password Spray Leads to RansomHub Deployment" (2025-06).
' The original was used by the actor to launch rclone with no console window.
' Lab fidelity only — runs against LocalStack S3, not a real exfil endpoint.

Set objShell = CreateObject("WScript.Shell")
' Run rcl.bat hidden (0 = no window) and do NOT wait for it to return.
objShell.Run "cmd.exe /c C:\Users\Public\rcl.bat", 0, False
