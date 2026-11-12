#!/usr/bin/env bash
# Add the RansomHub cloud sandbox without restarting the existing lab services.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
docker compose up -d --wait --wait-timeout 180 localstack cloudtrail-gen filebeat
aws_lab() { docker compose exec -T localstack awslocal "$@"; }
if ! aws_lab s3api head-bucket --bucket ransomhub-exfil-lab >/dev/null 2>&1; then
  aws_lab s3api create-bucket --bucket ransomhub-exfil-lab >/dev/null
fi
if ! aws_lab iam get-user --user-name analyst-readonly >/dev/null 2>&1; then
  aws_lab iam create-user --user-name analyst-readonly >/dev/null
fi
aws_lab s3api head-bucket --bucket ransomhub-exfil-lab
aws_lab iam get-user --user-name analyst-readonly >/dev/null
printf '%s\n' '[localstack] Verified RansomHub bucket and analyst-readonly IAM user.'
printf '%s\n' '[localstack] API operation logs are converted to simulated CloudTrail-shaped events for Kibana.'
