#!/usr/bin/env bash
# generate_cloudtrail_activity.sh
# One-shot LocalStack seeder.
#
# Creates a small set of baseline AWS resources (S3 buckets with sample
# objects + a couple of IAM users) so the lab has something to hunt
# against on day one. Each `aws` call here is a real LocalStack API
# request, so cloudtrail_tailer.py picks them up and turns them into
# real CloudTrail events in logs-aws.cloudtrail-*.
#
# This script used to also emit synthetic CloudTrail JSON on a 60s
# loop. That's gone — events now come from real LocalStack traffic
# (this seed step + anything Caldera abilities trigger at runtime).
#
# Idempotent: re-running is a no-op for resources that already exist.
#
# Environment (set by docker-compose.yml):
#   LOCALSTACK_ENDPOINT  e.g. http://localstack:4566

set -euo pipefail

ENDPOINT="${LOCALSTACK_ENDPOINT:-http://localstack:4566}"
REGION="us-east-1"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION="${REGION}"

log() { echo "[seed] $*"; }

# Wait for LocalStack to be reachable (depends_on healthy should cover this,
# but be defensive — first-run cold starts can race the entrypoint).
for i in $(seq 1 30); do
  if curl -sf "${ENDPOINT}/_localstack/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

log "Endpoint: ${ENDPOINT}"

aws s3 mb s3://company-financials --endpoint-url "${ENDPOINT}" 2>/dev/null || true
aws s3 mb s3://hr-data             --endpoint-url "${ENDPOINT}" 2>/dev/null || true
aws s3 mb s3://cloudtrail-logs     --endpoint-url "${ENDPOINT}" 2>/dev/null || true

echo '{"name":"John Doe","salary":150000}' \
  | aws s3 cp - s3://hr-data/employees/john_doe.json \
      --endpoint-url "${ENDPOINT}" 2>/dev/null || true

echo '{"q4_revenue":42000000}' \
  | aws s3 cp - s3://company-financials/2025-q4-report.json \
      --endpoint-url "${ENDPOINT}" 2>/dev/null || true

aws iam create-user --user-name analyst-readonly \
  --endpoint-url "${ENDPOINT}" 2>/dev/null || true
aws iam create-user --user-name dev-ops \
  --endpoint-url "${ENDPOINT}" 2>/dev/null || true

log "Baseline seed complete."
