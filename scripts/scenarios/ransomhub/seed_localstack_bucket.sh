#!/usr/bin/env bash
# seed_localstack_bucket.sh
# Hunt Lab: create the S3 bucket the RansomHub recreation exfils to.
# Run from the docker host (or any box that can reach LocalStack on
# 192.168.56.10:4566).
#
# Idempotent: 'mb' on an existing bucket is a no-op for our purposes,
# we suppress the BucketAlreadyOwnedByYou error.

set -euo pipefail

ENDPOINT="${LOCALSTACK_ENDPOINT:-http://192.168.56.10:4566}"
BUCKET="${EXFIL_BUCKET:-ransomhub-exfil-lab}"

export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

log() { echo "[seed-bucket] $*"; }

if ! command -v aws >/dev/null 2>&1; then
    log "ERROR: aws CLI not found on PATH. Install awscli or run from the bootstrap container."
    exit 1
fi

log "Endpoint: $ENDPOINT"
log "Bucket:   $BUCKET"

aws --endpoint-url "$ENDPOINT" s3api create-bucket \
    --bucket "$BUCKET" \
    --region us-east-1 2>/dev/null \
    || log "(bucket already exists - continuing)"

aws --endpoint-url "$ENDPOINT" s3api put-bucket-tagging \
    --bucket "$BUCKET" \
    --tagging 'TagSet=[{Key=hunt-lab,Value=ransomhub-recreation}]' >/dev/null

log "Bucket ready. Listing..."
aws --endpoint-url "$ENDPOINT" s3 ls "s3://${BUCKET}" || true
log "Done."
