#!/usr/bin/env bash
# load_cloud_scenarios.sh
# Bulk-ingests pre-built CloudTrail attack scenario logs into Elasticsearch.
# Called at the end of install_cloud_sim.sh provisioning.

set -euo pipefail

ELASTIC_HOST="192.168.56.10"
ES_PORT="9200"
INDEX_NAME="cloudtrail-scenarios"
SCENARIOS_DIR="/vagrant/scripts/scenarios"

log() { echo "[scenarios] $*"; }

# Read elastic credentials
ELASTIC_CREDS=""
if [[ -f /vagrant/elastic-credentials.txt ]]; then
  ELASTIC_CREDS=$(cat /vagrant/elastic-credentials.txt)
fi
ELASTIC_USER=$(echo "${ELASTIC_CREDS}" | cut -d: -f1)
ELASTIC_PASS=$(echo "${ELASTIC_CREDS}" | cut -d: -f2)
AUTH="${ELASTIC_USER}:${ELASTIC_PASS}"

# Wait for Elasticsearch
log "Waiting for Elasticsearch..."
for i in $(seq 1 20); do
  if curl -sf -u "${AUTH}" "http://${ELASTIC_HOST}:${ES_PORT}" &>/dev/null; then
    log "Elasticsearch is reachable."
    break
  fi
  sleep 5
done

# Adjust timestamps in NDJSON to be relative to now
# This makes the pre-built scenarios look like they happened recently
adjust_timestamps() {
  local file="$1"
  local now
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local today
  today=$(date -u +%Y-%m-%d)

  # Replace placeholder dates with today's date, stagger times
  local line_num=0
  while IFS= read -r line; do
    line_num=$((line_num + 1))
    # Add a few seconds per event to create a realistic timeline
    local offset=$((line_num * 15))
    local event_time
    event_time=$(date -u -d "+${offset} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                 date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "${line}" | sed "s/TIMESTAMP_PLACEHOLDER/${event_time}/g"
  done < "${file}"
}

# Ingest a single NDJSON scenario file
ingest_scenario() {
  local file="$1"
  local scenario_name
  scenario_name=$(basename "${file}" .ndjson)
  log "Ingesting scenario: ${scenario_name}..."

  # Adjust timestamps and build bulk request body
  local bulk_body=""
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    bulk_body+='{"index":{"_index":"'"${INDEX_NAME}"'"}}'$'\n'
    bulk_body+="${line}"$'\n'
  done < <(adjust_timestamps "${file}")

  if [[ -z "${bulk_body}" ]]; then
    log "  WARNING: No events in ${file}. Skipping."
    return
  fi

  # Send bulk request
  RESPONSE=$(curl -s -w "\n%{http_code}" \
    -u "${AUTH}" \
    -H "Content-Type: application/x-ndjson" \
    -XPOST "http://${ELASTIC_HOST}:${ES_PORT}/_bulk" \
    --data-binary "${bulk_body}")

  HTTP_CODE=$(echo "${RESPONSE}" | tail -1)
  if [[ "${HTTP_CODE}" == "200" ]]; then
    ERRORS=$(echo "${RESPONSE}" | head -1 | jq -r '.errors // false')
    if [[ "${ERRORS}" == "false" ]]; then
      COUNT=$(echo "${RESPONSE}" | head -1 | jq '.items | length')
      log "  Ingested ${COUNT} events from ${scenario_name}."
    else
      log "  WARNING: Some events failed for ${scenario_name}."
    fi
  else
    log "  ERROR: Bulk ingest returned HTTP ${HTTP_CODE} for ${scenario_name}."
  fi
}

# Create index template for cloudtrail data
log "Creating cloudtrail index template..."
curl -s -u "${AUTH}" -XPUT "http://${ELASTIC_HOST}:${ES_PORT}/_index_template/cloudtrail-template" \
  -H "Content-Type: application/json" -d '{
  "index_patterns": ["cloudtrail-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "eventTime": {"type": "date"},
        "@timestamp": {"type": "date"},
        "eventName": {"type": "keyword"},
        "eventSource": {"type": "keyword"},
        "awsRegion": {"type": "keyword"},
        "sourceIPAddress": {"type": "ip", "ignore_malformed": true},
        "userAgent": {"type": "text"},
        "userIdentity.type": {"type": "keyword"},
        "userIdentity.arn": {"type": "keyword"},
        "userIdentity.userName": {"type": "keyword"},
        "userIdentity.accountId": {"type": "keyword"},
        "requestParameters": {"type": "object", "enabled": true},
        "responseElements": {"type": "object", "enabled": true},
        "errorCode": {"type": "keyword"},
        "errorMessage": {"type": "text"},
        "event.action": {"type": "keyword"},
        "event.dataset": {"type": "keyword"},
        "event.module": {"type": "keyword"},
        "cloud.provider": {"type": "keyword"},
        "cloud.service.name": {"type": "keyword"},
        "cloud.region": {"type": "keyword"},
        "source.ip": {"type": "ip", "ignore_malformed": true},
        "user_agent.original": {"type": "text"}
      }
    }
  }
}' &>/dev/null || true

# Ingest all scenario files
if [[ -d "${SCENARIOS_DIR}" ]]; then
  for ndjson in "${SCENARIOS_DIR}"/*.ndjson; do
    [[ -f "${ndjson}" ]] && ingest_scenario "${ndjson}"
  done
else
  log "WARNING: Scenarios directory ${SCENARIOS_DIR} not found."
fi

# Create Kibana data view for cloudtrail-*
log "Creating Kibana data view for cloudtrail-*..."
KIBANA_URL="http://${ELASTIC_HOST}:5601"
curl -s -u "${AUTH}" -XPOST "${KIBANA_URL}/api/data_views/data_view" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
  "data_view": {
    "title": "cloudtrail-*",
    "name": "CloudTrail Logs",
    "timeFieldName": "@timestamp"
  }
}' &>/dev/null || true

log "Scenario loading complete."
