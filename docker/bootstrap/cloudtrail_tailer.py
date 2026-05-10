#!/usr/bin/env python3
"""
cloudtrail_tailer.py
Streams LocalStack's stdout via the Docker engine API and writes a
CloudTrail-formatted JSON event per real AWS API call to
$CLOUDTRAIL_LOG_DIR. Filebeat picks the events up from that shared
volume and ships them to Elasticsearch.

Replaces the previous 60s synthetic emitter — events in
logs-aws.cloudtrail-* now reflect actual lab activity against
LocalStack, so any Caldera ability that hits an AWS API (rclone S3
exfil, IAM privesc, etc.) shows up in Kibana automatically.

LocalStack request log format (3.x, INFO level):
    2026-05-10T12:34:56.789  INFO --- [asgi_gw_0] localstack.request.aws  : AWS s3.PutObject => 200

Environment (set by docker-compose.yml):
    CLOUDTRAIL_LOG_DIR    e.g. /cloudtrail        (where Filebeat reads from)
    DOCKER_SOCK           e.g. /var/run/docker.sock
    LOCALSTACK_CONTAINER  e.g. localstack
"""
import datetime
import json
import os
import re
import sys
import time
import uuid

import docker  # docker-py — handles the demuxed log stream for us

LOG_DIR        = os.environ.get("CLOUDTRAIL_LOG_DIR", "/cloudtrail")
DOCKER_SOCK    = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
CONTAINER_NAME = os.environ.get("LOCALSTACK_CONTAINER", "localstack")
ACCT           = "000000000000"
REGION         = "us-east-1"

# Match the AWS request line LocalStack emits at INFO. Service can include
# hyphens (e.g. cognito-idp); operation is CamelCase.
REQ_RE = re.compile(
    r"AWS\s+(?P<service>[\w-]+)\.(?P<operation>\w+)\s+=>\s+(?P<status>\d+)"
)

os.makedirs(LOG_DIR, exist_ok=True)


def emit_event(service: str, operation: str, status: int) -> None:
    eid  = str(uuid.uuid4())
    now  = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = os.path.join(LOG_DIR, f"{operation}-{eid}.json")
    body = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type":        "IAMUser",
            "principalId": f"AIDAI{eid[:16].upper()}",
            "arn":         f"arn:aws:iam::{ACCT}:user/lab-actor",
            "accountId":   ACCT,
            "userName":    "lab-actor",
        },
        "eventTime":          now,
        "eventSource":        f"{service.lower()}.amazonaws.com",
        "eventName":          operation,
        "awsRegion":          REGION,
        "sourceIPAddress":    "127.0.0.1",
        "userAgent":          "localstack-request-log",
        "requestParameters":  {},
        "responseElements":   None,
        "eventID":            eid,
        "readOnly":           operation.startswith(("Get", "List", "Describe", "Head")),
        "eventType":          "AwsApiCall",
        "managementEvent":    True,
        "recipientAccountId": ACCT,
    }
    if status >= 400:
        body["errorCode"] = f"HTTP_{status}"
    with open(path, "w") as f:
        json.dump(body, f, indent=2)


def stream_logs():
    """Yield decoded lines from the LocalStack container, with reconnect."""
    client = docker.DockerClient(base_url=f"unix://{DOCKER_SOCK}")
    while True:
        try:
            container = client.containers.get(CONTAINER_NAME)
        except docker.errors.NotFound:
            print(f"[tailer] container '{CONTAINER_NAME}' not found yet; retry in 5s", flush=True)
            time.sleep(5)
            continue

        since = int(time.time())
        print(f"[tailer] attached to {CONTAINER_NAME} (since={since})", flush=True)
        try:
            for chunk in container.logs(stream=True, follow=True, since=since):
                # docker-py yields bytes; may contain multiple lines per chunk
                for line in chunk.decode("utf-8", errors="replace").splitlines():
                    yield line
        except (docker.errors.APIError, ConnectionError, OSError) as e:
            print(f"[tailer] log stream lost: {e}; reconnecting in 5s", flush=True)
            time.sleep(5)


def main() -> int:
    print(f"[tailer] watching '{CONTAINER_NAME}', writing CloudTrail JSON to {LOG_DIR}", flush=True)
    n = 0
    for line in stream_logs():
        m = REQ_RE.search(line)
        if not m:
            continue
        emit_event(m.group("service"), m.group("operation"), int(m.group("status")))
        n += 1
        if n % 25 == 0:
            print(f"[tailer] {n} CloudTrail events emitted", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
