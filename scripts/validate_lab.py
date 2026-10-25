#!/usr/bin/env python3
"""Read-only workshop readiness check, run inside docker-host (Python 3 stdlib).

From the repository on either supported host OS:
    vagrant ssh docker-host -c 'python3 /vagrant/scripts/validate_lab.py'

Checks current service/agent/telemetry readiness, not detection effectiveness.
No attack operations are created. Credentials and response bodies stay private.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

EXPECTED_HOSTS = {"win-dc", "win-server", "win11-victim"}


def hostname(value):
    return str(value or "").lower().split(".")[0]


def recent(value, now, minutes=5):
    try:
        # Caldera emits UTC timestamps, sometimes without an explicit offset.
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return now - timedelta(minutes=minutes) <= stamp <= now + timedelta(minutes=1)
    except (ValueError, TypeError):
        return False


def live_caldera_hosts(agents, now):
    return {hostname(a.get("host")) for a in agents
            if a.get("trusted") is True and recent(a.get("last_seen"), now)}


def online_fleet_hosts(agents):
    return {hostname(a.get("local_metadata", {}).get("host", {}).get("hostname"))
            for a in agents if a.get("status") == "online"}


def missing_hosts(found):
    return sorted(EXPECTED_HOSTS - set(found))


def request_json(url, headers, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = Request(url, data=data, headers={**headers, "Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=20) as response:
            return json.load(response)
    except HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}") from None
    except (URLError, TimeoutError, OSError, ValueError):
        raise RuntimeError("unreachable service, timeout, or invalid JSON") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.56.10")
    parser.add_argument("--minutes", type=int, default=30)
    parser.add_argument("--credentials", type=Path,
                        default=Path(__file__).resolve().parents[1] / "elastic-credentials.txt")
    args = parser.parse_args(argv)
    if args.minutes < 1:
        parser.error("--minutes must be positive")
    try:
        raw = args.credentials.read_text(encoding="utf-8-sig").strip()
        if not raw:
            raise ValueError("empty credentials")
    except (OSError, ValueError):
        print("[FAIL] Missing or empty elastic-credentials.txt. Finish docker-host provisioning first.")
        return 1
    userpass = raw if ":" in raw else "elastic:" + raw
    auth = {"Authorization": "Basic " + base64.b64encode(userpass.encode()).decode()}
    kb_auth = {**auth, "kbn-xsrf": "true"}
    # This is the repository's lab API key, not a production credential.
    cd_auth = {"KEY": "ADMIN123"}
    es = f"http://{args.host}:9200"
    kb = f"http://{args.host}:5601"
    cd = f"http://{args.host}:8888"
    failures = 0

    def check(label, action):
        nonlocal failures
        try:
            ok, detail = action()
        except (RuntimeError, KeyError, TypeError, AttributeError):
            ok, detail = False, "service unavailable or unexpected response; check VM/container logs"
        print(f"[{' OK ' if ok else 'FAIL'}] {label}: {detail}")
        failures += not ok

    def cluster():
        result = request_json(es + "/_cluster/health", auth)
        status = result.get("status", "unknown")
        return status in ("green", "yellow"), f"cluster {status}"

    def kibana():
        status = request_json(kb + "/api/status", kb_auth)["status"]["overall"]["level"]
        return status == "available", str(status)

    def fleet():
        # Paginate so old enrollments cannot hide current hosts.
        agents, page = [], 1
        while True:
            result = request_json(kb + f"/api/fleet/agents?perPage=100&page={page}", kb_auth)
            items = result["items"]
            agents.extend(items)
            if not items or len(agents) >= result["total"]:
                break
            page += 1
        missing = missing_hosts(online_fleet_hosts(agents))
        return not missing, "missing online hosts: " + ", ".join(missing) if missing else "all three Windows hosts online"

    def caldera():
        agents = request_json(cd + "/api/v2/agents", cd_auth)
        missing = missing_hosts(live_caldera_hosts(agents, datetime.now(timezone.utc)))
        return not missing, "missing recent trusted hosts: " + ", ".join(missing) if missing else "all three hosts trusted and seen within five minutes"

    def telemetry():
        result = request_json(es + "/logs-*/_search", auth, {
            "size": 0,
            "query": {"bool": {"filter": [
                {"term": {"event.dataset": "windows.sysmon_operational"}},
                {"range": {"@timestamp": {"gte": f"now-{args.minutes}m", "lte": "now"}}}
            ]}},
            "aggs": {"hosts": {"terms": {"field": "host.name", "size": 100}}}
        })
        found = {hostname(b["key"]) for b in result["aggregations"]["hosts"]["buckets"] if b["doc_count"] > 0}
        missing = missing_hosts(found)
        return not missing, "missing Sysmon hosts: " + ", ".join(missing) if missing else f"all three hosts have Sysmon events in last {args.minutes} minutes"

    check("Elasticsearch", cluster)
    check("Kibana", kibana)
    check("Fleet enrollment", fleet)
    check("Caldera agents", caldera)
    check("Sysmon telemetry", telemetry)
    if failures:
        print("Readiness incomplete. Allow enrollment/ingestion to settle, then rerun. Do not rebuild healthy VMs just to retry this check.")
        return 1
    print("Core workshop services, agents and telemetry are ready. Rehearse the selected operation separately.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
