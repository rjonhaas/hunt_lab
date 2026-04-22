# Kibana — Hunt Lab Saved Objects

## What this directory contains

| File | Description |
|------|-------------|
| `hunt_report_template.ndjson` | Kibana saved-objects export (10 objects) — ready to import |
| `generate_template.py` | Standalone generator (regenerate the NDJSON from scratch) |
| `create_all_objects.py` | Creates objects in Kibana via API, then re-exports (used during initial build) |

---

## What gets installed

Importing `hunt_report_template.ndjson` creates 10 saved objects:

| Type | ID | Description |
|------|----|-------------|
| `index-pattern` | `hunt-lab-logs-data-view` | **Hunt Lab Logs** data view (`logs-*`, `@timestamp`) |
| `lens` | `hl-metric-total-events` | Metric: total event count |
| `lens` | `hl-metric-hosts` | Metric: unique hosts |
| `lens` | `hl-metric-users` | Metric: unique users |
| `lens` | `hl-metric-event-cats` | Metric: unique event categories |
| `lens` | `hl-table-processes` | Table: process execution (`event.category: process`) |
| `lens` | `hl-table-auth` | Table: authentication activity (`event.category: authentication`) |
| `lens` | `hl-chart-timeline` | Area chart: events over time |
| `lens` | `hl-table-network` | Table: network destinations (`event.category: network`) |
| `dashboard` | `hl-threat-hunt-report-template` | **HL - Threat Hunt Report Template** |

---

## Dashboard layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  # Threat Hunt Report Template  (header)                            │
├─────────────────────────────────────────────────────────────────────┤
│  Hunt Summary  (markdown: Scenario / Analyst / Hypothesis / Scope)  │
├─────────────────────────────────────────────────────────────────────┤
│  Key Metrics                                                         │
│  [ Total Events ] [ Unique Hosts ] [ Unique Users ] [ Event Cats ]  │
├─────────────────────────────────────────────────────────────────────┤
│  Evidence Panels                                                     │
│  [ Process Execution Review  |  Authentication Activity           ] │
│  [ Activity Over Time (area chart, full width)                    ] │
│  [ Network Destinations (full width)                              ] │
├─────────────────────────────────────────────────────────────────────┤
│  Findings       (markdown: Observations / Suspicious Indicators)    │
├─────────────────────────────────────────────────────────────────────┤
│  Assessment     (markdown: Verdict / Why / Recommended Actions)     │
├─────────────────────────────────────────────────────────────────────┤
│  Detection Opportunities  (markdown: table + Sigma sketch)          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Assumed data view and fields

| Item | Value |
|------|-------|
| Data view name | `Hunt Lab Logs` |
| Index pattern | `logs-*` |
| Time field | `@timestamp` |

### ECS fields used

All evidence panels use standard Elastic Common Schema (ECS) fields:

| Panel | Fields |
|-------|--------|
| Process Execution | `host.name`, `user.name`, `process.name` |
| Authentication | `user.name`, `host.name`, `event.outcome` |
| Activity Over Time | `@timestamp` (date histogram) |
| Network Destinations | `host.name`, `destination.ip`, `destination.domain` |
| Metric panels | `host.name`, `user.name`, `event.category` |

If a panel shows "No results" it means no data matched its filter for the selected time range (e.g. no `event.category: process` events yet). This is expected in a new lab before attack simulation has run.

---

## How `setup.ps1` imports the template

`setup.ps1` automatically imports the template immediately after `elastic-siem` is provisioned:

1. Parses credentials from `elastic-credentials.txt`
2. Polls `http://192.168.56.10:5601/api/status` until Kibana is available (3-minute timeout)
3. Posts `kibana/hunt_report_template.ndjson` to `/api/saved_objects/_import?overwrite=true`
4. Logs success or failure

If the import step is skipped (Kibana timeout or network issue), run it manually:

```powershell
# From the hunt_lab directory:
$creds = Get-Content elastic-credentials.txt -Raw | % { $_.Trim() }
curl.exe -s -u $creds `
  -X POST "http://192.168.56.10:5601/api/saved_objects/_import?overwrite=true" `
  -H "kbn-xsrf: true" `
  -F "file=@kibana\hunt_report_template.ndjson"
```

---

## How to start a new hunt

1. Open Kibana: `http://192.168.56.10:5601`
2. Navigate to **Dashboards** → **HL - Threat Hunt Report Template**
3. Click the **⋮** menu → **Duplicate**
4. Rename the copy to your hunt ID (e.g. `HL-2026-001 — Lateral Movement via PsExec`)
5. Set the time picker to your hunt window
6. Edit the **Hunt Summary** markdown panel — click the pencil icon → **Edit panel** → update the placeholders
7. Fill in **Findings**, **Assessment**, and **Detection Opportunities** as the hunt progresses

> The original template is never modified — always duplicate before filling it in.

---

## Portability notes

- All visualizations use **`logs-*`** (Filebeat, Elastic Agent) — the most common index pattern in Elastic SIEM deployments.
- The `Hunt Lab Logs` data view is included in the NDJSON so it is created automatically on import; no manual data view setup required.
- Evidence panels filter by ECS `event.category` values (`process`, `authentication`, `network`). These are standard categories emitted by Elastic Agent integrations and Sysmon via Winlogbeat. If your data uses different index patterns, update the Lens panel filters after import.
- The template was built and validated against **Kibana 8.19.14**. It should be compatible with Kibana 8.9.0 and later (the `typeMigrationVersion` embedded in the NDJSON reflects `lens 8.9.0`).

---

## Regenerating the template

If you need to rebuild from scratch after changes:

```bash
# From the hunt_lab directory (requires Python 3, network access to Kibana VM)
python kibana/create_all_objects.py
```

This will recreate all Lens objects and the dashboard in the running Kibana instance, then re-export a clean `hunt_report_template.ndjson`.
