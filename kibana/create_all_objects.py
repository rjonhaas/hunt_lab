#!/usr/bin/env python3
"""
Creates all Hunt Lab saved objects in Kibana via API, then exports them.
"""
import json, sys
import urllib.request
import urllib.error
import base64

KIBANA_URL = "http://192.168.56.10:5601"
USER = "elastic"
PASS = "9XxgDwUqYK=G89627age"
DATA_VIEW_ID = "hunt-lab-logs-data-view"


def kibana_request(method, path, body=None):
    url = KIBANA_URL + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    creds = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    req.add_header("kbn-xsrf", "true")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  HTTP {e.code} {method} {path}: {body[:300]}", file=sys.stderr)
        return None


def create_saved_object(obj_type, obj_id, attributes, references):
    result = kibana_request(
        "POST",
        f"/api/saved_objects/{obj_type}/{obj_id}?overwrite=true",
        {"attributes": attributes, "references": references},
    )
    if result:
        print(f"  OK  {obj_type}/{obj_id}")
    else:
        print(f"  ERR {obj_type}/{obj_id}")
    return result


# ── Markdown content ──────────────────────────────────────────────────────────

HUNT_SUMMARY_MD = """## Hunt Summary

| Field | Value |
|-------|-------|
| **Scenario** | _(enter scenario name / ATT&CK technique)_ |
| **Analyst** | _(analyst name)_ |
| **Date Range** | _(start date) → (end date)_ |
| **Hypothesis** | _(what adversary behaviour are you looking for?)_ |
| **Scope** | _(affected hosts / users / systems)_ |
| **Hunt ID** | HL-YYYY-NNN |

> **Instructions:** Duplicate this dashboard before filling it in.
> Use the time picker above to constrain all panels to the hunt window.
"""

SECTION3_HDR = """## Evidence Panels

*Filter panels by adjusting the KQL bar or time picker above.
All panels use common ECS fields — add index-specific filters as needed.*"""

FINDINGS_MD = """## Findings

### Observations
_(What did you observe during the hunt? List significant events, patterns, or anomalies.)_

- Observation 1:
- Observation 2:
- Observation 3:

### Suspicious Indicators
| Indicator | Type | Context |
|-----------|------|---------|
| _(e.g. 192.168.1.99)_ | IP | Outbound to rare destination |
| _(e.g. lsass.exe dump)_ | Process | Credential access pattern |
| | | |
"""

ASSESSMENT_MD = """## Assessment

### Verdict
- [ ] True Positive — confirmed malicious activity
- [ ] True Positive — suspicious, requires escalation
- [ ] Benign Positive — expected behaviour
- [ ] False Positive — rule / data quality issue
- [ ] Inconclusive — insufficient data

### Why
_(Explain the reasoning behind the verdict.
Reference specific evidence panels, IOCs, or ATT&CK techniques.)_

### Recommended Actions
1. _(e.g. Isolate host XYZ)_
2. _(e.g. Reset credentials for user ABC)_
3. _(e.g. Create detection rule for T1059.001)_
"""

DETECTION_MD = """## Detection Opportunities

*Use this section to capture follow-on detection engineering ideas discovered during the hunt.*

| Opportunity | ATT&CK Technique | Priority | Notes |
|------------|-----------------|----------|-------|
| _(e.g. Alert on encoded PowerShell args)_ | T1059.001 | High | _(implementation notes)_ |
| _(e.g. Detect rare parent-child process)_ | T1055 | Medium | |
| | | | |

### Sigma / EQL Sketch
```
# Paste a Sigma rule or EQL query sketch here
```
"""


# ── Helper builders ───────────────────────────────────────────────────────────

def lens_metric_attrs(title, operation, source_field, color):
    return {
        "title": title,
        "description": "",
        "visualizationType": "lnsMetric",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer-1": {
                            "columns": {
                                "col-metric": {
                                    "label": title,
                                    "dataType": "number",
                                    "operationType": operation,
                                    "isBucketed": False,
                                    "scale": "ratio",
                                    "sourceField": source_field,
                                    "params": {"emptyAsNull": False},
                                }
                            },
                            "columnOrder": ["col-metric"],
                            "incompleteColumns": {},
                            "sampling": 1,
                        }
                    }
                }
            },
            "visualization": {
                "layerId": "layer-1",
                "layerType": "data",
                "metricAccessor": "col-metric",
                "color": color,
            },
            "query": {"language": "kuery", "query": ""},
            "filters": [],
            "internalReferences": [],
            "adHocDataViews": {},
        },
    }


def lens_metric_refs():
    return [
        {
            "type": "index-pattern",
            "id": DATA_VIEW_ID,
            "name": "indexpattern-datasource-layer-layer-1",
        }
    ]


def lens_datatable_attrs(title, bucket_cols, kql_filter=""):
    """bucket_cols: list of (col_id, label, source_field)"""
    count_col = "col-count"
    columns = {}
    col_order = []

    for col_id, label, source_field in bucket_cols:
        columns[col_id] = {
            "label": label,
            "dataType": "string",
            "operationType": "terms",
            "isBucketed": True,
            "scale": "ordinal",
            "sourceField": source_field,
            "params": {
                "size": 20,
                "orderBy": {"type": "column", "columnId": count_col},
                "orderDirection": "desc",
                "otherBucket": False,
                "missingBucket": False,
                "parentFormat": {"id": "terms"},
            },
        }
        col_order.append(col_id)

    columns[count_col] = {
        "label": "Count",
        "dataType": "number",
        "operationType": "count",
        "isBucketed": False,
        "scale": "ratio",
        "sourceField": "___records___",
        "params": {"emptyAsNull": False},
    }
    col_order.append(count_col)

    return {
        "title": title,
        "description": "",
        "visualizationType": "lnsDatatable",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer-1": {
                            "columns": columns,
                            "columnOrder": col_order,
                            "incompleteColumns": {},
                            "sampling": 1,
                        }
                    }
                }
            },
            "visualization": {
                "layerId": "layer-1",
                "layerType": "data",
                "columns": [{"columnId": cid, "hidden": False} for cid in col_order],
                "sorting": {"columnId": count_col, "direction": "desc"},
            },
            "query": {"language": "kuery", "query": kql_filter},
            "filters": [],
            "internalReferences": [],
            "adHocDataViews": {},
        },
    }


def lens_area_chart_attrs(title):
    return {
        "title": title,
        "description": "",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer-1": {
                            "columns": {
                                "col-time": {
                                    "label": "@timestamp",
                                    "dataType": "date",
                                    "operationType": "date_histogram",
                                    "sourceField": "@timestamp",
                                    "isBucketed": True,
                                    "scale": "interval",
                                    "params": {
                                        "interval": "auto",
                                        "includeEmptyRows": True,
                                        "dropPartials": False,
                                    },
                                },
                                "col-count": {
                                    "label": "Events",
                                    "dataType": "number",
                                    "operationType": "count",
                                    "isBucketed": False,
                                    "scale": "ratio",
                                    "sourceField": "___records___",
                                    "params": {"emptyAsNull": False},
                                },
                            },
                            "columnOrder": ["col-time", "col-count"],
                            "incompleteColumns": {},
                            "sampling": 1,
                        }
                    }
                }
            },
            "visualization": {
                "legend": {"isVisible": True, "position": "right"},
                "valueLabels": "hide",
                "fittingFunction": "None",
                "axisTitlesVisibilitySettings": {
                    "x": True,
                    "yLeft": True,
                    "yRight": True,
                },
                "tickLabelsVisibilitySettings": {
                    "x": True,
                    "yLeft": True,
                    "yRight": True,
                },
                "gridlinesVisibilitySettings": {
                    "x": True,
                    "yLeft": True,
                    "yRight": True,
                },
                "preferredSeriesType": "area",
                "layers": [
                    {
                        "layerId": "layer-1",
                        "accessors": ["col-count"],
                        "layerType": "data",
                        "seriesType": "area",
                        "xAccessor": "col-time",
                    }
                ],
            },
            "query": {"language": "kuery", "query": ""},
            "filters": [],
            "internalReferences": [],
            "adHocDataViews": {},
        },
    }


# ── Panel helpers ─────────────────────────────────────────────────────────────

def mk_markdown_panel(pid, x, y, w, h, markdown, title=""):
    return {
        "type": "visualization",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
        "panelIndex": pid,
        "title": title,
        "embeddableConfig": {
            "savedVis": {
                "title": title,
                "description": "",
                "type": "markdown",
                "params": {
                    "fontSize": 12,
                    "markdown": markdown,
                    "openLinksInNewTab": False,
                },
                "uiState": {},
                "data": {
                    "aggs": [],
                    "searchSource": {
                        "query": {"language": "kuery", "query": ""},
                        "filter": [],
                    },
                },
            },
            "enhancements": {},
        },
    }


def mk_lens_panel(pid, x, y, w, h, ref_name, title=""):
    return {
        "type": "lens",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
        "panelIndex": pid,
        "title": title,
        "panelRefName": ref_name,
        "embeddableConfig": {"enhancements": {}},
    }


# ── Main ──────────────────────────────────────────────────────────────────────

print("=== Phase 1: Creating Lens visualizations ===")

# Metrics
create_saved_object("lens", "hl-metric-total-events",
    lens_metric_attrs("Total Events", "count", "___records___", "#1BA9F5"),
    lens_metric_refs())

create_saved_object("lens", "hl-metric-hosts",
    lens_metric_attrs("Unique Hosts", "unique_count", "host.name", "#00BFB3"),
    lens_metric_refs())

create_saved_object("lens", "hl-metric-users",
    lens_metric_attrs("Unique Users", "unique_count", "user.name", "#F04E98"),
    lens_metric_refs())

create_saved_object("lens", "hl-metric-event-cats",
    lens_metric_attrs("Event Categories", "unique_count", "event.category", "#FEC514"),
    lens_metric_refs())

# Evidence tables
create_saved_object("lens", "hl-table-processes",
    lens_datatable_attrs("HL - Process Execution Review",
        [("col-host","Host","host.name"),
         ("col-user","User","user.name"),
         ("col-process","Process","process.name")],
        kql_filter="event.category: process"),
    lens_metric_refs())

create_saved_object("lens", "hl-table-auth",
    lens_datatable_attrs("HL - Authentication Activity",
        [("col-user","User","user.name"),
         ("col-host","Host","host.name"),
         ("col-outcome","Outcome","event.outcome")],
        kql_filter="event.category: authentication"),
    lens_metric_refs())

create_saved_object("lens", "hl-chart-timeline",
    lens_area_chart_attrs("HL - Activity Over Time"),
    lens_metric_refs())

create_saved_object("lens", "hl-table-network",
    lens_datatable_attrs("HL - Network Destinations",
        [("col-src","Source Host","host.name"),
         ("col-dst-ip","Dest IP","destination.ip"),
         ("col-dst-domain","Dest Domain","destination.domain")],
        kql_filter="event.category: network"),
    lens_metric_refs())

print()
print("=== Phase 2: Building dashboard ===")

panels = []
refs = []

# Section 1 — header + summary
panels.append(mk_markdown_panel("md-s1-hdr", 0, 0, 48, 3,
    "# Threat Hunt Report Template\n*Hunt Lab — Interactive Threat Hunt Report*\n\n---"))
panels.append(mk_markdown_panel("md-s1-body", 0, 3, 48, 14, HUNT_SUMMARY_MD, "Hunt Summary"))

# Section 2 — Key Metrics
panels.append(mk_markdown_panel("md-s2-hdr", 0, 17, 48, 3,
    "## Key Metrics\n\n*Counts reflect data within the selected time range.*"))

panels.append(mk_lens_panel("p-metric-1", 0, 20, 12, 9, "panel_0", "Total Events"))
refs.append({"type": "lens", "id": "hl-metric-total-events", "name": "panel_0"})
panels.append(mk_lens_panel("p-metric-2", 12, 20, 12, 9, "panel_1", "Unique Hosts"))
refs.append({"type": "lens", "id": "hl-metric-hosts", "name": "panel_1"})
panels.append(mk_lens_panel("p-metric-3", 24, 20, 12, 9, "panel_2", "Unique Users"))
refs.append({"type": "lens", "id": "hl-metric-users", "name": "panel_2"})
panels.append(mk_lens_panel("p-metric-4", 36, 20, 12, 9, "panel_3", "Event Categories"))
refs.append({"type": "lens", "id": "hl-metric-event-cats", "name": "panel_3"})

# Section 3 — Evidence Panels
panels.append(mk_markdown_panel("md-s3-hdr", 0, 29, 48, 4, SECTION3_HDR))

panels.append(mk_lens_panel("p-procs", 0, 33, 24, 17, "panel_4", "Process Execution Review"))
refs.append({"type": "lens", "id": "hl-table-processes", "name": "panel_4"})
panels.append(mk_lens_panel("p-auth", 24, 33, 24, 17, "panel_5", "Authentication Activity"))
refs.append({"type": "lens", "id": "hl-table-auth", "name": "panel_5"})
panels.append(mk_lens_panel("p-timeline", 0, 50, 48, 13, "panel_6", "Activity Over Time"))
refs.append({"type": "lens", "id": "hl-chart-timeline", "name": "panel_6"})
panels.append(mk_lens_panel("p-network", 0, 63, 48, 17, "panel_7", "Network Destinations"))
refs.append({"type": "lens", "id": "hl-table-network", "name": "panel_7"})

# Sections 4-6 — Narrative sections
panels.append(mk_markdown_panel("md-s4", 0, 80, 48, 16, FINDINGS_MD, "Findings"))
panels.append(mk_markdown_panel("md-s5", 0, 96, 48, 16, ASSESSMENT_MD, "Assessment"))
panels.append(mk_markdown_panel("md-s6", 0, 112, 48, 14, DETECTION_MD, "Detection Opportunities"))

dash_attrs = {
    "title": "HL - Threat Hunt Report Template",
    "description": "Hunt Lab — Interactive Threat Hunt Report Template. Duplicate before use.",
    "panelsJSON": json.dumps(panels, separators=(",", ":")),
    "optionsJSON": json.dumps({
        "useMargins": True,
        "syncColors": False,
        "syncCursor": True,
        "syncTooltips": False,
        "hidePanelTitles": False,
    }),
    "timeRestore": False,
    "kibanaSavedObjectMeta": {
        "searchSourceJSON": json.dumps({
            "query": {"language": "kuery", "query": ""},
            "filter": [],
        })
    },
    "version": 1,
    "hits": 0,
}

result = create_saved_object("dashboard", "hl-threat-hunt-report-template",
                             dash_attrs, refs)

print()
print("=== Phase 3: Exporting all objects ===")

# Export all HL objects
export_body = {
    "objects": [
        {"type": "dashboard", "id": "hl-threat-hunt-report-template"},
    ],
    "includeReferencesDeep": True,
    "excludeExportDetails": False,
}

req_url = KIBANA_URL + "/api/saved_objects/_export"
data = json.dumps(export_body).encode()
req = urllib.request.Request(req_url, data=data, method="POST")
creds = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
req.add_header("Authorization", f"Basic {creds}")
req.add_header("kbn-xsrf", "true")
req.add_header("Content-Type", "application/json")

with urllib.request.urlopen(req, timeout=30) as resp:
    export_content = resp.read().decode()

lines = [l for l in export_content.splitlines() if l.strip() and '"exportedCount"' not in l]
print(f"  Exported {len(lines)} objects")
for l in lines:
    obj = json.loads(l)
    print(f"  {obj['type']:20s}  {obj['id']}")

out_path = "kibana/hunt_report_template.ndjson"
with open(out_path, "w", encoding="utf-8") as f:
    for l in lines:
        f.write(l + "\n")

print()
print(f"Written to {out_path}")
print("Done.")
