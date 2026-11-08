"""Minimal SARIF 2.1.0 and self-contained HTML exports from sanitized findings."""
from html import escape
import json


def sarif(report):
    tools = sorted({t["tool"] for t in report["scanners"]})
    runs = []
    for tool in tools:
        tool_findings = [f for f in report["findings"] if tool in f["tools"]]
        rules = sorted({f["rule"] for f in tool_findings})
        results = []
        for f in tool_findings:
            level = {"CRITICAL": "error", "HIGH": "error", "ERROR": "error",
                     "MEDIUM": "warning", "WARNING": "warning"}.get(f["severity"], "note")
            row = {"ruleId": f["rule"], "level": level, "message": {"text": "Security finding; manually verify before remediation."}}
            if f["path"] and f["path"] != "[outside-target]":
                row["locations"] = [{"physicalLocation": {
                    "artifactLocation": {"uri": f["path"], "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, f["line"])}}}]
            results.append(row)
        runs.append({
            "tool": {"driver": {"name": tool, "rules": [{"id": rule} for rule in rules]}},
            "results": results,
            "properties": {"scanStatus": next(t["status"] for t in report["scanners"] if t["tool"] == tool)}
        })
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": runs}


def html(report):
    rows = []
    for f in report["findings"]:
        cols = [f["severity"], f["rule"], f["path"], str(f["line"]), ", ".join(f["tools"])]
        rows.append("<tr>" + "".join("<td>" + escape(x, quote=True) + "</td>" for x in cols) + "</tr>")
    scanner_rows = []
    for s in report["scanners"]:
        scanner_rows.append("<tr><td>" + escape(s["tool"]) + "</td><td>" +
                            escape(s["status"]) + "</td><td>" + str(len(s["findings"])) + "</td></tr>")
    return """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Nile Minds Security Audit</title><style>
body{font:16px system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#182237}
h1{font-size:1.7rem}table{width:100%;border-collapse:collapse;margin:1rem 0}
th,td{padding:.65rem;border:1px solid #cdd3dc;text-align:left;overflow-wrap:anywhere}
th{background:#f1f4f7}small{color:#555}
</style></head><body><h1>Nile Minds Security Audit</h1><p><strong>Status: """ + escape(report["status"]) + """</strong></p>
<h2>Scanner status</h2><table><thead><tr><th>Tool</th><th>Status</th><th>Findings</th></tr></thead><tbody>""" + "".join(scanner_rows) + """</tbody></table>
<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Sources</th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table>
<small>Results need manual verification. Incomplete scans are not clean scans. Secret matches and source snippets are omitted.</small>
</body></html>"""
