"""Versioned results and escaped standalone reports."""

from datetime import datetime, timezone
from html import escape
import json

EXIT = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}


def finding(check, status, evidence, next_step="No action required."):
    return {"check": check, "status": status, "evidence": evidence, "next_step": next_step}


def overall(checks):
    statuses = {c["status"] for c in checks}
    for status in ("CRITICAL", "UNKNOWN", "WARNING"):
        if status in statuses:
            return status
    return "OK" if checks else "UNKNOWN"


def make_report(endpoints, mode):
    return {"schema_version": "1.0", "tool_version": "0.1.0", "mode": mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": overall([c for e in endpoints for c in e["checks"]]), "endpoints": endpoints}


def render(data, format):
    if format == "json":
        return json.dumps(data, indent=2, allow_nan=False) + "\n"
    if format == "text":
        lines = [f"DC Network Diagnostics | {data['mode']} | {data['status']}"]
        for endpoint in data["endpoints"]:
            lines.append(f"{endpoint['host']}:{endpoint['port']}")
            for c in endpoint["checks"]:
                lines.append(f"  [{c['status']}] {c['check']}: {c['evidence']} | {c['next_step']}")
        return "\n".join(lines) + "\n"
    def e(value):
        return escape(str(value), quote=True)
    rows = "".join(f"<tr><td>{e(endpoint['host'])}:{e(endpoint['port'])}</td>"
                   f"<td>{e(c['check'])}</td><td>{e(c['status'])}</td>"
                   f"<td>{e(c['evidence'])}</td><td>{e(c['next_step'])}</td></tr>"
                   for endpoint in data["endpoints"] for c in endpoint["checks"])
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>DC Network Diagnostics</title><style>"
            "body{font:16px system-ui;max-width:1200px;margin:3rem auto;padding:0 1rem;color:#203047}"
            "h1{color:#125b82}table{border-collapse:collapse;width:100%}"
            "th,td{text-align:left;padding:12px;border-bottom:1px solid #cbd5df;vertical-align:top}"
            "th{background:#edf3fa}.table{overflow:auto}footer{margin-top:2rem;color:#526171}"
            f"</style><h1>DC Network Diagnostics</h1><p>{e(data['mode'])} | "
            f"{e(data['status'])} | {e(data['timestamp'])}</p><div class='table'><table>"
            "<thead><tr><th>Endpoint</th><th>Check</th><th>Status</th><th>Evidence</th>"
            f"<th>Next step</th></tr></thead><tbody>{rows}</tbody></table></div>"
            "<footer>Point-in-time diagnostics. DEMO uses synthetic data. "
            "Successful connections do not establish application health.</footer></html>")
