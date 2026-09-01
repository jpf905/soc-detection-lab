"""JSON and standalone HTML report generation."""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from .models import Alert, AuthEvent


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def write_json(alerts: list[Alert], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps([alert.to_dict() for alert in alerts], indent=2) + "\n", encoding="utf-8")


def write_html(events: list[AuthEvent], alerts: list[Alert], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter(alert.severity for alert in alerts)
    rows = "\n".join(
        "<tr>"
        f"<td><span class='badge {html.escape(a.severity)}'>{html.escape(a.severity.upper())}</span></td>"
        f"<td>{html.escape(a.title)}</td><td>{html.escape(a.timestamp.isoformat())}</td>"
        f"<td>{html.escape(a.source_ip)}</td><td>{html.escape(a.username)}</td>"
        f"<td>{html.escape(', '.join(a.mitre_attack))}</td></tr>"
        for a in sorted(alerts, key=lambda item: (SEVERITY_ORDER[item.severity], item.timestamp))
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Detection Lab</title><style>
:root{{--navy:#071426;--panel:#0e2039;--blue:#24a8ff;--cyan:#60e1e0;--text:#edf6ff;--muted:#9db0c8;}}
*{{box-sizing:border-box}} body{{margin:0;background:linear-gradient(135deg,#050c17,#0a1b31);color:var(--text);font:15px system-ui,sans-serif}}
main{{max-width:1150px;margin:auto;padding:42px 24px}} h1{{font-size:34px;margin:0}} .sub{{color:var(--muted);margin:8px 0 28px}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}} .card{{background:var(--panel);padding:20px;border:1px solid #1d385a;border-radius:12px}}
.value{{font-size:30px;font-weight:750;color:var(--cyan)}} .label{{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.08em}}
.table-wrap{{overflow:auto;background:var(--panel);border:1px solid #1d385a;border-radius:12px}} table{{width:100%;border-collapse:collapse}} th,td{{padding:14px;text-align:left;border-bottom:1px solid #193452;white-space:nowrap}} th{{color:var(--cyan);font-size:12px;text-transform:uppercase}}
.badge{{font-size:11px;font-weight:800;padding:5px 8px;border-radius:999px}} .critical{{background:#8d2035;color:#ffdbe3}} .high{{background:#844614;color:#ffe4c1}}
.foot{{color:var(--muted);font-size:12px;margin-top:18px}} @media(max-width:700px){{.grid{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body><main><h1>SOC Detection Lab</h1><p class="sub">Identity threat detection summary • synthetic telemetry • safe for public demonstration</p>
<section class="grid"><div class="card"><div class="value">{len(events)}</div><div class="label">Events analyzed</div></div>
<div class="card"><div class="value">{len(alerts)}</div><div class="label">Alerts generated</div></div>
<div class="card"><div class="value">{counts.get('critical', 0)}</div><div class="label">Critical</div></div>
<div class="card"><div class="value">{counts.get('high', 0)}</div><div class="label">High</div></div></section>
<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Detection</th><th>UTC time</th><th>Source</th><th>Account</th><th>MITRE</th></tr></thead><tbody>{rows}</tbody></table></div>
<p class="foot">Generated locally by the SOC Detection Lab. No real credentials or production data are included.</p></main></body></html>"""
    target.write_text(document, encoding="utf-8")

