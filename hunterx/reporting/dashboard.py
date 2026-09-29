"""Static dashboard generator.

Reads the latest finished run and writes a self-contained HTML page at
``reports/dashboard.html`` with KPIs, top findings and recent runs. Pure
local DB work.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..context import ScanContext
from .builder import _esc, build_html

log = logging.getLogger("hunterx.reporting.dashboard")


def _theme() -> str:
    return """{{THEME}}"""


def build_dashboard(ctx: ScanContext, out: Path | None = None) -> Path:
    out = out or ctx.cfg.paths.reports / "dashboard.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    findings = ctx.store.findings(limit=200)
    if not findings:
        out.write_text("<html><body><h1>HunterX - no data yet</h1></body></html>", encoding="utf-8")
        return out

    runs = ctx.db.list_runs(limit=10)
    rows = []
    for f in sorted(findings[:200], key=lambda x: -(float(x.get("priority") or 0))):
        rows.append(
            '<tr><td><span style="font-family:monospace">'
            + _esc(f.get("type", ""))
            + '</span></td><td>' + _esc(f.get("asset", ""))
            + '</td><td>' + _esc(f.get("severity", ""))
            + '</td><td>' + _esc(f.get("status", ""))
            + "</td></tr>"
        )
    run_rows = "".join(
        f'<tr><td>{_esc(r["id"])}</td><td>{_esc(r.get("target", ""))}</td>'
        f'<td>{_esc(r.get("profile", ""))}</td><td>{_esc(r.get("status", ""))}</td>'
        f'<td>{_esc(r.get("started_at", ""))}</td></tr>'
        for r in runs
    )
    total, by_sev = ctx.store.findings_meta()
    kpis = "".join(
        f'<div class="kpi"><b>{by_sev[k]}</b><div>{k}</div></div>'
        for k in ("critical", "high", "medium", "low", "info")
    )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>HunterX Dashboard</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f8fa;color:#24292f}}
header{{background:#24292f;color:#fff;padding:16px 24px}}
.wrap{{max-width:1100px;margin:24px auto;padding:0 16px}}
.kpis{{display:flex;gap:12px}}
.kpi{{flex:1;background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:14px 20px}}
.kpi b{{font-size:26px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px}}
th,td{{padding:8px 12px;font-size:13px;border-bottom:1px solid #eaeef2;text-align:left}}
</style></head><body>
<header><b>HunterX</b> &mdash; attack surface monitor</header>
<div class="wrap">
<h2>Overview</h2><div class="kpis">{kpis}<div class="kpi"><b>{total}</b><div>total</div></div></div>
<h2>Top findings</h2><table><thead><tr><th>Type</th><th>Asset</th><th>Severity</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Recent runs</h2><table><thead><tr><th>Run</th><th>Target</th><th>Profile</th><th>Status</th><th>Started</th></tr></thead><tbody>{run_rows}</tbody></table>
</div></body></html>"""
    out.write_text(html, encoding="utf-8")
    log.info("dashboard: %s", out)
    return out