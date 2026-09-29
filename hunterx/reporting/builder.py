"""Report builders: JSON, Markdown, CSV, HTML.

All renderers operate on the local DB. Evidence embedded in reports is the
already-stored (redacted where needed) evidence; raw secrets never leave the
storage layer.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path

from ..context import ScanContext

log = logging.getLogger("hunterx.reporting.builder")

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
COLORS = {
    "critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
    "low": "#27ae60", "info": "#2980b9", "noise": "#bdc3c7",
}


def _clean_finding(f: dict) -> dict:
    out = dict(f)
    out["evidence"] = f.get("evidence") or {}
    for key in ("id", "fingerprint"):
        out.pop(key, None)
    return out


def build_json(ctx: ScanContext, findings: list[dict], meta: dict) -> str:
    payload = {
        "report": "hunterx",
        "version": meta.get("version", "unknown"),
        "generated_at": meta.get("generated_at"),
        "run_id": meta.get("run_id"),
        "target": meta.get("target"),
        "profile": meta.get("profile"),
        "status": meta.get("status"),
        "counts": meta.get("counts", {}),
        "deltas": meta.get("deltas", {}),
        "findings": [_clean_finding(f) for f in findings],
    }
    return json.dumps(payload, indent=2)


def build_markdown(ctx: ScanContext, findings: list[dict], meta: dict) -> str:
    lines = [
        f"# HunterX Report — {meta.get('target', '?')}",
        "",
        f"- Run: `{meta.get('run_id', '-')}`",
        f"- Generated: {meta.get('generated_at', '')}",
        f"- Profile: {meta.get('profile', 'balanced')}",
        f"- Status: {meta.get('status', '')}",
        "",
        "## Executive summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    by_sev = meta.get("counts", {}).get("by_severity", {})
    for sev in SEV_ORDER:
        lines.append(f"| {sev} | {by_sev.get(sev, 0)} |")
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("_No findings recorded._")
    for f in sorted(findings, key=lambda x: (SEV_ORDER.get(str(x.get("severity", "info")), 9),
                                             -float(x.get("priority") or 0))):
        lines += [
            f"### [{f.get('severity', 'info').upper()}] {f.get('type', '')}",
            f"- Asset: `{f.get('asset', '')}`",
            f"- URL: `{f.get('url', '-')}`",
            f"- Confidence: {f.get('confidence', '')}",
            f"- Status: {f.get('status', '')}",
            f"- Source: {f.get('source', '')}",
            "",
        ]
        if f.get("ai_note"):
            lines += ["> **AI triage:** " + str(f["ai_note"]), ""]
        ev = f.get("evidence") or {}
        if ev:
            lines += ["Evidence:", "```json", json.dumps(ev, indent=2)[:2000], "```", ""]
    return "\n".join(lines)


def build_csv(ctx: ScanContext, findings: list[dict], meta: dict) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["severity", "type", "asset", "url", "confidence", "status",
                     "source", "cve", "priority", "ai_note", "evidence_json"])
    for f in findings:
        writer.writerow([
            f.get("severity", ""), f.get("type", ""), f.get("asset", ""), f.get("url", ""),
            f.get("confidence", ""), f.get("status", ""), f.get("source", ""),
            f.get("cve", ""), f.get("priority") or 0,
            f.get("ai_note", ""),
            json.dumps(f.get("evidence") or {}, default=str)[:4000],
        ])
    return out.getvalue()


def _row(f: dict) -> str:
    sev = str(f.get("severity", "info")).lower()
    color = COLORS.get(sev, "#999")
    return (
        f'<tr style="border-bottom:1px solid #eee">'
        f'<td><span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'background:{color};color:#fff;font-size:11px">{sev}</span></td>'
        f"<td><code>{_esc(f.get('type', ''))}</code></td>"
        f"<td>{_esc(f.get('asset', ''))}</td>"
        f"<td><code>{_esc(f.get('url', '-') or '-')}</code></td>"
        f"<td>{f.get('confidence', '')}</td>"
        f"<td>{f.get('status', '')}</td>"
        f"<td>{_esc(f.get('cve', '') or '')}</td>"
        f"</tr>"
    )


def _esc(value: str) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def build_html(ctx: ScanContext, findings: list[dict], meta: dict) -> str:
    by_sev = meta.get("counts", {}).get("by_severity", {})
    rows = "".join(_row(f) for f in sorted(
        findings, key=lambda x: (SEV_ORDER.get(str(x.get("severity", "info")), 9),
                                 -float(x.get("priority") or 0))))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HunterX Report - {_esc(meta.get('target', '?'))}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f7f8fa;color:#24292f}}
.wrap{{max-width:1000px;margin:24px auto;padding:0 16px}}
h1{{font-size:24px}} .meta{{color:#57606a;font-size:13px;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden}}
th{{text-align:left;padding:10px 12px;background:#f6f8fa;border-bottom:1px solid #d0d7de}}
td{{padding:10px 12px;font-size:13px}}
.kpis{{display:flex;gap:12px;margin:16px 0}}
.kpi{{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:12px 18px}}
.kpi b{{font-size:20px}}
</style>
</head>
<body>
<div class="wrap">
<h1>HunterX Report</h1>
<div class="meta">Run {_esc(meta.get('run_id','-'))} · target {_esc(meta.get('target','-'))}
· profile {_esc(meta.get('profile','balanced'))} · status {_esc(meta.get('status',''))}
· generated {_esc(meta.get('generated_at',''))}</div>
<div class="kpis">
{"".join(f'<div class="kpi"><div>{k}</div><b>{v}</b></div>' for k, v in [
    ("critical", by_sev.get("critical", 0)), ("high", by_sev.get("high", 0)),
    ("medium", by_sev.get("medium", 0)), ("low", by_sev.get("low", 0)),
    ("info", by_sev.get("info", 0)), ("total", len(findings))])}
</div>
<table><thead><tr><th>Severity</th><th>Type</th><th>Asset</th><th>URL</th>
<th>Confidence</th><th>Status</th><th>CVE</th></tr></thead><tbody>{rows}</tbody></table>
</div>
</body>
</html>"""


_FORMATS = {
    "json": (build_json, ".json"),
    "markdown": (build_markdown, ".md"),
    "md": (build_markdown, ".md"),
    "csv": (build_csv, ".csv"),
    "html": (build_html, ".html"),
}


def render_all(ctx: ScanContext, findings: list[dict], meta: dict, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, (builder, ext) in _FORMATS.items():
        try:
            content = builder(ctx, findings, meta)
        except Exception as exc:
            log.warning("report renderer %s failed: %s", name, exc)
            continue
        path = out_dir / f"hunterx-report{ext}"
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written