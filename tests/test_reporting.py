"""Reporting renderer checks: builders produce non-empty output, dashboard writes."""

import asyncio
from pathlib import Path

from hunterx.config import Config, DEFAULTS, ProjectPaths, deep_merge
from hunterx.context import ScanContext
from hunterx.database import Database
from hunterx.scope import Scope
from hunterx.store import Store
from hunterx.tools import Tools

from test_analysis import make_ctx  # noqa: F401 - reuse the ctx factory


def test_json_markdown_csv_render(tmp_path):
    ctx = make_ctx(tmp_path)
    try:
        ctx.store.upsert_finding(asset="a.example.com", url="https://a.example.com/p",
                                 type_="TEST", severity="medium", confidence="high",
                                 source="t", status="needs_manual_verification",
                                 evidence={"probe": "ok"})
        findings = ctx.store.findings()
        meta = {"version": "0.2.0", "generated_at": "now", "run_id": ctx.run_id,
                "target": ctx.target, "profile": "balanced", "status": "finished",
                "counts": {"total": 1, "by_severity": {"medium": 1}}}

        from hunterx.reporting.builder import build_csv, build_json, build_markdown, build_html
        j = build_json(ctx, findings, meta)
        m = build_markdown(ctx, findings, meta)
        c = build_csv(ctx, findings, meta)
        h = build_html(ctx, findings, meta)
        assert "a.example.com" in j
        assert "CDN" not in j
        assert findings[0]["evidence"]["probe"] in c       # raw evidence exported
        assert "medium" in m
        assert "<table>" in h
        assert len(c.splitlines()) >= 2
    finally:
        ctx.db.close()


def test_html_escapes_findings(tmp_path):
    ctx = make_ctx(tmp_path)
    try:
        ctx.store.upsert_finding(asset="a.example.com", type_="HTML", severity="info",
                                 confidence="low", source="t",
                                 url="https://a.example.com/?q=<script>alert(1)</script>")
        from hunterx.reporting.builder import build_html
        html = build_html(ctx, ctx.store.findings(),
                          {"counts": {"by_severity": {"info": 1}}})
        assert "&lt;script&gt;" in html and "<script>alert" not in html
    finally:
        ctx.db.close()


def test_dashboard_writes_file(tmp_path):
    ctx = make_ctx(tmp_path)
    try:
        ctx.store.upsert_finding(asset="a.example.com", type_="DASH", severity="low",
                                 confidence="potential", source="t",
                                 status="needs_manual_verification")
        ctx.db.create_scan_run(ctx.target, "balanced")
        from hunterx.reporting.dashboard import build_dashboard
        out = ctx.cfg.paths.reports / "dashboard.html"
        path = build_dashboard(ctx, out=out)
        assert path.exists()
        assert "HunterX" in path.read_text(encoding="utf-8")
    finally:
        ctx.db.close()