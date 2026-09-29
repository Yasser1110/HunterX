"""Analysis-phase tests: dedup, correlation, prioritization against a temp DB."""

import asyncio

from hunterx.config import Config, DEFAULTS, ProjectPaths, deep_merge
from hunterx.context import ScanContext
from hunterx.database import Database
from hunterx.scope import Scope
from hunterx.store import Store
from hunterx.tools import Tools


def make_ctx(tmp_path, run_id="RUN-test-001", target="a.example.com", overrides=None):
    base = tmp_path / "lab"
    base.mkdir(exist_ok=True)
    raw = deep_merge(DEFAULTS, {"target": {"domain": target, "wildcard": "*.example.com"}})
    if overrides:
        raw = deep_merge(raw, overrides)
    paths = ProjectPaths(base=base, data=base / "data", reports=base / "reports",
                         log_dir=base / "log", config_dir=base / "config",
                         wordlists=base / "wordlists")
    cfg = Config(raw, paths)
    db = Database(paths.data / "hunterx.db")
    store = Store(db)
    scope = Scope.from_config(cfg.scope_cfg(), cfg.target)
    ctx = ScanContext(cfg=cfg, scope=scope, db=db, store=store, run_id=run_id,
                      target=target, wildcard="*.example.com", profile_name="balanced",
                      profile=cfg.profile_cfg("balanced"), session=None, tools=Tools(cfg))
    return ctx


def test_dedup_collapses_same_asset_type(tmp_path):
    ctx = make_ctx(tmp_path)
    try:
        store = ctx.store
        store.upsert_finding(asset="a.example.com", url="https://a.example.com/x", type_="DUPE",
                             severity="low", confidence="potential", source="s1",
                             status="needs_manual_verification")
        store.upsert_finding(asset="a.example.com", url="https://a.example.com/y", type_="DUPE",
                             severity="high", confidence="high", source="s2",
                             status="needs_manual_verification")
        assert len(store.findings()) == 2  # distinct fingerprints -> two rows

        from hunterx.analysis.dedup import run
        duplicates, noise = asyncio.run(run(ctx))
        assert duplicates == 1
        remaining = store.findings()
        assert len(remaining) == 1
        assert remaining[0]["severity"] == "high"
    finally:
        ctx.db.close()


def test_prioritization_scores_and_persists(tmp_path):
    ctx = make_ctx(tmp_path)
    try:
        ctx.store.upsert_finding(asset="api.example.com", type_="CRIT", severity="critical",
                                 confidence="high", source="s", status="needs_manual_verification",
                                 evidence={"kev": True})
        ctx.store.upsert_finding(asset="www.example.com", type_="INFO", severity="info",
                                 confidence="low", source="s", status="informational")

        from hunterx.analysis.prioritization import run
        assert asyncio.run(run(ctx)) == 2

        rows = ctx.db.query("SELECT id, priority FROM findings ORDER BY priority DESC")
        assert rows[0]["priority"] > rows[1]["priority"]
    finally:
        ctx.db.close()


def test_correlation_annotates_groups(tmp_path):
    ctx = make_ctx(tmp_path)
    try:
        store = ctx.store
        store.upsert_finding(asset="a.example.com", type_="SAME", severity="low",
                             confidence="potential", source="s", status="needs_manual_verification")
        store.upsert_finding(asset="b.example.com", type_="SAME", severity="low",
                             confidence="potential", source="s", status="needs_manual_verification")
        from hunterx.analysis.correlation import run
        assert asyncio.run(run(ctx)) == 1
        rows = ctx.db.query("SELECT evidence FROM findings LIMIT 1")
        assert "_group_hosts" in rows[0]["evidence"]
    finally:
        ctx.db.close()