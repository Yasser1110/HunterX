"""Pipeline orchestrator: runs the resumable phase pipeline for one run.

Order matters (see :data:`hunterx.database.PHASES`). Each phase is a module
with ``async def run(ctx)``; phases are marked running/done/failed/pending in
the ``scan_runs.phases`` column so ``--resume`` can continue where a run was
stopped. The global stop switch is honored between requests (workers raise
:class:`StopRequested`).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from .config import Config
from .context import ScanContext
from .database import PHASES
from .database import Database
from .scope import Scope
from .stop import StopRequested, arm as _arm_stop, check_stop
from .store import Store
from .tools import Tools

log = logging.getLogger("hunterx.scan")

# name -> (module_path, function) pairs. Functions are resolved lazily so
# importing scan.py never pulls in every phase dependency.
PHASE_MODULES: dict[str, Callable[[ScanContext], Any]] = {}


def _lazy(module: str, func: str) -> Callable[[ScanContext], Any]:
    async def _call(ctx: ScanContext) -> Any:
        mod = __import__(module, fromlist=[func])
        return await getattr(mod, func)(ctx)

    return _call


async def _notify_phase(ctx: ScanContext) -> int:
    from .integrations.notify import notify

    findings = ctx.store.findings(status="needs_manual_verification", limit=30)
    return await notify(ctx, findings)


async def _urls_phase(ctx: ScanContext) -> int:
    """Passive URL discovery first, then active crawling of live seeds."""
    from .web import crawler, urls

    passive = await urls.run(ctx)
    crawled = await crawler.run(ctx)
    return passive + crawled


for _name, (_mod, _fn) in {
    "discovery": ("hunterx.discovery.subdomains", "run"),
    "dns": ("hunterx.discovery.dns", "run"),
    "http": ("hunterx.web.probe", "run"),
    "ports": ("hunterx.network.ports", "run"),
    "fingerprinting": ("hunterx.web.fingerprint", "run"),
    "javascript": ("hunterx.web.js_analysis", "run"),
    "parameters": ("hunterx.web.parameters", "run"),
    "fuzzing": ("hunterx.web.fuzzing", "run"),
    "scanners": ("hunterx.scanners.run", "run"),
    "cve": ("hunterx.intelligence.cve", "run"),
    "dedup": ("hunterx.analysis.dedup", "run"),
    "evidence": ("hunterx.analysis.evidence", "run"),
    "prioritization": ("hunterx.analysis.prioritization", "run"),
    "ai": ("hunterx.analysis.ai", "run"),
    "reporting": ("hunterx.reporting.run", "run"),
}.items():
    PHASE_MODULES[_name] = _lazy(_mod, _fn)
PHASE_MODULES["notification"] = _notify_phase
PHASE_MODULES["urls"] = _urls_phase


def phase_result_count(name: str, result: Any) -> int:
    if isinstance(result, tuple):
        return int(result[0] or 0)
    try:
        return int(result or 0)
    except (TypeError, ValueError):
        return 0


async def execute_scan(
    cfg: Config,
    *,
    run_id: str,
    target: str,
    profile: str,
    wildcard: str | None = None,
    phases: list[str] | None = None,
    start_phase: str | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    cfg.paths.ensure()
    _arm_stop(cfg.paths.data)

    db = Database(cfg.paths.data / "hunterx.db")
    scope = Scope.from_config(cfg.scope_cfg(), cfg.target)
    store = Store(db)
    profile_cfg = cfg.profile_cfg(profile)

    ctx = ScanContext(
        cfg=cfg, scope=scope, db=db, store=store,
        run_id=run_id, target=target, wildcard=wildcard,
        profile_name=profile, profile=profile_cfg,
        session=None, tools=Tools(cfg),
        logger=logging.getLogger("hunterx.scan"),
    )

    # Seed the target apex itself so a bare host/IP target works even when
    # passive discovery finds nothing (idempotent + resumable).
    if scope.is_allowed_host(target):
        db.upsert_asset(target, source="target")

    if start_phase:
        if start_phase not in PHASES:
            db.finish_run(run_id, "failed")
            raise ValueError(f"unknown phase {start_phase!r}")
        db.mark_phase(run_id, start_phase, "pending")

    summary: dict[str, Any] = {"run_id": run_id, "phases": {}, "stopped": False}
    try:
        for name in PHASES:
            check_stop()
            if name == "scope":
                continue  # validated before the pipeline starts
            if phases and name not in phases:
                continue
            state = db.run_phases(run_id).get(name, "pending")
            if resume and state == "done":
                summary["phases"][name] = "done"
                continue

            db.mark_phase(run_id, name, "running")
            log.info("phase %s: starting", name)
            try:
                result = await PHASE_MODULES[name](ctx)
                db.mark_phase(run_id, name, "done")
                count = phase_result_count(name, result)
                summary["phases"][name] = {"state": "done", "count": count}
                ctx.stats[name] = count
                log.info("phase %s: done (%s items)", name, count)
            except StopRequested:
                db.mark_phase(run_id, name, "pending")
                db.finish_run(run_id, "stopped")
                summary["phases"][name] = {"state": "stopped"}
                summary["stopped"] = True
                log.info("phase %s: gracefully stopped", name)
                break
            except KeyboardInterrupt:
                db.mark_phase(run_id, name, "pending")
                db.finish_run(run_id, "interrupted")
                summary["phases"][name] = {"state": "interrupted"}
                summary["stopped"] = True
                raise
            except Exception as exc:
                db.mark_phase(run_id, name, "failed")
                db.finish_run(run_id, "failed")
                summary["phases"][name] = {"state": "failed", "error": str(exc)[:300]}
                log.exception("phase %s: failed: %s", name, exc)
                break
        else:
            db.finish_run(run_id, "finished")
            summary["status"] = "finished"
    finally:
        await ctx.close()
        db.close()

    if not summary.get("status"):
        summary["status"] = "stopped" if summary.get("stopped") else "failed"
    return summary