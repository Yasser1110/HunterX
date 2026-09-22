"""Report orchestration for the pipeline: gathers counts + findings, renders
all formats into ``reports/<run_id>/``, and returns the written paths.

Phase: "reporting"
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from ..context import ScanContext
from .builder import render_all

log = logging.getLogger("hunterx.reporting")


def _meta_from_ctx(ctx: ScanContext) -> dict:
    from .. import __version__
    total, by_sev = ctx.store.findings_meta()
    run = ctx.db.get_run(ctx.run_id) or {}
    return {
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_id": ctx.run_id,
        "target": ctx.target,
        "profile": ctx.profile_name,
        "status": run.get("status", "running"),
        "counts": {"total": total, "by_severity": by_sev,
                   "objects": ctx.store.counts()},
        "deltas": [dict(d) for d in ctx.store.deltas(run_id=ctx.run_id)],
    }


async def run(ctx: ScanContext) -> list[Path]:
    findings = ctx.store.findings()
    meta = _meta_from_ctx(ctx)
    out_dir: Path = ctx.cfg.paths.reports / ctx.run_id
    written = render_all(ctx, findings, meta, out_dir)
    log.info("reporting: %d format(s) written to %s", len(written), out_dir)
    return written