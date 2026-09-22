"""Evidence capture: collect a snapshot of the raw evidence attachments for
confirmed-looking findings so a report can reference them without re-running
anything.

Because HunterX never auto-fetches exploit content, evidence files are only
created when a finding is explicitly marked (by the operator via CLI) as
verified. This module stages those files into ``data/evidence/<run_id>/``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..context import ScanContext

log = logging.getLogger("hunterx.analysis.evidence")

VERIFIED_STATUSES = {"open", "verified"}


async def run(ctx: ScanContext) -> tuple[int, list[Path]]:
    evidence_dir = ctx.cfg.paths.data / "evidence"
    for f in ctx.store.findings():
        if f.get("status") not in VERIFIED_STATUSES:
            continue
        if not f.get("evidence"):
            continue
        safe = "".join(c for c in f["id"] if c.isalnum())[:24]
        out = evidence_dir / ctx.run_id / f"{safe}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({
            "id": f["id"], "asset": f["asset"], "url": f["url"],
            "type": f["type"], "severity": f["severity"], "evidence": f["evidence"],
            "captured_at": f["last_seen"],
        }, indent=2), encoding="utf-8")
    log.info("evidence: staged files under %s", evidence_dir / ctx.run_id)
    return 0, []