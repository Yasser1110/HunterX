"""Dedup of findings: cross-source collapse and false-positive suppression.

Operations here are read-mostly. The dedup strategy:
  * identical fingerprint rows are already merged by :class:`~hunterx.store.Store`;
  * cluster near-duplicate rows (same asset+type) keeping the record with the
    highest confidence/severity and the merged evidence;
  * mark obviously non-issues (e.g. informational MUTED types) as 'noise' so
    reporting can filter them.
"""

from __future__ import annotations

import json
import logging

from ..context import ScanContext
from ..store import Store

log = logging.getLogger("hunterx.analysis.dedup")

MUTED_TYPES = {"MISSING_SECURITY_HEADER", "SERVER_VERSION_INFO", "SOURCE_MAP_EXPOSED"}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def run(ctx: ScanContext) -> tuple[int, int]:
    findings = ctx.store.findings()
    grouped: dict[tuple[str, str], list[dict]] = {}
    for f in findings:
        grouped.setdefault((f["asset"], f["type"]), []).append(f)

    duplicates = 0
    noise = 0
    for (asset, _type), rows in grouped.items():
        if not rows:
            continue
        rows_sorted = sorted(rows, key=lambda r: (SEV_ORDER.get(r.get("severity", "info"), 10),
                                                  r.get("confidence", "low")))
        keeper = rows_sorted[0]
        for other in rows_sorted[1:]:
            if other["id"] == keeper["id"]:
                continue
            # Merge evidence of the duplicate into the keeper if different.
            ev_k = keeper.get("evidence") or {}
            ev_o = other.get("evidence") or {}
            if ev_o and ev_o != ev_k:
                merged = {"source_hints": sorted({str(ev_k.get("__src", "")) or ""})}
                merged = {**ev_k, **ev_o}
                ctx.db.execute("UPDATE findings SET evidence=? WHERE id=?", (json.dumps(merged), keeper["id"]))
            # Keep only the keeper; delete the duplicate row.
            ctx.db.execute("DELETE FROM findings WHERE id=?", (other["id"],))
            duplicates += 1
        if _type in MUTED_TYPES and ctx.db.query("SELECT 1 FROM findings WHERE id=? AND status='informational'",
                                                 (keeper["id"],)):
            ctx.db.execute("UPDATE findings SET status='noise' WHERE id=?", (keeper["id"],))
            noise += 1

    log.info("dedup: %d duplicates removed, %d noise-marked", duplicates, noise)
    return duplicates, noise