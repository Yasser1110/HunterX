"""Correlation of findings across assets (cross-host propagation).

Links findings that share a type/deploy or mark related assets so reports
can say "same issue on N hosts". Operates purely in local DB - no network.
"""

from __future__ import annotations

import json
import logging

from ..context import ScanContext

log = logging.getLogger("hunterx.analysis.correlation")


async def run(ctx: ScanContext) -> int:
    findings = ctx.store.findings()
    by_type: dict[str, list[dict]] = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f)

    groups = 0
    for _type, rows in by_type.items():
        assets = sorted({r["asset"] for r in rows})
        if len(assets) < 2:
            continue
        groups += 1
        # annotate each row's evidence with the group size
        payload = json.dumps({"group": _type, "hosts": len(assets)})
        for r in rows:
            ev = dict(r.get("evidence") or {})
            ev["_group_hosts"] = len(assets)
            ctx.db.execute("UPDATE findings SET evidence=? WHERE id=?",
                           (json.dumps(ev), r["id"]))
    log.info("correlation: %d cross-host groups identified", groups)
    return groups