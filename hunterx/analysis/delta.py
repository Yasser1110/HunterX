"""Delta detection between runs (what changed since the last scan).

Purely DB-local: snapshots current object identity sets (assets, urls,
ports, technologies, findings) into the ``snapshots`` table, compares to the
most recent earlier run, and stores the diff in ``deltas`` for reporting.
"""

from __future__ import annotations

import json
import logging

from ..context import ScanContext

log = logging.getLogger("hunterx.analysis.delta")

_SCOPES = (
    ("assets", "SELECT fqdn FROM assets", "fqdn"),
    ("urls", "SELECT url FROM urls", "url"),
    ("ports", "SELECT host||':'||port FROM ports", "host:port"),
    ("technologies", "SELECT host||'|'||technology FROM technologies", "host|tech"),
    ("findings", "SELECT id FROM findings", "id"),
)


def _snapshot(ctx: ScanContext, run_id: str) -> dict[str, set[str]]:
    current: dict[str, set[str]] = {}
    for scope, sql, _label in _SCOPES:
        try:
            rows = ctx.db.query(sql)
        except Exception:
            rows = []
        current[scope] = {str(r[0]) for r in rows}
    for scope, ids in current.items():
        ctx.db.execute(
            "INSERT INTO snapshots(run_id, scope, ids, created_at) VALUES(?,?,?,?) "
            "ON CONFLICT(run_id, scope) DO UPDATE SET ids=excluded.ids, created_at=excluded.created_at",
            (run_id, scope, json.dumps(sorted(ids)), __import__("hunterx.database", fromlist=["utcnow"]).utcnow()),
        )
    return current


def _last_previous(ctx: ScanContext, run_id: str) -> dict[str, set[str]]:
    rows = ctx.db.query(
        "SELECT s.scope, s.ids FROM snapshots s WHERE s.run_id != ? "
        "ORDER BY s.created_at DESC LIMIT 100", (run_id,))
    snapshot: dict[str, set[str]] = {}
    for r in rows:
        scope = str(r["scope"])
        if scope not in snapshot:
            try:
                snapshot[scope] = set(json.loads(r["ids"] or "[]"))
            except Exception:
                snapshot[scope] = set()
    return snapshot


async def run(ctx: ScanContext, *, run_id: str | None = None) -> dict[str, dict[str, int]]:
    run_id = run_id or ctx.run_id
    current = _snapshot(ctx, run_id)
    previous = _last_previous(ctx, run_id)

    results: dict[str, dict[str, int]] = {}
    for scope, _sql, _label in _SCOPES:
        cur = current.get(scope, set())
        prev = previous.get(scope, set())
        added = sorted(cur - prev)
        removed = sorted(prev - cur)
        results[scope] = {"added": len(added), "removed": len(removed),
                          "changed": len(cur & prev)}
        ctx.store.upsert_delta(run_id, scope,
                               added=len(added), removed=len(removed),
                               changed=len(cur & prev),
                               detail={"added": added[:300], "removed": removed[:300]})
    log.info("delta: %s", {k: v["added"] for k, v in results.items()})
    return results