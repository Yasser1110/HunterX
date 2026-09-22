"""CORS misconfiguration detection.

Sends an arbitrary reflected Origin header and checks the response. The
Origin is a random, obviously-not-a-real-service host and is never fetched.
Mirroring the Origin alone is common; only *Allow-Credentials: true* with a
reflected Origin is elevated from potential to high-priority.
"""

from __future__ import annotations

import logging
import random

from ..context import ScanContext
from ..utils import bounded_map
from . import live_urls

log = logging.getLogger("hunterx.scanners.cors")

EVIL = "hunterx-cors-check.invalid"


async def _check(ctx: ScanContext, base: str) -> None:
    origin = f"https://{random.randint(100, 999)}.{EVIL}"
    resp = await ctx.session_now().fetch(base + "/", headers={"Origin": origin}, timeout=10)
    if resp is None:
        return
    acao = resp.headers.get("access-control-allow-origin")
    if not acao:
        return
    allows_creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    if origin not in acao and "*" not in acao:
        return
    if "*" in acao:
        ctx.store.upsert_finding(
            asset=base.split("//")[1].split(":")[0], url=base + "/",
            type_="CORS_WILDCARD_ALLOW", severity="medium", confidence="high",
            source="hunterx-cors", status="needs_manual_verification",
            evidence={"acao": acao, "note": "Access-Control-Allow-Origin: * harms credentialed cross-origin flows"}
        )
        return
    severity = "high" if allows_creds else "medium"
    ctx.store.upsert_finding(
        asset=base.split("//")[1].split(":")[0], url=base + "/",
        type_="POTENTIAL_CORS_MISCONFIGURATION", severity=severity, confidence="potential",
        source="hunterx-cors", status="needs_manual_verification",
        evidence={"sent_origin": origin, "acao": acao, "allow_credentials": allows_creds,
                  "required": "manually confirm the response reflects untrusted origins and whether credentials are used"}
    )


async def scan(ctx: ScanContext) -> int:
    bases = live_urls(ctx, limit=100)
    await bounded_map(bases, ctx.profile["concurrency"].get("http", 10),
                      lambda b: _check(ctx, b))
    log.info("cors: checked %d origins", len(bases))
    return 0