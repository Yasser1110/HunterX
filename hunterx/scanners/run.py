"""Runs all enabled safe scanners in one phase (headers, CORS, redirects,
exposures, nuclei)."""

from __future__ import annotations

import logging

from ..context import ScanContext
from . import cors, exposures, headers, nuclei, redirects

log = logging.getLogger("hunterx.scanners.run")


async def run(ctx: ScanContext) -> int:
    total = 0
    for module in (headers, cors, redirects, exposures):
        try:
            total += await module.scan(ctx)
        except Exception as exc:
            log.warning("scanner %s failed: %s", module.__name__, exc)
    try:
        total += await nuclei.scan(ctx)
    except Exception as exc:
        log.warning("nuclei failed: %s", exc)
    log.info("scanners: complete (%d new findings)", total)
    return total