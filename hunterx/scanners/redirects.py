"""Open redirect indicator scanning.

Uses the first query parameter seen on each discovered URL. The injected
value is an obviously bogus absolute URL; redirects are inspected WITHOUT
following them, so we never touch whatever host the app would redirect to.
A Finding is only raised when a Location header contains the injected value.
"""

from __future__ import annotations

import logging
import random
from urllib.parse import parse_qsl, urlencode, urlsplit

from ..context import ScanContext
from ..store import Store
from ..utils import bounded_map

log = logging.getLogger("hunterx.scanners.redirects")

EVIL = "redirect-check.invalid"


async def _check_url(ctx: ScanContext, url: str) -> None:
    parts = urlsplit(url)
    if not parts.query:
        return
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return
    evil = f"https://{random.randint(100, 999)}.{EVIL}"
    key = params[0][0]
    new_query = urlencode([(k, evil if k == key else v) for k, v in params])
    candidate = parts._replace(query=new_query).geturl()

    resp = await ctx.session_now().fetch(candidate, follow_redirects=False, timeout=10)
    if resp is None:
        return
    location = resp.headers.get("location", "")
    if evil not in location:
        return
    ctx.store.upsert_finding(
        asset=parts.hostname or "", url=url,
        type_="POTENTIAL_OPEN_REDIRECT", severity="medium", confidence="potential",
        source="hunterx-redirect", status="needs_manual_verification",
        evidence={"parameter": key, "injected": evil, "location_header": location[:300],
                  "required": "manually verify redirect with a harmless in-scope value; never browse attacker hosts automatically"}
    )


async def scan(ctx: ScanContext) -> int:
    urls = [row["url"] for row in ctx.store.urls() if row.get("url")]
    urls = [u for u in urls if "?" in u][:300]
    await bounded_map(urls, ctx.profile["concurrency"].get("http", 8),
                      lambda u: _check_url(ctx, u))
    log.info("redirect: checked %d parameterized URLs", len(urls))
    return 0