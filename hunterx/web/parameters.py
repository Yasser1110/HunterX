"""Parameter inventory building.

Harvests query-string parameters from every stored URL plus any that were
already pulled from forms/JS during earlier phases. Pure DB work: no
requests are emitted here.
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qsl, urlsplit

from ..context import ScanContext

log = logging.getLogger("hunterx.web.parameters")


async def run(ctx: ScanContext) -> int:
    collected = 0
    for url_row in ctx.store.urls():
        url = url_row["url"]
        query = urlsplit(url).query
        if not query:
            continue
        endpoint = url.split("?", 1)[0]
        for key, _ in parse_qsl(query):
            ctx.store.upsert_parameter(endpoint, key, method=url_row.get("method") or "GET",
                                       source="url-query")
            collected += 1
    log.info("parameters: %d query parameters indexed", collected)
    return collected