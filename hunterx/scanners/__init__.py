"""Safe custom scanners (headers, CORS, redirects, exposures) + runner.

Every check labels findings conservatively:
  DETECTED  - the observed behavior directly supports the claim
  POTENTIAL - evidence is consistent but manual verification is required
  INFORMATIONAL - observation only

No check sends exploit payloads or follows out-of-scope redirects.
"""

from __future__ import annotations

import logging
import random
from typing import Any

from ..context import ScanContext
from ..store import Store
from ..utils import bounded_map

log = logging.getLogger("hunterx.scanners")


def live_urls(ctx: ScanContext, limit: int = 200) -> list[str]:
    """Distinct scheme://host bases observed as live."""
    seen: set[str] = set()
    for row in ctx.store.urls():
        url = row["url"]
        parts = url.split("/", 3)
        if len(parts) >= 3:
            base = f"{parts[0]}//{parts[2]}"
        else:
            base = url
        seen.add(base)
        if len(seen) >= limit:
            break
    return sorted(seen)