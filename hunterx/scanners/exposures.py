"""Exposure / misconfiguration endpoint detection.

Checks a small allowlist of well-known endpoints (/server-status, /.git/HEAD,
/swagger-ui.html, /graphql, /api/docs, phpinfo.php, debug paths). For each
path we fetch and only record existence when the response clearly differs
from a baseline random path (avoiding wildcard false positives). Response
bodies are never fully stored.
"""

from __future__ import annotations

import hashlib
import logging
import random

from ..context import ScanContext
from ..utils import bounded_map
from . import live_urls

log = logging.getLogger("hunterx.scanners.exposures")

CHECKS = [
    ("/server-status", "POTENTIAL_EXPOSED_SERVER_STATUS", "low"),
    ("/.git/HEAD", "POTENTIAL_EXPOSED_GIT_DIR", "medium"),
    ("/.env", "POTENTIAL_EXPOSED_ENV_FILE", "medium"),
    ("/swagger-ui.html", "API_DOCUMENTATION_EXPOSED", "info"),
    ("/swagger/index.html", "API_DOCUMENTATION_EXPOSED", "info"),
    ("/api/docs", "API_DOCUMENTATION_EXPOSED", "info"),
    ("/openapi.json", "API_DOCUMENTATION_EXPOSED", "info"),
    ("/graphql", "GRAPHQL_ENDPOINT_EXPOSED", "info"),
    ("/actuator", "POTENTIAL_EXPOSED_ACTUATOR", "medium"),
    ("/phpinfo.php", "POTENTIAL_EXPOSED_PHPINFO", "medium"),
    ("/debug", "POTENTIAL_EXPOSED_DEBUG_ENDPOINT", "info"),
    ("/actuator/env", "POTENTIAL_EXPOSED_ACTUATOR", "medium"),
]

TITLE_HINTS = ("swagger", "openapi", "graphql", "actuator", "server-status", "phpinfo", "index of /")


async def _check_base(ctx: ScanContext, base: str) -> None:
    session = ctx.session_now()
    rand = f"/{random.randint(10_000_000, 99_000_000)}-nonexistent"
    baseline = await session.fetch(base + rand, timeout=10)
    baseline_sig = None
    if baseline is not None:
        body = baseline.text[:3000] if baseline.text else ""
        baseline_sig = (baseline.status_code, len(body),
                        hashlib.sha256(body.encode("utf-8")).hexdigest())

    host = base.split("//")[1].split(":")[0]
    for path, finding_type, severity in CHECKS:
        url = f"{base}{path}"
        resp = await session.fetch(url, timeout=10)
        if resp is None or resp.status_code == 404:
            continue
        body = resp.text[:3000] if resp.text else ""
        sig = (resp.status_code, len(body), hashlib.sha256(body.encode("utf-8")).hexdigest())
        if baseline_sig and sig == baseline_sig:
            continue  # wildcard fallback -- not a real exposure
        if any(h in (body or "").lower() for h in TITLE_HINTS) or finding_type.startswith("POTENTIAL"):
            ctx.store.upsert_finding(
                asset=host, url=url, type_=finding_type,
                severity=severity, confidence="potential",
                source="hunterx-exposures",
                status="needs_manual_verification",
                evidence={"path": path, "status": resp.status_code, "content_type": resp.headers.get("content-type", ""),
                          "snippet": (body[:160].strip() if body else ""),
                          "required": "manually inspect whether the endpoint exposes sensitive data"}
            )


async def scan(ctx: ScanContext) -> int:
    bases = live_urls(ctx, limit=80)
    await bounded_map(bases, ctx.profile["concurrency"].get("http", 8),
                      lambda b: _check_base(ctx, b))
    log.info("exposures: checked %d origins", len(bases))
    return 0