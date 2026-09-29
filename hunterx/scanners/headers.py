"""Security headers scanner.

Flags *observed absence* of recommended response headers. This is a
DETECTED observation (not a vulnerability), reported as low/informational
to keep noise low. Only the first URL per origin is checked to avoid alert
flooding (dedup handles the rest).
"""

from __future__ import annotations

import logging

from ..context import ScanContext
from . import live_urls

log = logging.getLogger("hunterx.scanners.headers")

RECOMMENDED = [
    ("content-security-policy", "missing Content-Security-Policy (board for XSS mitigation)"),
    ("x-frame-options", "missing X-Frame-Options or CSP frame-ancestors (clickjacking risk)"),
    ("strict-transport-security", "missing Strict-Transport-Security (HTTPS-only resource)"),
    ("x-content-type-options", "missing X-Content-Type-Options: nosniff"),
    ("referrer-policy", "missing Referrer-Policy"),
]

SOFT_HEADERS = ("server", "x-powered-by", "via", "x-aspnet-version")


async def scan(ctx: ScanContext) -> int:
    bases = live_urls(ctx)
    findings = 0
    for base in bases:
        resp = await ctx.session_now().fetch(base + "/", timeout=10)
        if resp is None:
            continue
        headers = {k.lower(): v for k, v in resp.headers.items()}
        observed = {k.lower() for k in headers}
        missing = [name for name, _why in RECOMMENDED
                   if name not in observed and
                   not (name == "x-frame-options" and "content-security-policy" in observed and "frame-ancestors" in headers.get("content-security-policy", ""))]
        host = base.split("//")[1].split(":")[0]
        for name in missing:
            reason = next(why for n, why in RECOMMENDED if n == name)
            _new, is_new = ctx.store.upsert_finding(
                asset=host, url=base + "/", type_="MISSING_SECURITY_HEADER",
                severity="low", confidence="high", source="hunterx-headers",
                status="informational",
                evidence={"header": name, "observed_headers": sorted(observed & set(SOFT_HEADERS)),
                          "reason": reason},
            )
            if is_new:
                findings += 1
    log.info("headers: %d new missing-header findings", findings)
    return findings