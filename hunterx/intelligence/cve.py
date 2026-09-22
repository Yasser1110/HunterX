"""CVE correlation engine.

Maps detected technologies (+versions) against the intelligence stored in
``cves`` (static tech-vulndb + live KEV/NVD rows) and raises Findings only
when the version range genuinely matches. Any ambiguous/false-positive-prone
match is downgraded to a POTENTIAL_ finding that requires manual
verification, and never auto-escalates to "confirmed".
"""

from __future__ import annotations

import logging
import re

from ..context import ScanContext
from .technologies import candidates_for

log = logging.getLogger("hunterx.intelligence.cve")

_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.I)


def _extract_cves(text: str | None) -> list[str]:
    if not text:
        return []
    found = sorted({m.upper() for m in _CVE_RE.findall(text)})
    return found[:10]


async def run(ctx: ScanContext) -> int:
    if ctx.profile_name == "passive":
        log.info("cve: passive profile - skipping correlation")
        return 0

    total = 0

    for row in ctx.store.technologies():
        tech = str(row.get("technology", "")).strip().lower()
        version = row.get("version")
        candidates = candidates_for(tech, version)
        matched = [c for c in candidates if c["matched"]]
        if not matched:
            continue
        host = str(row.get("host", ""))
        if not ctx.scope.is_allowed_host(host):
            continue
        for c in matched:
            severity = "high" if c["kev"] else c["severity"]
            _new, is_new = ctx.store.upsert_finding(
                asset=host,
                url=None,
                type_=f"CVE:{c['cve']}",
                severity=severity,
                confidence="high" if c["kev"] else "potential",
                source="hunterx-intel",
                status="needs_manual_verification",
                cve=c["cve"],
                evidence={
                    "technology": tech,
                    "version": version,
                    "cve": c["cve"],
                    "cvss": c["cvss"],
                    "kev": c["kev"],
                    "description": c["description"],
                    "remediation": c["remediation"],
                    "has_template": c["has_template"],
                    "required": "confirm the running version and product on the live system before action",
                },
            )
            if is_new:
                total += 1

    log.info("cve: %d new correlated findings", total)
    return total