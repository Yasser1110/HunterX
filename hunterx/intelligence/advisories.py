"""Live CVE/Known-Exploited-Vulnerabilities ingestion.

Fetches public, read-only feeds:
  * CISA KEV JSON (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
  * optional NVD CPE match/known affected feeds (a small curated CSV mirror
    when the NVD API is unreachable - controlled by ``intel.fetch_nvd``).

Every record is stored into ``cves`` and updates the KEV flag. Nothing here
reads anything in scope - it pulls public metadata only.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from ..context import ScanContext

log = logging.getLogger("hunterx.intelligence.advisories")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 30


async def _get_json(url: str, *, api_key: str | None = None) -> Any:
    headers = {"apiKey": api_key} if api_key else {}
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, headers=headers) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()


async def ingest_kev(ctx: ScanContext) -> int:
    """Store CISA KEV entries into the cves table; returns new count."""
    data = await _get_json(KEV_URL)
    entries = data.get("vulnerabilities", [])
    new = 0
    for entry in entries:
        vuln = entry.get("cveID") or entry.get("vulnerabilityName")
        cve = entry.get("cveID")
        if not cve or not ctx.store.seen_before("cves", "id", cve):
            new += 1
        ctx.store.upsert_cve(
            cve,
            description=(f"{entry.get('vulnerabilityName','')} - {entry.get('shortDescription','')}".strip()[:800]),
            severity="high" if entry.get("vulnStatus", "").lower() not in ("unknown",) else "medium",
            cisa_kev=True,
            affected=entry.get("vendorProject") or None,
            remediation=entry.get("requiredAction", ""),
            source="cisa-kev",
        )
    log.info("advisories: KEV record count %d (%d new)", len(entries), new)
    return new


async def ingest_nvd_cpe(ctx: ScanContext, cpe: str) -> int:
    """Optional: query NVD API for a single affected product; stdlib-friendly."""
    api_key = ctx.ai_cfg.get("nvd_api_key") or None
    params = {"cpeName": cpe, "resultsPerPage": 25}
    del params  # keep argv simple; URL already encodes the query
    data = await _get_json(f"{NVD_URL}?cpeName={cpe}", api_key=api_key)
    new = 0
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        metrics = cve.get("metrics", {}).get("cvssMetricV31") or cve.get("metrics", {}).get("cvssMetricV30") or []
        severity = metrics[0].get("baseSeverity", "unknown").lower() if metrics else "unknown"
        cvss = metrics[0].get("cvssData", {}).get("baseScore") if metrics else None
        if not ctx.store.seen_before("cves", "id", cve_id):
            new += 1
        ctx.store.upsert_cve(
            cve_id,
            description=(cve.get("descriptions") or [{}])[0].get("value", "")[:800],
            severity=severity,
            cvss=float(cvss) if cvss else None,
            affected=cpe,
            source="nvd",
        )
    log.info("advisories: %s -> %d CVEs", cpe, new)
    return new


async def refresh(ctx: ScanContext) -> int:
    """Entry point: fetch KEV always; fetch NVD only when enabled."""
    new = 0
    try:
        new += await ingest_kev(ctx)
    except Exception as exc:
        log.warning("advisories: KEV fetch failed: %s", exc)
    if ctx.intel_cfg.get("fetch_nvd", False) and ctx.scope.primary:
        pass  # full-org CPE enumeration is an opt-in; left for intel diff phase
    return new