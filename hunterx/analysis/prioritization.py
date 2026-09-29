"""Prioritization: a deterministic risk score for every finding.

Score = f(severity, confidence, exposure, asset importance, KEV flag).
Higher number = more urgent. This is a triage heuristic, not a statement of
exploitability; nothing is auto-confirmed.
"""

from __future__ import annotations

import logging

from ..context import ScanContext

log = logging.getLogger("hunterx.analysis.prioritization")

SEV_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 5}
CONFIDENCE_SCORE = {"high": 1.0, "potential": 0.6, "medium": 0.7, "low": 0.4, "detected": 0.9}
STATUS_EXPOSURE = {"needs_manual_verification": 1.0, "open": 1.0, "informational": 0.15, "noise": 0.05}

IMPORTANT_ASSET_HINTS = ("api", "auth", "admin", "admin-console", "console", "dev.", "staging", "internal")


def asset_importance(host: str) -> float:
    lowered = host.lower()
    return 1.25 if any(h in lowered for h in IMPORTANT_ASSET_HINTS) else 1.0


def score_finding(finding: dict) -> float:
    sev = float(SEV_SCORE.get(str(finding.get("severity", "info")).lower(), 10))
    conf = float(CONFIDENCE_SCORE.get(str(finding.get("confidence", "low")).lower(), 0.4))
    exposure = float(STATUS_EXPOSURE.get(str(finding.get("status", "needs_manual_verification")), 1.0))
    evidence = finding.get("evidence") or {}
    kev = 1.5 if bool(evidence.get("kev")) else 1.0
    importance = asset_importance(str(finding.get("asset", "")))
    group = 1.0 + 0.15 * int(evidence.get("_group_hosts", 1)) if evidence.get("_group_hosts") else 1.0
    return round(sev * conf * exposure * kev * importance * group, 2)


async def run(ctx: ScanContext) -> int:
    findings = ctx.store.findings()
    ranked = 0
    for f in findings:
        score = score_finding(f)
        ctx.db.execute("UPDATE findings SET priority=? WHERE id=?", (score, f["id"]))
        ranked += 1
    ctx.cfg.paths.data.mkdir(parents=True, exist_ok=True)
    log.info("prioritization: scored %d findings", ranked)
    return ranked