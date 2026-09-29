"""Report draft rendering for editing before distribution.

Draft = the same markdown as the formal report but with all
``needs_manual_verification`` findings grouped under a review checklist.
Writes to ``reports/drafts/<run_id>.md``.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..context import ScanContext
from .builder import build_markdown

log = logging.getLogger("hunterx.reporting.draft")


async def make_draft(ctx: ScanContext, findings: list[dict], meta: dict) -> Path:
    pending = [f for f in findings if f.get("status") == "needs_manual_verification"]
    body = build_markdown(ctx, findings, meta)
    checklist = []
    for f in pending:
        checklist.append(f"- [{f.get('severity', 'info').upper()}] `{f['id'][:12]}` {f.get('type')} @ {f.get('asset')}")
    draft = body + "\n\n## Manual verification checklist\n\n" + ("\n".join(checklist) if checklist else "_None pending._")
    out_dir: Path = ctx.cfg.paths.reports / "drafts"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{ctx.run_id}.md"
    path.write_text(draft, encoding="utf-8")
    log.info("draft: %d findings need manual review -> %s", len(checklist), path)
    return path