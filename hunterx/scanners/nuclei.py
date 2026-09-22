"""Nuclei integration.

Runs Nuclei against in-scope live URLs using the template categories and
severities from config. Findings are parsed from JSON output and stored with
the template id + matched text (evidence is truncated/redacted). Always
respects ``nuclei.aggressive`` - intrusive templates never run unless the
user explicitly re-enables them.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ..context import ScanContext

log = logging.getLogger("hunterx.scanners.nuclei")


def _output_path(ctx: ScanContext) -> Path:
    out_dir = ctx.cfg.paths.data / "tool-outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"nuclei-{int(time.time())}.json"


def _build_args(ctx: ScanContext, urls_file: Path, out_file: Path) -> list[str]:
    nuclei = ctx.cfg.nuclei_cfg()
    args = ["-l", str(urls_file), "-jsonl", "-o", str(out_file),
            "-rate-limit", str(ctx.profile["rate_limit"]["requests_per_second"]),
            "-concurrency", str(ctx.profile["concurrency"].get("nuclei", 10)),
            "-timeout", str(ctx.cfg.scan_cfg()["timeout"].get("read", 10)),
            "-severity", ",".join(nuclei.get("severities", ["info", "low", "medium", "high", "critical"])),
            "-stats", ]
    tags = nuclei.get("tags", [])
    if tags:
        safe_tags = [t for t in tags if t != "intrusive"]
        if safe_tags:
            args += ["-tags", ",".join(safe_tags)]
    if not nuclei.get("aggressive", False):
        args += ["-exclude-tags", "intrusive"]
    if nuclei.get("update_templates", True):
        pass  # template update is handled separately to avoid slowing the scan
    return args


async def scan(ctx: ScanContext) -> int:
    if ctx.profile_name == "passive":
        log.info("nuclei: passive profile - skipping")
        return 0
    if not ctx.tools.available("nuclei"):
        log.info("nuclei: not installed; skipped")
        return 0

    urls = [u["url"] for u in ctx.store.urls()][:800]
    if not urls:
        hosts = [str(r["fqdn"]) for r in ctx.db.assets() if ctx.scope.is_allowed_host(str(r["fqdn"]))]
        urls = [f"https://{h}/" for h in hosts if ctx.scope.is_allowed_url(f"https://{h}/")]
    if not urls:
        return 0

    urls_file = ctx.cfg.paths.data / "tool-outputs" / "nuclei-urls.txt"
    urls_file.parent.mkdir(parents=True, exist_ok=True)
    urls_file.write_text("\n".join(urls), encoding="utf-8")
    out_file = _output_path(ctx)

    result = await ctx.atool("nuclei", _build_args(ctx, urls_file, out_file), timeout=900)
    if not result.ok and result.exit_code not in (None, -1):
        log.warning("nuclei exited with %s; parsing partial output", result.exit_code)

    findings = 0
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = entry.get("host") or (urls[0].split("/")[2] if urls else "?")
            template = entry.get("template-id", entry.get("templateID", ""))
            matched = entry.get("matched-at") or entry.get("matcher-name", "")
            info = entry.get("info", {})
            severity = str(info.get("severity", "info")).lower()
            matched_text = entry.get("extracted-results", entry.get("matcher-name", ""))
            if isinstance(matched_text, list):
                matched_text = ",".join(str(t) for t in matched_text[:3])
            _new, is_new = ctx.store.upsert_finding(
                asset=host, url=entry.get("matched-at") or entry.get("url"),
                type_=f"NUCLEI:{template or 'unknown'}",
                severity=severity,
                confidence="high" if severity in ("high", "critical") else "medium",
                source="nuclei", status="needs_manual_verification",
                cve=info.get("cve") if isinstance(info.get("cve"), str) else None,
                evidence={"template": template, "matched": str(matched)[:200],
                          "extracted": str(matched_text)[:200],
                          "required": "manually confirm the observation; nuclei heuristics are not final proof"},
            )
            if is_new:
                findings += 1
    log.info("nuclei: %d new findings", findings)
    return findings