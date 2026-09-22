"""URL discovery from multiple passive/low-impact sources.

Sources: wayback (gau / waybackurls), katana crawl output, robots.txt,
sitemap.xml. Non-tool sources are fetched through the scope-aware session.
All URLs are normalized, deduplicated, and scope-checked before storing.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any

from ..context import ScanContext
from ..utils import bounded_map, join_url, normalize_url

log = logging.getLogger("hunterx.web.urls")

_SITEMAP_URL = re.compile(r"<loc>(.*?)</loc>", re.I | re.S)


async def _tool_urls(ctx: ScanContext, tool: str, args: list[str]) -> list[str]:
    if not ctx.tools.available(tool):
        return []
    result = await ctx.atool(tool, args, timeout=300)
    if not result.ok or not result.output_file:
        return []
    try:
        text = open(result.output_file, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    candidates: list[str] = []
    for line in text.splitlines():
        url = _first_url(line)
        if url:
            candidates.append(url)
    return candidates


def _first_url(line: str) -> str | None:
    m = re.search(r"https?://[^\s\"'<>]+", line)
    return m.group(0) if m else None


async def _robots_sitemaps(ctx: ScanContext, host: str) -> list[str]:
    if not ctx.scope.is_allowed_host(host):
        return []
    session = ctx.session_now()
    found: list[str] = []
    robots = f"https://{host}/robots.txt"
    resp = await session.fetch(robots, timeout=10)
    if resp and resp.status_code == 200:
        for line in (resp.text or "").splitlines():
            if line.lower().startswith("sitemap:"):
                url = _first_url(line)
                if url and ctx.scope.is_allowed_url(url):
                    found.append(url)
    for sm in found[:5]:
        sitemap = await session.fetch(sm, timeout=10)
        if sitemap and sitemap.status_code == 200:
            for m in _SITEMAP_URL.finditer(sitemap.text or ""):
                url = m.group(1).strip()
                if ctx.scope.is_allowed_url(url):
                    found.append(url)
            found.append(sm)
    return found


async def run(ctx: ScanContext) -> int:
    hosts = [str(r["fqdn"]) for r in ctx.db.assets() if ctx.scope.is_allowed_host(str(r["fqdn"]))]
    candidates: list[str] = []

    sources = [
        ("gau", lambda: _tool_urls(ctx, "gau", ["--subs", ctx.target])),
        ("waybackurls", lambda: _tool_urls(ctx, "waybackurls", [ctx.target])),
        ("katana", lambda: _tool_urls(ctx, "katana", ["-u", *[f"https://{h}/" for h in hosts], "-jc", "-silent",
                                                       "-d", "2", "-c", str(ctx.profile["concurrency"].get("http", 10))])),
    ]
    for name, fn in sources:
        try:
            got = await fn()
            log.info("urls: %s returned %d", name, len(got))
            candidates.extend(got)
        except Exception as exc:
            log.debug("urls: %s failed: %s", name, exc)

    sm = await bounded_map(hosts, 5, lambda h: _robots_sitemaps(ctx, h))
    for outcome in sm:
        if isinstance(outcome, Exception):
            continue
        candidates.extend(outcome)

    stored = 0
    visited: set[str] = set()
    for raw in candidates:
        url = normalize_url(raw)
        if not url or url in visited or not ctx.scope.is_allowed_url(url):
            continue
        if len(visited) >= int(ctx.http_cfg.get("url_limit", 20000)):
            break
        visited.add(url)
        ctx.store.upsert_url(url, source="discovery")
        stored += 1
    log.info("urls: stored %d URLs (%d candidates)", stored, len(candidates))
    return stored