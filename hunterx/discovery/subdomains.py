"""Passive subdomain discovery.

Sources are optional plugins: crt.sh (built-in HTTP), and subfinder /
assetfinder / amass when installed. Every discovered name is normalized,
deduplicated, and validated against the scope engine BEFORE being stored.

Discovered names are never scanned automatically; storing is metadata-only
until a later phase re-validates the host against scope.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..context import ScanContext
from ..scope import normalize_host
from ..store import Store
from ..utils import bounded_map

log = logging.getLogger("hunterx.discovery.subdomains")

NAME_SPLIT = re.compile(r"[\s,;]+")


def _clean_candidate(raw: str) -> str | None:
    name = normalize_host(raw.split()[0] if raw else "")
    if not name or name == "*":
        return None
    if name.startswith("*."):
        name = name[2:]
    return name or None


async def crtsh(ctx: ScanContext) -> list[tuple[str, str]]:
    """Certificate transparency via crt.sh. Returns (host, source)."""
    url = f"https://crt.sh/?q=%25.{_esc(ctx.target)}&output=json"
    result = await _crtsh_fetch(ctx, url)
    if not result:
        log.info("crt.sh unavailable (transient upstream); retrying once")
        result = await _crtsh_fetch(ctx, url)
    results: list[tuple[str, str]] = []
    entries = result or []
    for entry in entries if isinstance(entries, list) else []:
        name_value = entry.get("name_value") or ""
        for raw in NAME_SPLIT.split(name_value):
            host = _clean_candidate(raw)
            if host and ctx.scope.is_allowed_host(host):
                results.append((host, "crtsh"))
    return results


async def _crtsh_fetch(ctx: ScanContext, url: str) -> list | None:
    session = ctx.session_now()
    try:
        resp = await session.fetch(url, timeout=30, check_scope=False)
    except Exception:
        return None
    if resp is None or resp.status_code != 200:
        return None
    try:
        return resp.json()
    except Exception:
        return None


async def tool_source(ctx: ScanContext, tool: str, args: list[str]) -> list[tuple[str, str]]:
    if not ctx.tools.available(tool):
        log.info("subdomain source %s not installed; skipped", tool)
        return []
    result = await ctx.atool(tool, args)
    if not result.ok or not result.output_file:
        return []
    try:
        text = open(result.output_file, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        host = _clean_candidate(line.strip())
        if host and ctx.scope.is_allowed_host(host):
            out.append((host, tool))
    return out


async def subfinder(ctx: ScanContext) -> list[tuple[str, str]]:
    return await tool_source(ctx, "subfinder", ["-d", ctx.target, "-silent"])


async def assetfinder(ctx: ScanContext) -> list[tuple[str, str]]:
    return await tool_source(ctx, "assetfinder", ["--subs-only", ctx.target])


async def amass(ctx: ScanContext) -> list[tuple[str, str]]:
    return await tool_source(ctx, "amass", ["enum", "-passive", "-d", ctx.target])


def _esc(domain: str) -> str:
    return domain.replace("%", "%25").replace(".", ".")


async def run(ctx: ScanContext) -> int:
    """Run discovery, persist in-scope assets. Returns count of new assets."""
    log.info("discovery: collecting subdomains for %s", ctx.target)
    if ctx.scope.is_allowed_host(ctx.target):
        ctx.db.upsert_asset(ctx.target, source="target")
    per_source = await bounded_map(
        [crtsh, subfinder, assetfinder, amass], 3, lambda fn: fn(ctx)
    )
    seen: dict[str, str] = {}
    for source_results in per_source:
        if isinstance(source_results, Exception):
            continue
        for host, source in source_results or []:
            if host not in seen:
                seen[host] = source
    ctx.bump("discovered", len(seen))

    new: list[str] = []
    for host, source in seen.items():
        if not ctx.scope.is_allowed_host(host):
            continue
        exists = ctx.db.query("SELECT 1 FROM assets WHERE fqdn=?", (host,))
        ctx.db.upsert_asset(host, source=source)
        if not exists:
            new.append(host)

    log.info("discovery: %d in-scope names (%d new)", len(seen), len(new))
    ctx.logger.info("NEW ASSETS: %s", ", ".join(new) if new else "(none)")
    for host in new:
        ctx.logger.info("+ %s", host)
    return len(new)