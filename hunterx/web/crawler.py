"""BFS crawler over in-scope hosts.

Respects (best-effort) robots.txt disallow rules, caps pages/depth per host,
stores every new in-scope URL, and harvests HTML form fields into the
parameters inventory. Never fetches out-of-scope URLs.
"""

from __future__ import annotations

import logging
from html.parser import HTMLParser
from urllib.parse import unquote

from ..context import ScanContext
from ..utils import bounded_map, join_url, normalize_url
from ..store import Store

log = logging.getLogger("hunterx.web.crawler")


class _LinkParser(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__()
        self.base = base
        self.links: list[str] = []
        self.forms: list[tuple[str, list[str], str]] = []  # (action, fields, method)
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "a" and attr.get("href"):
            self.links.append(unquote(attr["href"]))
        elif tag in ("script", "iframe", "img") and attr.get("src"):
            self.links.append(unquote(attr["src"]))
        elif tag == "form":
            self._current_form = {
                "action": attr.get("action") or self.base,
                "method": (attr.get("method") or "GET").upper(),
                "fields": [],
            }
        elif tag == "input" and self._current_form is not None and attr.get("name"):
            self._current_form["fields"].append(attr["name"])
        elif tag == "meta" and (attr.get("http-equiv", "")).lower() == "refresh" and attr.get("content"):
            content = attr["content"].split(";", 1)[-1]
            if "url=" in content.lower():
                self.links.append(unquote(content.split("=", 1)[1]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append((self._current_form["action"], self._current_form["fields"],
                               self._current_form["method"]))
            self._current_form = None


def _same_host(base: str, absolute: str) -> bool:
    from ..utils import host_from_url, base_scheme_host
    base_host = host_from_url(base)
    target_host = host_from_url(absolute)
    return bool(target_host) and target_host == base_host


async def _crawl_host(ctx: ScanContext, seed: str) -> tuple[int, dict[str, int]]:
    from ..stop import check_stop

    max_pages = int(ctx.http_cfg.get("crawl", {}).get("max_pages", 200))
    max_depth = int(ctx.http_cfg.get("crawl", {}).get("max_depth", 3))
    session = ctx.session_now()

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(seed, 0)]
    stats = {"pages": 0, "links": 0, "forms": 0}
    disallowed = await _robots_disallowed(ctx, seed)

    while queue and stats["pages"] < max_pages:
        check_stop()
        url, depth = queue.pop(0)
        normalized = normalize_url(url, canonical=False)
        path = normalized.split("?", 1)[0].rstrip("/")
        if normalized in visited:
            continue
        if any(disallowed and (path == d or path.startswith(d)) for d in disallowed if d):
            continue
        visited.add(normalized)

        resp = await session.fetch(url, timeout=10)
        if resp is None or resp.status_code >= 400:
            continue
        stats["pages"] += 1
        body = ""
        try:
            body = resp.text or ""
        except Exception:
            continue

        parser = _LinkParser(url)
        try:
            parser.feed(body[:500000])
        except Exception:
            continue
        stats["links"] += len(parser.links)
        for href in parser.links:
            absolute = join_url(url, href)
            if absolute == url or not ctx.scope.is_allowed_url(absolute):
                continue
            n = normalize_url(absolute)
            if n not in visited:
                ctx.store.upsert_url(n, source="crawler")
                if depth < max_depth:
                    queue.append((absolute, depth + 1))
        for action, fields, method in parser.forms:
            stats["forms"] += 1
            absolute = join_url(url, action) if action else url
            if ctx.scope.is_allowed_url(absolute):
                endpoint = normalize_url(absolute)
                for field in fields[:50]:
                    ctx.store.upsert_parameter(endpoint, field, method=method, source="crawler")
    ctx.bump("crawled_pages", stats["pages"])
    return stats["pages"], stats


async def _robots_disallowed(ctx: ScanContext, seed: str) -> list[str]:
    from ..utils import base_scheme_host

    session = ctx.session_now()
    base = base_scheme_host(seed)
    robots = f"{base}/robots.txt"
    if not ctx.scope.is_allowed_url(robots):
        return []
    resp = await session.fetch(robots, timeout=8)
    if resp is None or resp.status_code != 200:
        return []
    rules: list[str] = []
    agent = None
    for line in (resp.text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("user-agent:"):
            agent = line.split(":", 1)[1].strip().lower()
        elif agent in (None, "*") and line.lower().startswith("disallow:"):
            value = line.split(":", 1)[1].strip()
            if value and value != "/":
                rules.append(value)
    return rules


async def run(ctx: ScanContext) -> int:
    if not ctx.http_cfg.get("crawl", {}).get("enabled", True):
        log.info("crawler: disabled in config")
        return 0
    seeds = _seed_urls(ctx)
    if not seeds:
        log.info("crawler: no live seeds yet")
        return 0
    log.info("crawler: crawling %d seeds", len(seeds))
    results = await bounded_map(seeds[: int(ctx.http_cfg.get("url_limit", 20000))],
                                ctx.profile["concurrency"].get("http", 20),
                                lambda s: _crawl_host(ctx, s))
    pages = sum((r if isinstance(r, tuple) else (0, {}) )[0] for r in results
                if not isinstance(r, Exception))
    log.info("crawler: done (%d pages)", pages)
    return int(pages)


def _seed_urls(ctx: ScanContext) -> list[str]:
    seen: set[str] = set()
    # Prefer URLs already observed as live during probing (port-aware roots).
    for row in ctx.store.urls():
        url = row["url"]
        if (url or "").endswith("/") and ctx.scope.is_allowed_url(url):
            seen.add(url)
    for host in [str(r["fqdn"]) for r in ctx.db.assets() if ctx.scope.is_allowed_host(str(r["fqdn"]))]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            if ctx.scope.is_allowed_url(url) and url not in seen:
                seen.add(url)
    return sorted(seen)