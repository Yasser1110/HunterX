"""JavaScript analysis: endpoint/parameter/secret extraction.

Conservatively scans JS assets for API endpoints, interesting URL paths,
parameter names, and secret-like strings. Secrets are REDACTED before any
persistence or notification (only a masked prefix + suffix survive).
Nothing here executes JavaScript.
"""

from __future__ import annotations

import logging
import re

from ..context import ScanContext
from ..store import Store
from ..utils import bounded_map, normalize_url

log = logging.getLogger("hunterx.web.js")

_ENDPOINT_RE = re.compile(r"""["']((?:/[^"'\s?&]+)+)[?&]?[^"'\s]*["']""")
_PARAM_RE = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]{1,31})=")
_DOMAIN_RE = re.compile(r"https?://([a-z0-9.-]+\.[a-z]{2,})")
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)", re.I)

SECRET_PATTERNS = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("api_key", re.compile(r"(?i)(?:api[_-]?key|apikey|api_token|access[_-]?token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9._\/\-]{12,}[\"']")),
]


def _redact_secret(value: str, keep_head: int = 4, keep_tail: int = 4) -> str:
    if len(value) <= keep_head + keep_tail:
        return "*" * len(value)
    return value[:keep_head] + "*" * 12 + value[-keep_tail:]


def analyze_js(url: str, body: str) -> dict:
    extraction = {
        "endpoints": [],
        "params": [],
        "domains": [],
        "sourcemap": None,
        "secrets": [],
    }
    for m in _ENDPOINT_RE.finditer(body):
        endpoint = m.group(1)
        clean = re.sub(r"\${[^}]+}", "{x}", endpoint)
        if len(clean) > 1 and clean.startswith("/") and clean not in extraction["endpoints"]:
            extraction["endpoints"].append(clean[:300])
    extraction["params"] = sorted(set(_PARAM_RE.findall(body)))[:200]
    for d in _DOMAIN_RE.findall(body):
        if d not in extraction["domains"]:
            extraction["domains"].append(d[:253])
    m = _SOURCEMAP_RE.search(body)
    if m:
        extraction["sourcemap"] = m.group(1)[:400]
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(body):
            extraction["secrets"].append({"kind": kind, "value": _redact_secret(match.group(0))})
    return extraction


async def _analyze_url(ctx: ScanContext, url: str) -> None:
    if not ctx.scope.is_allowed_url(url):
        return
    session = ctx.session_now()
    resp = await session.fetch(url, timeout=15)
    if resp is None:
        return
    body = ""
    try:
        body = resp.text or ""
    except Exception:
        return
    result = analyze_js(url, body[:100000])
    host = url.split("/")[2]
    for ep in result["endpoints"]:
        endpoint_url = normalize_url(f"{url.split('/')[0]}//{host}{ep}")
        if ctx.scope.is_allowed_url(endpoint_url):
            ctx.store.upsert_url(endpoint_url, host=host, path=(ep.split("?")[0] or "/"), source="js-analysis")
            for p in result["params"]:
                ctx.store.upsert_parameter(endpoint_url, p, source="js")
    for domain in result["domains"]:
        if ctx.scope.is_allowed_host(domain):
            ctx.db.upsert_asset(domain, source="js-analysis")
    if result["secrets"]:
        ctx.store.upsert_finding(
            asset=host,
            url=url,
            type_="POTENTIAL_SECRET_IN_JS",
            severity="medium",
            confidence="low",
            source="hunterx-js",
            status="needs_manual_verification",
            evidence={"secrets": result["secrets"][:5],
                      "required": "manually verify whether the token is live and whether the file is in scope"},
        )
    if result["sourcemap"]:
        ctx.store.upsert_finding(
            asset=host,
            url=url,
            type_="SOURCE_MAP_EXPOSED",
            severity="info",
            confidence="medium",
            source="hunterx-js",
            status="needs_manual_verification",
            evidence={"sourcemap": result["sourcemap"]},
        )


async def run(ctx: ScanContext) -> int:
    urls = ctx.store.urls()
    js_urls = [u["url"] for u in urls if u["url"].split("?")[0].endswith(".js")][:500]
    if not js_urls:
        # look for js assets from crawl content-type endpooints is already captured; fallback none
        log.info("js-analysis: no .js URLs yet")
    else:
        log.info("js-analysis: analyzing %d js files", len(js_urls))
        await bounded_map(js_urls, ctx.profile["concurrency"].get("http", 10),
                          lambda u: _analyze_url(ctx, u))
    # Also treat /static/*.js style pages found via discovery as candidates later.
    return len(js_urls)