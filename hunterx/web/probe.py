"""HTTP/HTTPS probing.

Probes ``http://`` and ``https://`` variations for every in-scope asset on
the configured ports plus anything found by the ports phase. Collects status,
headers of interest, title, server banner, redirect target, response time and
(optionally) TLS metadata. Stores each live URL with observed status.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from ..context import ScanContext
from ..httpclient import fetch_tls_info
from ..utils import bounded_map, normalize_url

log = logging.getLogger("hunterx.web.probe")

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

INTERESTING_HEADERS = (
    "server", "x-powered-by", "location", "set-cookie", "x-frame-options",
    "content-security-policy", "strict-transport-security", "www-authenticate",
    "x-aspnet-version", "x-request-id", "via",
)


def _ports_for(ctx: ScanContext, host: str) -> list[int]:
    ports = {int(p) for p in ctx.http_cfg.get("ports", [80, 443])}
    if ctx.cfg.scan_cfg().get("extra_ports"):
        ports.update(int(p) for p in ctx.cfg.scan_cfg()["extra_ports"])
    port_records = ctx.store.ports(host)
    ports.update(int(r["port"]) for r in port_records if r.get("port"))
    if host in {"localhost", "127.0.0.1", "::1"}:
        ports.add(18080)
    return sorted(ports)


async def _probe_one(ctx: ScanContext, host: str, scheme: str, port: int) -> dict[str, Any] | None:
    url = f"{scheme}://{host}:{port}/"
    if not ctx.scope.is_allowed_url(url):
        return None
    session = ctx.session_now()
    started = time.monotonic()
    resp = await session.fetch(url, allow_status=set(range(100, 600)))
    if resp is None:
        return None
    duration_ms = int((time.monotonic() - started) * 1000)

    body = ""
    try:
        body = resp.text if resp.text else ""
    except Exception:
        pass
    title = ""
    m = TITLE_RE.search(body[:20000])
    if m:
        title = m.group(1).strip()[:200]

    headers = {k: (v[:400] if len(v) > 400 else v) for k, v in resp.headers.items() if k.lower() in INTERESTING_HEADERS}

    # Try to converge on a canonical (scheme,port) even after redirects.
    final_url = str(resp.url)
    record = {
        "host": host,
        "scheme": scheme,
        "port": port,
        "url": normalize_url(url),
        "final_url": normalize_url(final_url) if final_url else url,
        "status_code": resp.status_code,
        "title": title,
        "server": headers.get("server", ""),
        "content_length": len(resp.content) if resp.content else 0,
        "redirect_location": headers.get("location", ""),
        "response_time_ms": duration_ms,
        "tech_headers": {k: v for k, v in headers.items()},
        "tls": None,
    }

    if resp.status_code in (401, 403):
        record["notes"] = "auth-required"

    ctx.store.upsert_url(
        urllib_url(url), host=host, scheme=scheme, path="/",
        status_code=resp.status_code, source="probe",
    )
    return record


async def _probe_host(ctx: ScanContext, host: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for port in _ports_for(ctx, host):
        if host == ":" or not host:
            continue
        resp = await _probe_one(ctx, host, "http", port)
        if resp:
            records.append(resp)
        if port in (443, 8443, 9443) or ctx.http_cfg.get("probe_https", True):
            resp = await _probe_one(ctx, host, "https", port)
            if resp:
                records.append(resp)
    return records


async def run(ctx: ScanContext) -> int:
    if ctx.profile_name == "passive":
        log.info("probe: passive profile - skipping HTTP probing")
        return 0
    hosts = [str(r["fqdn"]) for r in ctx.db.assets()]
    hosts = [h for h in hosts if ctx.scope.is_allowed_host(h)]
    if not hosts:
        log.info("probe: no in-scope hosts yet")
        return 0
    log.info("probe: checking %d hosts", len(hosts))
    results = await bounded_map(hosts, ctx.profile["concurrency"].get("http", 20),
                                lambda h: _probe_host(ctx, h))
    live = 0
    for outcome in results:
        if isinstance(outcome, Exception):
            log.debug("probe error: %s", outcome)
            continue
        live += len(outcome)
    log.info("probe: %d live endpoints recorded", live)
    return live


def urllib_url(url: str) -> str:
    # normalize_url already handles this; kept as thin alias for import safety
    return url