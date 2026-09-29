"""DNS enumeration for every in-scope hostname.

Collects A/AAAA/CNAME/MX/NS/TXT/CAA/SOA using dnspython (fallback: ``dig``),
records them, and flags *dangling CNAME* conditions as
``POTENTIAL_SUBDOMAIN_TAKEOVER`` (requires manual verification - never
claimed as a confirmed takeover).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..context import ScanContext
from ..utils import bounded_map

log = logging.getLogger("hunterx.discovery.dns")

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"]

TAKEOVER_SERVICES = (
    "github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com",
    "cloudfront.net", "azurewebsites.net", "netlify.app", "surge.sh",
    "pages.dev", "fastly.net", "ghost.io", "readthedocs.io", "pantheon.io",
    "bitbucket.io", "tumblr.com", "wordpress.com", "cargocollective.com",
    "us-east-1.elb.amazonaws.com", "elasticbeanstalk.com", "sentry.io",
    "zendesk.com", "ngrok.io", "servicebus.windows.net", "trafficmanager.net",
)


async def _dig_one(host: str, rtype: str, ctx: ScanContext) -> list[str]:
    result = await ctx.atool("dig", [f"+short", f"{rtype}", host], timeout=20)
    if not result.ok or not result.output_file:
        return []
    try:
        text = open(result.output_file, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


async def _resolve_one(host: str, rtype: str, ctx: ScanContext) -> list[str]:
    try:
        import dns.asyncresolver
        import dns.exception
    except ImportError:
        return await _dig_one(host, rtype, ctx)

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 8
    try:
        if rtype in ("A", "AAAA"):
            # dnspython addresses are handy but asyncio.getaddrinfo is more
            # representative of real clients, so use it for address records.
            return await _resolve_addresses(host, rtype)
        answers = await asyncio.wait_for(resolver.resolve(host, rtype), timeout=10)
        if rtype == "MX":
            return [f"{r.preference} {r.exchange}" for r in answers]
        if rtype == "SOA":
            return [str(answers[0].mname) + " " + str(answers[0].rname)]
        return [str(r).rstrip(".") for r in answers]
    except (dns.exception.DNSException, asyncio.TimeoutError):
        return []


async def _resolve_addresses(host: str, rtype: str) -> list[str]:
    import socket
    family = socket.AF_INET6 if rtype == "AAAA" else socket.AF_INET
    try:
        infos = await asyncio.wait_for(
            asyncio.getaddrinfo(host, None, family, socket.SOCK_STREAM), timeout=6
        )
    except (socket.gaierror, asyncio.TimeoutError):
        return []
    return list(dict.fromkeys(addr[4][0] for addr in infos))


async def _enumerate_host(ctx: ScanContext, host: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        values = await _resolve_one(host, rtype, ctx)
        if values:
            records[rtype] = values
    return host, records


def _is_dangling(cname_target: str) -> bool:
    for service in TAKEOVER_SERVICES:
        if cname_target.endswith(service) or f".{service}" in cname_target:
            return True
    return False


async def run(ctx: ScanContext) -> int:
    hosts = [str(r["fqdn"]) for r in ctx.db.assets()]
    if not hosts:
        log.info("dns: no assets to enumerate yet")
        return 0
    log.info("dns: resolving %d hosts", len(hosts))
    results = await bounded_map(hosts, ctx.profile["concurrency"].get("dns", 20),
                                lambda h: _enumerate_host(ctx, h))
    dangling = 0
    for outcome in results:
        if isinstance(outcome, Exception):
            continue
        host, records = outcome
        asset_id = ctx.db.upsert_asset(host)
        for rtype, values in records.items():
            for value in values:
                try:
                    ctx.db.execute(
                        "INSERT OR IGNORE INTO dns_records(asset_id,type,value,first_seen) "
                        "VALUES(?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                        (asset_id, rtype, value),
                    )
                except Exception as exc:  # PK collisions from concurrent workers are minimized by upsert-ignore
                    log.debug("dns store skip %s %s: %s", host, value, exc)
        # Dangling CNAME heuristic (never a confirmed takeover).
        for value in records.get("CNAME", []):
            target = value.rstrip(".")
            if not _is_dangling(target):
                continue
            addresses = await _resolve_addresses(target, "A")
            if addresses:
                continue
            ctx.store.upsert_finding(
                asset=host,
                url=f"https://{host}/" if ctx.scope.is_allowed_url(f"https://{host}/") else None,
                type_="POTENTIAL_SUBDOMAIN_TAKEOVER",
                severity="low",
                confidence="low",
                source="hunterx-dns",
                status="needs_manual_verification",
                evidence={"cname": target, "service": next((s for s in TAKEOVER_SERVICES if target.endswith(s)), "?"),
                          "nxdomain_heuristic": True,
                          "required": "manually verify whether this asset is actually claimable"},
            )
            dangling += 1
    log.info("dns: %d hosts resolved, %d dangling-CNAME potentials", len(hosts), dangling)
    return len(hosts)