"""Port / service discovery.

Preferred tool: ``naabu`` (safe, fast, low noise). Optional ``nmap`` for
service/version fingerprinting on discovered open ports. Fallback: an
asyncio TCP connect scan over the configured common port list, with bounded
concurrency and short timeouts. Nothing here touches application state.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from ..context import ScanContext
from ..utils import bounded_map

log = logging.getLogger("hunterx.network.ports")


async def _naabu(ctx: ScanContext, hosts: list[str]) -> set[tuple[str, int]]:
    if not ctx.tools.available("naabu"):
        return set()
    found: set[tuple[str, int]] = set()
    for host in hosts:
        result = await ctx.atool(
            "naabu", ["-host", host, "-silent", "-top-ports", "100", "-rate", str(min(200, int(ctx.profile["rate_limit"]["requests_per_second"]) * 4))],
            timeout=300,
        )
        if not result.ok or not result.output_file:
            continue
        try:
            text = open(result.output_file, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            try:
                h, port = line.rsplit(":", 1)
                found.add((h.strip(), int(port)))
            except ValueError:
                continue
    return found


async def _nmap_services(ctx: ScanContext, hosts: list[str]) -> list[tuple[str, int, str, str]]:
    if not ctx.tools.available("nmap") or not ctx.cfg.ports_cfg().get("nmap", {}).get("enabled"):
        return []
    out: list[tuple[str, int, str, str]] = []
    top = int(ctx.cfg.ports_cfg()["nmap"].get("top_ports", 200))
    for host in hosts:
        result = await ctx.atool(
            "nmap", ["-Pn", "-sT", "--top-ports", str(top), "--open", "-T3", "-oG", "-", "-v", host],
            timeout=600,
        )
        if not result.ok or not result.output_file:
            continue
        try:
            text = open(result.output_file, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for line in text.splitlines():
            for match in re.finditer(r"(\d+)/open/(\w+)/(?:[^/]*)/([^/]*)/([^/]*)/", line):
                port_no = int(match.group(1))
                service = match.group(3)
                version = match.group(4).strip()
                out.append((host, port_no, service, version))
    return out


async def _connect_scan(ctx: ScanContext, host: str, ports: list[int]) -> list[int]:
    from ..stop import check_stop

    concurrency = ctx.profile["concurrency"].get("http", 20)
    sem = asyncio.Semaphore(concurrency)
    timeout = float(ctx.scan_cfg["timeout"].get("connect", 3))

    async def try_port(port: int) -> int | None:
        check_stop()
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except (asyncio.TimeoutError, OSError):
                return None

    results = await bounded_map(ports, concurrency, try_port, stop=check_stop)
    return [p for p in results if not isinstance(p, Exception) and p is not None]


async def run(ctx: ScanContext) -> int:
    from ..stop import check_stop

    ports_cfg = ctx.cfg.ports_cfg()
    if ctx.profile_name == "passive":
        log.info("ports: passive profile - skipping port scan")
        return 0
    hosts = [str(r["fqdn"]) for r in ctx.db.assets() if ctx.scope.is_allowed_host(str(r["fqdn"]))]
    if not hosts:
        return 0
    common_ports = [int(p) for p in ports_cfg.get("common", [])]
    found: set[tuple[str, int]] = set()

    if ports_cfg.get("enabled", True):
        if ctx.tools.available("naabu") and ports_cfg.get("naabu", {}).get("enabled", True):
            found.update(await _naabu(ctx, hosts))
        else:
            for host in hosts:
                check_stop()
                opens = await _connect_scan(ctx, host, common_ports)
                for port in opens:
                    found.add((host, int(port)))
            log.info("ports: fallback connect-scan across %d hosts", len(hosts))

    for host, port in sorted(found):
        ctx.store.upsert_port(host, port, protocol="tcp")

    # Service/version enrichment via nmap (optional, safe defaults).
    services = await _nmap_services(ctx, [h for h, _ in found])
    for host, port, service, version in services:
        ctx.store.upsert_port(host, port, protocol="tcp", service=service, version=version)

    log.info("ports: %d open ports across %d hosts", len(found), len(hosts))
    ctx.bump("open_ports", len(found))
    return len(found)