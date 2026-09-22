"""DNS resolution helpers used across phases."""

from __future__ import annotations

import asyncio
import socket


async def resolve_addresses(host: str, *, include_aaaa: bool = True) -> list[str]:
    """Best-effort A/AAAA resolution using asyncio.getaddrinfo."""
    ips: list[str] = []
    family = socket.AF_UNSPEC if include_aaaa else socket.AF_INET
    try:
        infos = await asyncio.wait_for(asyncio.getaddrinfo(host, None, family, socket.SOCK_STREAM),
                                       timeout=8)
    except (socket.gaierror, asyncio.TimeoutError):
        return ips
    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            ips.append(addr)
    return ips


async def resolve_host(host: str) -> tuple[str, list[str]]:
    tls_host = host
    ips = await resolve_addresses(host)
    return tls_host, ips