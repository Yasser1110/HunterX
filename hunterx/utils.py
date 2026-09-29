"""Shared helpers: URL normalization, async concurrency, hashing."""

from __future__ import annotations

import asyncio
import hashlib
import urllib.parse
from typing import Any, Awaitable, Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")

DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(url: str, *, canonical: bool = True) -> str:
    """Stable URL form for deduplication.

    * lowercases scheme + host
    * strips default ports and fragments
    * fully-qualified relative URLs are not supported (returned unchanged)
    """
    if not url or not isinstance(url, str):
        return ""
    url = url.strip()
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    if parts.scheme not in ("http", "https"):
        return url
    host = (parts.hostname or "").lower()
    port = parts.port
    if port in DEFAULT_PORTS.values():
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if canonical and path != "/" and path.endswith("/"):
        path = path.rstrip("/") or "/"
    query = parts.query
    fragment = ""  # fragments never matter for dedup
    return urllib.parse.urlunsplit((parts.scheme, netloc, path, query, fragment))


def host_from_url(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def scheme_from_url(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).scheme
    except ValueError:
        return ""


def is_http_url(url: str) -> bool:
    try:
        return urllib.parse.urlsplit(url).scheme in ("http", "https")
    except ValueError:
        return False


def base_scheme_host(of_url: str) -> str:
    """``https://a.example.com/x?a=1`` -> ``https://a.example.com``"""
    parts = urllib.parse.urlsplit(of_url)
    port = "" if parts.port in DEFAULT_PORTS.values() or parts.port is None else f":{parts.port}"
    return f"{parts.scheme}://{parts.hostname.lower()}{port}"


def join_url(base: str, href: str) -> str:
    return urllib.parse.urljoin(base, href.strip())


def chunked(items: Iterable[T], size: int) -> list[list[T]]:
    it = list(items)
    return [it[i : i + size] for i in range(0, len(it), size)]


async def bounded_map(
    items: Iterable[T],
    concurrency: int,
    fn: Callable[[T], Awaitable[R]],
    *,
    stop: Callable[[], None] | None = None,
) -> list[R]:
    """Run ``fn`` per item with at most *concurrency* in flight."""
    sem = asyncio.Semaphore(max(1, concurrency))

    async def worker(item: T) -> R:
        if stop is not None:
            stop()
        async with sem:
            return await fn(item)

    return await asyncio.gather(*(worker(i) for i in items), return_exceptions=True)


async def bounded_consume(
    items: Iterable[T],
    concurrency: int,
    fn: Callable[[T], Awaitable[R]],
    *,
    stop: Callable[[], None] | None = None,
) -> list[R]:
    """Same as :func:`bounded_map` but silently swallows StopRequested and
    returns the exceptions with their items for the caller to inspect."""
    results = await bounded_map(items, concurrency, fn, stop=stop)
    return list(results)


def sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def redact_text(text: str, keep: int = 120) -> str:
    """Short snippet builder used inside findings evidence."""
    text = " ".join(str(text).split())
    return text[:keep] + ("…" if len(text) > keep else "")


def version_tuple(version: str | None) -> tuple[int, ...] | None:
    """Parse dotted version to numeric tuple (ignore non-numeric tokens)."""
    if not version:
        return None
    out: list[int] = []
    for token in str(version).split("."):
        digits = ""
        for ch in token:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits and not out:
            continue
        if not digits:
            break
        out.append(int(digits))
    return tuple(out) if out else None


class AsyncTaskTracker:
    """Simple ordered task bookkeeping for phases that spawn many workers."""

    def __init__(self, max_pending: int = 5000) -> None:
        self._sem = asyncio.Semaphore(max_pending)
        self.tasks: list[asyncio.Task] = []

    async def wait(self) -> None:
        if not self.tasks:
            return
        for task in self.tasks:
            if not task.done():
                await task
        self.tasks = []