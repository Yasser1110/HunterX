"""Scope-aware async HTTP client shared by every web/scan phase.

Every request is:
  1. validated against the scope engine,
  2. rate-limited by a global token bucket,
  3. covered by the global stop switch,
  4. retried with backoff on transient failures,
  5. logged (URL, status, duration) without secrets.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from .config import Config
from .database import Database, utcnow
from .ratelimit import TokenBucket
from .scope import Scope
from .stop import check_stop

log = logging.getLogger("hunterx.http")


class ScanSession:
    def __init__(self, cfg: Config, scope: Scope, db: Database | None = None,
                 run_id: str | None = None) -> None:
        self.cfg = cfg
        self.scope = scope
        self.db = db
        self.run_id = run_id
        self.scan_cfg = cfg.scan_cfg()
        self.http_cfg = cfg.http_cfg()
        self.connect_timeout = float(self.scan_cfg["timeout"].get("connect", 5))
        self.read_timeout = float(self.scan_cfg["timeout"].get("read", 10))
        self.retries = int(self.scan_cfg.get("retries", 2))
        self.limiter = TokenBucket(float(self.scan_cfg["rate_limit"].get("requests_per_second", 5)))
        self.user_agent = self.scan_cfg.get("user_agent", "HunterX/0.2")
        self._client: httpx.AsyncClient | None = None

    async def _client_now(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            timeout = httpx.Timeout(self.read_timeout, connect=self.connect_timeout)
            limits = httpx.Limits(max_connections=200, max_keepalive_connections=50)
            self._client = httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                follow_redirects=True,
                verify=True,
                headers={"User-Agent": self.user_agent},
            )
        return self._client

    async def fetch(self, url: str, *, method: str = "GET", headers: dict[str, str] | None = None,
                    follow_redirects: bool | None = None, check_scope: bool = True,
                    allow_status: set[int] | None = None, timeout: float | None = None) -> httpx.Response | None:
        """Fetch *url* through the safe pipeline; None = blocked or failed."""
        if check_scope and not self.scope.is_allowed_url(url):
            log.debug("blocked by scope: %s", url)
            return None
        await self.limiter.acquire()
        check_stop()

        client = await self._client_now()
        effective_timeout = timeout
        attempts = self.retries + 1
        for attempt in range(attempts):
            check_stop()
            started = utcnow()
            try:
                response = await client.request(
                    method, url, headers=headers or {},
                    follow_redirects=follow_redirects if follow_redirects is not None else True,
                    timeout=effective_timeout,
                )
                self._log_request(url, response.status_code, started, method)
                if response.status_code == 429:
                    delay = _retry_after(response.headers.get("retry-after")) or 3.0
                    log.info("429 on %s -> sleeping %.1fs (Retry-After)", url, delay)
                    await asyncio.sleep(delay)
                    continue
                if allow_status is not None and response.status_code not in allow_status:
                    # Not a fatal error, just not what the caller wants.
                    return response
                return response
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as exc:
                log.debug("fetch failed (attempt %d/%d): %s %s", attempt + 1, attempts, url, exc)
                if attempt < attempts - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
                else:
                    return None
        return None

    def _log_request(self, url: str, status: int, started: str, method: str) -> None:
        log.info("%s %s -> %s", method, url, status, extra={"run_id": self.run_id})
        if self.db:
            pass  # URL persistence is done by callers that know the source

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "ScanSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


async def fetch_tls_info(host: str, port: int = 443, timeout: float = 5.0,
                         server_hostname: str | None = None) -> dict[str, Any] | None:
    """Best-effort TLS certificate info via the ssl module (no third-party lib)."""
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_hostname or host),
            timeout=timeout,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else None
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=2)
    except Exception:
        return None
    if not cert:
        return {"protocol": None, "subject": None, "issuer": None, "not_after": None}
    subject = dict(x[0] for x in cert.get("subject", []) if x)
    issuer = dict(x[0] for x in cert.get("issuer", []) if x)
    return {
        "protocol": ssl_obj.version(),
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "not_after": cert.get("notAfter"),
        "SAN": cert.get("subjectAltName"),
    }