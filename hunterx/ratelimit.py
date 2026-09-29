"""Asyncio token-bucket rate limiter.

``hunterx scan`` shares one limiter across all phases so a target never
receives more than ``rate_limit.requests_per_second`` requests regardless
of how many workers are active.
"""

from __future__ import annotations

import asyncio
import time


class TokenBucket:
    def __init__(self, rate: float, burst: int | None = None) -> None:
        self.rate = max(float(rate), 0.001)
        self.capacity = float(burst) if burst else max(self.rate, 1.0)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self._tokens + (now - self._updated) * self.rate, self.capacity)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens) / self.rate)


class NullLimiter:
    async def acquire(self) -> None:
        return None