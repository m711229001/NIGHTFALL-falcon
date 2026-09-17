"""Falcon MAG Framework - Rate Limiter (token bucket)"""
import time
import asyncio
from typing import Dict


class RateLimiter:
    """Per-host rate limiter using token bucket algorithm."""

    def __init__(self, rate_per_sec: float = 20.0, burst: int = 5):
        self.rate = rate_per_sec
        self.burst = burst
        self._buckets: Dict[str, tuple] = {}
        self._locks: Dict[str, asyncio.Lock] = {}

    async def acquire(self, host: str) -> None:
        """Wait until a token is available for the host."""
        if host not in self._locks:
            self._locks[host] = asyncio.Lock()
            self._buckets[host] = (float(self.burst), time.monotonic())

        async with self._locks[host]:
            tokens, last = self._buckets[host]
            now = time.monotonic()
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                wait = (1 - tokens) / self.rate
                await asyncio.sleep(wait)
                tokens = 0
            else:
                tokens -= 1
            self._buckets[host] = (tokens, time.monotonic())

    def wait_sync(self) -> None:
        """Synchronous rate limiting (for requests)."""
        elapsed = time.time() - getattr(self, "_last_sync", 0.0)
        min_interval = 1.0 / max(self.rate, 1)
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_sync = time.time()