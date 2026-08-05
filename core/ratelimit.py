"""
Per-host token bucket rate limiter with jitter and adaptive backoff.

Keeps the campaign alive on aggressive WAFs by exponentially backing off
when the target starts refusing (429) or slowing, then recovering
when things stabilize.
"""
from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict

import structlog

logger = structlog.get_logger(__name__)


class HostBucket:
    """Token-bucket rate limiter for a single host.

    Args:
        rps: Requests per second (token refill rate).
        burst: Maximum burst size (bucket capacity).
    """

    def __init__(self, rps: float, burst: int = 5):
        self.rate = rps
        self.burst = burst
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self.backoff = 1.0
        self.lock = asyncio.Lock()
        self._total_waits = 0
        self._total_acquired = 0

    async def acquire(self) -> None:
        """Wait until a token is available, then consume one.

        Introduces jitter (0-50ms) to avoid thundering-herd on the target.
        Respects the current backoff multiplier.
        """
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.updated
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.updated = now

            if self.tokens < 1.0:
                wait = ((1.0 - self.tokens) / self.rate) * self.backoff
                jitter = random.uniform(0, 0.05)
                total_wait = wait + jitter
                self._total_waits += 1
                logger.debug(
                    "rate_limit_wait",
                    wait_s=round(total_wait, 3),
                    backoff=round(self.backoff, 2),
                )
                await asyncio.sleep(total_wait)
                # After sleeping, recalculate tokens
                now2 = time.monotonic()
                self.tokens = min(
                    self.burst,
                    self.tokens + (now2 - self.updated) * self.rate,
                )
                self.updated = now2

            self.tokens -= 1.0
            self._total_acquired += 1

    def on_429_or_slowdown(self) -> None:
        """Exponentially increase backoff (capped at 30s multiplier)."""
        old = self.backoff
        self.backoff = min(self.backoff * 2.0, 30.0)
        logger.warning(
            "rate_limit_backoff_increased",
            old=round(old, 2),
            new=round(self.backoff, 2),
        )

    def on_success(self) -> None:
        """Gradually recover from backoff (0.9x decay)."""
        if self.backoff > 1.0:
            self.backoff = max(1.0, self.backoff * 0.9)

    @property
    def stats(self) -> dict:
        return {
            "total_acquired": self._total_acquired,
            "total_waits": self._total_waits,
            "current_backoff": round(self.backoff, 2),
            "current_tokens": round(self.tokens, 2),
        }


class RateLimiter:
    """Manages per-host token buckets.

    Automatically creates a new bucket when a new host is first seen.
    """

    def __init__(self, rps: float = 30.0, burst: int = 5):
        self.rps = rps
        self.burst = burst
        self._buckets: dict[str, HostBucket] = defaultdict(
            lambda: HostBucket(self.rps, self.burst)
        )

    def bucket(self, host: str) -> HostBucket:
        return self._buckets[host]

    async def acquire(self, host: str) -> None:
        await self._buckets[host].acquire()

    def on_429(self, host: str) -> None:
        self._buckets[host].on_429_or_slowdown()

    def on_success(self, host: str) -> None:
        self._buckets[host].on_success()

    @property
    def all_stats(self) -> dict[str, dict]:
        return {host: bucket.stats for host, bucket in self._buckets.items()}
