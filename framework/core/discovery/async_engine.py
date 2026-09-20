"""Async discovery engine using httpx - 5-10x faster than sync."""
import asyncio
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin

from core.logger import get_logger
from .intelligence import URLNormalizer, ScoreRanker, ScopeGuard
from .sources_history import fetch_all_historical

log = get_logger("discovery.async")

try:
    import httpx
    HAS_HTTPX = True
except Exception:
    HAS_HTTPX = False


@dataclass
class AsyncDiscoveryConfig:
    target: str
    max_pages: int = 50
    max_depth: int = 3
    budget_requests: int = 300
    concurrency: int = 20
    timeout: float = 8.0
    use_history: bool = True
    use_tls_impersonate: bool = False


@dataclass
class AsyncDiscoveryResult:
    target: str
    endpoints: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    js_files: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    def summary(self):
        s = self.stats
        return (
            "Async Discovery of " + self.target + "\n"
            "  Endpoints: " + str(len(self.endpoints)) + "\n"
            "  JS files: " + str(len(self.js_files)) + "\n"
            "  Requests: " + str(s.get("requests", 0)) + "\n"
            "  Duration: " + ("%.1f" % s.get("duration", 0)) + "s"
        )


class AsyncDiscoveryEngine:
    def __init__(self, config):
        self.config = config
        self.scope = ScopeGuard(config.target)
        self.ranker = ScoreRanker()
        self.normalizer = URLNormalizer()
        self.stats = {"requests": 0, "errors": 0}
        self._sem = asyncio.Semaphore(config.concurrency)
        self._client = None
        self._results_lock = asyncio.Lock()

    async def _get_client(self):
        if self._client is None:
            limits = httpx.Limits(
                max_connections=self.config.concurrency * 2,
                max_keepalive_connections=self.config.concurrency,
            )
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                limits=limits,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "FalconMAG/2.0"},
            )
        return self._client

    async def _fetch(self, url):
        async with self._sem:
            try:
                client = await self._get_client()
                r = await client.get(url)
                self.stats["requests"] += 1
                return r
            except Exception:
                self.stats["errors"] += 1
                return None

    async def discover(self):
        if not HAS_HTTPX:
            return AsyncDiscoveryResult(
                target=self.config.target,
                stats={"error": "httpx not available"},
            )

        t0 = time.time()
        target = self.config.target.rstrip("/")
        log.info("Async Discovery: " + target)

        # 1. Seeds
        seeds = [(target, 0)]
        if self.config.use_history:
            try:
                hist = fetch_all_historical(target, limit=300)
                for u in hist[:300]:
                    if self.scope.in_scope(u):
                        seeds.append((u, 1))
                log.info("  Historical: +" + str(len(hist)) + " seeds")
            except Exception as e:
                log.debug("  history failed: " + str(e))

        # 2. Async crawl
        seen = set()
        pages = []
        js_files = set()

        # Batch fetch
        queue = [s for s in seeds if self.scope.in_scope(s[0])][:self.config.max_pages]
        tasks = [self._fetch(u) for u, _ in queue]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (url, depth), resp in zip(queue, results):
            if isinstance(resp, Exception) or resp is None:
                continue
            if resp.status_code >= 400:
                continue

            key = self.normalizer.normalize(url)
            if key in seen:
                continue
            seen.add(key)

            pages.append({
                "url": url,
                "status": resp.status_code,
                "size": len(resp.content),
                "depth": depth,
            })

            # Extract links + forms + js
            try:
                from .sources import parse_html
                parsed = parse_html(resp.content, url)
                for js in parsed["js_files"]:
                    js_files.add(js)
            except Exception:
                pass

        await self._close()

        endpoints = []
        for p in pages:
            endpoints.append({
                "url": p["url"],
                "status": p["status"],
                "source": "async-crawl",
                "depth": p["depth"],
                "score": self.ranker.score(p["url"]),
            })
        endpoints.sort(key=lambda x: x["score"], reverse=True)

        result = AsyncDiscoveryResult(
            target=target,
            endpoints=endpoints,
            js_files=sorted(js_files),
            stats={
                "duration": time.time() - t0,
                "requests": self.stats["requests"],
                "errors": self.stats["errors"],
            },
        )
        return result

    async def _close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


def async_discover(config):
    return asyncio.run(AsyncDiscoveryEngine(config).discover())
