# -*- coding: utf-8 -*-
from pathlib import Path
import py_compile
import sys

BASE = Path("framework/core/discovery")
CORE = Path("framework/core")

# ============================================================
# FILE 1: tls_client.py
# ============================================================
TLS_CLIENT = '''
"""TLS impersonation client - bypasses Cloudflare/Akamai via JA3."""
from core.logger import get_logger

log = get_logger("tls_client")

try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except Exception:
    HAS_CURL_CFFI = False
    log.warning("curl_cffi not installed - TLS impersonation disabled")


IMPERSONATE_PROFILES = [
    "chrome124", "chrome120", "chrome119", "chrome116",
    "safari17_0", "firefox133", "edge101",
]


class _Wrap:
    """Wrapper to mimic requests.Response interface."""
    def __init__(self, r):
        self._r = r
        self.status = r.status_code
        self.status_code = r.status_code
        self.headers = dict(r.headers)
        self.content = r.content
        self.text = r.text
        self.url = str(r.url)

    def json(self):
        return self._r.json()


class TLSClient:
    """HTTP client with TLS fingerprint impersonation."""

    def __init__(self, profile="chrome124", timeout=15, proxy=None):
        self.profile = profile
        self.timeout = timeout
        self.proxy = proxy
        self._session = None
        if not HAS_CURL_CFFI:
            raise RuntimeError("curl_cffi not available")

    def _get_session(self):
        if self._session is None:
            self._session = curl_requests.Session(
                impersonate=self.profile,
                timeout=self.timeout,
                verify=False,
            )
            if self.proxy:
                self._session.proxies = {"http": self.proxy, "https": self.proxy}
        return self._session

    def get(self, url, **kwargs):
        try:
            s = self._get_session()
            r = s.get(url, **kwargs)
            return _Wrap(r)
        except Exception as e:
            log.debug("TLS GET failed: " + str(e)[:100])
            return None

    def post(self, url, **kwargs):
        try:
            s = self._get_session()
            r = s.post(url, **kwargs)
            return _Wrap(r)
        except Exception as e:
            log.debug("TLS POST failed: " + str(e)[:100])
            return None


def get_tls_client(profile="chrome124"):
    if not HAS_CURL_CFFI:
        return None
    try:
        return TLSClient(profile=profile)
    except Exception as e:
        log.debug("TLS client failed: " + str(e))
        return None
'''

# ============================================================
# FILE 2: async_engine.py
# ============================================================
ASYNC_ENGINE = '''
"""Async discovery engine using httpx - 5-10x faster than sync."""
import asyncio
import time
from dataclasses import dataclass, field, asdict

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
            "Async Discovery of " + self.target + "\\n"
            "  Endpoints: " + str(len(self.endpoints)) + "\\n"
            "  JS files: " + str(len(self.js_files)) + "\\n"
            "  Requests: " + str(s.get("requests", 0)) + "\\n"
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

        seen = set()
        pages = []
        js_files = set()

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

        return AsyncDiscoveryResult(
            target=target,
            endpoints=endpoints,
            js_files=sorted(js_files),
            stats={
                "duration": time.time() - t0,
                "requests": self.stats["requests"],
                "errors": self.stats["errors"],
            },
        )

    async def _close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


def async_discover(config):
    return asyncio.run(AsyncDiscoveryEngine(config).discover())
'''


def patch_http_client():
    hc_path = CORE / "http_client.py"
    src = hc_path.read_text(encoding="utf-8")

    if "HAS_TLS_IMPERSONATE" in src:
        print("  http_client.py already patched - skipping")
        return

    OLD = 'log = get_logger("http")'
    NEW = '''log = get_logger("http")

# TLS impersonation (optional) - ADDED 2026-09-20
try:
    from core.discovery.tls_client import get_tls_client, HAS_CURL_CFFI
    HAS_TLS_IMPERSONATE = HAS_CURL_CFFI
except Exception:
    HAS_TLS_IMPERSONATE = False
    def get_tls_client(profile="chrome124"):
        return None'''

    if OLD not in src:
        print("  [FAIL] log line not found")
        return
    if src.count(OLD) != 1:
        print("  [FAIL] log line multiple matches")
        return
    src = src.replace(OLD, NEW, 1)
    hc_path.write_text(src, encoding="utf-8")
    print("  [OK]   TLS import added")


def update_requirements():
    req_path = Path("requirements.txt")
    src = req_path.read_text(encoding="utf-8")

    if "curl_cffi" in src:
        print("  requirements.txt already has curl_cffi - skipping")
        return

    src = src.rstrip() + "\\n\\n# TLS impersonation (JA3 bypass)\\ncurl_cffi>=0.7.0\\n"
    req_path.write_text(src, encoding="utf-8")
    print("  [OK]   curl_cffi added")


def main():
    print("=" * 60)
    print("Installing Package B: Async + TLS Impersonation")
    print("=" * 60)

    tls_path = BASE / "tls_client.py"
    tls_path.write_text(TLS_CLIENT.lstrip(), encoding="utf-8")
    print("  wrote tls_client.py (" + str(len(TLS_CLIENT)) + " chars)")

    async_path = BASE / "async_engine.py"
    async_path.write_text(ASYNC_ENGINE.lstrip(), encoding="utf-8")
    print("  wrote async_engine.py (" + str(len(ASYNC_ENGINE)) + " chars)")

    print()
    print("Patching http_client.py:")
    patch_http_client()

    print()
    print("Updating requirements.txt:")
    update_requirements()

    print()
    print("Syntax check:")
    errors = 0
    for f in ["tls_client.py", "async_engine.py"]:
        path = BASE / f
        try:
            py_compile.compile(str(path), doraise=True)
            print("  [OK]   " + f)
        except py_compile.PyCompileError as e:
            print("  [FAIL] " + f + ": " + str(e))
            errors += 1

    try:
        py_compile.compile(str(CORE / "http_client.py"), doraise=True)
        print("  [OK]   http_client.py")
    except py_compile.PyCompileError as e:
        print("  [FAIL] http_client.py: " + str(e))
        errors += 1

    print()
    if errors:
        print("FAILED")
        sys.exit(1)
    print("SUCCESS - Package B installed")
    print()
    print("NEXT: docker compose build backend && docker compose up -d backend")


if __name__ == "__main__":
    main()