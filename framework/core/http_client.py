"""Falcon MAG Framework - Unified HTTP Client (Enhanced v2)

Features:
  - User-Agent rotation (10 real browser UAs)
  - Smart exponential backoff (503/429)
  - Adaptive rate limiting (auto-slow on blocking)
  - Circuit breaker (stops if target blocks)
  - Clear blocking detection + reporting
"""
import warnings
import urllib3
import random
import time
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, List
from core.rate_limiter import RateLimiter
from core.logger import get_logger

log = get_logger("http")


# ============================================================
# User-Agent pool (real browsers, updated 2025)
# ============================================================
USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Mobile Chrome (Android)
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]


# ============================================================
# Static resource detection (ADDED 2026-09-20)
# ============================================================
STATIC_EXTENSIONS = {
    ".css", ".js", ".mjs", ".map", ".ico", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".webp", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".webm", ".ogg", ".wav",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".xml", ".txt", ".csv", ".xls", ".xlsx", ".doc", ".docx",
    ".ppt", ".pptx",
}

STATIC_PATH_PREFIXES = (
    "/assets/", "/static/", "/public/", "/dist/", "/build/",
    "/media/", "/images/", "/img/", "/css/", "/js/", "/fonts/",
    "/_next/static/", "/_nuxt/", "/_astro/", "/wp-content/uploads/",
)

STATIC_EXACT_FILES = {
    "favicon.ico", "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "manifest.json", "browserconfig.xml", "crossdomain.xml",
    "clientaccesspolicy.xml", "humans.txt", "security.txt",
}


def is_static_resource(url: str) -> bool:
    """Check if a URL points to a static resource (should not be fuzzed)."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        path = (p.path or "/").lower()
        filename = path.rsplit("/", 1)[-1]

        # Exact known files
        if filename in STATIC_EXACT_FILES:
            return True

        # Extension check (last dot)
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[-1]
            if ext in STATIC_EXTENSIONS:
                return True

        # Path prefix check
        for prefix in STATIC_PATH_PREFIXES:
            if prefix in path:
                return True

        return False
    except Exception:
        return False


def is_testable_url(url: str) -> bool:
    """URL is safe to inject payloads into."""
    return not is_static_resource(url)


class HTTPResponse:
    """Normalized HTTP response."""
    __slots__ = ("url", "status", "headers", "text", "content",
                 "elapsed_ms", "error", "redirects", "blocked")

    def __init__(self, url, status, headers, text, content,
                 elapsed_ms=0.0, error="", redirects=None, blocked=False):
        self.url = url
        self.status = status
        self.headers = headers
        self.text = text
        self.content = content
        self.elapsed_ms = elapsed_ms
        self.error = error
        self.redirects = redirects or []
        self.blocked = blocked

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def json(self) -> Any:
        import json
        try:
            return json.loads(self.text)
        except Exception:
            return None

    def __repr__(self):
        return f"<HTTPResponse {self.status} {self.url[:60]}>"


class HTTPClient:
    """Enhanced HTTP client with UA rotation, smart backoff, and circuit breaker."""

    # Circuit breaker thresholds
    MAX_CONSECUTIVE_BLOCKS = 5       # stop after 5 consecutive 503s
    MAX_TOTAL_BLOCKS = 15            # or 15 total in session

    def __init__(self, config: dict):
        self.config = config
        scan_cfg = config.get("scan", {})

        # Adaptive rate limiter
        base_rate = scan_cfg.get("rate_limit", 20)
        self.rate_limiter = RateLimiter(
            rate_per_sec=base_rate,
            burst=scan_cfg.get("burst", 5),
        )
        self._base_rate = base_rate
        self._current_rate = base_rate

        # Session
        self.session = requests.Session()

        # User-Agent: use configured or random from pool
        ua = scan_cfg.get("user_agent", "").strip()
        if ua and ua != "FalconMAG/1.0":
            self._default_ua = ua
            self._rotate_ua = False
        else:
            self._default_ua = random.choice(USER_AGENTS)
            self._rotate_ua = True

        headers = {"User-Agent": self._default_ua}
        headers.update(config.get("headers", {}))
        self.session.headers.update(headers)
        self.session.verify = scan_cfg.get("verify_ssl", False)

        # Proxy
        proxy = scan_cfg.get("proxy")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Retry adapter (for connection errors only, not 503)
        retries = scan_cfg.get("retries", 1)
        retry = Retry(
            total=retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.history: list = []

        # Blocking tracking
        self._lock = threading.Lock()
        self._consecutive_blocks = 0
        self._total_blocks = 0
        self._circuit_open = False
        self._last_503_time = 0
        self._backoff_until = 0
        self._backoff_level = 0          # 0, 1, 2, 3 → 0s, 5s, 15s, 45s

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    def _rotate_user_agent(self):
        """Rotate UA for next request (only if not pinned by config)."""
        if not self._rotate_ua:
            return
        ua = random.choice(USER_AGENTS)
        self.session.headers["User-Agent"] = ua

    def _is_blocking_status(self, status: int) -> bool:
        """503/429/403-frequent → blocking signals."""
        return status in (429, 503)

    def _handle_block(self):
        """Called when a 503/429 is detected."""
        with self._lock:
            self._consecutive_blocks += 1
            self._total_blocks += 1

            # Circuit breaker
            if (self._consecutive_blocks >= self.MAX_CONSECUTIVE_BLOCKS or
                    self._total_blocks >= self.MAX_TOTAL_BLOCKS):
                if not self._circuit_open:
                    self._circuit_open = True
                    log.warning(
                        f"[!] CIRCUIT BREAKER OPEN — target blocking "
                        f"({self._total_blocks} blocks). Stopping requests."
                    )
                return

            # Exponential backoff: 5s → 15s → 45s → 60s
            backoff_map = {1: 5, 2: 15, 3: 45}
            backoff = backoff_map.get(self._consecutive_blocks, 60)
            self._backoff_until = time.time() + backoff
            self._backoff_level = min(self._consecutive_blocks, 3)

            log.warning(
                f"[!] Target blocking detected (503/429). "
                f"Backoff {backoff}s (consecutive: {self._consecutive_blocks})"
            )

    def _handle_success(self):
        """Reset block counters on success."""
        with self._lock:
            if self._consecutive_blocks > 0:
                self._consecutive_blocks = 0
                self._backoff_level = 0
                self._backoff_until = 0
                log.info("[+] Target responding again — resuming normal rate")

    def _wait_backoff(self):
        """Wait if we're in a backoff period."""
        wait = self._backoff_until - time.time()
        if wait > 0:
            log.debug(f"  ... waiting backoff {wait:.1f}s")
            time.sleep(wait)

    @property
    def is_blocked(self) -> bool:
        """Has the target blocked us (circuit open)?"""
        return self._circuit_open

    @property
    def block_summary(self) -> dict:
        return {
            "total_blocks": self._total_blocks,
            "consecutive_blocks": self._consecutive_blocks,
            "circuit_open": self._circuit_open,
        }

    # ----------------------------------------------------------
    # Core request
    # ----------------------------------------------------------
    def request(self, method: str, url: str, **kwargs) -> Optional[HTTPResponse]:
        """Send request with UA rotation, backoff, and circuit breaker."""

        # Circuit breaker
        if self._circuit_open:
            return HTTPResponse(
                url=url, status=0, headers={}, text="", content=b"",
                error="Circuit breaker open: target blocking requests",
                blocked=True,
            )

        # Exclude
        for exc in self.config.get("exclude", []):
            if exc and exc in url:
                log.debug(f"Skipped (excluded): {url}")
                return None

        # Scope
        if not self.in_scope(url):
            log.debug(f"Skipped (out of scope): {url}")
            return None

        # Wait for backoff if active
        self._wait_backoff()

        # Rotate UA (every request)
        self._rotate_user_agent()

        # Rate limit
        self.rate_limiter.wait_sync()

        scan_cfg = self.config.get("scan", {})
        kwargs.setdefault("timeout", scan_cfg.get("timeout", 10))
        kwargs.setdefault("allow_redirects", scan_cfg.get("follow_redirects", True))

        try:
            resp = self.session.request(method, url, **kwargs)

            entry = {
                "method": method,
                "url": url,
                "status": resp.status_code,
                "size": len(resp.content),
                "time": round(resp.elapsed.total_seconds(), 3),
            }
            self.history.append(entry)

            # Detect blocking
            blocked = self._is_blocking_status(resp.status_code)

            if blocked:
                self._handle_block()
            else:
                self._handle_success()

            return HTTPResponse(
                url=str(resp.url),
                status=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text[:500000],
                content=resp.content[:500000],
                elapsed_ms=resp.elapsed.total_seconds() * 1000,
                redirects=[r.url for r in resp.history],
                blocked=blocked,
            )

        except requests.RequestException as e:
            err_str = str(e)

            # Detect 503 in exception message
            if "too many 503" in err_str or "503" in err_str:
                self._handle_block()
                log.debug(f"Request failed (503): {method} {url}")
            else:
                log.debug(f"Request failed: {method} {url} -> {e}")

            self.history.append({
                "method": method, "url": url,
                "status": "ERROR", "error": err_str,
            })

            return HTTPResponse(
                url=url, status=0, headers={}, text="", content=b"",
                error=err_str,
                blocked=("503" in err_str),
            )

    # ----------------------------------------------------------
    # Convenience methods
    # ----------------------------------------------------------
    def get(self, url: str, **kw) -> Optional[HTTPResponse]:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Optional[HTTPResponse]:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw) -> Optional[HTTPResponse]:
        return self.request("PUT", url, **kw)

    def delete(self, url: str, **kw) -> Optional[HTTPResponse]:
        return self.request("DELETE", url, **kw)

    def head(self, url: str, **kw) -> Optional[HTTPResponse]:
        return self.request("HEAD", url, **kw)

    def options(self, url: str, **kw) -> Optional[HTTPResponse]:
        return self.request("OPTIONS", url, **kw)

    # ----------------------------------------------------------
    # Aliases (for backward compat with modules)
    # ----------------------------------------------------------
    def scan_request(self, url: str, method: str = "GET", **kw):
        """Alias: scan_request(url, method='GET') -> HTTPResponse"""
        return self.request(method, url, **kw)

    def scan_get(self, url: str, **kw):
        return self.get(url, **kw)

    def scan_post(self, url: str, **kw):
        return self.post(url, **kw)

    def scan_put(self, url: str, **kw):
        return self.put(url, **kw)

    def scan_delete(self, url: str, **kw):
        return self.delete(url, **kw)

    def scan_options(self, url: str, **kw):
        return self.options(url, **kw)

    def scan_head(self, url: str, **kw):
        return self.head(url, **kw)

    # ----------------------------------------------------------
    # Scope check
    # ----------------------------------------------------------
    def in_scope(self, url: str) -> bool:
        """Check if URL is in scope (allow all if no scope defined)."""
        scope = self.config.get("scope", [])
        if not scope:
            return True
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            for s in scope:
                if s and (s == host or host.endswith("." + s.lstrip("*."))):
                    return True
            return False
        except Exception:
            return True
