"""Falcon MAG Framework - Unified HTTP Client (v3)

Features (all consolidated):
  - User-Agent rotation (10 real browsers)
  - Smart exponential backoff (503/429)
  - Circuit breaker (blocking + unreachable)
  - Timeout tracking
  - Preflight connectivity check
  - Auth: cookies, bearer, basic, custom headers
  - Session verification
  - Scope + exclude filters
  - Static resource skip helper
"""
import warnings
import urllib3
import random
import time
import threading
import socket
from urllib.parse import urlparse

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
# User-Agent pool
# ============================================================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]


# ============================================================
# Static resource detection
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
    """Check if URL points to a static resource."""
    try:
        p = urlparse(url)
        path = (p.path or "/").lower()
        filename = path.rsplit("/", 1)[-1]

        if filename in STATIC_EXACT_FILES:
            return True

        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[-1]
            if ext in STATIC_EXTENSIONS:
                return True

        for prefix in STATIC_PATH_PREFIXES:
            if prefix in path:
                return True

        return False
    except Exception:
        return False


def is_testable_url(url: str) -> bool:
    return not is_static_resource(url)


# ============================================================
# Preflight
# ============================================================
def preflight_check(target: str, timeout: int = 5) -> tuple:
    """Quick connectivity check. Returns (ok, reason)."""
    p = urlparse(target)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)

    if not host:
        return False, "invalid URL"

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
    except socket.timeout:
        return False, f"TCP connect timeout ({host}:{port})"
    except socket.gaierror:
        return False, f"DNS resolution failed for {host}"
    except Exception as e:
        return False, f"connect failed: {str(e)[:60]}"

    try:
        r = requests.head(target, timeout=timeout, verify=False, allow_redirects=True)
        return True, f"HTTP {r.status_code}"
    except Exception:
        return True, "TCP ok"


# ============================================================
# HTTPResponse
# ============================================================
class HTTPResponse:
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


# ============================================================
# HTTPClient
# ============================================================
class HTTPClient:
    MAX_CONSECUTIVE_BLOCKS = 5
    MAX_TOTAL_BLOCKS = 15
    MAX_CONSECUTIVE_TIMEOUTS = 3
    MAX_TOTAL_TIMEOUTS = 10

    def __init__(self, config: dict, **http_kwargs):
        self.config = config
        scan_cfg = config.get("scan", {})

        # --- Rate limiter ---
        base_rate = scan_cfg.get("rate_limit", 20)
        self.rate_limiter = RateLimiter(
            rate_per_sec=base_rate,
            burst=scan_cfg.get("burst", 5),
        )
        self._base_rate = base_rate
        self._current_rate = base_rate

        # --- Session ---
        self.session = requests.Session()

        # --- User-Agent ---
        ua = scan_cfg.get("user_agent", "").strip()
        if ua and ua != "FalconMAG/1.0":
            self._default_ua = ua
            self._rotate_ua = False
        else:
            self._default_ua = random.choice(USER_AGENTS)
            self._rotate_ua = True

        headers = {"User-Agent": self._default_ua}
        headers.update(config.get("headers", {}))
        # Extra headers from CLI
        if http_kwargs.get("extra_headers"):
            headers.update(http_kwargs["extra_headers"])
        self.session.headers.update(headers)
        self.session.verify = scan_cfg.get("verify_ssl", False)

        # --- Auth (cookies, bearer, basic) ---
        self._apply_auth(config)
        self._auth_verified = False
        self._auth_reason = ""

        # --- Proxy ---
        proxy = scan_cfg.get("proxy")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # --- Retry adapter ---
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

        # --- History ---
        self.history: list = []

        # --- Blocking tracking ---
        self._lock = threading.Lock()
        self._consecutive_blocks = 0
        self._total_blocks = 0
        self._circuit_open = False
        self._last_503_time = 0
        self._backoff_until = 0
        self._backoff_level = 0

        # --- Timeout tracking ---
        self._consecutive_timeouts = 0
        self._total_timeouts = 0
        self._host_unreachable = False

    # ----------------------------------------------------------
    # Auth
    # ----------------------------------------------------------
    def _apply_auth(self, config: dict):
        """Apply cookies, bearer token, and basic auth."""
        # 1) Cookie string
        cookie_str = config.get("_manual_cookie") or config.get("manual_cookie")
        if cookie_str:
            try:
                count = 0
                for pair in cookie_str.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        self.session.cookies.set(k.strip(), v.strip())
                        count += 1
                log.info(f"[auth] Loaded {count} cookies")
            except Exception as e:
                log.warning(f"[auth] Cookie parse failed: {e}")

        # 2) Bearer token
        bearer = config.get("_bearer_token") or config.get("bearer_token")
        if bearer:
            self.session.headers["Authorization"] = f"Bearer {bearer}"
            log.info("[auth] Bearer token applied")

        # 3) Basic auth
        username = config.get("_auth_username")
        password = config.get("_auth_password")
        if username and password:
            self.session.auth = (username, password)
            log.info("[auth] Basic auth applied")

        # 4) Custom auth headers
        auth_headers = config.get("_auth_headers") or {}
        if isinstance(auth_headers, dict):
            for k, v in auth_headers.items():
                self.session.headers[k] = v

    def verify_auth(self, target: str) -> tuple:
        """Check that auth is working (not redirected to login)."""
        has_cookies = len(self.session.cookies) > 0
        has_bearer = "Authorization" in self.session.headers

        if not has_cookies and not has_bearer:
            return False, "no auth configured"

        try:
            r = self.session.get(target, timeout=8, verify=False, allow_redirects=True)
            status = r.status_code
            final_url = str(r.url).lower()

            login_hints = ("/login", "/signin", "/auth/", "/sso", "/account/login")
            if any(h in final_url for h in login_hints):
                return False, f"redirected to login"

            if status in (200, 201, 202, 204):
                return True, f"HTTP {status}"

            return False, f"HTTP {status}"
        except Exception as e:
            return False, str(e)[:80]

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    def _rotate_user_agent(self):
        if not self._rotate_ua:
            return
        self.session.headers["User-Agent"] = random.choice(USER_AGENTS)

    def _is_blocking_status(self, status: int) -> bool:
        return status in (429, 503)

    def _handle_block(self):
        with self._lock:
            self._consecutive_blocks += 1
            self._total_blocks += 1

            if (self._consecutive_blocks >= self.MAX_CONSECUTIVE_BLOCKS or
                    self._total_blocks >= self.MAX_TOTAL_BLOCKS):
                if not self._circuit_open:
                    self._circuit_open = True
                    log.warning(
                        f"[!] CIRCUIT BREAKER OPEN — target blocking "
                        f"({self._total_blocks} blocks). Stopping requests."
                    )
                return

            backoff_map = {1: 5, 2: 15, 3: 45}
            backoff = backoff_map.get(self._consecutive_blocks, 60)
            self._backoff_until = time.time() + backoff
            self._backoff_level = min(self._consecutive_blocks, 3)

            log.warning(
                f"[!] Target blocking detected (503/429). "
                f"Backoff {backoff}s (consecutive: {self._consecutive_blocks})"
            )

    def _handle_success(self):
        with self._lock:
            if self._consecutive_blocks > 0:
                self._consecutive_blocks = 0
                self._backoff_level = 0
                self._backoff_until = 0
                log.info("[+] Target responding again — resuming normal rate")

    def _wait_backoff(self):
        wait = self._backoff_until - time.time()
        if wait > 0:
            log.debug(f"  ... waiting backoff {wait:.1f}s")
            time.sleep(wait)

    def _handle_timeout(self):
        with self._lock:
            self._consecutive_timeouts += 1
            self._total_timeouts += 1
            ct = self._consecutive_timeouts

            if (ct >= self.MAX_CONSECUTIVE_TIMEOUTS or
                    self._total_timeouts >= self.MAX_TOTAL_TIMEOUTS):
                if not self._host_unreachable:
                    self._host_unreachable = True
                    log.warning(f"[!] TARGET UNREACHABLE — {ct} consecutive timeouts. Aborting.")
            else:
                log.warning(f"  [timeout] {ct}/{self.MAX_CONSECUTIVE_TIMEOUTS}")

    def _reset_timeouts(self):
        with self._lock:
            self._consecutive_timeouts = 0

    # ----------------------------------------------------------
    # Properties
    # ----------------------------------------------------------
    @property
    def is_blocked(self) -> bool:
        return self._circuit_open

    @property
    def is_unreachable(self) -> bool:
        return self._host_unreachable

    @property
    def block_summary(self) -> dict:
        return {
            "total_blocks": self._total_blocks,
            "consecutive_blocks": self._consecutive_blocks,
            "circuit_open": self._circuit_open,
            "total_timeouts": self._total_timeouts,
            "host_unreachable": self._host_unreachable,
        }

    # ----------------------------------------------------------
    # Core request
    # ----------------------------------------------------------
    def request(self, method: str, url: str, **kwargs) -> Optional[HTTPResponse]:
        # Circuit breaker
        if self._circuit_open:
            return HTTPResponse(
                url=url, status=0, headers={}, text="", content=b"",
                error="Circuit breaker open: target blocking",
                blocked=True,
            )
        if self._host_unreachable:
            return HTTPResponse(
                url=url, status=0, headers={}, text="", content=b"",
                error="Target unreachable",
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

        # Backoff
        self._wait_backoff()

        # UA rotation
        self._rotate_user_agent()

        # Rate limit
        self.rate_limiter.wait_sync()

        scan_cfg = self.config.get("scan", {})
        kwargs.setdefault("timeout", scan_cfg.get("timeout", 10))
        kwargs.setdefault("allow_redirects", scan_cfg.get("follow_redirects", True))

        try:
            resp = self.session.request(method, url, **kwargs)

            entry = {
                "method": method, "url": url,
                "status": resp.status_code,
                "size": len(resp.content),
                "time": round(resp.elapsed.total_seconds(), 3),
            }
            self.history.append(entry)

            blocked = self._is_blocking_status(resp.status_code)
            if blocked:
                self._handle_block()
            else:
                self._reset_timeouts()
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
            err_lower = err_str.lower()

            is_timeout = ("timeout" in err_lower or "timed out" in err_lower)
            if is_timeout:
                self._handle_timeout()
                log.debug(f"Request timeout: {method} {url}")
            elif "too many 503" in err_str or "503" in err_str:
                self._handle_block()
                log.debug(f"Request 503: {method} {url}")
            else:
                log.debug(f"Request failed: {method} {url} -> {err_str[:100]}")

            self.history.append({
                "method": method, "url": url,
                "status": "ERROR", "error": err_str,
            })
            return HTTPResponse(
                url=url, status=0, headers={}, text="", content=b"",
                error=err_str, blocked=("503" in err_str),
            )

    # ----------------------------------------------------------
    # Convenience + aliases
    # ----------------------------------------------------------
    def get(self, url, **kw):     return self.request("GET", url, **kw)
    def post(self, url, **kw):    return self.request("POST", url, **kw)
    def put(self, url, **kw):     return self.request("PUT", url, **kw)
    def delete(self, url, **kw):  return self.request("DELETE", url, **kw)
    def head(self, url, **kw):    return self.request("HEAD", url, **kw)
    def options(self, url, **kw): return self.request("OPTIONS", url, **kw)

    # Aliases for backward compat with modules
    def scan_request(self, url, method="GET", **kw):
        return self.request(method, url, **kw)
    def scan_get(self, url, **kw):    return self.get(url, **kw)
    def scan_post(self, url, **kw):   return self.post(url, **kw)
    def scan_put(self, url, **kw):    return self.put(url, **kw)
    def scan_delete(self, url, **kw): return self.delete(url, **kw)
    def scan_options(self, url, **kw): return self.options(url, **kw)
    def scan_head(self, url, **kw):   return self.head(url, **kw)

    # ----------------------------------------------------------
    # Scope
    # ----------------------------------------------------------
    def in_scope(self, url: str) -> bool:
        scope = self.config.get("scope", [])
        if not scope:
            return True
        try:
            host = urlparse(url).hostname or ""
            for s in scope:
                if s and (s == host or host.endswith("." + s.lstrip("*."))):
                    return True
            return False
        except Exception:
            return True
