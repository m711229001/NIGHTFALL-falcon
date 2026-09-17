"""Falcon MAG Framework - Unified HTTP Client"""
"""Falcon MAG Framework - Unified HTTP Client"""
import warnings
import urllib3

# Disable SSL warnings globally (we intentionally use verify=False in pentest mode)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import requests
import httpx
from urllib.parse import urlparse
# ... rest of imports
import requests
import httpx
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any
from core.rate_limiter import RateLimiter
from core.logger import get_logger

log = get_logger("http")


class HTTPResponse:
    """Normalized HTTP response."""
    __slots__ = ("url", "status", "headers", "text", "content",
                 "elapsed_ms", "error", "redirects")

    def __init__(self, url, status, headers, text, content,
                 elapsed_ms=0.0, error="", redirects=None):
        self.url = url
        self.status = status
        self.headers = headers
        self.text = text
        self.content = content
        self.elapsed_ms = elapsed_ms
        self.error = error
        self.redirects = redirects or []

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
    """Unified HTTP client with rate limiting and retries."""

    def __init__(self, config: dict):
        self.config = config
        scan_cfg = config.get("scan", {})
        self.rate_limiter = RateLimiter(
            rate_per_sec=scan_cfg.get("rate_limit", 20),
            burst=scan_cfg.get("burst", 5),
        )
        self.session = requests.Session()

        headers = {"User-Agent": scan_cfg.get("user_agent", "FalconMAG/1.0")}
        headers.update(config.get("headers", {}))
        self.session.headers.update(headers)
        self.session.verify = scan_cfg.get("verify_ssl", False)

        proxy = scan_cfg.get("proxy")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        retries = scan_cfg.get("retries", 2)
        retry = Retry(
            total=retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.history: list = []

    # ----------------------------------------------------------
    # Core request
    # ----------------------------------------------------------
    def request(self, method: str, url: str, **kwargs) -> Optional[HTTPResponse]:
        """Send a request with rate limiting."""
        # Check exclude
        for exc in self.config.get("exclude", []):
            if exc and exc in url:
                log.debug(f"Skipped (excluded): {url}")
                return None

        # Check scope
        if not self.in_scope(url):
            log.debug(f"Skipped (out of scope): {url}")
            return None

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

            return HTTPResponse(
                url=str(resp.url),
                status=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text[:500000],
                content=resp.content[:500000],
                elapsed_ms=resp.elapsed.total_seconds() * 1000,
                redirects=[r.url for r in resp.history],
            )
        except requests.RequestException as e:
            log.debug(f"Request failed: {method} {url} -> {e}")
            self.history.append({
                "method": method, "url": url,
                "status": "ERROR", "error": str(e),
            })
            return HTTPResponse(url=url, status=0, headers={}, text="",
                                content=b"", error=str(e))

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
    # Scope check
    # ----------------------------------------------------------
    def in_scope(self, url: str) -> bool:
        """Check if URL is within scope."""
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        if not host:
            return False
        scope = self.config.get("scope", [])
        if not scope:
            return True
        for s in scope:
            s = s.lower().replace("*.", "")
            if host == s or host.endswith("." + s):
                return True
        return False

    # ----------------------------------------------------------
    # Async helper
    # ----------------------------------------------------------
    # ----------------------------------------------------------
    # Convenience: apply HTTP method/body from config
    # ----------------------------------------------------------
    def scan_request(self, url, **extra):
        """Send request using method/body configured in config (if any)."""
        method = self.config.get("_http_method", "GET") or "GET"
        post_data = self.config.get("_post_data", "") or ""
        post_json = self.config.get("_post_json", "") or ""

        kwargs = dict(extra)
        if method in ("POST", "PUT", "PATCH"):
            if post_json:
                try:
                    import json as _json
                    kwargs["json"] = _json.loads(post_json)
                except Exception:
                    kwargs["data"] = post_json
            elif post_data:
                kwargs["data"] = post_data

        return self.request(method, url, **kwargs)

    async def async_get(self, url: str, **kw) -> Optional[HTTPResponse]:
        """Async GET using httpx."""
        try:
            host = urlparse(url).hostname or ""
            await self.rate_limiter.acquire(host)
            timeout = kw.pop("timeout", 10.0)
            async with httpx.AsyncClient(
                timeout=timeout, verify=False,
                follow_redirects=True,
            ) as client:
                resp = await client.request("GET", url, **kw)
                return HTTPResponse(
                    url=str(resp.url),
                    status=resp.status_code,
                    headers=dict(resp.headers),
                    text=resp.text[:500000],
                    content=resp.content[:500000],
                    elapsed_ms=resp.elapsed.total_seconds() * 1000,
                )
        except Exception as e:
            return HTTPResponse(url=url, status=0, headers={}, text="",
                                content=b"", error=str(e))