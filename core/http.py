"""
Async HTTP pool with per-session cookie jars, header profiles, and full
request/response evidence capture.

Every outbound request is gated by the ScopeGuard and RateLimiter before
being dispatched. Responses are captured as Evidence objects for the
triage pipeline.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import structlog

from nightfall.core.ratelimit import RateLimiter
from nightfall.core.scope import ScopeGuard

logger = structlog.get_logger(__name__)


@dataclass
class SessionProfile:
    """Per-identity session configuration (cookies + headers)."""
    name: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Evidence:
    """Captured request/response pair for triage and reporting.

    Every HTTP exchange that the detection engines care about is wrapped
    in an Evidence object. The triage LLM reads these to make its decision.
    """
    url: str
    method: str
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    latency_ms: float = 0.0
    session: str = "default"
    timestamp: float = 0.0
    oob_nonce: Optional[str] = None

    # Classification fields (set by engines after detection)
    vuln_class: str = ""
    subtype: str = ""
    param: str = ""
    payload: str = ""
    marker: str = ""
    confidence: float = 0.0
    severity: str = ""
    reason: str = ""
    remediation: str = ""
    evidence_snip: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        return f"{self.url}|{self.vuln_class}|{self.param}"


class HttpPool:
    """Async HTTP connection pool with scope enforcement and rate limiting.

    Maintains a separate httpx.AsyncClient per session identity (default,
    userA, userB, etc.) for dual-session IDOR differential.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        rate_limiter: RateLimiter,
        sessions: dict[str, SessionProfile] | None = None,
        proxy: str | None = None,
        timeout: float = 20.0,
    ):
        self.guard = guard
        self.rate_limiter = rate_limiter
        self.proxy = proxy
        self.timeout = timeout
        self.sessions = sessions or {"default": SessionProfile("default")}
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._evidence_log: list[Evidence] = []

    def _get_client(self, session: str = "default") -> httpx.AsyncClient:
        """Get or create a per-session AsyncClient."""
        if session not in self._clients:
            profile = self.sessions.get(session, SessionProfile(session))
            self._clients[session] = httpx.AsyncClient(
                proxy=self.proxy,
                follow_redirects=False,
                verify=False,  # pentest mode: accept any cert
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 NIGHTFALL/1.0"
                    ),
                    **profile.headers,
                },
                cookies=profile.cookies,
                timeout=httpx.Timeout(self.timeout, connect=10.0),
            )
        return self._clients[session]

    async def send(
        self,
        method: str,
        url: str,
        *,
        session: str = "default",
        params: dict[str, Any] | None = None,
        data: Any = None,
        content: str | bytes | None = None,
        json_payload: Any = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> Evidence:
        """Send an HTTP request with scope/rate enforcement and evidence capture.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL (must be in scope).
            session: Session identity name.
            params: Query parameters.
            data: Form data body.
            content: Raw body content.
            json_payload: JSON body.
            headers: Additional headers (merged with session profile).
            cookies: Additional cookies.
            follow_redirects: Follow 3xx redirects.

        Returns:
            Evidence object with full request/response capture.

        Raises:
            OutOfScope: If the URL is not in the declared scope.
        """
        # Scope enforcement — this is the hard boundary
        await self.guard.assert_allowed(url)

        # Rate limiting per host
        host = urlparse(url).hostname or "unknown"
        await self.rate_limiter.acquire(host)

        client = self._get_client(session)
        start = time.monotonic()

        try:
            kwargs: dict[str, Any] = {}
            if params:
                kwargs["params"] = params
            if data:
                kwargs["data"] = data
            if content is not None:
                kwargs["content"] = content
            if json_payload is not None:
                kwargs["json"] = json_payload
            if headers:
                kwargs["headers"] = headers
            if cookies:
                kwargs["cookies"] = cookies
            if follow_redirects:
                kwargs["follow_redirects"] = True

            response = await client.request(method, url, **kwargs)
            elapsed_ms = (time.monotonic() - start) * 1000

            # Adaptive rate limiting feedback
            if response.status_code == 429:
                self.rate_limiter.on_429(host)
                logger.warning("http_429", url=url, host=host)
            else:
                self.rate_limiter.on_success(host)

            # Build evidence
            response_body = response.text[:50000]  # cap body capture at 50KB
            ev = Evidence(
                url=str(response.url),
                method=method.upper(),
                request_headers=dict(response.request.headers),
                request_body=str(data or content or json_payload or "")[:5000],
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response_body,
                latency_ms=round(elapsed_ms, 2),
                session=session,
                timestamp=time.time(),
            )
            self._evidence_log.append(ev)

            logger.debug(
                "http_exchange",
                method=method,
                url=url,
                status=response.status_code,
                latency_ms=round(elapsed_ms, 1),
                session=session,
            )
            return ev

        except httpx.TimeoutException:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.warning("http_timeout", url=url, elapsed_ms=round(elapsed_ms, 1))
            return Evidence(
                url=url,
                method=method.upper(),
                response_status=0,
                response_body="[TIMEOUT]",
                latency_ms=round(elapsed_ms, 2),
                session=session,
                timestamp=time.time(),
            )

        except httpx.RequestError as exc:
            logger.error("http_error", url=url, error=str(exc))
            return Evidence(
                url=url,
                method=method.upper(),
                response_status=0,
                response_body=f"[ERROR: {exc}]",
                latency_ms=0.0,
                session=session,
                timestamp=time.time(),
            )

    async def close(self) -> None:
        """Close all session clients."""
        for name, client in self._clients.items():
            await client.aclose()
            logger.debug("http_client_closed", session=name)
        self._clients.clear()

    @property
    def evidence_log(self) -> list[Evidence]:
        return self._evidence_log

    @classmethod
    def from_config(cls, cfg, guard: ScopeGuard, rate_limiter: RateLimiter) -> "HttpPool":
        """Build an HttpPool from a NightfallConfig."""
        sessions = {}
        for name, sess_cfg in cfg.sessions.items():
            sessions[name] = SessionProfile(
                name=name,
                cookies=sess_cfg.cookies,
                headers=sess_cfg.headers,
            )
        return cls(
            guard=guard,
            rate_limiter=rate_limiter,
            sessions=sessions,
            proxy=cfg.proxy,
        )
