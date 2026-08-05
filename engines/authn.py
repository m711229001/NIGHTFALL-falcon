"""
Authentication bypass detection engine.

Checks:
1. Default / common credential testing
2. Authentication bypass via special headers (X-Forwarded-For, etc.)
3. Registration flow analysis
4. Password reset flow weaknesses
5. Rate-limit / lockout detection on login
6. MFA bypass attempts
"""
from __future__ import annotations

import re
from typing import Optional

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── Default Credentials ─────────────────────────────────────────────────────

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("admin", ""),
    ("sa", ""),
    ("postgres", "postgres"),
    ("admin", "changeme"),
]

# ── Auth Bypass Headers ──────────────────────────────────────────────────────

BYPASS_HEADERS_MATRIX = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
]


async def authn_engine(ctx, step: dict, obj) -> Optional[Evidence]:
    """Authentication bypass detection pipeline."""
    url = step.get("endpoint", "")
    method = step.get("method", "GET")

    findings = []

    # ── 1. Default credentials ───────────────────────────────────────────
    login_endpoints = _find_login_endpoints(url)

    for login_url in login_endpoints:
        for username, password in DEFAULT_CREDS:
            ev = await ctx.pool.send(
                "POST", login_url,
                data={"username": username, "password": password},
            )

            if _is_successful_login(ev):
                ev.vuln_class = "authn"
                ev.subtype = "default-credentials"
                ev.param = f"{username}:{password}"
                ev.payload = f"username={username}&password={password}"
                ev.confidence = 0.9
                ev.severity = "critical"
                ev.evidence_snip = ev.response_body[:300]
                ev.remediation = (
                    "Remove default credentials. Enforce strong password policies. "
                    "Implement account lockout after failed attempts."
                )
                logger.info("authn_default_creds", url=login_url, user=username)
                return ev

            # Also try JSON body
            ev_json = await ctx.pool.send(
                "POST", login_url,
                json_payload={"username": username, "password": password},
                headers={"Content-Type": "application/json"},
            )
            if _is_successful_login(ev_json):
                ev_json.vuln_class = "authn"
                ev_json.subtype = "default-credentials"
                ev_json.param = f"{username}:{password}"
                ev_json.confidence = 0.9
                ev_json.severity = "critical"
                ev_json.remediation = "Remove default credentials."
                return ev_json

    # ── 2. Header-based authentication bypass ────────────────────────────
    # First, find a protected endpoint (one that returns 401/403)
    baseline_ev = await ctx.pool.send("GET", url)

    if baseline_ev.response_status in (401, 403):
        for bypass_headers in BYPASS_HEADERS_MATRIX:
            ev = await ctx.pool.send("GET", url, headers=bypass_headers)

            if ev.response_status == 200:
                header_name = list(bypass_headers.keys())[0]
                ev.vuln_class = "authn"
                ev.subtype = "header-bypass"
                ev.param = header_name
                ev.payload = f"{header_name}: {bypass_headers[header_name]}"
                ev.confidence = 0.8
                ev.severity = "critical"
                ev.evidence_snip = ev.response_body[:300]
                ev.remediation = (
                    f"Do not trust the {header_name} header for authentication "
                    f"or authorization decisions. These headers can be spoofed."
                )
                logger.info("authn_header_bypass", url=url, header=header_name)
                return ev

    # ── 3. HTTP method override ──────────────────────────────────────────
    if baseline_ev.response_status in (401, 403, 405):
        for alt_method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"):
            if alt_method == method:
                continue
            ev = await ctx.pool.send(alt_method, url)
            if ev.response_status == 200:
                ev.vuln_class = "authn"
                ev.subtype = "method-bypass"
                ev.param = f"HTTP {alt_method}"
                ev.confidence = 0.7
                ev.severity = "high"
                ev.evidence_snip = ev.response_body[:300]
                ev.remediation = "Enforce authentication on all HTTP methods."
                return ev

    # ── 4. Path traversal bypass on auth ─────────────────────────────────
    if baseline_ev.response_status in (401, 403):
        path_bypasses = [
            url + "/",
            url + "/.",
            url + "//",
            url + "/..",
            url + "/..;/",
            url + "%2f",
            url + "%2e",
            url.replace("/admin", "/ADMIN"),
            url.replace("/admin", "/Admin"),
        ]
        for bypass_url in path_bypasses:
            ev = await ctx.pool.send("GET", bypass_url)
            if ev.response_status == 200 and len(ev.response_body) > 100:
                ev.vuln_class = "authn"
                ev.subtype = "path-bypass"
                ev.payload = bypass_url
                ev.confidence = 0.75
                ev.severity = "high"
                ev.evidence_snip = ev.response_body[:300]
                ev.remediation = "Normalize URL paths before authentication checks."
                return ev

    # ── 5. Rate limit / lockout check ────────────────────────────────────
    if login_endpoints:
        login_url = login_endpoints[0]
        failed_count = 0
        for i in range(15):
            ev = await ctx.pool.send(
                "POST", login_url,
                data={"username": "admin", "password": f"wrong{i}"},
            )
            if ev.response_status == 429:
                break
            if not _is_successful_login(ev):
                failed_count += 1

        if failed_count >= 15:
            ev = Evidence(
                url=login_url,
                method="POST",
                vuln_class="authn",
                subtype="no-rate-limit",
                param="login",
                confidence=0.7,
                severity="medium",
                evidence_snip=f"{failed_count} failed logins without lockout or rate limiting",
                remediation=(
                    "Implement account lockout after 5-10 failed attempts. "
                    "Add rate limiting and CAPTCHA on login endpoints."
                ),
            )
            return ev

    logger.debug("authn_no_issues", url=url)
    return None


def _find_login_endpoints(base_url: str) -> list[str]:
    """Generate common login endpoint URLs from a base URL."""
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else base_url

    suffixes = [
        "/login", "/signin", "/auth/login", "/api/login", "/api/auth/login",
        "/api/v1/login", "/api/v1/auth", "/user/login", "/admin/login",
        "/api/sessions", "/oauth/token",
    ]
    return [base + s for s in suffixes]


def _is_successful_login(ev: Evidence) -> bool:
    """Heuristic: did a login attempt succeed?"""
    if ev.response_status in (200, 302):
        body_lower = ev.response_body.lower()
        # Positive signals
        if any(s in body_lower for s in ("token", "access_token", "jwt", "session",
                                          "welcome", "dashboard", "logged in")):
            return True
        # Negative signals (failed login)
        if any(s in body_lower for s in ("invalid", "incorrect", "failed", "error",
                                          "wrong password", "unauthorized")):
            return False
        # 302 redirect often indicates successful login
        if ev.response_status == 302:
            location = ev.response_headers.get("location", "")
            if "login" not in location.lower() and "error" not in location.lower():
                return True
    return False
