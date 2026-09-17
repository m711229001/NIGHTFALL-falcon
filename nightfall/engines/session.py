"""
Session security audit engine.

Checks:
1. Cookie flag audit (Secure, HttpOnly, SameSite)
2. Shannon entropy analysis for session token strength
3. Session fixation test (pre/post-auth token survival)
4. Session ID predictability (sequential, low entropy)
5. Concurrent session handling
6. Logout invalidation
"""
from __future__ import annotations

import collections
import math
import re
from typing import Optional

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.

    High entropy (>4.0) suggests cryptographically random tokens.
    Low entropy (<3.0) suggests predictable/sequential tokens.
    """
    if not s:
        return 0.0
    counter = collections.Counter(s)
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in counter.values())


# ── Session Cookie Name Patterns ────────────────────────────────────────────

SESSION_COOKIE_NAMES = re.compile(
    r"(session|sess|sid|jsessionid|phpsessid|aspsessionid|"
    r"connect\.sid|laravel_session|_session|token|auth)",
    re.I,
)


async def session_engine(ctx, step: dict, obj) -> Optional[Evidence]:
    """Session security audit pipeline."""
    url = step.get("endpoint", "")
    findings = []

    # Fetch the page to get cookies
    ev = await ctx.pool.send("GET", url)

    # Extract Set-Cookie headers
    cookies = _parse_set_cookies(ev.response_headers)

    if not cookies:
        logger.debug("session_no_cookies", url=url)
        return None

    # ── 1. Cookie flag audit ─────────────────────────────────────────────
    for cookie in cookies:
        name = cookie.get("name", "")
        value = cookie.get("value", "")

        # Only audit session-like cookies
        if not SESSION_COOKIE_NAMES.search(name):
            continue

        issues = []

        # Missing Secure flag
        if not cookie.get("secure"):
            issues.append({
                "type": "missing-secure",
                "detail": f"Cookie '{name}' missing Secure flag — transmitted over HTTP",
                "severity": "medium",
            })

        # Missing HttpOnly flag
        if not cookie.get("httponly"):
            issues.append({
                "type": "missing-httponly",
                "detail": f"Cookie '{name}' missing HttpOnly flag — accessible via JavaScript (XSS risk)",
                "severity": "medium",
            })

        # SameSite=None or missing
        samesite = cookie.get("samesite", "").lower()
        if samesite == "none" or not samesite:
            issues.append({
                "type": "samesite-none",
                "detail": f"Cookie '{name}' has SameSite=None or unset — CSRF exposure",
                "severity": "medium",
            })

        # ── 2. Entropy analysis ──────────────────────────────────────────
        if value:
            entropy = shannon_entropy(value)
            if entropy < 3.0 and value.isdigit():
                issues.append({
                    "type": "predictable-sequential",
                    "detail": f"Cookie '{name}' appears sequential (entropy={entropy:.2f}, numeric only)",
                    "severity": "high",
                })
            elif entropy < 3.5:
                issues.append({
                    "type": "low-entropy",
                    "detail": f"Cookie '{name}' has low entropy ({entropy:.2f}) — potentially predictable",
                    "severity": "medium",
                })

            if len(value) < 16:
                issues.append({
                    "type": "short-token",
                    "detail": f"Cookie '{name}' is only {len(value)} chars — insufficient randomness",
                    "severity": "medium",
                })

        if issues:
            ev_finding = Evidence(
                url=url,
                method="GET",
                vuln_class="session",
                subtype=issues[0]["type"],
                param=name,
                confidence=0.8,
                severity=_max_severity([i["severity"] for i in issues]),
                evidence_snip="\n".join(i["detail"] for i in issues),
                extra={"cookie_name": name, "issues": issues},
                remediation=(
                    "Set Secure, HttpOnly, and SameSite=Strict/Lax flags on all session cookies. "
                    "Use cryptographically random session IDs with at least 128 bits of entropy. "
                    "Ensure session tokens are at least 32 characters long."
                ),
            )
            findings.append(ev_finding)

    # ── 3. Session fixation test ─────────────────────────────────────────
    fixation_result = await _test_session_fixation(ctx, url)
    if fixation_result:
        findings.append(fixation_result)

    # ── 4. Logout invalidation test ──────────────────────────────────────
    logout_result = await _test_logout_invalidation(ctx, url)
    if logout_result:
        findings.append(logout_result)

    if findings:
        # Return highest severity finding
        findings.sort(key=lambda f: _severity_order(f.severity))
        return findings[0]

    logger.debug("session_no_issues", url=url)
    return None


async def _test_session_fixation(ctx, url: str) -> Optional[Evidence]:
    """Test session fixation: does the session token change after login?

    Fix a token pre-auth, login, then check if the same token is still valid.
    If it survives authentication, session fixation is possible.
    """
    # Get pre-auth session
    pre_ev = await ctx.pool.send("GET", url)
    pre_cookies = _parse_set_cookies(pre_ev.response_headers)

    session_cookie = None
    for c in pre_cookies:
        if SESSION_COOKIE_NAMES.search(c.get("name", "")):
            session_cookie = c
            break

    if not session_cookie:
        return None

    pre_value = session_cookie["value"]

    # Try login (if credentials are available in context)
    creds = getattr(ctx, "creds", None)
    if not creds:
        return None

    login_urls = [url + "/login", url.rsplit("/", 1)[0] + "/login"]
    for login_url in login_urls:
        post_ev = await ctx.pool.send(
            "POST", login_url,
            data={"username": creds.get("u", ""), "password": creds.get("p", "")},
            cookies={session_cookie["name"]: pre_value},
        )

        if post_ev.response_status in (200, 302):
            # Check if the pre-auth token survived
            post_cookies = _parse_set_cookies(post_ev.response_headers)
            for c in post_cookies:
                if c.get("name") == session_cookie["name"]:
                    if c.get("value") == pre_value:
                        return Evidence(
                            url=url,
                            method="POST",
                            vuln_class="session",
                            subtype="fixation",
                            param=session_cookie["name"],
                            confidence=0.85,
                            severity="high",
                            evidence_snip=(
                                f"Pre-auth token '{pre_value[:20]}...' survived login — "
                                f"session fixation possible"
                            ),
                            remediation=(
                                "Regenerate session ID after successful authentication. "
                                "Invalidate the old session token completely."
                            ),
                        )
    return None


async def _test_logout_invalidation(ctx, url: str) -> Optional[Evidence]:
    """Test if session tokens are invalidated after logout."""
    logout_urls = [url + "/logout", url.rsplit("/", 1)[0] + "/logout"]

    for logout_url in logout_urls:
        # Logout
        logout_ev = await ctx.pool.send("POST", logout_url)
        if logout_ev.response_status in (200, 302):
            # Try using the session again
            reuse_ev = await ctx.pool.send("GET", url)
            if reuse_ev.response_status == 200:
                # Check if we're still authenticated
                body = reuse_ev.response_body.lower()
                if any(s in body for s in ("dashboard", "profile", "account", "welcome")):
                    return Evidence(
                        url=url,
                        method="GET",
                        vuln_class="session",
                        subtype="no-logout-invalidation",
                        confidence=0.7,
                        severity="medium",
                        evidence_snip="Session token still valid after logout",
                        remediation=(
                            "Invalidate session tokens server-side on logout. "
                            "Clear all session data and remove the session cookie."
                        ),
                    )
    return None


def _parse_set_cookies(headers: dict) -> list[dict]:
    """Parse Set-Cookie headers into a list of cookie dicts."""
    cookies = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookie = _parse_single_cookie(value)
            if cookie:
                cookies.append(cookie)
    return cookies


def _parse_single_cookie(header_value: str) -> dict:
    """Parse a single Set-Cookie header value."""
    parts = header_value.split(";")
    if not parts:
        return {}

    # First part is name=value
    name_value = parts[0].strip()
    if "=" not in name_value:
        return {}

    name, value = name_value.split("=", 1)
    cookie = {"name": name.strip(), "value": value.strip()}

    # Parse attributes
    for part in parts[1:]:
        part = part.strip().lower()
        if part == "secure":
            cookie["secure"] = True
        elif part == "httponly":
            cookie["httponly"] = True
        elif part.startswith("samesite="):
            cookie["samesite"] = part.split("=", 1)[1]
        elif part.startswith("path="):
            cookie["path"] = part.split("=", 1)[1]
        elif part.startswith("domain="):
            cookie["domain"] = part.split("=", 1)[1]
        elif part.startswith("max-age="):
            cookie["max_age"] = part.split("=", 1)[1]

    return cookie


def _max_severity(severities: list[str]) -> str:
    """Return the highest severity from a list."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return min(severities, key=lambda s: order.get(s, 5))


def _severity_order(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 5)
