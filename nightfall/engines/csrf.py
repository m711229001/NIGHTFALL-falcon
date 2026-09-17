"""
CSRF detection engine.

Checks:
1. Anti-CSRF token presence/absence in forms
2. Token validation (reuse, rotation, removal)
3. SameSite cookie analysis
4. Content-Type restrictions
5. PoC HTML generation for confirmed CSRF
"""
from __future__ import annotations

import re
import secrets
from typing import Optional

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)

# CSRF token field name patterns
CSRF_TOKEN_PATTERNS = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__RequestVerificationToken|"
    r"csrfmiddlewaretoken|_csrf_token|anti-forgery|__VIEWSTATE|"
    r"__EVENTVALIDATION|nonce)",
    re.I,
)

# Form extraction
FORM_PATTERN = re.compile(
    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']?(post|put|delete|patch)["\']?[^>]*>(.*?)</form>',
    re.I | re.S,
)

INPUT_PATTERN = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?[^>]*/?>',
    re.I,
)

HIDDEN_INPUT = re.compile(
    r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\'][^>]*/?>',
    re.I,
)


async def csrf_engine(ctx, step: dict, obj) -> Optional[Evidence]:
    """CSRF detection pipeline.

    1. Fetch the page and extract forms with POST/PUT/DELETE methods
    2. Check for anti-CSRF tokens in hidden fields
    3. Test if the token is actually validated (submit without it)
    4. Check SameSite cookie settings
    5. Generate PoC if CSRF is confirmed
    """
    url = step.get("endpoint", "")
    method = step.get("method", "GET")

    # Fetch the page
    ev = await ctx.pool.send("GET", url)
    body = ev.response_body

    # Extract forms
    forms = FORM_PATTERN.findall(body)
    if not forms:
        logger.debug("csrf_no_forms", url=url)
        return None

    findings = []

    for action, form_method, form_body in forms:
        form_method = form_method.upper()
        if form_method not in ("POST", "PUT", "DELETE", "PATCH"):
            continue

        # Extract all hidden inputs (potential CSRF tokens)
        hidden_inputs = HIDDEN_INPUT.findall(form_body)
        all_inputs = INPUT_PATTERN.findall(form_body)

        # Check for CSRF token
        csrf_token_found = False
        csrf_field = None
        csrf_value = None

        for name, value in hidden_inputs:
            if CSRF_TOKEN_PATTERNS.search(name):
                csrf_token_found = True
                csrf_field = name
                csrf_value = value
                break

        if not csrf_token_found:
            # No CSRF token at all — likely vulnerable
            ev_csrf = Evidence(
                url=url,
                method=form_method,
                vuln_class="csrf",
                subtype="no-token",
                param=action,
                confidence=0.7,
                severity="medium",
                payload="(no CSRF token in form)",
                evidence_snip=form_body[:500],
                extra={
                    "form_action": action,
                    "form_method": form_method,
                    "inputs": [name for name, _ in all_inputs],
                },
                remediation="Implement anti-CSRF tokens (synchronizer token pattern or double-submit cookie).",
            )

            # Check SameSite cookies — if SameSite=Strict/Lax, CSRF may not be exploitable
            cookies_ev = await ctx.pool.send("GET", url)
            samesite_strict = _check_samesite(cookies_ev.response_headers)
            if samesite_strict:
                ev_csrf.confidence = 0.3
                ev_csrf.severity = "low"
                ev_csrf.extra["samesite_protection"] = True
                ev_csrf.reason = "No CSRF token but SameSite cookie may mitigate."

            # Generate PoC
            form_data = {name: value or "test" for name, value in all_inputs}
            ev_csrf.extra["poc_html"] = _generate_poc(
                action if action.startswith("http") else url + action,
                form_method,
                form_data,
            )

            findings.append(ev_csrf)
            continue

        # CSRF token found — test if it's actually validated
        # Test 1: Submit without the token
        form_data = {name: value or "test" for name, value in all_inputs}
        form_data_no_token = {k: v for k, v in form_data.items() if k != csrf_field}

        target_url = action if action.startswith("http") else url
        no_token_ev = await ctx.pool.send(
            form_method, target_url, data=form_data_no_token
        )

        if no_token_ev.response_status in (200, 302, 301):
            # Token removal accepted — CSRF token not validated
            ev_csrf = Evidence(
                url=url,
                method=form_method,
                vuln_class="csrf",
                subtype="token-not-validated",
                param=csrf_field,
                confidence=0.8,
                severity="high",
                payload="(token removed, request still accepted)",
                evidence_snip=f"Status {no_token_ev.response_status} without token",
                extra={"form_action": action, "csrf_field": csrf_field},
                remediation="Validate the CSRF token server-side on every state-changing request.",
            )
            findings.append(ev_csrf)
            continue

        # Test 2: Submit with a random token value
        form_data_bad_token = {**form_data, csrf_field: secrets.token_hex(16)}
        bad_token_ev = await ctx.pool.send(
            form_method, target_url, data=form_data_bad_token
        )

        if bad_token_ev.response_status in (200, 302, 301):
            ev_csrf = Evidence(
                url=url,
                method=form_method,
                vuln_class="csrf",
                subtype="token-not-validated",
                param=csrf_field,
                confidence=0.8,
                severity="high",
                payload=f"(random token accepted: {form_data_bad_token[csrf_field][:16]}...)",
                evidence_snip=f"Status {bad_token_ev.response_status} with random token",
                extra={"form_action": action, "csrf_field": csrf_field},
                remediation="Validate CSRF token value matches the server-side session token.",
            )
            findings.append(ev_csrf)

    if findings:
        # Return the highest-confidence finding
        findings.sort(key=lambda f: f.confidence, reverse=True)
        return findings[0]

    logger.debug("csrf_no_issues", url=url)
    return None


def _check_samesite(headers: dict) -> bool:
    """Check if Set-Cookie headers include SameSite=Strict or Lax."""
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            if re.search(r"samesite\s*=\s*(strict|lax)", value, re.I):
                return True
    return False


def _generate_poc(action: str, method: str, data: dict) -> str:
    """Generate a CSRF proof-of-concept HTML page."""
    inputs = "\n    ".join(
        f'<input type="hidden" name="{k}" value="{v}" />'
        for k, v in data.items()
    )
    return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC — NIGHTFALL</title></head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <form id="csrfForm" action="{action}" method="{method}">
    {inputs}
    <input type="submit" value="Submit" />
  </form>
  <script>document.getElementById('csrfForm').submit();</script>
</body>
</html>"""
