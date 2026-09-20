"""Falcon MAG Framework - CSRF Checker (v2)

Checks POST forms for missing anti-CSRF tokens.
Uses crawled forms from _crawl_result when available.
"""
import re
from urllib.parse import urljoin
from core.logger import get_logger

log = get_logger("csrf")

# Common CSRF token field names
TOKEN_PATTERNS = [
    r"csrf",
    r"_token",
    r"token",
    r"authenticity_token",
    r"__RequestVerificationToken",
    r"xsrf",
    r"_xsrf",
    r"nonce",
    r"security_token",
]


def _has_csrf_token(form_html: str) -> bool:
    """Check if a form's HTML contains a CSRF token field."""
    if not form_html:
        return False
    lower = form_html.lower()
    for pat in TOKEN_PATTERNS:
        if re.search(pat, lower):
            return True
    return False


def run(client, config, crawl_result=None):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info("CSRF check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}

    # Get forms from crawl result
    crawl = crawl_result or config.get("_crawl_result", {}) or {}
    forms = crawl.get("forms", []) or []

    # ALWAYS fetch target and parse forms directly (self-sufficient)
    resp = client.get(target)
    if resp and resp.status == 200:
        # Parse all <form> blocks from HTML
        form_blocks = re.findall(
            r"<form[^>]*>(.*?)</form>",
            resp.text,
            re.IGNORECASE | re.DOTALL,
        )
        form_tags = re.findall(
            r"<form[^>]*>",
            resp.text,
            re.IGNORECASE,
        )
        for i, tag in enumerate(form_tags):
            method_match = re.search(r'method=["\']?(\w+)', tag, re.IGNORECASE)
            method = (method_match.group(1) if method_match else "GET").upper()
            # CSRF affects both GET and POST forms (state-changing actions)
            action_match = re.search(r'action=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            action = action_match.group(1) if action_match else target
            if action and not action.startswith(("http://", "https://")):
                from urllib.parse import urljoin
                action = urljoin(target, action)
            inner_html = form_blocks[i] if i < len(form_blocks) else ""
            # Extract input names
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', inner_html, re.IGNORECASE)
            # Also include textarea/select
            inputs += re.findall(r'<(?:textarea|select)[^>]+name=["\']([^"\']+)["\']', inner_html, re.IGNORECASE)
            forms.append({
                "action": action or target,
                "method": method,
                "html": inner_html,
                "inputs": [{"name": n} for n in inputs],
            })
        log.info(f"  Found {len(forms)} form(s) in HTML")

    if not forms:
        log.info("  No forms found")
        return result

    log.info("  Testing " + str(len(forms)) + " form(s)")

    for form in forms:
        if not isinstance(form, dict):
            continue
        method = (form.get("method") or "GET").upper()
        if method != "POST":
            continue

        result["tested"] += 1
        action = form.get("action") or target
        inputs = form.get("inputs", []) or []
        form_html = form.get("html", "")

        # Collect field names
        field_names = []
        if inputs:
            for inp in inputs:
                if isinstance(inp, dict) and inp.get("name"):
                    field_names.append(inp["name"])
        # If we have raw HTML, use it for token check
        if form_html:
            has_token = _has_csrf_token(form_html)
        else:
            # Check field names
            has_token = any(
                any(re.search(pat, (f or "").lower()) for pat in TOKEN_PATTERNS)
                for f in field_names
            )

        if not has_token:
            log.warning("  CSRF MISSING in form: " + action[:80])
            result["vulnerable"].append({
                "url": action,
                "original_url": action,
                "injected_url": action,
                "param": "",
                "payload": "",
                "severity": "medium",
                "description": "POST form without anti-CSRF token",
                "evidence": "Fields: " + ", ".join(field_names[:10]),
            })
        else:
            log.debug("  OK: form has CSRF token")

    if not result["vulnerable"]:
        log.info("  All POST forms have anti-CSRF tokens")
    return result
