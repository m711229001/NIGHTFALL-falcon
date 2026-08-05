"""
False-positive triage engine — the semantic evidence analyzer.

Two-stage triage:
1. Fast-path regex pre-filter: cheap deterministic signatures run first to
   classify obvious positives/negatives without burning LLM tokens.
2. LLM semantic triage: uncertain candidates go to the reasoning model for
   deep analysis of reflection context, timing baselines, OOB callbacks, and
   response-body semantic similarity.

The LLM only thinks when a finding is on the line — ~95% of requests are
cheap deterministic probes.
"""
from __future__ import annotations

import re
import time
from typing import Any, Optional

import structlog

from nightfall.ai.client import ModelClient
from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── LLM Triage System Prompt ────────────────────────────────────────────────

TRIAGE_SYSTEM = """You are an expert penetration testing triage analyst. Given request,
response, and payload evidence, decide whether this is a REAL vulnerability or
a false positive.

Consider:
1. Reflection context — is the payload actually reflected in an executable context?
2. Status codes — does a 200 with error text differ from a normal 200?
3. Error signatures — are database/framework errors genuine or generic?
4. Timing baselines — is the latency delta significant (>4s for sleep-based)?
5. OOB callbacks — was an out-of-band interaction actually observed?
6. Response-body semantic similarity — how different is the response from a baseline?
7. WAF behavior — could this be a WAF-generated response mimicking vulnerability?

Be conservative: an uncertain verdict is 'benign' but with low confidence,
flag it for manual review.

Output ONLY valid JSON:
{
  "accepted": true|false,
  "severity": "critical|high|medium|low|info",
  "class": "sqli|xss|xxe|ssrf|idor|jwt|csrf|authn|session",
  "subtype": "error|boolean|time|oob|reflected|stored|dom|blind|...",
  "confidence": 0.0-1.0,
  "reason": "one paragraph explaining the verdict",
  "remediation": "specific fix recommendation",
  "dedup_key": "url+class+param",
  "manual_review": false
}"""


# ── Fast-Path Regex Pre-Filters ─────────────────────────────────────────────

# These run before any LLM call to quickly classify obvious cases.

SQLI_ERROR_SIGNATURES = {
    "mysql": re.compile(
        r"(SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException|"
        r"com\.mysql\.jdbc|Unclosed quotation mark after the character string)",
        re.I,
    ),
    "postgres": re.compile(
        r"(PG::SyntaxError|ERROR:\s+syntax error at or near|"
        r"org\.postgresql\.util\.PSQLException|valid PostgreSQL result)",
        re.I,
    ),
    "mssql": re.compile(
        r"(Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|"
        r"Microsoft SQL Native Client error|ODBC SQL Server Driver|"
        r"SqlException.*System\.Data\.SqlClient)",
        re.I,
    ),
    "oracle": re.compile(
        r"(ORA-\d{5}|Oracle error|oracle\.jdbc\.driver|"
        r"quoted string not properly terminated|SQL command not properly ended)",
        re.I,
    ),
    "sqlite": re.compile(
        r"(SQLITE_ERROR|SQLite3::SQLException|near \"\w+\": syntax error|"
        r"unrecognized token)",
        re.I,
    ),
}

XSS_REFLECTION_MARKERS = re.compile(
    r"(<script[^>]*>.*?</script>|on\w+\s*=\s*[\"']|javascript:|<img[^>]+onerror)",
    re.I | re.S,
)

XXE_FILE_READ_MARKERS = re.compile(
    r"(root:.*:0:0:|/bin/(bash|sh)|/etc/(passwd|shadow|hosts)|"
    r"\[boot loader\]|\[operating systems\])",
    re.I,
)

SSRF_METADATA_MARKERS = re.compile(
    r"(ami-id|instance-id|iam/security-credentials|"
    r"computeMetadata/v1|metadata\.google\.internal|"
    r"169\.254\.169\.254)",
    re.I,
)


def fast_triage(ev: Evidence, expected_class: str) -> Optional[dict]:
    """Fast-path deterministic triage using regex signatures.

    Returns:
        A verdict dict if a definitive classification can be made,
        or None if the evidence needs LLM triage.
    """
    body = ev.response_body or ""

    # SQLi error-based: definitive if a DB error signature is present
    if expected_class == "sqli":
        for dbms, pattern in SQLI_ERROR_SIGNATURES.items():
            if pattern.search(body):
                return {
                    "accepted": True,
                    "severity": "high",
                    "class": "sqli",
                    "subtype": "error",
                    "confidence": 0.9,
                    "reason": f"Database error signature detected ({dbms}). "
                              f"The application leaks SQL error details to the response body.",
                    "remediation": "Use parameterized queries / prepared statements. "
                                   "Disable verbose error messages in production.",
                    "dedup_key": f"{ev.url}|sqli|{ev.param}",
                    "manual_review": False,
                    "dbms": dbms,
                }

    # XSS reflected: definitive if our marker is reflected in executable context
    if expected_class == "xss" and ev.marker:
        if ev.marker in body:
            # Check if it's in an executable context
            marker_pos = body.find(ev.marker)
            context_window = body[max(0, marker_pos - 200):marker_pos + len(ev.marker) + 200]
            if XSS_REFLECTION_MARKERS.search(context_window):
                return {
                    "accepted": True,
                    "severity": "high",
                    "class": "xss",
                    "subtype": "reflected",
                    "confidence": 0.85,
                    "reason": "Injected marker is reflected in an executable HTML/JS context.",
                    "remediation": "Encode output based on context (HTML entity, JS string, URL). "
                                   "Implement Content-Security-Policy headers.",
                    "dedup_key": f"{ev.url}|xss|{ev.param}",
                    "manual_review": False,
                }

    # XXE file read: definitive if /etc/passwd content appears
    if expected_class == "xxe" and XXE_FILE_READ_MARKERS.search(body):
        return {
            "accepted": True,
            "severity": "critical",
            "class": "xxe",
            "subtype": "file-read",
            "confidence": 0.95,
            "reason": "Server-side file content (e.g. /etc/passwd) is present in the response, "
                       "confirming XML External Entity injection with file read capability.",
            "remediation": "Disable DTD processing and external entity resolution in the XML parser. "
                           "Use defusedxml or equivalent safe parser.",
            "dedup_key": f"{ev.url}|xxe|{ev.param}",
            "manual_review": False,
        }

    # SSRF metadata: definitive if cloud metadata content appears
    if expected_class == "ssrf" and SSRF_METADATA_MARKERS.search(body):
        return {
            "accepted": True,
            "severity": "critical",
            "class": "ssrf",
            "subtype": "cloud-metadata",
            "confidence": 0.9,
            "reason": "Cloud metadata endpoint content detected in response, "
                       "confirming Server-Side Request Forgery with internal network access.",
            "remediation": "Validate and whitelist URLs on the server side. "
                           "Block requests to internal/metadata IPs. Use IMDSv2.",
            "dedup_key": f"{ev.url}|ssrf|{ev.param}",
            "manual_review": False,
        }

    # OOB callback confirmed: definitive signal
    if ev.oob_nonce:
        return {
            "accepted": True,
            "severity": "high",
            "class": expected_class,
            "subtype": "oob",
            "confidence": 0.9,
            "reason": f"Out-of-band callback received (nonce: {ev.oob_nonce}), "
                       f"confirming blind {expected_class} via DNS/HTTP interaction.",
            "remediation": f"Address the {expected_class} vulnerability at the application layer.",
            "dedup_key": f"{ev.url}|{expected_class}|{ev.param}",
            "manual_review": False,
        }

    # No fast-path match — needs LLM triage
    return None


# ── LLM Triage ───────────────────────────────────────────────────────────────

def _extract_marker_context(body: str, marker: str, radius: int = 600) -> str:
    """Extract the context around a reflected marker for the LLM to analyze."""
    if not marker or marker not in body:
        return body[:1500]
    pos = body.find(marker)
    start = max(0, pos - radius)
    end = min(len(body), pos + len(marker) + radius)
    return body[start:end]


async def triage(
    ai: ModelClient,
    ev: Evidence,
    expected_class: str,
) -> dict:
    """Full triage pipeline: fast-path regex → LLM semantic analysis.

    Args:
        ai: ModelClient for LLM reasoning.
        ev: Evidence from the detection engine.
        expected_class: The vulnerability class being tested.

    Returns:
        Verdict dict with accepted, severity, confidence, reason, etc.
    """
    # Stage 1: Fast-path regex pre-filter
    fast_result = fast_triage(ev, expected_class)
    if fast_result is not None:
        logger.info(
            "triage_fast_path",
            accepted=fast_result["accepted"],
            vuln_class=fast_result["class"],
            confidence=fast_result["confidence"],
        )
        return fast_result

    # Stage 2: LLM semantic triage (only for uncertain candidates)
    marker_context = _extract_marker_context(
        ev.response_body or "", ev.marker, radius=600
    )

    prompt = f"""EVIDENCE FOR TRIAGE:

PAYLOAD / USER INPUT:
{ev.request_body[:1500] if ev.request_body else ev.payload[:1500] if ev.payload else '(no payload captured)'}

HTTP METHOD: {ev.method}
URL: {ev.url}
PARAMETER: {ev.param or '(unknown)'}

HTTP STATUS: {ev.response_status}

RESPONSE SNIPPET (around the reflected/interesting marker):
{marker_context}

RESPONSE HEADERS:
{json.dumps(dict(list(ev.response_headers.items())[:20])) if ev.response_headers else '{}'}

LATENCY: {ev.latency_ms}ms
OOB CALLBACK RECEIVED: {bool(ev.oob_nonce)}
EXPECTED VULNERABILITY CLASS: {expected_class}

SESSION: {ev.session}"""

    import json

    logger.info("triage_llm_invoked", url=ev.url, expected_class=expected_class)
    verdict = await ai.think(TRIAGE_SYSTEM, prompt, temperature=0.0)

    # Validate and normalize
    if "error" in verdict and len(verdict) == 1:
        logger.warning("triage_llm_error", error=verdict["error"][:200])
        return {
            "accepted": False,
            "severity": "info",
            "class": expected_class,
            "confidence": 0.0,
            "reason": f"Triage LLM error: {verdict['error'][:200]}",
            "manual_review": True,
        }

    verdict.setdefault("accepted", False)
    verdict.setdefault("severity", "info")
    verdict.setdefault("class", expected_class)
    verdict.setdefault("confidence", 0.0)
    verdict.setdefault("reason", "")
    verdict.setdefault("remediation", "")
    verdict.setdefault("manual_review", False)

    # Only accept high-confidence findings
    if verdict["accepted"] and verdict.get("confidence", 0) < 0.6:
        verdict["accepted"] = False
        verdict["manual_review"] = True
        verdict["reason"] += " [Auto-downgraded: confidence below threshold]"

    logger.info(
        "triage_llm_result",
        accepted=verdict["accepted"],
        severity=verdict["severity"],
        confidence=verdict.get("confidence"),
        vuln_class=verdict["class"],
    )

    return verdict
