"""
Markdown report generator for NIGHTFALL.

Generates a rich, professional penetration test report with:
- Executive summary with severity breakdown
- Detailed findings with evidence (request/response)
- Remediation guidance per vulnerability
- Campaign statistics
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Severity Badges ──────────────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Remediation Templates ───────────────────────────────────────────────────

REMEDIATION_TEMPLATES = {
    "sqli": (
        "**SQL Injection Remediation:**\n"
        "- Use parameterized queries / prepared statements for all database interactions\n"
        "- Implement input validation using allowlists\n"
        "- Apply the principle of least privilege to database accounts\n"
        "- Disable verbose SQL error messages in production\n"
        "- Consider using an ORM that generates parameterized queries"
    ),
    "xss": (
        "**Cross-Site Scripting Remediation:**\n"
        "- Encode all output based on context (HTML entity, JS string, URL, CSS)\n"
        "- Implement Content-Security-Policy headers (script-src 'self')\n"
        "- Use HttpOnly flag on session cookies\n"
        "- Validate and sanitize all user input\n"
        "- Consider using a templating engine with auto-escaping"
    ),
    "xxe": (
        "**XML External Entity Remediation:**\n"
        "- Disable DTD processing in all XML parsers\n"
        "- Disable external entity and parameter entity resolution\n"
        "- Use defusedxml or equivalent safe XML parser\n"
        "- Validate and sanitize XML input\n"
        "- Consider using JSON instead of XML where possible"
    ),
    "ssrf": (
        "**Server-Side Request Forgery Remediation:**\n"
        "- Validate and whitelist URLs/IPs on the server side\n"
        "- Block requests to internal/RFC1918/metadata IP ranges\n"
        "- Use allowlists for URL schemes (http/https only)\n"
        "- Implement network segmentation\n"
        "- Use IMDSv2 on AWS (requires token-based access)"
    ),
    "idor": (
        "**Insecure Direct Object Reference Remediation:**\n"
        "- Implement object-level authorization checks on every request\n"
        "- Verify that the authenticated user owns/has access to the requested resource\n"
        "- Use indirect references (UUIDs) instead of sequential IDs\n"
        "- Implement authorization middleware/interceptors\n"
        "- Log and alert on authorization failures"
    ),
    "jwt": (
        "**JWT Security Remediation:**\n"
        "- Use a strict allowlist of accepted algorithms (e.g. RS256 only)\n"
        "- Reject tokens with alg=none\n"
        "- Use cryptographically strong secrets (>=256 bits)\n"
        "- Validate all claims (exp, iss, aud) server-side\n"
        "- Consider using asymmetric algorithms (RS256, ES256)"
    ),
    "csrf": (
        "**Cross-Site Request Forgery Remediation:**\n"
        "- Implement anti-CSRF tokens (synchronizer token pattern)\n"
        "- Set SameSite=Strict or Lax on session cookies\n"
        "- Validate the Origin/Referer header\n"
        "- Use custom request headers for API endpoints"
    ),
    "authn": (
        "**Authentication Remediation:**\n"
        "- Remove all default credentials\n"
        "- Enforce strong password policies\n"
        "- Implement account lockout after failed attempts\n"
        "- Add multi-factor authentication\n"
        "- Do not trust client-supplied headers for authentication"
    ),
    "session": (
        "**Session Security Remediation:**\n"
        "- Set Secure, HttpOnly, and SameSite flags on all session cookies\n"
        "- Use cryptographically random session IDs (>=128 bits)\n"
        "- Regenerate session ID after authentication\n"
        "- Invalidate sessions on logout (server-side)\n"
        "- Implement session timeout"
    ),
}


def render(findings: list[dict], campaign_stats: dict | None = None) -> str:
    """Generate a full Markdown penetration test report.

    Args:
        findings: List of finding dicts from the database.
        campaign_stats: Optional campaign statistics dict.

    Returns:
        Complete Markdown report string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Sort findings by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 5))

    # Severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    md = []

    # ── Header ───────────────────────────────────────────────────────────
    md.append("# 🌑 NIGHTFALL — Security Assessment Report")
    md.append("")
    md.append(f"**Generated:** {now}")
    md.append(f"**Tool:** NIGHTFALL Autonomous AI VAPT Platform v1.0.0")
    if campaign_stats:
        md.append(f"**Duration:** {campaign_stats.get('elapsed_seconds', 0)}s")
        md.append(f"**Requests Used:** {campaign_stats.get('budget_used', 0)}")
    md.append("")
    md.append("---")
    md.append("")

    # ── Executive Summary ────────────────────────────────────────────────
    md.append("## Executive Summary")
    md.append("")
    md.append(f"| Severity | Count |")
    md.append(f"|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts[sev]
        emoji = SEVERITY_EMOJI[sev]
        md.append(f"| {emoji} **{sev.upper()}** | {count} |")
    md.append("")
    md.append(f"**Total Findings:** {len(findings)}")
    md.append("")

    if severity_counts["critical"] > 0:
        md.append("> ⚠️ **CRITICAL vulnerabilities found.** Immediate remediation required.")
        md.append("")

    md.append("---")
    md.append("")

    # ── Detailed Findings ────────────────────────────────────────────────
    md.append("## Detailed Findings")
    md.append("")

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        vuln_class = f.get("vuln_class", "unknown")
        emoji = SEVERITY_EMOJI.get(sev, "⚪")

        md.append(f"### {emoji} Finding #{i}: {vuln_class.upper()} — {f.get('subtype', '')}")
        md.append("")
        md.append(f"| Field | Value |")
        md.append(f"|-------|-------|")
        md.append(f"| **Severity** | {sev.upper()} |")
        md.append(f"| **Confidence** | {f.get('confidence', 0):.0%} |")
        md.append(f"| **URL** | `{f.get('url', '')}` |")
        md.append(f"| **Method** | {f.get('method', 'GET')} |")
        md.append(f"| **Parameter** | `{f.get('param', 'N/A')}` |")
        md.append(f"| **Class** | {vuln_class} / {f.get('subtype', '')} |")
        md.append("")

        # AI Reasoning
        reason = f.get("ai_reason", "") or f.get("reason", "")
        if reason:
            md.append(f"**Analysis:** {reason}")
            md.append("")

        # Evidence
        evidence = f.get("evidence_snip", "")
        if evidence:
            md.append("**Evidence:**")
            md.append(f"```")
            md.append(evidence[:1500])
            md.append(f"```")
            md.append("")

        # Request HAR
        request_har = f.get("request_har", "")
        if request_har and request_har != "{}":
            md.append("**Request:**")
            md.append(f"```http")
            md.append(request_har[:1000])
            md.append(f"```")
            md.append("")

        # Remediation
        remediation = f.get("remediation", "")
        if not remediation:
            remediation = REMEDIATION_TEMPLATES.get(vuln_class, "")
        if remediation:
            md.append("**Remediation:**")
            md.append(remediation)
            md.append("")

        md.append("---")
        md.append("")

    # ── Campaign Statistics ──────────────────────────────────────────────
    if campaign_stats:
        md.append("## Campaign Statistics")
        md.append("")
        md.append(f"| Metric | Value |")
        md.append(f"|--------|-------|")
        for key, value in campaign_stats.items():
            md.append(f"| {key.replace('_', ' ').title()} | {value} |")
        md.append("")

    # ── Footer ───────────────────────────────────────────────────────────
    md.append("---")
    md.append("")
    md.append("*Report generated by NIGHTFALL — Autonomous AI VAPT Platform*")
    md.append(f"*Classification: CONFIDENTIAL — Authorized personnel only*")

    return "\n".join(md)
