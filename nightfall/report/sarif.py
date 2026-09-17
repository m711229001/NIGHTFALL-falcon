"""
SARIF 2.1.0 report generator for NIGHTFALL.

Produces Static Analysis Results Interchange Format (SARIF) output
for CI/CD integration:
- GitHub Code Scanning
- DefectDojo
- Azure DevOps
- Any SARIF-consuming tool

Schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── SARIF Severity Mapping ──────────────────────────────────────────────────

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SEVERITY_TO_SARIF_RANK = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}

# ── CWE Mapping ─────────────────────────────────────────────────────────────

VULN_CLASS_TO_CWE = {
    "sqli": {"id": "CWE-89", "name": "SQL Injection"},
    "xss": {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)"},
    "xxe": {"id": "CWE-611", "name": "XML External Entity (XXE)"},
    "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)"},
    "idor": {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key"},
    "jwt": {"id": "CWE-345", "name": "Insufficient Verification of Data Authenticity"},
    "csrf": {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)"},
    "authn": {"id": "CWE-287", "name": "Improper Authentication"},
    "session": {"id": "CWE-384", "name": "Session Fixation"},
}


def _rule_id(vuln_class: str, subtype: str) -> str:
    """Generate a stable SARIF rule ID."""
    return f"NIGHTFALL/{vuln_class.upper()}/{subtype.replace('-', '_').upper()}"


def _fingerprint(finding: dict) -> str:
    """Generate a stable fingerprint for a finding."""
    key = f"{finding.get('url', '')}|{finding.get('vuln_class', '')}|{finding.get('param', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def to_sarif(findings: list[dict], campaign_stats: dict | None = None) -> dict:
    """Convert NIGHTFALL findings to SARIF 2.1.0 format.

    Args:
        findings: List of finding dicts from the database.
        campaign_stats: Optional campaign statistics.

    Returns:
        SARIF 2.1.0 compliant dict (serialize with json.dumps).
    """
    now = datetime.now(timezone.utc).isoformat()

    # ── Build rules ──────────────────────────────────────────────────────
    rules_map: dict[str, dict] = {}
    results: list[dict] = []

    for finding in findings:
        vuln_class = finding.get("vuln_class", "unknown")
        subtype = finding.get("subtype", "generic")
        severity = finding.get("severity", "info")
        rule_id = _rule_id(vuln_class, subtype)

        # Register rule if not seen
        if rule_id not in rules_map:
            cwe = VULN_CLASS_TO_CWE.get(vuln_class, {"id": "CWE-1", "name": "Unknown"})
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f"{vuln_class.upper()}_{subtype.replace('-', '_').upper()}",
                "shortDescription": {
                    "text": f"{vuln_class.upper()} - {subtype}",
                },
                "fullDescription": {
                    "text": (
                        finding.get("ai_reason", "")
                        or finding.get("reason", "")
                        or f"Detected {vuln_class} vulnerability ({subtype})"
                    ),
                },
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
                },
                "properties": {
                    "security-severity": str(SEVERITY_TO_SARIF_RANK.get(severity, 1.0)),
                    "tags": ["security", vuln_class, f"cwe-{cwe['id'].split('-')[1]}"],
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe['id'].split('-')[1]}.html",
                "help": {
                    "text": finding.get("remediation", f"Fix {vuln_class} vulnerability"),
                    "markdown": finding.get("remediation", f"Fix {vuln_class} vulnerability"),
                },
                "relationships": [
                    {
                        "target": {
                            "id": cwe["id"],
                            "guid": hashlib.sha256(cwe["id"].encode()).hexdigest()[:36],
                            "toolComponent": {"name": "CWE", "guid": "a0a0a0a0-0000-0000-0000-000000000001"},
                        },
                        "kinds": ["superset"],
                    }
                ],
            }

        # ── Build result ─────────────────────────────────────────────────
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": list(rules_map.keys()).index(rule_id),
            "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
            "message": {
                "text": (
                    f"**{vuln_class.upper()} ({subtype})** detected at "
                    f"`{finding.get('url', '')}` "
                    f"(parameter: `{finding.get('param', 'N/A')}`, "
                    f"confidence: {finding.get('confidence', 0):.0%}). "
                    f"{finding.get('ai_reason', '') or finding.get('reason', '')}"
                ),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("url", ""),
                            "uriBaseId": "%SRCROOT%",
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": finding.get("param", ""),
                            "kind": "parameter",
                            "fullyQualifiedName": (
                                f"{finding.get('method', 'GET')} "
                                f"{finding.get('url', '')} "
                                f"[{finding.get('param', '')}]"
                            ),
                        }
                    ],
                }
            ],
            "fingerprints": {
                "nightfall/v1": _fingerprint(finding),
            },
            "partialFingerprints": {
                "primaryLocationLineHash": _fingerprint(finding),
            },
            "properties": {
                "nightfall-severity": severity,
                "nightfall-confidence": finding.get("confidence", 0),
                "nightfall-class": vuln_class,
                "nightfall-subtype": subtype,
            },
        }

        # Add evidence as code flow
        evidence = finding.get("evidence_snip", "")
        if evidence:
            result["codeFlows"] = [
                {
                    "message": {"text": "HTTP exchange evidence"},
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "message": {"text": evidence[:500]},
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": finding.get("url", ""),
                                            },
                                        },
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]

        results.append(result)

    # ── Assemble SARIF document ──────────────────────────────────────────
    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NIGHTFALL",
                        "fullName": "NIGHTFALL Autonomous AI VAPT Platform",
                        "version": "1.0.0",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/nightfall-security/nightfall",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": now,
                        "endTimeUtc": now,
                        "properties": campaign_stats or {},
                    }
                ],
            }
        ],
    }

    return sarif


def to_sarif_json(findings: list[dict], campaign_stats: dict | None = None) -> str:
    """Convenience: return SARIF as formatted JSON string."""
    return json.dumps(to_sarif(findings, campaign_stats), indent=2)
