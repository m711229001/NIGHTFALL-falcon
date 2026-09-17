"""Falcon MAG - SARIF 2.1.0 Export for CI/CD integration."""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from pathlib import Path
from datetime import datetime, timezone
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.security import get_current_user
from core import nightfall_db

router = APIRouter(prefix="/api/scans", tags=["sarif"])


# Severity mapping to SARIF levels
SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Severity to CVSS score (for security-severity property)
SEVERITY_TO_CVSS = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}


def _build_rules(findings: list) -> list:
    """Build unique rules from findings (one per vuln_class)."""
    seen = {}
    for f in findings:
        cls = f.get("vuln_class", "unknown")
        if cls in seen:
            continue
        severity = f.get("severity", "info")
        seen[cls] = {
            "id": f"NIGHTFALL-{cls.upper()}",
            "name": cls.replace("_", " ").title().replace(" ", ""),
            "shortDescription": {
                "text": f"{cls.upper()} vulnerability"
            },
            "fullDescription": {
                "text": f"Detected {cls.upper()} vulnerability by NIGHTFALL autonomous scanner."
            },
            "helpUri": f"https://owasp.org/www-community/vulnerabilities/",
            "properties": {
                "tags": ["security", cls.lower(), severity],
                "security-severity": SEVERITY_TO_CVSS.get(severity, "0.0"),
            },
        }
    return list(seen.values())


def _build_results(findings: list) -> list:
    """Build SARIF results from findings."""
    results = []
    for i, f in enumerate(findings, 1):
        severity = f.get("severity", "info").lower()
        cls = f.get("vuln_class", "unknown")
        url = f.get("url", "")
        param = f.get("param", "") or ""
        evidence = f.get("evidence", "") or ""
        description = f.get("description", "") or f"{cls.upper()} at {url}"

        # Extract file path from URL
        file_path = "unknown"
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            file_path = parsed.path or "/"
        except Exception:
            pass

        result = {
            "ruleId": f"NIGHTFALL-{cls.upper()}",
            "ruleIndex": 0,  # Will be resolved by consumer
            "level": SEVERITY_TO_SARIF.get(severity, "note"),
            "message": {
                "text": f"[{severity.upper()}] {cls.upper()} in {url}" + (f" (param: {param})" if param else "")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": url,
                        },
                    },
                }
            ],
            "properties": {
                "severity": severity,
                "vuln_class": cls,
                "param": param,
                "evidence": evidence[:500],
                "description": description[:1000],
            },
        }
        results.append(result)
    return results


def generate_sarif(scan: dict, findings: list) -> dict:
    """Generate SARIF 2.1.0 report."""
    scan_id = scan.get("id", 0)
    target = scan.get("target", "")
    started_at = scan.get("started_at", 0)
    completed_at = scan.get("completed_at", 0)

    # Convert unix timestamp to ISO 8601
    def ts_to_iso(ts):
        if not ts:
            return datetime.now(timezone.utc).isoformat()
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    rules = _build_rules(findings)
    results = _build_results(findings)

    # Map rule IDs to indices
    rule_index_map = {r["id"]: i for i, r in enumerate(rules)}
    for r in results:
        rid = r.get("ruleId")
        if rid in rule_index_map:
            r["ruleIndex"] = rule_index_map[rid]

    sarif = {
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
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": scan.get("status") == "completed",
                        "startTimeUtc": ts_to_iso(started_at),
                        "endTimeUtc": ts_to_iso(completed_at),
                        "properties": {
                            "scan_id": scan_id,
                            "target": target,
                            "elapsed_seconds": scan.get("elapsed_seconds", 0),
                            "requests_used": scan.get("requests_used", 0),
                            "budget": scan.get("budget", 0),
                            "findings_count": len(findings),
                            "ai_tokens": scan.get("ai_tokens", 0),
                            "waf": scan.get("waf"),
                        },
                    }
                ],
                "properties": {
                    "target": target,
                    "scan_id": scan_id,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
            }
        ],
    }
    return sarif


@router.get("/{scan_id}/export/sarif")
async def export_scan_sarif(
    scan_id: int,
    download: bool = False,
    user: dict = Depends(get_current_user),
):
    """Export scan results as SARIF 2.1.0."""
    scan = nightfall_db.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = nightfall_db.get_findings(scan_id=scan_id)

    try:
        sarif = generate_sarif(scan, findings)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SARIF generation failed: {exc}")

    if download:
        filename = f"nightfall_scan_{scan_id}_{int(datetime.utcnow().timestamp())}.sarif"
        return JSONResponse(
            content=sarif,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    return JSONResponse(content=sarif)