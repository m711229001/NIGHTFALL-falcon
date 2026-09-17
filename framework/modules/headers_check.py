"""Falcon MAG Framework - Security Headers Check
Real analysis of HTTP response headers. No hardcoded data."""

from core.logger import get_logger

log = get_logger("headers")


HEADER_INFO = {
    "content-security-policy": {
        "purpose": "Restricts sources of scripts, styles, images",
        "severity": "medium",
        "recommendation": "Implement a restrictive CSP policy",
    },
    "x-frame-options": {
        "purpose": "Prevents clickjacking via iframes",
        "severity": "medium",
        "recommendation": "Set to DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "purpose": "Prevents MIME-type sniffing",
        "severity": "low",
        "recommendation": "Set to nosniff",
    },
    "strict-transport-security": {
        "purpose": "Forces HTTPS connections",
        "severity": "medium",
        "recommendation": "Set max-age=31536000; includeSubDomains",
    },
    "x-xss-protection": {
        "purpose": "Legacy XSS filter (deprecated)",
        "severity": "info",
        "recommendation": "Rely on CSP instead",
    },
    "referrer-policy": {
        "purpose": "Controls referrer information",
        "severity": "low",
        "recommendation": "Set to strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "purpose": "Controls browser features",
        "severity": "low",
        "recommendation": "Restrict unused features",
    },
}

INFO_LEAK_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
    "x-version",
]


def run(client, config) -> dict:
    """Check security headers on target."""
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info(f"🛡️  Checking headers on {target}")

    resp = client.scan_request(target)
    if not resp or resp.status == 0:
        return {"error": "Target unreachable"}

    result = {
        "target": target,
        "present": {},
        "missing": {},
        "info_leak": {},
        "findings": [],
    }

    # Check each recommended security header
    for header, info in HEADER_INFO.items():
        val = resp.headers.get(header) or resp.headers.get(header.title())
        if val:
            result["present"][header] = val
        else:
            result["missing"][header] = info["recommendation"]
            result["findings"].append({
                "severity": info["severity"],
                "title": f"Missing security header: {header}",
                "description": info["purpose"],
                "evidence": f"Header '{header}' is not set in the response.",
                "url": target,
                "category": "Headers",
            })

    # Check for info-leaking headers
    for h in INFO_LEAK_HEADERS:
        val = resp.headers.get(h) or resp.headers.get(h.title())
        if val:
            result["info_leak"][h] = val
            result["findings"].append({
                "severity": "info",
                "title": f"Information disclosure: {h}",
                "description": f"Header '{h}' reveals implementation details.",
                "evidence": f"{h}: {val}",
                "url": target,
                "category": "Headers",
            })

    log.info(f"  ✓ Present: {len(result['present'])}")
    log.info(f"  ✗ Missing: {len(result['missing'])}")

    return result