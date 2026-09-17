"""Falcon MAG Framework - CORS Misconfiguration Checker

Tests the target for common CORS misconfigurations:
  - Arbitrary Origin reflected in Access-Control-Allow-Origin
  - Wildcard ACAO combined with credentials
  - Null origin accepted
  - Subdomain prefix/suffix bypass

Returns findings in unified schema: {"vulnerable": [ ... ]}
"""

from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("cors")


# Evil origins to test
EVIL_ORIGINS = [
    "https://evil.example.com",
    "null",
    "https://attacker.com",
]


def _extract_origin(target: str) -> str:
    """Return scheme://host from target (for subdomain tests)."""
    p = urlparse(target)
    if not p.hostname:
        return ""
    return f"{p.scheme}://{p.hostname}"


def _build_subdomain_origin(target: str) -> str:
    """Return scheme://evil.<hostname> for subdomain bypass tests."""
    p = urlparse(target)
    if not p.hostname:
        return ""
    return f"{p.scheme}://evil.{p.hostname}"


def run(client, config) -> dict:
    """Run CORS misconfiguration check."""
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info(f"CORS check on {target}")

    result = {
        "target": target,
        "url": target,
        "tests": [],
        "vulnerable": [],
    }

    # Build list of origins to test
    real_origin = _extract_origin(target)
    subdomain_origin = _build_subdomain_origin(target)

    origins_to_test = list(EVIL_ORIGINS)
    if subdomain_origin and subdomain_origin not in origins_to_test:
        origins_to_test.append(subdomain_origin)

    # Baseline (no Origin header)
    baseline = client.get(target, headers={"Origin": real_origin})
    if not baseline or baseline.status == 0:
        log.warning(f"  Baseline failed: {baseline.error if baseline else 'no response'}")
        result["error"] = "baseline failed"
        return result

    baseline_acao = baseline.headers.get("Access-Control-Allow-Origin")
    baseline_acac = baseline.headers.get("Access-Control-Allow-Credentials")
    result["baseline"] = {
        "acao": baseline_acao,
        "acac": baseline_acac,
    }

    # Test each evil origin
    for origin in origins_to_test:
        resp = client.get(target, headers={"Origin": origin})
        if not resp or resp.status == 0:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        vary = resp.headers.get("Vary", "")

        test_entry = {
            "origin": origin,
            "status": resp.status,
            "acao": acao,
            "acac": acac,
            "vary": vary,
        }

        # ---- Verdict ----
        is_vulnerable = False
        reason = ""

        if acao and acac and acac.lower() == "true":
            # Case A: exact origin reflected + credentials
            if acao == origin and origin != real_origin:
                is_vulnerable = True
                reason = f"Origin '{origin}' reflected with credentials=true"

            # Case B: wildcard + credentials (invalid but misconfigured)
            elif acao == "*" and acac.lower() == "true":
                is_vulnerable = True
                reason = "Wildcard ACAO with credentials=true"

        # Case C: null origin accepted with credentials
        if origin == "null" and acao == "null" and acac and acac.lower() == "true":
            is_vulnerable = True
            reason = "Null origin accepted with credentials=true"

        # Case D: subdomain prefix/suffix bypass (ACAO reflects evil.<host>)
        if subdomain_origin and acao == subdomain_origin and origin == subdomain_origin:
            is_vulnerable = True
            reason = f"Subdomain bypass: evil.{urlparse(target).hostname} reflected"

        test_entry["vulnerable"] = is_vulnerable
        test_entry["reason"] = reason
        result["tests"].append(test_entry)

        if is_vulnerable:
            log.warning(f"  CORS VULN: {reason}")
            result["vulnerable"].append({
                "url": target,
                "original_url": target,
                "injected_url": target,
                "param": "Origin",
                "payload": origin,
                "evil_origin": origin,
                "acao": acao,
                "acac": acac,
                "severity": "high",
                "description": reason,
            })

    if not result["vulnerable"]:
        log.info(f"  No CORS issues detected ({len(origins_to_test)} origins tested)")
    else:
        log.warning(f"  Found {len(result['vulnerable'])} CORS issue(s)")

    return result
