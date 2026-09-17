"""Falcon MAG Framework - HTTP Methods Checker

Tests the target for dangerous HTTP methods:
  - TRACE (Cross-Site Tracing)
  - PUT / DELETE (unauthenticated modification)
  - Also reports the Allow header and OPTIONS response.

Returns findings in unified schema: {"vulnerable": [ ... ]}
"""

from core.logger import get_logger

log = get_logger("http_methods")


# Dangerous methods to test
DANGEROUS = ["TRACE", "PUT", "DELETE", "PATCH", "CONNECT"]


def run(client, config) -> dict:
    """Run HTTP methods check."""
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info(f"HTTP Methods check on {target}")

    result = {
        "target": target,
        "url": target,
        "status": None,
        "allow_header": None,
        "options_status": None,
        "tested_methods": [],
        "dangerous": [],
        "vulnerable": [],
    }

    # --- Step 1: OPTIONS request ---
    opt = client.options(target)
    if opt and opt.status != 0:
        result["options_status"] = opt.status
        allow = opt.headers.get("Allow") or opt.headers.get("allow")
        result["allow_header"] = allow
        if allow:
            log.info(f"  Allow: {allow}")
        else:
            log.info(f"  OPTIONS: HTTP {opt.status} (no Allow header)")

    # --- Step 2: Test each dangerous method ---
    for method in DANGEROUS:
        try:
            resp = client.request(method, target)
        except Exception as e:
            log.debug(f"  {method}: error {e}")
            continue

        if not resp or resp.status == 0:
            continue

        entry = {
            "method": method,
            "status": resp.status,
            "size": len(resp.content),
        }
        result["tested_methods"].append(entry)

        # --- Verdict per method ---
        is_dangerous = False
        reason = ""

        if method == "TRACE" and resp.status == 200:
            is_dangerous = True
            reason = "TRACE returns 200 OK"
        elif method in ("PUT", "DELETE") and resp.status in (200, 201, 202, 204):
            is_dangerous = True
            reason = f"{method} accepted (HTTP {resp.status})"
        elif method == "PATCH" and resp.status in (200, 201, 202, 204):
            is_dangerous = True
            reason = f"PATCH accepted (HTTP {resp.status})"
        elif method == "CONNECT" and resp.status == 200:
            is_dangerous = True
            reason = "CONNECT accepted"

        entry["dangerous"] = is_dangerous
        entry["reason"] = reason

        if is_dangerous:
            log.warning(f"  DANGEROUS: {reason}")
            result["dangerous"].append(entry)
            result["vulnerable"].append({
                "url": target,
                "original_url": target,
                "injected_url": target,
                "param": "HTTP-Method",
                "payload": method,
                "method": method,
                "status": resp.status,
                "severity": "medium",
                "description": reason,
            })

    if not result["vulnerable"]:
        log.info(f"  No dangerous HTTP methods detected")

    return result
