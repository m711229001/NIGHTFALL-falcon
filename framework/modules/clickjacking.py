"""Falcon MAG Framework - Clickjacking Checker"""
from core.logger import get_logger

log = get_logger("clickjacking")

VALID_XFO = {"deny", "sameorigin"}


def _parse_csp_frame_ancestors(csp_value):
    if not csp_value:
        return None
    for directive in csp_value.split(";"):
        directive = directive.strip()
        if directive.lower().startswith("frame-ancestors"):
            parts = directive.split(None, 1)
            if len(parts) == 2:
                return parts[1].strip()
    return None


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info(f"Clickjacking check on {target}")

    result = {
        "target": target,
        "url": target,
        "status": None,
        "x_frame_options": None,
        "csp": None,
        "frame_ancestors": None,
        "vulnerable": [],
    }

    resp = client.scan_request(target)
    if not resp or resp.status == 0:
        log.warning("  Target unreachable")
        result["error"] = resp.error if resp else "no response"
        return result

    result["status"] = resp.status
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    xfo = headers_lower.get("x-frame-options")
    csp = headers_lower.get("content-security-policy")
    result["x_frame_options"] = xfo
    result["csp"] = csp

    xfo_ok = False
    if xfo:
        xfo_val = xfo.strip().lower()
        if xfo_val in VALID_XFO or xfo_val.startswith("allow-from"):
            xfo_ok = True

    csp_ok = False
    frame_ancestors = _parse_csp_frame_ancestors(csp)
    result["frame_ancestors"] = frame_ancestors
    if frame_ancestors:
        fa = frame_ancestors.lower().strip()
        if fa == "'none'" or fa not in ("*", ""):
            csp_ok = True

    if xfo_ok or csp_ok:
        log.info(f"  Protected (XFO: {xfo or 'none'})")
    else:
        reasons = []
        if not xfo:
            reasons.append("X-Frame-Options missing")
        else:
            reasons.append(f"X-Frame-Options invalid: {xfo}")
        if not frame_ancestors:
            reasons.append("CSP frame-ancestors missing")
        else:
            reasons.append(f"CSP frame-ancestors insecure: {frame_ancestors}")

        result["vulnerable"].append({
            "url": target,
            "original_url": target,
            "injected_url": target,
            "param": "",
            "payload": "",
            "x_frame_options": xfo,
            "csp": csp,
            "frame_ancestors": frame_ancestors,
            "severity": "medium",
            "reason": " | ".join(reasons),
        })
        log.warning(f"  CLICKJACKING: {' | '.join(reasons)}")

    return result
