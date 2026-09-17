from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("cookies")

SESSION_HINTS = ("session", "sess", "sid", "auth", "token", "jwt")


def _parse_one(cookie_str):
    if not cookie_str:
        return None
    parts = [p.strip() for p in cookie_str.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    info = {"name": name.strip(), "value": value.strip(), "secure": False, "httponly": False, "samesite": None}
    for attr in parts[1:]:
        k, _, v = attr.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "secure":
            info["secure"] = True
        elif k == "httponly":
            info["httponly"] = True
        elif k == "samesite":
            info["samesite"] = v
    return info


def _extract_from_resp(resp):
    if not resp:
        return []
    raw = resp.headers.get("Set-Cookie") or resp.headers.get("set-cookie")
    if not raw:
        return []
    import re
    return re.split(r",:s*(?=[A-Za-z0-9_-]+=)", raw)


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    log.info(f"Cookies check on {target}")
    result = {"target": target, "url": target, "cookies": [], "vulnerable": []}
    resp = client.get(target, allow_redirects=False)
    if not resp or resp.status == 0:
        log.warning("  Target unreachable")
        result["error"] = resp.error if resp else "no response"
        return result
    cookie_strs = _extract_from_resp(resp)
    if not cookie_strs:
        log.info("  No cookies set by target")
        return result
    for cs in cookie_strs:
        info = _parse_one(cs)
        if not info:
            continue
        result["cookies"].append(info)
        missing = []
        if not info["secure"]:
            missing.append("Secure")
        if not info["httponly"]:
            missing.append("HttpOnly")
        if not info["samesite"]:
            missing.append("SameSite")
        if not missing:
            log.info("  Cookie OK")
            continue
        reason = "missing " + ", ".join(missing)
        log.warning("  Insecure cookie: " + reason)
        result["vulnerable"].append({"url": target, "original_url": target, "injected_url": target, "param": info["name"], "payload": "", "severity": "medium", "description": "Cookie " + info["name"] + " " + reason})
    if not result["vulnerable"]:
        log.info("  All cookies secure")
    return result