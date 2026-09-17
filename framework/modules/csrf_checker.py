from urllib.parse import urljoin, urlparse
from core.logger import get_logger
from bs4 import BeautifulSoup

log = get_logger("csrf")

TOKEN_HINTS = ("csrf", "xsrf", "token", "authenticity", "_token", "nonce")


def _has_token(fields):
    for name in fields:
        n = name.lower()
        for hint in TOKEN_HINTS:
            if hint in n:
                return True
    return False


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    log.info("CSRF check on " + target)
    result = {"target": target, "url": target, "forms_found": 0, "vulnerable_forms": []}
    resp = client.scan_request(target)
    if not resp or resp.status == 0:
        log.warning("  Target unreachable")
        result["error"] = resp.error if resp else "no response"
        return result
    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")
    result["forms_found"] = len(forms)
    if not forms:
        log.info("  No forms found")
        return result
    for form in forms:
        method = (form.get("method") or "GET").upper()
        if method != "POST":
            continue
        action = form.get("action") or target
        action = urljoin(target, action)
        inputs = form.find_all(["input", "textarea", "select"])
        field_names = []
        for inp in inputs:
            name = inp.get("name")
            if name:
                field_names.append(name)
        if not field_names:
            continue
        if _has_token(field_names):
            continue
        log.warning("  CSRF-vulnerable POST form at " + action)
        result["vulnerable_forms"].append({
            "url": target,
            "action": action,
            "method": method,
            "fields": field_names,
            "original_url": target,
            "injected_url": action,
            "param": "",
            "payload": "",
        })
    if not result["vulnerable_forms"]:
        log.info("  All POST forms have anti-CSRF tokens")
    return result