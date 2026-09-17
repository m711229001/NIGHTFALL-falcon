from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import get_logger

log = get_logger("open_redirect")

EVIL = "https://evil.example.com/"

PARAM_NAMES = ("url", "redirect", "next", "return", "returnurl", "return_url", "redirect_uri", "redirect_url", "continue", "target", "dest", "destination", "go", "out", "view", "callback", "forward")


def _inject(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def _is_redirect_to_evil(resp):
    if not resp:
        return None
    loc = resp.headers.get("Location") or resp.headers.get("location")
    if loc and "evil.example.com" in loc:
        return ("Location", loc)
    if resp.text and "evil.example.com" in resp.text:
        return ("body", "evil.example.com found in response body")
    return None


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    log.info("Open Redirect check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}
    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    params = list(qs.keys())
    if not params:
        params = ["url", "redirect", "next", "return"]
        base = target
    else:
        base = target
    for param in params:
        test_url = _inject(base, param, EVIL)
        result["tested"] += 1
        resp = client.scan_request(test_url, allow_redirects=False)
        if not resp or resp.status == 0:
            continue
        match = _is_redirect_to_evil(resp)
        if match:
            where, evidence = match
            log.warning("  OPEN REDIRECT in " + param + " (" + where + ")")
            result["vulnerable"].append({
                "url": target,
                "original_url": target,
                "injected_url": test_url,
                "test_url": test_url,
                "param": param,
                "payload": EVIL,
                "redirect_to": evidence,
                "severity": "medium",
            })
    if not result["vulnerable"]:
        log.info("  No open redirect found (" + str(result["tested"]) + " params tested)")
    return result