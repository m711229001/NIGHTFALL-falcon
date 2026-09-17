"""Falcon MAG Framework - NoSQL Injection Scanner"""

from urllib.parse import urlparse, parse_qs
from core.logger import get_logger

log = get_logger("nosql")

PAYLOADS = [
    ("[$ne]=null", "ne-null"),
    ("[$ne]=1", "ne-1"),
    ("[$gt]=", "gt-empty"),
    ("[$regex]=.*", "regex-all"),
    ("[$where]=1", "where-1"),
]


def _inject_raw(url, param, raw_suffix):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs.pop(param, None)
    parts = []
    for k, v in qs.items():
        for vv in v:
            parts.append(k + "=" + vv)
    parts.append(param + raw_suffix)
    return p.scheme + "://" + p.netloc + p.path + "?" + "&".join(parts)


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    log.info("NoSQL check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}
    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        log.info("  No parameters to test")
        return result
    baseline = client.scan_request(target)
    if not baseline or baseline.status == 0:
        return result
    baseline_len = len(baseline.content)
    for param in qs:
        for suffix, label in PAYLOADS:
            result["tested"] += 1
            test_url = _inject_raw(target, param, suffix)
            resp = client.scan_request(test_url)
            if not resp or resp.status == 0:
                continue
            new_len = len(resp.content)
            if resp.status == 200 and new_len > baseline_len * 1.5:
                log.warning("  NoSQL in " + param + " (" + label + ")")
                result["vulnerable"].append({
                    "url": target,
                    "original_url": target,
                    "injected_url": test_url,
                    "test_url": test_url,
                    "param": param,
                    "payload": suffix,
                    "operator": label,
                    "severity": "high",
                })
                break
    if not result["vulnerable"]:
        log.info("  No NoSQL injection found (" + str(result["tested"]) + " tested)")
    return result