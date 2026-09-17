"""Falcon MAG Framework - IDOR Scanner"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import get_logger

log = get_logger("idor")

TEST_VALUES = ["2", "3", "100", "0", "-1", "999999"]


def _inject(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    log.info("IDOR check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}
    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        log.info("  No numeric parameters to test")
        return result
    baseline = client.scan_request(target)
    if not baseline or baseline.status == 0:
        return result
    baseline_size = len(baseline.content)
    for param, values in qs.items():
        original_value = values[0] if values else ""
        if not original_value.isdigit():
            continue
        for test_value in TEST_VALUES:
            if test_value == original_value:
                continue
            result["tested"] += 1
            test_url = _inject(target, param, test_value)
            resp = client.scan_request(test_url)
            if not resp or resp.status == 0:
                continue
            if resp.status == 200:
                new_size = len(resp.content)
                diff = abs(new_size - baseline_size)
                similarity = 1.0 - (diff / max(baseline_size, 1))
                if 0.3 < similarity < 0.95:
                    log.warning("  Potential IDOR in " + param + " (size diff: " + str(diff) + ")")
                    result["vulnerable"].append({
                        "url": target,
                        "original_url": target,
                        "injected_url": test_url,
                        "test_url": test_url,
                        "param": param,
                        "payload": test_value,
                        "original_id": original_value,
                        "tested_id": test_value,
                        "similarity": round(similarity, 2),
                        "severity": "high",
                    })
                    break
    if not result["vulnerable"]:
        log.info("  No IDOR indicators (" + str(result["tested"]) + " values tested)")
    return result