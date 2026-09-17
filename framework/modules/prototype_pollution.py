"""Falcon MAG Framework - Prototype Pollution Scanner (baseline-aware)"""

from urllib.parse import urlparse, parse_qs
from core.logger import get_logger

log = get_logger("prototype")

PAYLOADS = [
    ("__proto__[polluted]=yes", "__proto__-bracket"),
    ("constructor[prototype][polluted]=yes", "constructor-proto"),
    ("__proto__.polluted=yes", "__proto__-dot"),
]

MARKER_KEY = "polluted"
MARKER_VAL = "yes"


def _inject_raw(url, param, raw_suffix):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs.pop(param, None)
    parts = []
    for k, v in qs.items():
        for vv in v:
            parts.append(k + "=" + vv)
    parts.append(raw_suffix)
    return p.scheme + "://" + p.netloc + p.path + "?" + "&".join(parts)


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    log.info("Prototype Pollution check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}
    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        log.info("  No parameters to test")
        return result

    # Baseline response (no payload)
    baseline_resp = client.scan_request(target)
    if not baseline_resp or baseline_resp.status == 0:
        return result

    baseline_has_polluted = (MARKER_KEY in baseline_resp.text) and (MARKER_VAL in baseline_resp.text)

    for param in qs:
        for suffix, label in PAYLOADS:
            result["tested"] += 1
            test_url = _inject_raw(target, param, suffix)
            resp = client.scan_request(test_url)
            if not resp or resp.status == 0:
                continue

            # Skip if payload suffix itself is reflected (httpbin echo)
            if suffix in resp.text:
                # Strip the payload from the response
                stripped = resp.text.replace(suffix, "")
            else:
                stripped = resp.text

            # Only report if: "polluted" and "yes" appear OUTSIDE the payload
            # AND were NOT in baseline
            if (MARKER_KEY in stripped and MARKER_VAL in stripped
                    and not baseline_has_polluted):
                log.warning("  Prototype Pollution in " + param + " (" + label + ")")
                result["vulnerable"].append({
                    "url": target,
                    "original_url": target,
                    "injected_url": test_url,
                    "test_url": test_url,
                    "param": param,
                    "payload": suffix,
                    "evidence": "polluted=" + MARKER_VAL + " reflected outside payload",
                    "severity": "high",
                })
                break

    if not result["vulnerable"]:
        log.info("  No prototype pollution found (" + str(result["tested"]) + " tested)")
    return result