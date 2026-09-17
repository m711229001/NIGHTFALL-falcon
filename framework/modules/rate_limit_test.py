from core.logger import get_logger

log = get_logger("rate_limit")

DEFAULT_REQUESTS = 20


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    n = config.get("scan", {}).get("rate_limit_test_count", DEFAULT_REQUESTS)
    log.info("Rate limit test on " + target + " (" + str(n) + " requests)")
    result = {"target": target, "url": target, "requests_sent": 0, "rate_limited_count": 0, "statuses": {}, "vulnerable": []}
    for i in range(n):
        resp = client.get(target)
        if not resp:
            continue
        result["requests_sent"] += 1
        st = resp.status
        result["statuses"][st] = result["statuses"].get(st, 0) + 1
        if st == 429:
            result["rate_limited_count"] += 1
    sent = result["requests_sent"]
    limited = result["rate_limited_count"]
    if limited > 0:
        log.info("  Rate limiting ACTIVE (" + str(limited) + " 429 responses)")
    else:
        log.warning("  NO rate limiting detected (" + str(sent) + " requests, no 429)")
        result["vulnerable"].append({
            "url": target,
            "original_url": target,
            "injected_url": target,
            "param": "rate-limit",
            "payload": "",
            "severity": "low",
            "description": "No rate limiting after " + str(sent) + " requests",
        })
    return result