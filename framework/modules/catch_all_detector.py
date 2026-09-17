"""Falcon MAG Framework - Catch-All Detector"""

import hashlib
import uuid
from urllib.parse import urljoin
from core.logger import get_logger

log = get_logger("catchall")


def _hash_response(resp):
    if not resp or resp.status == 0:
        return None
    body = resp.content or b""
    return hashlib.md5(body).hexdigest()


def run(client, config) -> dict:
    target = config.get("target", "").rstrip("/")
    if not target:
        return {"error": "No target"}

    log.info("Catch-all detection on " + target)

    result = {
        "target": target,
        "url": target,
        "tested": 0,
        "catch_all_detected": False,
        "unique_hashes": 0,
        "samples": [],
        "vulnerable": [],
    }

    baseline = client.get(target)
    if not baseline or baseline.status == 0:
        log.warning("  Baseline failed")
        result["error"] = "baseline failed"
        return result

    baseline_hash = _hash_response(baseline)
    log.info("  Baseline: HTTP " + str(baseline.status)
             + ", " + str(len(baseline.content)) + " bytes")

    n_samples = 8
    hashes = {}
    for i in range(n_samples):
        uid = uuid.uuid4().hex
        test_url = urljoin(target + "/", uid)
        result["tested"] += 1
        resp = client.get(test_url)
        if not resp or resp.status == 0:
            continue
        h = _hash_response(resp)
        hashes.setdefault(h, []).append({
            "path": "/" + uid,
            "status": resp.status,
            "size": len(resp.content),
        })

    unique_count = len(hashes)
    result["unique_hashes"] = unique_count

    if unique_count == 1:
        only_hash = list(hashes.keys())[0]
        samples = hashes[only_hash]
        result["catch_all_detected"] = True
        result["samples"] = samples[:3]
        same_as_baseline = (only_hash == baseline_hash)

        log.warning("  CATCH-ALL DETECTED")
        log.warning("    All " + str(n_samples) + " random paths returned same response")
        log.warning("    Status: " + str(samples[0]["status"])
                    + ", Size: " + str(samples[0]["size"]) + " bytes")
        if same_as_baseline:
            log.warning("    Same as baseline (target itself)")

        result["vulnerable"].append({
            "url": target,
            "original_url": target,
            "injected_url": urljoin(target + "/", uuid.uuid4().hex),
            "param": "",
            "payload": "",
            "severity": "info",
            "description": "Catch-all route detected: all random paths return "
                           + str(samples[0]["status"]) + " with same content. "
                           + "This causes false positives in path discovery.",
            "catch_all_hash": only_hash,
            "same_as_baseline": same_as_baseline,
            "sample_count": n_samples,
        })
    elif unique_count <= 2:
        log.warning("  Possible catch-all (" + str(unique_count) + " unique responses)")
    else:
        log.info("  No catch-all (" + str(unique_count) + " unique responses from "
                 + str(n_samples) + " paths)")

    return result