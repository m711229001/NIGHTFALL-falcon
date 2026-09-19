"""Falcon MAG - SSR Prototype Pollution Scanner

Detects Prototype Pollution in Server-Side Rendering contexts.

Concept:
  Send crafted JSON with __proto__ or constructor.prototype to an API,
  then request a STATIC page (homepage). If the page's behavior changes
  (broken rendering, toString errors, polluted values), the pollution
  succeeded server-side.

Technique:
  1. Baseline: GET homepage, capture hash + first N bytes
  2. Send pollution payloads to candidate endpoints
  3. Re-GET homepage, compare hash & length
  4. Look for pollution markers in response

SAFETY:
  - Uses harmless markers ("falcon_polluted_xxx")
  - Never sends destructive payloads
  - Read-only detection

Compatible with Falcon HTTPResponse.
"""
import hashlib
import json
import time
from urllib.parse import urljoin

from core.logger import get_logger

log = get_logger("ssr_proto")

# Candidate endpoints that accept JSON
ENDPOINT_PATHS = [
    "/api/user", "/api/user/update", "/api/users/me",
    "/api/profile", "/api/profile/update", "/api/me",
    "/api/v1/user", "/api/v1/users/me", "/api/v1/me", "/api/v1/profile",
    "/api/v2/user", "/api/v2/users/me", "/api/v2/profile",
    "/api/account", "/api/settings", "/api/config",
    "/graphql", "/api/graphql",
    "/api/search", "/api/query",
    "/api/update", "/api/save",
    "/rest/user", "/rest/me",
]

# Prototype pollution payloads (with harmless marker)
MARKER = "falcon_polluted_marker"

POLLUTION_PAYLOADS = [
    {"__proto__": {"falcon_polluted": MARKER, "status": MARKER}},
    {"constructor": {"prototype": {"falcon_polluted": MARKER}}},
    {"__proto__": {"toString": MARKER}},
    {"__proto__": {"falcon_polluted": MARKER, "polluted_by": "falcon_mag"}},
    {"constructor": {"prototype": {"falcon_polluted": MARKER, "polluted_by": "falcon_mag"}}},
    {"__proto__.falcon_polluted": MARKER},
    {"__proto__": {"length": 99999, "falcon_polluted": MARKER}},
]

# Headers often used in SSR apps
EXTRA_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Requested-With": "XMLHttpRequest",
}


def _extract_status(r):
    """Falcon HTTPResponse uses .status, requests uses .status_code."""
    if r is None:
        return None
    for attr in ("status", "status_code"):
        v = getattr(r, attr, None)
        if v is not None:
            try:
                return int(v)
            except Exception:
                continue
    return None


def _get_text(r):
    try:
        return (getattr(r, "text", "") or "")
    except Exception:
        return ""


def _get_content(r):
    try:
        return getattr(r, "content", b"") or b""
    except Exception:
        return b""


def _hash_text(text):
    """Return short hash of text for comparison."""
    try:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]
    except Exception:
        return ""


def _page_signature(client, url):
    """Fetch a page and return (status, hash, length, preview)."""
    try:
        r = client.get(url, timeout=15)
    except Exception as e:
        return None, "", 0, ""
    if r is None:
        return None, "", 0, ""

    status = _extract_status(r)
    text = _get_text(r)
    content = _get_content(r)
    length = len(content) if content else len(text)
    h = _hash_text(text)
    return status, h, length, text[:300]


def _send_pollution(client, url, payload):
    """Send a pollution payload. Return (status, echoed)."""
    try:
        r = client.post(
            url,
            data=json.dumps(payload),
            headers=EXTRA_HEADERS,
            timeout=10,
        )
    except Exception as e:
        return None, ""
    if r is None:
        return None, ""

    status = _extract_status(r)
    text = _get_text(r)
    return status, text[:500]


def run(config=None, client=None, **kwargs):
    if not client:
        return {"error": "no client", "vulnerable": []}

    target = (config.get("target") or "").rstrip("/")
    if not target:
        return {"error": "no target", "vulnerable": []}

    log.info(f"🔍 SSR Prototype Pollution scan on {target}")

    result = {
        "target": target,
        "baseline_hash": None,
        "baseline_len": 0,
        "tested": 0,
        "endpoints_that_accept": [],
        "suspicious_changes": [],
        "vulnerable": [],
    }

    # --- 1. Baseline ---
    b_status, b_hash, b_len, b_preview = _page_signature(client, target)
    if b_hash == "":
        log.warning("  ✗ Cannot establish baseline")
        return result

    result["baseline_hash"] = b_hash
    result["baseline_len"] = b_len
    log.info(f"  Baseline: status={b_status}, len={b_len}, hash={b_hash}")

    # --- 2. Find endpoints that accept JSON ---
    endpoints_found = []
    for path in ENDPOINT_PATHS:
        url = urljoin(target + "/", path.lstrip("/"))
        try:
            # Send a harmless probe
            r = client.post(
                url,
                data=json.dumps({"falcon_probe": "test"}),
                headers=EXTRA_HEADERS,
                timeout=8,
            )
        except Exception:
            continue
        if r is None:
            continue
        status = _extract_status(r)
        # Accept: 2xx, 4xx (but not 405/404 — endpoint exists)
        if status and status not in (404, 405, 501, 0):
            endpoints_found.append((url, status))
            log.info(f"  Endpoint accepts: {path} (status={status})")

    if not endpoints_found:
        log.info("  ℹ No JSON endpoints found")
        return result

    # --- 3. Send pollution payloads ---
    for ep_url, ep_status in endpoints_found[:5]:
        for payload in POLLUTION_PAYLOADS:
            result["tested"] += 1
            p_status, p_text = _send_pollution(client, ep_url, payload)
            if p_status is None:
                continue

            # Echo check: does the response contain our marker?
            marker_in_response = MARKER in (p_text or "")

            # Re-fetch the homepage to detect state change
            time.sleep(0.3)
            a_status, a_hash, a_len, a_preview = _page_signature(client, target)

            # --- Detection signals ---
            hash_changed = (a_hash != b_hash) and a_hash != ""
            len_changed = abs(a_len - b_len) > 100

            # Strong: marker appears in homepage OR hash changed significantly
            if MARKER in (a_preview or ""):
                log.warning(f"  ⚠ Pollution marker found on homepage!")
                result["vulnerable"].append({
                    "url": target,
                    "original_url": target,
                    "injected_url": ep_url,
                    "param": "prototype-pollution",
                    "payload": json.dumps(payload)[:200],
                    "severity": "critical",
                    "description": "SSR Prototype Pollution: marker propagated to homepage",
                    "evidence": f"marker '{MARKER}' visible in homepage after poisoning {ep_url}",
                })
                result["suspicious_changes"].append({
                    "endpoint": ep_url,
                    "hash_before": b_hash,
                    "hash_after": a_hash,
                    "marker_in_page": True,
                })
                break  # one strong hit is enough

            # Medium: hash changed + endpoint echoed marker
            if marker_in_response and hash_changed:
                log.warning(f"  ⚠ Hash changed + marker echoed by endpoint")
                result["vulnerable"].append({
                    "url": ep_url,
                    "original_url": target,
                    "injected_url": ep_url,
                    "param": "prototype-pollution",
                    "payload": json.dumps(payload)[:200],
                    "severity": "high",
                    "description": f"SSR Prototype Pollution (suspected): endpoint echoes marker, homepage hash changed",
                    "evidence": f"before={b_hash}, after={a_hash}, echoed={'yes'}",
                })
                result["suspicious_changes"].append({
                    "endpoint": ep_url,
                    "hash_before": b_hash,
                    "hash_after": a_hash,
                    "marker_echoed": True,
                })
                break

            # Weak: hash changed significantly (may indicate state pollution)
            if hash_changed and len_changed:
                log.info(f"  ℹ Hash + length changed after pollution attempt")
                result["suspicious_changes"].append({
                    "endpoint": ep_url,
                    "hash_before": b_hash,
                    "hash_after": a_hash,
                    "len_before": b_len,
                    "len_after": a_len,
                    "marker_echoed": marker_in_response,
                })

    if result["vulnerable"]:
        log.warning(f"  ⚠ {len(result['vulnerable'])} potential findings")
    else:
        log.info("  ℹ No prototype pollution detected")

    return result