"""Falcon MAG - React2Shell RCE Scanner (RSC Deserialization)

Targets React Server Components deserialization vulnerabilities
(CVE-2025-55182 family / Flight Protocol gadget chains).

Concept:
  Next.js App Router uses the "Flight" protocol over POST requests with
  Content-Type: text/x-component. The server deserializes the body. If
  deserialization is not strict, an attacker can smuggle references like
  $@1, $1, then, _response that trigger built-in gadgets → RCE.

Detection:
  Send crafted serialized payloads. Watch response for:
    - HTTP 500 with Flight internals ("Flight", "react-server-dom")
    - JS errors: "hasOwnProperty of undefined", "Cannot read prop"
    - Stack traces mentioning: react-server-dom-webpack, react-server-dom-turbopack

SAFETY:
  - Non-destructive payloads (no system commands executed)
  - Sends only "gadget probes" that trigger errors, not RCE chains
  - Read-only detection

Compatible with Falcon HTTPResponse.
"""
import re
from urllib.parse import urljoin

from core.logger import get_logger

log = get_logger("react2shell")

ENDPOINT_PATHS = [
    "/",
    "/api",
    "/_next/data",
]

# Flight protocol payloads (error probes only — not executed RCE)
PAYLOADS = [
    # Basic Flight thenable probe
    '["$@1",{"then":true,"_response":{}}]',
    # Reference + then combination
    '["$1","$@2",{"$2":{"then":"built-in-gadget"}}]',
    # hasOwnProperty probe
    '["$@1",{"then":"$1","_response":"$2","$1":{},"$2":{}}]',
    # Minimal malformed Flight
    '["$"]',
    # Thenable chain
    '["$@1",{"_response":{"then":true,"status":"ok"}}]',
    # Suspense boundary probe
    '["$@1",{"then":true,"_response":{"_prefix":"","_chunks":"","_formData":""}}]',
    # Prototype access probe
    '["$@1",{"then":"$1","constructor":{"prototype":{"then":true}}}]',
]

# Error patterns indicating Flight deserialization issues
ERROR_INDICATORS = [
    "hasownproperty",
    "react-server-dom",
    "react_server_dom",
    "flight",
    "thenable",
    "cannot read property",
    "cannot read propert",
    "property 'hasownproperty'",
    "undefined is not a function",
    "is not a function",
    "__next_f",
    "unexpected token",
    "reading 'then'",
    'reading "then"',
    "reactservercomponents",
]

RSC_HEADERS = [
    "x-nextjs-cache",
    "x-nextjs-prerender",
    "x-nextjs-stale-time",
    "x-middleware-next",
    "vary",
]


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


def _get_headers(r):
    try:
        return {k.lower(): str(v).lower() for k, v in (getattr(r, "headers", {}) or {}).items()}
    except Exception:
        return {}


def _check_is_next(client, target):
    """Quickly detect Next.js."""
    try:
        r = client.get(target, timeout=10)
    except Exception:
        return False
    if r is None:
        return False

    headers_l = _get_headers(r)
    html = _get_text(r)

    if "x-powered-by" in headers_l and "next" in headers_l["x-powered-by"]:
        return True
    if any(h in headers_l for h in ("x-nextjs-cache", "x-nextjs-prerender")):
        return True
    if "__next_data__" in html.lower() or "self.__next_f" in html:
        return True
    return False


def _try_payload(client, url, payload):
    """Send one Flight payload. Return dict of detection signals."""
    headers = {
        "Content-Type": "text/x-component",
        "Accept": "text/x-component",
        "Next-Action": "x",
        "RSC": "1",
    }
    try:
        # Falcon HTTPClient.post uses kwargs
        r = client.post(url, data=payload, headers=headers, timeout=15)
    except Exception as e:
        return {"error": str(e)}
    if r is None:
        return {"error": "no response"}

    status = _extract_status(r)
    body = _get_text(r).lower()
    hdrs = _get_headers(r)

    found_indicators = [ind for ind in ERROR_INDICATORS if ind in body]
    rsc_headers_present = [h for h in RSC_HEADERS if h in hdrs]

    return {
        "status": status,
        "body_len": len(getattr(r, "content", b"") or b""),
        "indicators": found_indicators,
        "rsc_headers": rsc_headers_present,
        "content_type": hdrs.get("content-type", ""),
        "body_preview": _get_text(r)[:500],
    }


def run(config=None, client=None, **kwargs):
    if not client:
        return {"error": "no client", "vulnerable": []}

    target = (config.get("target") or "").rstrip("/")
    if not target:
        return {"error": "no target", "vulnerable": []}

    log.info(f"🔍 React2Shell RCE probe on {target}")

    result = {
        "target": target,
        "is_next": False,
        "tested": 0,
        "suspicious": [],
        "vulnerable": [],
    }

    # Confirm Next.js
    if _check_is_next(client, target):
        result["is_next"] = True
        log.info("  ✓ Next.js detected")
    else:
        log.info("  ⚠ Next.js not confirmed (continuing anyway)")

    # Baseline
    try:
        base = client.get(target, timeout=10)
        base_status = _extract_status(base)
    except Exception:
        base_status = None

    for path in ENDPOINT_PATHS:
        url = urljoin(target + "/", path.lstrip("/"))

        for i, payload in enumerate(PAYLOADS):
            result["tested"] += 1
            resp = _try_payload(client, url, payload)
            if "error" in resp:
                continue

            status = resp.get("status")
            indicators = resp.get("indicators") or []
            rsc_headers = resp.get("rsc_headers") or []

            # STRONG: 500 + multiple indicators
            if status == 500 and len(indicators) >= 2:
                log.warning(f"  ⚠ RSC error leak: payload #{i} → {indicators[:3]}")
                result["suspicious"].append({
                    "url": url,
                    "payload": payload,
                    "indicators": indicators,
                    "response": resp.get("body_preview"),
                })
                result["vulnerable"].append({
                    "url": url,
                    "original_url": target,
                    "injected_url": url,
                    "param": "RSC-Flight-Payload",
                    "payload": payload,
                    "severity": "critical",
                    "description": f"React2Shell: RSC deserialization leaked internals — indicators: {', '.join(indicators[:3])}",
                    "evidence": (resp.get("body_preview") or "")[:400],
                })
                break  # one hit per path

            # MEDIUM: any indicator + status differs from baseline
            elif indicators and status != base_status:
                log.info(f"  ℹ Weak signal: payload #{i} → {indicators[:2]}")
                result["suspicious"].append({
                    "url": url,
                    "payload": payload,
                    "indicators": indicators,
                    "response": resp.get("body_preview"),
                })

    if result["vulnerable"]:
        log.warning(f"  ⚠ {len(result['vulnerable'])} critical findings")
    else:
        log.info("  ℹ No RSC deserialization errors detected")

    return result