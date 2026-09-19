"""Falcon MAG - RSC Data Leakage Scanner

Detects sensitive data leaking into the client-side hydration state of:
  - Next.js Pages Router: <script id="__NEXT_DATA__" type="application/json">
  - Next.js App Router:   self.__next_f.push([1, "..."])  (Flight data)

Why it matters:
  Server components often fetch full DB rows (including password_hash,
  api_keys, internal_notes) and pass them to the client without filtering.
  The data lives in plain text inside <script> tags → readable by anyone.

Technique:
  1. GET the target page
  2. Extract __NEXT_DATA__ or __next_f.push fragments
  3. Recursively scan JSON for sensitive keys/values
  4. Report with evidence

Compatible with Falcon HTTPResponse.
"""
import json
import re
from urllib.parse import urlparse

from core.logger import get_logger

log = get_logger("rsc_leak")

# Sensitive key names (case-insensitive substring match)
SENSITIVE_KEYS = [
    "password", "passwd", "pwd", "pass_hash", "password_hash",
    "secret", "client_secret", "api_secret",
    "token", "access_token", "refresh_token", "id_token",
    "api_key", "apikey", "api-key",
    "private_key", "privatekey",
    "aws_", "stripe_", "github_",
    "session", "sessionid", "session_id",
    "credit_card", "creditcard", "card_number", "cvv",
    "ssn", "national_id", "iqama",
    "internal_", "admin_", "root_",
    "db_", "database_", "connection_string",
    "smtp_", "mail_password",
    "webhook_secret", "hmac",
]

# Value patterns (regex on strings)
VALUE_PATTERNS = [
    (r"sk_live_[A-Za-z0-9]{24,}", "Stripe Live Key"),
    (r"sk_test_[A-Za-z0-9]{24,}", "Stripe Test Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Token"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token"),
    (r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}", "JWT Token"),
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Private Key"),
    (r"[a-z]+://[^:\s]+:[^@\s]+@[^\s\"]+", "Connection String with credentials"),
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "Possible Visa Card"),
    (r"\b5[1-5][0-9]{14}\b", "Possible MasterCard"),
]

# Ignore list (public/common false positives)
IGNORE_KEYS = {
    "createdAt", "updatedAt", "publishedAt", "id", "_id",
    "version", "created_at", "updated_at",
    "page_id", "_nextI18Next", "buildId", "assetPrefix",
    "userAgent", "locale", "language", "nextExport",
    "page", "query", "props", "runtimeConfig",
    "isFallback", "gip", "appGip", "gsp",
}


def _safe_repr(v):
    """Short masked representation of a value."""
    try:
        if isinstance(v, str):
            s = v
            if len(s) > 80:
                s = s[:40] + "..." + s[-20:]
            return s
        return repr(v)[:120]
    except Exception:
        return "<repr failed>"


def _scan_json(obj, path="", depth=0, out=None, max_depth=15):
    """Recursive JSON scan for sensitive keys/values."""
    if out is None:
        out = []
    if depth > max_depth:
        return out

    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                continue
            k_l = k.lower()
            if k not in IGNORE_KEYS:
                for sens in SENSITIVE_KEYS:
                    if sens in k_l:
                        out.append({
                            "key": k,
                            "value": _safe_repr(v),
                            "path": f"{path}.{k}".lstrip("."),
                            "match": sens,
                        })
                        break
            _scan_json(v, f"{path}.{k}".lstrip("."), depth + 1, out, max_depth)

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _scan_json(item, f"{path}[{i}]", depth + 1, out, max_depth)

    elif isinstance(obj, str):
        for pattern, name in VALUE_PATTERNS:
            try:
                if re.search(pattern, obj):
                    out.append({
                        "key": "(value)",
                        "value": _safe_repr(obj),
                        "path": path,
                        "match": name,
                    })
                    break
            except Exception:
                continue

    return out


def _extract_next_data(html):
    """Pages Router: <script id="__NEXT_DATA__" ...>JSON</script>"""
    out = []
    for m in re.finditer(
        r'<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>',
        html, re.DOTALL | re.IGNORECASE
    ):
        out.append(m.group(1))
    return out


def _extract_rsc_payload(html):
    """App Router: self.__next_f.push([1, "..."]) — concatenated fragments."""
    fragments = []
    for m in re.finditer(
        r'self\.__next_f\.push\(\s*\[\s*1\s*,\s*"((?:[^"\\]|\\.)*)"\s*\]\s*\)',
        html, re.DOTALL
    ):
        raw = m.group(1)
        try:
            unescaped = bytes(raw, "utf-8").decode("unicode_escape", errors="ignore")
        except Exception:
            unescaped = raw
        fragments.append(unescaped)
    return fragments


def _scan_fragment(text, source_label):
    """Scan a text fragment for sensitive keys/values."""
    hits = []
    # Sensitive keys with values
    for sens in SENSITIVE_KEYS:
        pattern = rf'"{re.escape(sens)}[^"]*"\s*:\s*("[^"]*"|\d+|true|false|null)'
        for m in re.finditer(pattern, text, re.IGNORECASE):
            snippet = m.group(0)[:200]
            hits.append({
                "key": sens,
                "value": snippet,
                "path": source_label,
                "match": sens,
            })
    # Value patterns
    for pattern, name in VALUE_PATTERNS:
        try:
            for m in re.finditer(pattern, text):
                hits.append({
                    "key": "(value)",
                    "value": m.group(0)[:100],
                    "path": source_label,
                    "match": name,
                })
        except Exception:
            continue
    return hits


def run(config=None, client=None, crawl_result=None, **kwargs):
    if not client:
        return {"error": "no client", "vulnerable": []}

    target = (config.get("target") or "").rstrip("/")
    if not target:
        return {"error": "no target", "vulnerable": []}

    log.info(f"🔍 RSC Data Leakage scan on {target}")

    result = {
        "target": target,
        "pages_checked": 0,
        "next_data_found": 0,
        "rsc_payload_found": 0,
        "leaks": [],
        "vulnerable": [],
    }

    # Pages to check
    urls = {target}
    if crawl_result:
        for p in (crawl_result.get("pages") or []):
            u = p.get("url") if isinstance(p, dict) else None
            if u:
                urls.add(u)
    urls = list(urls)[:10]

    for url in urls:
        result["pages_checked"] += 1
        try:
            r = client.get(url, timeout=15)
        except Exception:
            continue

        if r is None:
            continue

        # Falcon HTTPResponse uses .status, not .status_code
        status = getattr(r, "status", None) or getattr(r, "status_code", 0)
        if status not in (200, 0):
            if not (200 <= (status or 0) < 400):
                continue

        html = getattr(r, "text", "") or ""

        # Pages Router: __NEXT_DATA__
        nds = _extract_next_data(html)
        if nds:
            result["next_data_found"] += 1
            for raw in nds:
                try:
                    data = json.loads(raw)
                    hits = _scan_json(data, path="__NEXT_DATA__")
                    if hits:
                        result["leaks"].extend(hits)
                except Exception:
                    hits = _scan_fragment(raw, "__NEXT_DATA__")
                    if hits:
                        result["leaks"].extend(hits)

        # App Router: __next_f.push
        rscs = _extract_rsc_payload(html)
        if rscs:
            result["rsc_payload_found"] += 1
            combined = "\n".join(rscs)
            hits = _scan_fragment(combined, "RSC")
            if hits:
                result["leaks"].extend(hits)

    # Dedup + convert to findings
    seen = set()
    for leak in result["leaks"]:
        key = (leak.get("key"), leak.get("match"), leak.get("path"))
        if key in seen:
            continue
        seen.add(key)

        sev = "high" if leak.get("match") in (
            "Stripe Live Key", "AWS Access Key", "GitHub Personal Token",
            "GitHub OAuth Token", "JWT Token", "Private Key",
            "Connection String with credentials",
            "Possible Visa Card", "Possible MasterCard",
        ) else "medium"

        result["vulnerable"].append({
            "url": target,
            "original_url": target,
            "injected_url": target,
            "param": leak.get("key") or leak.get("match"),
            "payload": leak.get("value"),
            "severity": sev,
            "description": f"Data leak in hydration state: '{leak.get('match')}' at {leak.get('path')}",
            "evidence": f"{leak.get('key')} = {leak.get('value')} (path: {leak.get('path')})",
        })

    if result["vulnerable"]:
        log.warning(f"  ⚠ Found {len(result['vulnerable'])} potential data leaks")
    else:
        log.info("  ℹ No data leaks detected")

    return result