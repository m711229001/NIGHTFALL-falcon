"""Falcon MAG Framework - JavaScript Analyzer
Real analysis of downloaded JS files. No hardcoded endpoints."""

import re
from core.logger import get_logger

log = get_logger("js")


# Real regex patterns for extracting endpoints from JS
ENDPOINT_PATTERNS = [
    # /api/v1/users, /api/users, etc.
    r'["\'](/api/[a-zA-Z0-9_\-/{}:.]{2,120})["\']',
    # /v1/users, /v2/users
    r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/{}:.]{2,120})["\']',
    # fetch("..."), axios.get("..."), axios.post("...")
    r'fetch\s*\(\s*["\']([^"\']{4,200})["\']',
    r'axios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']{4,200})["\']',
    r'\$\.\s*(?:ajax|get|post)\s*\(\s*["\']([^"\']{4,200})["\']',
    # Generic full URLs
    r'["\'](https?://[^"\']{6,200})["\']',
    # Paths with at least 2 segments
    r'["\'](/[a-z][a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/{}:.]{2,120})["\']',
]

# Real secret patterns
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub OAuth": r"gho_[0-9a-zA-Z]{36}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]+",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24,}",
    "JWT": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "Private Key": r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----",
    "Basic Auth": r"Basic\s+[A-Za-z0-9+/=]{20,}",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",
    "Generic API Key": r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
    "Generic Secret": r"(?i)(?:secret|client[_-]?secret)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
    "Generic Password": r"(?i)password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
}

# Real DOM XSS sinks
SINK_PATTERNS = {
    "innerHTML": r"\.innerHTML\s*=",
    "outerHTML": r"\.outerHTML\s*=",
    "document.write": r"document\.write\s*\(",
    "document.writeln": r"document\.writeln\s*\(",
    "eval": r"\beval\s*\(",
    "Function constructor": r"new\s+Function\s*\(",
    "setTimeout(string)": r"setTimeout\s*\(\s*['\"]",
    "setInterval(string)": r"setInterval\s*\(\s*['\"]",
    "insertAdjacentHTML": r"insertAdjacentHTML\s*\(",
    "dangerouslySetInnerHTML": r"dangerouslySetInnerHTML",
    "jQuery.html": r"\$\([^)]*\)\.html\s*\(",
    "jQuery.append": r"\$\([^)]*\)\.append\s*\(",
}

# Real DOM XSS sources
SOURCE_PATTERNS = {
    "location.hash": r"location\.hash",
    "location.search": r"location\.search",
    "location.href": r"location\.href",
    "location.pathname": r"location\.pathname",
    "document.referrer": r"document\.referrer",
    "document.URL": r"document\.URL",
    "document.documentURI": r"document\.documentURI",
    "window.name": r"window\.name",
    "postMessage": r"\.postMessage\s*\(",
}


def _extract_endpoints(text: str) -> set:
    """Extract real endpoints from JS content."""
    found = set()
    for pat in ENDPOINT_PATTERNS:
        try:
            for m in re.findall(pat, text):
                if not m or len(m) < 3:
                    continue
                # Filter out common false positives
                if m.startswith(("http://", "https://")):
                    # Keep full URLs
                    found.add(m)
                elif m.startswith("/"):
                    # Keep relative paths
                    if not m.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg",
                                       ".woff", ".woff2", ".ttf", ".eot",
                                       ".ico", ".css", ".map")):
                        found.add(m)
        except Exception:
            pass
    return found


def _extract_secrets(text: str, file_url: str) -> list:
    """Extract real secrets with context."""
    secrets = []
    for name, pat in SECRET_PATTERNS.items():
        try:
            for m in re.finditer(pat, text):
                value = m.group(0)
                if isinstance(m.groups(), tuple) and m.groups():
                    if m.group(1):
                        value = m.group(1)
                # Only add if not obviously a placeholder
                if value.lower() in ("example", "placeholder", "your_key",
                                     "your_secret", "xxx", "todo"):
                    continue
                # Get context (30 chars before)
                start = max(0, m.start() - 40)
                context = text[start:m.start() + len(value) + 10]
                secrets.append({
                    "type": name,
                    "value": value[:80] + ("..." if len(value) > 80 else ""),
                    "file": file_url,
                    "context": context.replace("\n", " ")[:120],
                })
        except Exception:
            pass
    return secrets


def _count_patterns(text: str, patterns: dict) -> dict:
    """Count real occurrences of each pattern."""
    counts = {}
    for name, pat in patterns.items():
        try:
            n = len(re.findall(pat, text))
            if n > 0:
                counts[name] = n
        except Exception:
            pass
    return counts


def run(client, config, crawl_result=None) -> dict:
    """Analyze JS files for endpoints, secrets, sinks, sources."""
    target = config.get("target", "")
    log.info(f"📜 Analyzing JS for {target}")

    result = {
        "target": target,
        "files_analyzed": 0,
        "files_failed": 0,
        "endpoints": set(),
        "secrets": [],
        "sinks": {},
        "sources": {},
        "file_details": [],
    }

    js_files = []
    if crawl_result:
        js_files = crawl_result.get("js_files", []) or []

    if not js_files:
        log.info("  ℹ No JS files found in crawl")
        result["endpoints"] = []
        return result

    max_js = config.get("scan", {}).get("max_js_files", 50)
    js_files = js_files[:max_js]

    for js_url in js_files:
        if not client.in_scope(js_url):
            continue

        resp = client.get(js_url)
        if not resp or resp.status != 200 or not resp.text:
            result["files_failed"] += 1
            log.debug(f"  ✗ Failed: {js_url[:80]}")
            continue

        text = resp.text
        result["files_analyzed"] += 1
        log.info(f"  📄 {js_url[:80]} ({len(text)} bytes)")

        # Extract endpoints
        endpoints = _extract_endpoints(text)
        result["endpoints"].update(endpoints)

        # Extract secrets
        secrets = _extract_secrets(text, js_url)
        result["secrets"].extend(secrets)

        # Count sinks
        sinks = _count_patterns(text, SINK_PATTERNS)
        for k, v in sinks.items():
            result["sinks"][k] = result["sinks"].get(k, 0) + v

        # Count sources
        sources = _count_patterns(text, SOURCE_PATTERNS)
        for k, v in sources.items():
            result["sources"][k] = result["sources"].get(k, 0) + v

        # Per-file summary
        result["file_details"].append({
            "url": js_url,
            "size": len(text),
            "endpoints": len(endpoints),
            "secrets": len(secrets),
            "sinks": sinks,
            "sources": sources,
        })

    result["endpoints"] = sorted(result["endpoints"])

    log.info(f"  ✓ Files analyzed: {result['files_analyzed']} (failed: {result['files_failed']})")
    log.info(f"  ✓ Endpoints: {len(result['endpoints'])}")
    log.info(f"  ✓ Secrets: {len(result['secrets'])}")
    log.info(f"  ✓ Sinks: {sum(result['sinks'].values())}")
    log.info(f"  ✓ Sources: {sum(result['sources'].values())}")

    return result