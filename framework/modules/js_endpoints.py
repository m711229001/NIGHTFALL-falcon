"""Falcon MAG Framework - JS Endpoints Extractor (LinkFinder-style)

Extracts API endpoints, URLs, and paths from JavaScript files.
Uses regex patterns to find:
  - /api/... paths
  - Full URLs (http/https)
  - Relative paths
  - WebSocket URLs (ws://, wss://)
"""

import re
from urllib.parse import urljoin, urlparse
from core.logger import get_logger

log = get_logger("js_endpoints")

# Regex patterns for endpoint extraction
PATTERNS = [
    # /api/v1/... or /api/...
    re.compile(r'["\'](/api/[a-zA-Z0-9_\-/\.{}]+)["\']'),
    # /v1/... or /v2/...
    re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/\.{}]+)["\']'),
    # Full URLs
    re.compile(r'["\'](https?://[a-zA-Z0-9_\-\./:{}\?&=]+)["\']'),
    # WebSocket
    re.compile(r'["\'](wss?://[a-zA-Z0-9_\-\./:{}\?&=]+)["\']'),
    # Common path segments
    re.compile(r'["\'](/[a-z][a-zA-Z0-9_\-/]{3,60})["\']'),
]

# Exclude these patterns
EXCLUDE_PATTERNS = [
    re.compile(r'\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|map)$', re.I),
    re.compile(r'^/static/'),
    re.compile(r'^/assets/'),
    re.compile(r'^/img/'),
    re.compile(r'^/fonts/'),
]


def _is_excluded(path):
    for pat in EXCLUDE_PATTERNS:
        if pat.search(path):
            return True
    return False


def _extract_from_text(text, base_url):
    """Extract endpoints from JS text."""
    found = set()
    for pattern in PATTERNS:
        for match in pattern.finditer(text):
            endpoint = match.group(1)
            if _is_excluded(endpoint):
                continue
            # Normalize
            if endpoint.startswith("/"):
                full = urljoin(base_url, endpoint)
            elif endpoint.startswith(("http://", "https://", "ws://", "wss://")):
                full = endpoint
            else:
                continue
            found.add(full)
    return found


def run(client, config, crawl_result=None):
    """Extract endpoints from JS files."""
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info("JS endpoints extraction on " + target)

    result = {
        "target": target,
        "url": target,
        "tested": 0,
        "endpoints": [],
        "js_files": [],
        "vulnerable": [],
    }

    # Get JS files from crawl result (if available)
    crawl = crawl_result or config.get("_crawl_result", {}) or {}
    js_files = crawl.get("js_files", []) or []

    # Also get from js_analyzer result if present
    js_data = config.get("_js_analyzer", {}) or {}
    extra_js = js_data.get("files", []) or []
    for f in extra_js:
        if isinstance(f, str):
            js_files.append(f)
        elif isinstance(f, dict) and "url" in f:
            js_files.append(f["url"])

    # Dedupe
    js_files = list(set(js_files))

    if not js_files:
        # Try fetching HTML and finding JS
        resp = client.get(target)
        if resp and resp.status == 200:
            html_js = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text)
            for src in html_js:
                full = urljoin(target, src)
                js_files.append(full)
        js_files = list(set(js_files))

    if not js_files:
        log.info("  No JS files found")
        return result

    log.info("  Analyzing " + str(len(js_files)) + " JS files")

    all_endpoints = set()
    for js_url in js_files[:30]:  # cap
        result["tested"] += 1
        resp = client.get(js_url)
        if not resp or resp.status != 200:
            continue
        result["js_files"].append(js_url)
        eps = _extract_from_text(resp.text, target)
        all_endpoints.update(eps)

    result["endpoints"] = sorted(all_endpoints)

    if result["endpoints"]:
        log.info("  Found " + str(len(result["endpoints"])) + " endpoints")
        for ep in result["endpoints"][:10]:
            log.info("    " + ep)
        if len(result["endpoints"]) > 10:
            log.info("    ... and " + str(len(result["endpoints"]) - 10) + " more")
    else:
        log.info("  No endpoints found")

    return result