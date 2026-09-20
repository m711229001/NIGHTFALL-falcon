"""Falcon MAG Framework - JS Endpoints Extractor (v2)

Extracts API endpoints + API paths from JavaScript files.
Shares results via config["_discovered_endpoints"] for downstream modules.

v2 (2026-09-20):
  - More patterns (fetch, axios, jQuery ajax, GraphQL)
  - Categorizes endpoints (api, graphql, auth, admin, ws)
  - Caps unique results, filters junk
  - Publishes endpoints for param_discovery
"""
import re
from urllib.parse import urljoin, urlparse
from core.logger import get_logger
from core.http_client import is_static_resource

log = get_logger("js_endpoints")

# ============================================================
# Extraction patterns
# ============================================================
PATTERNS = [
    # /api/... or /api/v1/...
    (re.compile(r'["\'`](/api/[a-zA-Z0-9_\-/\.{}:]+)["\'`]'), "api"),
    # /v1/... /v2/...
    (re.compile(r'["\'`](/v[0-9]+/[a-zA-Z0-9_\-/\.{}:]+)["\'`]'), "api"),
    # /rest/... /graphql
    (re.compile(r'["\'`](/rest/[a-zA-Z0-9_\-/\.{}:]+)["\'`]'), "rest"),
    (re.compile(r'["\'`](/graphql[a-zA-Z0-9_\-/\.{}:]*)["\'`]'), "graphql"),
    (re.compile(r'["\'`](/gql[a-zA-Z0-9_\-/\.{}:]*)["\'`]'), "graphql"),
    # fetch("url") or fetch('url')
    (re.compile(r'fetch\s*\(\s*["\'`]([^"\'`\s]+)["\'`]'), "fetch"),
    # axios.get/post/put/delete("url")
    (re.compile(r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\'`]([^"\'`\s]+)["\'`]'), "axios"),
    # $.ajax({url: "..."})
    (re.compile(r'url\s*:\s*["\'`]([^"\'`]+)["\'`]'), "jquery"),
    # .get("/path") / .post("/path") (generic HTTP client)
    (re.compile(r'\.\s*(?:get|post|put|delete)\s*\(\s*["\'`](/[a-zA-Z0-9_\-/\.{}:]+)["\'`]'), "client"),
    # Full URLs
    (re.compile(r'["\'`](https?://[a-zA-Z0-9_\-\./:{}\?&=@]+)["\'`]'), "external"),
    # WebSocket
    (re.compile(r'["\'`](wss?://[a-zA-Z0-9_\-\./:{}\?&=]+)["\'`]'), "ws"),
    # Common API path segments (lower priority)
    (re.compile(r'["\'`](/(?:admin|user|users|account|login|logout|auth|signin|signup|dashboard|settings|config|profile|order|product|item|search|upload|download|export|report)/[a-zA-Z0-9_\-/\.{}]*)["\'`]'), "path"),
]

# Exclude patterns
EXCLUDE_PATTERNS = [
    re.compile(r'\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|map|webp|bmp)$', re.I),
    re.compile(r'^/static/'),
    re.compile(r'^/assets/'),
    re.compile(r'^/img/'),
    re.compile(r'^/images/'),
    re.compile(r'^/fonts/'),
    re.compile(r'^/media/'),
    re.compile(r'^\$\{'),  # template literals
    re.compile(r'^<'),     # html
]

# Library files to skip (contain demo URLs, not real endpoints)
LIBRARY_PATTERNS = [
    r"swagger-ui",
    r"swagger\.js",
    r"jquery",
    r"bootstrap",
    r"popper",
    r"react(-dom)?(\.min)?\.js",
    r"vue(\.min)?\.js",
    r"angular(\.min)?\.js",
    r"lodash",
    r"moment",
    r"highlight\.js",
    r"prism",
    r"\.min\.js$",
    r"chunk-vendors",
]


def _is_library(js_url: str) -> bool:
    """Skip minified library files."""
    lower = js_url.lower()
    for pat in LIBRARY_PATTERNS:
        if __import__("re").search(pat, lower):
            return True
    return False


# Known external services (skip)
EXTERNAL_SKIP = [
    "google-analytics.com", "googletagmanager.com", "facebook.com",
    "twitter.com", "linkedin.com", "youtube.com", "w3.org",
    "schema.org", "cloudflare.com", "jquery.com", "bootstrapcdn.com",
]


def _is_excluded(path: str) -> bool:
    for pat in EXCLUDE_PATTERNS:
        if pat.search(path):
            return True
    return False


def _is_external_skip(url: str) -> bool:
    lower = url.lower()
    for s in EXTERNAL_SKIP:
        if s in lower:
            return True
    return False


def _normalize(endpoint: str, base_url: str):
    """Normalize an endpoint into a full URL or None."""
    if not endpoint or len(endpoint) < 3 or len(endpoint) > 300:
        return None
    if endpoint.startswith("/"):
        return urljoin(base_url, endpoint)
    if endpoint.startswith(("http://", "https://", "ws://", "wss://")):
        if _is_external_skip(endpoint):
            return None
        return endpoint
    return None


def _extract_from_text(text: str, base_url: str) -> dict:
    """Extract endpoints from JS text. Returns {category: set(urls)}."""
    found = {}
    for pattern, cat in PATTERNS:
        for match in pattern.finditer(text):
            endpoint = match.group(1)
            if _is_excluded(endpoint):
                continue
            full = _normalize(endpoint, base_url)
            if not full:
                continue
            found.setdefault(cat, set()).add(full)
    return found


def run(client, config, crawl_result=None):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info(f"JS endpoints extraction on {target}")

    result = {
        "target": target,
        "url": target,
        "tested": 0,
        "endpoints": [],
        "endpoints_by_cat": {},
        "js_files": [],
        "categories": {},
    }

    # Collect JS files
    js_files = set()

    crawl = crawl_result or config.get("_crawl_result", {}) or {}
    for jf in crawl.get("js_files", []) or []:
        if isinstance(jf, str):
            js_files.add(jf)
        elif isinstance(jf, dict) and "url" in jf:
            js_files.add(jf["url"])

    # From js_analyzer
    js_data = config.get("_js_analyzer", {}) or {}
    for jf in js_data.get("files", []) or []:
        if isinstance(jf, str):
            js_files.add(jf)
        elif isinstance(jf, dict) and "url" in jf:
            js_files.add(jf["url"])

    # Fallback: extract from HTML
    if not js_files:
        resp = client.get(target)
        if resp and resp.status == 200:
            html_js = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text)
            for src in html_js:
                js_files.add(urljoin(target, src))

    js_files = {jf for jf in js_files if jf and not _is_excluded(jf) and not _is_library(jf)}
    if not js_files:
        log.info("  No JS files to analyze")
        config["_discovered_endpoints"] = []
        return result

    log.info(f"  Analyzing {len(js_files)} JS files")

    all_by_cat = {}
    for js_url in list(js_files)[:25]:
        result["tested"] += 1
        resp = client.get(js_url)
        if not resp or resp.status != 200:
            continue
        result["js_files"].append(js_url)

        found = _extract_from_text(resp.text, target)
        for cat, urls in found.items():
            all_by_cat.setdefault(cat, set()).update(urls)

    # Deduplicate + filter same-origin-only for internal cats
    target_host = urlparse(target).hostname or ""
    internal_cats = {"api", "rest", "graphql", "path", "client", "fetch", "axios", "jquery"}
    external_cats = {"external", "ws"}

    final_eps = []
    for cat, urls in all_by_cat.items():
        for u in urls:
            # Keep internal-only for internal cats
            if cat in internal_cats:
                u_host = urlparse(u).hostname or ""
                if u_host and u_host != target_host:
                    continue
            final_eps.append((cat, u))

    # Unique by URL, prefer more specific category
    seen = {}
    cat_priority = {"api": 1, "graphql": 1, "rest": 2, "fetch": 3, "axios": 3,
                    "client": 4, "jquery": 4, "path": 5, "ws": 6, "external": 7}
    for cat, u in final_eps:
        prio = cat_priority.get(cat, 99)
        if u not in seen or prio < seen[u][0]:
            seen[u] = (prio, cat)

    # Build final output (cap at 100)
    unique = sorted(seen.items(), key=lambda x: (x[1][0], x[0]))[:100]

    by_cat = {}
    for url, (prio, cat) in unique:
        by_cat.setdefault(cat, []).append(url)

    result["endpoints"] = [u for u, _ in unique]
    result["endpoints_by_cat"] = {k: sorted(v) for k, v in by_cat.items()}
    result["categories"] = {k: len(v) for k, v in by_cat.items()}

    # Publish for downstream
    config["_discovered_endpoints"] = result["endpoints"]

    if result["endpoints"]:
        log.info(f"  ✓ Found {len(result['endpoints'])} endpoints")
        for cat, count in sorted(result["categories"].items()):
            log.info(f"    {cat}: {count}")
        # Show top 5
        for ep in result["endpoints"][:5]:
            log.info(f"      {ep}")
        if len(result["endpoints"]) > 5:
            log.info(f"      ... and {len(result['endpoints']) - 5} more")
    else:
        log.info("  No endpoints found")

    return result
