# -*- coding: utf-8 -*-
"""
JS Endpoint Discovery Phase — Complete
1. Rewrite js_endpoints.py (smarter extraction)
2. Register as FEEDER in cli.py
3. Integrate with param_discovery.py
"""
from pathlib import Path

framework = Path(r"C:\BugBounty\NIGHTFALL\framework")
modules = framework / "modules"

print("=" * 60)
print("JS Endpoint Discovery Phase")
print("=" * 60)
print()

# ============================================================
# 1. Rewrite js_endpoints.py (v2)
# ============================================================
print("[1/3] Rewriting js_endpoints.py...")

new_js_endpoints = r'''"""Falcon MAG Framework - JS Endpoints Extractor (v2)

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

    js_files = {jf for jf in js_files if jf and not _is_excluded(jf)}
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
'''

(modules / "js_endpoints.py").write_text(new_js_endpoints, encoding="utf-8")
print("     [OK] js_endpoints.py rewritten")

# ============================================================
# 2. Register as FEEDER in cli.py
# ============================================================
print("[2/3] Registering in cli.py...")
cli_f = framework / "cli.py"
cli = cli_f.read_text(encoding="utf-8")

# Update FEEDER_MODULES order
old_feeders = 'FEEDER_MODULES = ["crawler", "playwright_crawler", "js_analyzer", "param_discovery"]'
new_feeders = 'FEEDER_MODULES = ["crawler", "playwright_crawler", "js_analyzer", "js_endpoints", "param_discovery"]'

if old_feeders in cli:
    cli = cli.replace(old_feeders, new_feeders, 1)
    print("     [OK] js_endpoints added to FEEDER_MODULES")

# Update FEEDER_KEYS
old_keys = '''FEEDER_KEYS = {
    "crawler":            "_crawl_result",
    "playwright_crawler": "_crawl_result",
    "js_analyzer":        "_js_analyzer",
    "param_discovery":    "_param_discovery",
}'''

new_keys = '''FEEDER_KEYS = {
    "crawler":            "_crawl_result",
    "playwright_crawler": "_crawl_result",
    "js_analyzer":        "_js_analyzer",
    "js_endpoints":       "_js_endpoints",
    "param_discovery":    "_param_discovery",
}'''

if old_keys in cli:
    cli = cli.replace(old_keys, new_keys, 1)
    print("     [OK] js_endpoints added to FEEDER_KEYS")

cli_f.write_text(cli, encoding="utf-8")

# ============================================================
# 3. Patch param_discovery.py to iterate over endpoints
# ============================================================
print("[3/3] Integrating param_discovery with endpoints...")
pd_f = modules / "param_discovery.py"
pd = pd_f.read_text(encoding="utf-8")

# Find the section after "baseline = client.scan_request(target)"
old_baseline_section = '''    baseline = client.scan_request(target)
    if not baseline or baseline.status == 0:
        log.warning("  Cannot reach target")
        return result'''

new_baseline_section = '''    baseline = client.scan_request(target)
    if not baseline or baseline.status == 0:
        log.warning("  Cannot reach target")
        return result

    # === ADDED: gather targets from js_endpoints ===
    discovered_endpoints = config.get("_discovered_endpoints", []) or []
    endpoints_to_test = [target]
    if discovered_endpoints:
        # Add top 10 unique endpoints (avoid explosion)
        for ep in discovered_endpoints[:10]:
            if ep not in endpoints_to_test:
                endpoints_to_test.append(ep)
        log.info(f"  Testing {len(endpoints_to_test)} endpoint(s) from discovery")

    # If we have multiple endpoints, test each
    all_discovered = set()
    for ep_url in endpoints_to_test:
        # Skip static
        if is_static_resource(ep_url):
            continue
        # Skip if same as target (already tested below)
        if ep_url == target:
            continue

        log.debug(f"  Discovering params on: {ep_url}")
        try:
            ep_baseline = client.scan_request(ep_url)
            if not ep_baseline or ep_baseline.status == 0:
                continue
            wordlist = _load_wordlist(config)
            hits = _chunked_bruteforce(client, ep_url, wordlist, ep_baseline, quiet=True)
            for h in hits:
                all_discovered.add(h)
        except Exception as e:
            log.debug(f"    endpoint failed: {e}")

    # Merge endpoint-discovered params into from_bruteforce later
    # (they\'ll be added to from_bruteforce below)
    _pre_discovered = list(all_discovered)
    # === END ==='''

if old_baseline_section in pd:
    pd = pd.replace(old_baseline_section, new_baseline_section, 1)
    print("     [OK] endpoint iteration added to param_discovery")

# After brute_params computed, merge _pre_discovered
old_combine = '''    # ============================================================
    # Step 4: Combine
    # ============================================================
    all_params = sorted(set(result["from_html"]) | set(brute_params))
    result["discovered_params"] = all_params'''

new_combine = '''    # ============================================================
    # Step 4: Combine (target + endpoint-discovered)
    # ============================================================
    # Merge pre-discovered from endpoints
    try:
        for p in _pre_discovered:
            if p not in brute_params:
                brute_params.append(p)
        if _pre_discovered:
            log.info(f"  + {len(_pre_discovered)} params from discovered endpoints")
    except NameError:
        pass

    all_params = sorted(set(result["from_html"]) | set(brute_params))
    result["discovered_params"] = all_params'''

if old_combine in pd:
    pd = pd.replace(old_combine, new_combine, 1)
    print("     [OK] merge logic added")

pd_f.write_text(pd, encoding="utf-8")

print()
print("=" * 60)
print("Done! Files updated:")
print("  - framework/modules/js_endpoints.py (rewritten)")
print("  - framework/modules/param_discovery.py (endpoint integration)")
print("  - framework/cli.py (FEEDER registration)")
print("=" * 60)
