"""Falcon MAG Framework - DOM-based XSS Scanner (v2 - Smart)

Static analysis of JavaScript files for DOM XSS.

v2 fixes (2026-09-20):
  - Removed location.href from SOURCES (not attacker-controlled)
  - Reject self-reference (source == sink)
  - Require same-line assignment (sink <- source)
  - Skip minified/library files
  - Only flag TRUE tainted flows
"""

import re
from urllib.parse import urljoin
from core.logger import get_logger
from core.http_client import is_static_resource

log = get_logger("dom_xss")


# Dangerous sinks (where attacker data gets executed/rendered)
SINKS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write", "document.writeln",
    "eval(", "Function(", "setTimeout(", "setInterval(",
    "location.assign", "location.replace",
]

# True attacker-controlled sources (tainted)
# NOTE: location.href is NOT here (self-reference benign)
TAINTED_SOURCES = [
    "location.hash",
    "location.search",
    "document.referrer",
    "window.name",
    "event.data",
    "location.href.split",
]

# Files to skip entirely (minified libs — too noisy)
LIBRARY_PATTERNS = [
    r"jquery(\.min)?\.js",
    r"swagger-ui",
    r"bootstrap(\.min)?\.js",
    r"popper(\.min)?\.js",
    r"react(-dom)?(\.min)?\.js",
    r"vue(\.min)?\.js",
    r"angular(\.min)?\.js",
    r"lodash(\.min)?\.js",
    r"moment(\.min)?\.js",
    r"\.bundle\.js",
    r"\.min\.js$",
]


def _is_library(js_url: str) -> bool:
    """Skip minified library files."""
    lower = js_url.lower()
    for pattern in LIBRARY_PATTERNS:
        if re.search(pattern, lower):
            return True
    return False


def _find_true_flows(text: str):
    """Find only HIGH-CONFIDENCE DOM XSS flows.

    Criteria:
      1. sink and source appear on the SAME line (or 2-line window)
      2. source != sink
      3. The line looks like an assignment/call: sink = ... source ... OR sink(...source...)
    """
    hits = []
    lines = text.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip comments
        if stripped.startswith("//") or stripped.startswith("*"):
            continue

        # Find sink on this line
        for sink in SINKS:
            if sink not in line:
                continue

            # Find source on this line (same line only — reduces FP)
            for source in TAINTED_SOURCES:
                if source not in line:
                    continue

                # Skip if source's base name == sink's base name
                # (e.g., location.href <- location.href)
                sink_base = sink.rstrip("(.").replace("location.", "").strip()
                source_base = source.replace("location.", "").replace("document.", "").strip()
                if sink_base == source_base:
                    continue

                # Require assignment or call pattern
                # Pattern: sink = ...source... OR sink(...source...)
                pattern_match = False
                if "=" in line:
                    # sink on left side, source on right side
                    try:
                        eq_idx = line.index("=")
                        left = line[:eq_idx]
                        right = line[eq_idx:]
                        if sink in left and source in right:
                            pattern_match = True
                    except ValueError:
                        pass
                if "(" in line and source in line:
                    # sink(arg) - any call containing source
                    if sink + "(" in line or "(" + sink in line:
                        pattern_match = True

                if not pattern_match:
                    continue

                # Ignore obvious safe patterns
                # sink = "" + ... (empty concat)
                # sink = "static string"
                safe_patterns = [
                    r'innerHTML\s*=\s*["\'][^"\']*["\']\s*;',  # static string
                    r'innerHTML\s*=\s*""',
                ]
                is_safe = False
                for sp in safe_patterns:
                    if re.search(sp, line):
                        is_safe = True
                        break
                if is_safe:
                    continue

                hits.append((sink, source, stripped[:200]))
                break  # only one source per sink

    # Deduplicate by (sink, source)
    seen = set()
    unique = []
    for s, src, snip in hits:
        key = (s, src)
        if key not in seen:
            seen.add(key)
            unique.append((s, src, snip))
    return unique



def _playwright_dom_xss_test(target: str, config: dict) -> list:
    """Use Playwright to test DOM XSS via location.hash / location.search.

    Returns list of vulnerable URLs.
    """
    findings = []
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.debug("Playwright not available")
        return findings

    # Unique payload to detect execution
    payload_marker = "DOMXSS_" + str(int(__import__("time").time()))
    test_payloads = [
        "<script>window.__falcon_dom='" + payload_marker + "'</script>",
        "<img src=x onerror=\"window.__falcon_dom='" + payload_marker + "'\">",
        "javascript:window.__falcon_dom='" + payload_marker + "'",
    ]

    # Only test if URL has hash or query params potential
    from urllib.parse import urlparse
    p = urlparse(target)

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            # Track dialog (alert) and DOM mutation
            for payload in test_payloads:
                # Test via hash
                test_urls = []
                if p.fragment or "#" in target or True:  # always try hash
                    test_urls.append(target + "#" + payload)
                # Test via query param
                sep = "&" if "?" in target else "?"
                test_urls.append(target + sep + "q=" + payload)
                test_urls.append(target + sep + "default=" + payload)

                for test_url in test_urls:
                    try:
                        # Reset marker
                        page.goto("about:blank")
                        page.add_init_script(
                            "window.__falcon_dom = null;"
                        )
                        page.goto(test_url, timeout=8000, wait_until="domcontentloaded")
                        page.wait_for_timeout(800)

                        # Check if payload executed
                        marker_val = page.evaluate("window.__falcon_dom")
                        if marker_val == payload_marker:
                            log.warning(f"  DOM XSS EXECUTED: {test_url[:80]}")
                            findings.append({
                                "url": target,
                                "original_url": target,
                                "injected_url": test_url,
                                "param": "hash" if "#" in test_url else "query",
                                "payload": payload,
                                "severity": "high",
                                "description": "DOM XSS - payload executed via JavaScript",
                                "evidence": f"window.__falcon_dom = {payload_marker}",
                            })
                            break

                        # Also check body HTML for raw payload (unescaped)
                        body = page.content()
                        if payload in body and "&lt;script&gt;" not in body:
                            log.warning(f"  DOM XSS reflected unescaped: {test_url[:80]}")
                            findings.append({
                                "url": target,
                                "original_url": target,
                                "injected_url": test_url,
                                "param": "hash" if "#" in test_url else "query",
                                "payload": payload,
                                "severity": "high",
                                "description": "DOM XSS - payload appears unescaped in DOM",
                                "evidence": test_url[:200],
                            })
                            break
                    except Exception as e:
                        log.debug(f"Playwright test failed: {str(e)[:80]}")
                        continue

                if findings:
                    break

            browser.close()
    except Exception as e:
        log.debug(f"Playwright launch failed: {e}")

    return findings


def run(client, config, crawl_result=None):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info("DOM XSS static analysis on " + target)

    result = {
        "target": target,
        "url": target,
        "tested": 0,
        "js_files": [],
        "vulnerable": [],
        "skipped_libs": 0,
    }

    # Collect JS files
    js_files = set()
    crawl = crawl_result or config.get("_crawl_result", {}) or {}
    for jf in crawl.get("js_files", []) or []:
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

    if not js_files:
        log.info("  No JS files to analyze")
        return result

    # Analyze up to 25 JS files
    analyzed = 0
    for js_url in list(js_files)[:25]:
        # Skip static resources (css, images, etc.)
        if is_static_resource(js_url) and not js_url.lower().endswith(".js"):
            continue

        # Skip minified libraries (jquery, swagger, etc.)
        if _is_library(js_url):
            result["skipped_libs"] += 1
            continue

        analyzed += 1
        result["tested"] += 1
        resp = client.get(js_url)
        if not resp or resp.status != 200:
            continue
        result["js_files"].append(js_url)

        hits = _find_true_flows(resp.text)
        for sink, source, snippet in hits[:2]:  # max 2 per file
            log.warning(f"  DOM XSS: {sink} <- {source}  [{js_url}]")
            result["vulnerable"].append({
                "url": target,
                "original_url": target,
                "injected_url": js_url,
                "param": source,
                "payload": sink,
                "severity": "medium",  # lowered — static analysis only
                "description": f"Static: '{source}' flows to '{sink}'",
                "evidence": snippet,
                "confidence": "low",  # NEW: mark as low confidence
                "note": "Static analysis only — needs manual verification",
            })

    # === PLAYWRIGHT DYNAMIC DOM XSS TEST (ADDED 2026-09-20) ===
    playwright_findings = _playwright_dom_xss_test(target, config)
    for pf in playwright_findings:
        result["vulnerable"].append(pf)

    if not result["vulnerable"]:
        log.info(f"  No DOM XSS sinks detected (analyzed {analyzed} files, skipped {result['skipped_libs']} libs)")
    else:
        log.warning(f"  Found {len(result['vulnerable'])} potential DOM XSS (need verification)")

    return result
