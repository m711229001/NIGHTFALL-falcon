"""Falcon MAG Framework - Parameter Discovery (Arjun-style)

Finds hidden GET/POST parameters by:
  1. Extracting from HTML forms + JS + OpenAPI
  2. Chunked brute-force (10 params/request)
  3. Binary search on hit detection

Saves results to config["_discovered_params"] for downstream modules.
"""
import re
import time
from urllib.parse import urlparse, urlunparse, urlencode
from core.logger import get_logger
from core.http_client import is_static_resource

log = get_logger("param_disc")

# Chunk size (params per request)
CHUNK_SIZE = 10

# Response diff thresholds
SIZE_DIFF_THRESHOLD = 50       # bytes
STATUS_DIFF = True              # any status change counts

# Reflection marker
MARKER = "FalconParam9271"


def _add_param(url: str, param: str, value: str) -> str:
    """Add a query parameter to URL."""
    p = urlparse(url)
    existing = p.query
    new_q = (existing + "&" if existing else "") + f"{param}={value}"
    return urlunparse(p._replace(query=new_q))


def _add_many_params(url: str, params: list) -> str:
    """Add many params (all with same marker value)."""
    p = urlparse(url)
    parts = []
    for name in params:
        parts.append(f"{name}={MARKER}")
    new_q = "&".join(parts)
    if p.query:
        new_q = p.query + "&" + new_q
    return urlunparse(p._replace(query=new_q))


def _load_wordlist(config: dict) -> list:
    """Load params wordlist."""
    from pathlib import Path as _Path
    _fw = _Path(__file__).resolve().parent.parent

    wl_path = config.get("wordlists", {}).get("params_common", "")
    if wl_path:
        p = _fw / wl_path if not _Path(wl_path).is_absolute() else _Path(wl_path)
    else:
        p = _fw / "wordlists" / "params_common.txt"

    if not p.exists():
        # Fallback inline list
        return [
            "id", "user", "name", "email", "file", "url", "next", "debug",
            "admin", "token", "key", "api_key", "page", "limit", "offset",
            "q", "query", "search", "s", "sort", "order", "filter", "type",
            "action", "cmd", "exec", "redirect", "return", "callback",
        ]

    lines = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _extract_from_html(html: str, base_url: str) -> set:
    """Extract param names from forms + JS."""
    found = set()

    # <input name="...">
    for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE):
        found.add(m.group(1))

    # <textarea name> + <select name>
    for m in re.finditer(r'<(?:textarea|select)[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE):
        found.add(m.group(1))

    # JS: ?param= or &param=
    for m in re.finditer(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', html):
        found.add(m.group(1))

    # JS: url: '...' with {param}
    for m in re.finditer(r'[\"\'](\w+)[\"\']\s*:\s*[\"\'][^\"\']*\{', html):
        found.add(m.group(1))

    return found


def _diff_responses(baseline, test) -> bool:
    """Check if response differs significantly from baseline."""
    if not baseline or not test:
        return False

    # Status difference
    if STATUS_DIFF and baseline.status != test.status:
        return True

    # Size difference
    baseline_len = len(baseline.text or "")
    test_len = len(test.text or "")
    if abs(test_len - baseline_len) >= SIZE_DIFF_THRESHOLD:
        return True

    # Marker reflection
    if MARKER in (test.text or ""):
        return True

    return False


def _binary_search(client, url, baseline, candidates):
    """Find which params in candidates cause diff (binary search)."""
    if len(candidates) == 1:
        test_url = _add_param(url, candidates[0], MARKER)
        test = client.scan_request(test_url)
        if _diff_responses(baseline, test):
            return [candidates[0]]
        return []

    mid = len(candidates) // 2
    left = candidates[:mid]
    right = candidates[mid:]

    found = []

    # Test left
    test_url = _add_many_params(url, left)
    test = client.scan_request(test_url)
    if _diff_responses(baseline, test):
        if len(left) <= 2:
            found.extend(left)
        else:
            found.extend(_binary_search(client, url, baseline, left))

    # Test right
    test_url = _add_many_params(url, right)
    test = client.scan_request(test_url)
    if _diff_responses(baseline, test):
        if len(right) <= 2:
            found.extend(right)
        else:
            found.extend(_binary_search(client, url, baseline, right))

    return found


def _chunked_bruteforce(client, url: str, wordlist: list, baseline, quiet=False):
    """Chunked testing: 10 params at a time."""
    found = []

    # Remove already-known params
    parsed = urlparse(url)
    existing = set()
    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                existing.add(pair.split("=", 1)[0])
    candidates = [p for p in wordlist if p not in existing]

    total_chunks = (len(candidates) + CHUNK_SIZE - 1) // CHUNK_SIZE

    for i in range(0, len(candidates), CHUNK_SIZE):
        chunk = candidates[i:i + CHUNK_SIZE]
        chunk_num = (i // CHUNK_SIZE) + 1

        test_url = _add_many_params(url, chunk)
        try:
            test = client.scan_request(test_url)
        except Exception:
            continue

        if not test:
            continue

        if _diff_responses(baseline, test):
            if not quiet:
                log.debug(f"  Chunk {chunk_num}/{total_chunks} hit — narrowing...")
            # Binary search on this chunk
            hits = _binary_search(client, url, baseline, chunk)
            for h in hits:
                if h not in found:
                    found.append(h)
                    if not quiet:
                        log.info(f"  [+] Found param: {h}")

    return found


def run(client, config, crawl_result=None):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    # Skip static resources
    if is_static_resource(target):
        log.info(f"Parameter discovery on {target}")
        log.info("  Skipped (static resource)")
        return {"target": target, "skipped": "static_resource"}

    log.info(f"Parameter discovery on {target}")

    result = {
        "target": target,
        "discovered_params": [],
        "from_html": [],
        "from_bruteforce": [],
        "total_tested": 0,
    }

    # ============================================================
    # Step 1: Baseline
    # ============================================================
    baseline = client.scan_request(target)
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
    # (they'll be added to from_bruteforce below)
    _pre_discovered = list(all_discovered)
    # === END ===

    # ============================================================
    # Step 2: Extract from HTML
    # ============================================================
    html_params = set()

    # From main page
    if baseline.status == 200:
        html_params.update(_extract_from_html(baseline.text, target))

    # From crawled pages
    crawl = crawl_result or config.get("_crawl_result", {}) or {}
    for page in crawl.get("pages", []) or []:
        if isinstance(page, str):
            continue
        if isinstance(page, dict) and page.get("html"):
            html_params.update(_extract_from_html(page["html"], target))

    # From forms
    for form in crawl.get("forms", []) or []:
        if isinstance(form, dict):
            for inp in form.get("inputs", []) or []:
                name = inp.get("name") if isinstance(inp, dict) else None
                if name:
                    html_params.add(name)

    html_params = {p for p in html_params if p and 2 <= len(p) <= 40}
    result["from_html"] = sorted(html_params)

    if html_params:
        log.info(f"  From HTML/JS: {len(html_params)} params ({', '.join(list(html_params)[:5])}...)")

    # ============================================================
    # Step 3: Bruteforce wordlist
    # ============================================================
    wordlist = _load_wordlist(config)

    # === Mode-based cap (ADDED 2026-09-20) ===
    preset = config.get("_mode_preset", {}) or {}
    max_params = preset.get("param_discovery_max", 150)
    if max_params and max_params < len(wordlist):
        wordlist = wordlist[:max_params]
        log.info(f"  Mode cap: testing {max_params} params (of {len(_load_wordlist(config))})")
    # === END ===

    log.info(f"  Bruteforcing {len(wordlist)} candidate params (chunks of {CHUNK_SIZE})...")

    t0 = time.time()
    brute_params = _chunked_bruteforce(client, target, wordlist, baseline, quiet=False)
    elapsed = time.time() - t0
    result["from_bruteforce"] = brute_params
    result["total_tested"] = len(wordlist)

    log.info(f"  Bruteforce done in {elapsed:.1f}s — {len(brute_params)} params found")

    # ============================================================
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
    result["discovered_params"] = all_params

    # Save for downstream modules
    config["_discovered_params"] = all_params

    if not all_params:
        log.info("  No parameters discovered")
    else:
        log.info(f"  ✓ Total: {len(all_params)} unique params")

    return result
