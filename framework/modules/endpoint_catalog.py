"""Falcon MAG Framework - Endpoint Catalog

Aggregates ALL discovered endpoints/links from every source:
  - crawler (pages, forms, xhr, js_files)
  - js_endpoints (API/GraphQL)
  - path_discovery (real paths)
  - robots.txt / sitemap.xml
  - OpenAPI/Swagger (if detected)
  - form actions + input params

Each entry has:
  - url, method, type, source, data_carried, description, confidence
"""
import re
from urllib.parse import urlparse, urljoin, parse_qs
from core.logger import get_logger
from core.http_client import is_static_resource

log = get_logger("endpoints")


# ============================================================
# Classification
# ============================================================
TYPE_RULES = [
    ("graphql",  ["/graphql", "/gql"]),
    ("auth",     ["/login", "/logout", "/auth", "/signin", "/signup", "/oauth", "/sso"]),
    ("admin",    ["/admin", "/dashboard", "/manage", "/panel", "/console"]),
    ("upload",   ["/upload", "/attach", "/import"]),
    ("download", ["/download", "/export", "/file", "/pdf", "/csv", "/xml", "/report"]),
    ("api",      ["/api/", "/rest/", "/v1/", "/v2/", "/v3/"]),
    ("websocket",["ws://", "wss://"]),
]

# Data type detection by extension / pattern
DATA_RULES = [
    (r'\.json(\?|$)',        "JSON"),
    (r'\.xml(\?|$)',         "XML"),
    (r'\.csv(\?|$)',         "CSV"),
    (r'\.pdf(\?|$)',         "PDF"),
    (r'\.xlsx?(\?|$)',       "Excel"),
    (r'\.(png|jpg|jpeg|gif|svg|webp)(\?|$)', "Image"),
    (r'\.(js|mjs)(\?|$)',    "JavaScript"),
    (r'\.css(\?|$)',         "CSS"),
    (r'\.html?(\?|$)',       "HTML"),
]


def _classify_type(url: str, source: str) -> str:
    """Classify endpoint by URL pattern + source."""
    lower = url.lower()

    for t, patterns in TYPE_RULES:
        for p in patterns:
            if p in lower:
                return t

    # Source-based
    if source == "form":
        return "form"
    if source == "xhr":
        return "xhr"
    if source == "path_discovery":
        return "path"
    if source == "js_endpoint":
        return "api"

    # Extension-based
    path = urlparse(lower).path
    if path.endswith((".php", ".aspx", ".jsp", ".do", ".action")):
        return "page"
    if path.endswith((".html", ".htm")):
        return "page"

    return "unknown"


def _detect_data_type(url: str) -> str:
    """Detect payload type from URL extension."""
    lower = url.lower()
    for pattern, label in DATA_RULES:
        if re.search(pattern, lower):
            return label
    return "HTML"


def _extract_params(url: str) -> list:
    """Extract query param names from URL."""
    try:
        p = urlparse(url)
        return list(parse_qs(p.query, keep_blank_values=True).keys())
    except Exception:
        return []


def _describe(entry: dict) -> str:
    """Generate human-readable description."""
    t = entry["type"]
    method = entry["method"]
    params = entry.get("params") or []

    if t == "api":
        desc = f"API endpoint (likely {method})"
    elif t == "graphql":
        desc = "GraphQL endpoint — accepts queries/mutations"
    elif t == "auth":
        desc = "Authentication endpoint — login/logout"
    elif t == "admin":
        desc = "Administrative panel — may require auth"
    elif t == "upload":
        desc = "File upload endpoint — check for unrestricted upload"
    elif t == "download":
        desc = "File download/export endpoint"
    elif t == "form":
        desc = f"Form submission ({method})"
    elif t == "xhr":
        desc = "XHR/AJAX request made by JavaScript"
    elif t == "path":
        desc = "Discovered path"
    elif t == "websocket":
        desc = "WebSocket connection — real-time data"
    elif t == "page":
        desc = "HTML page"
    else:
        desc = "Endpoint"

    if params:
        desc += f" | params: {', '.join(params[:5])}"
        if len(params) > 5:
            desc += f" (+{len(params)-5})"

    return desc


# ============================================================
# Collectors
# ============================================================
def _collect_from_crawl(crawl: dict, target: str) -> list:
    """Extract from crawler result."""
    entries = []

    # Pages
    for page in crawl.get("pages", []) or []:
        url = page.get("url") if isinstance(page, dict) else page
        if not url or is_static_resource(url):
            continue
        entries.append({
            "url": url,
            "method": "GET",
            "source": "crawler",
            "confidence": "high",
        })

    # Forms
    for form in crawl.get("forms", []) or []:
        if not isinstance(form, dict):
            continue
        action = form.get("action", "") or target
        method = (form.get("method") or "GET").upper()
        inputs = form.get("inputs", []) or []
        params = [i.get("name") for i in inputs if isinstance(i, dict) and i.get("name")]
        entries.append({
            "url": action,
            "method": method,
            "source": "form",
            "params": params,
            "confidence": "high",
        })

    # XHR requests
    for xhr in crawl.get("xhr_requests", []) or []:
        url = xhr.get("url") if isinstance(xhr, dict) else xhr
        method = xhr.get("method", "GET") if isinstance(xhr, dict) else "GET"
        if not url:
            continue
        entries.append({
            "url": url,
            "method": method.upper(),
            "source": "xhr",
            "confidence": "high",
        })

    return entries


def _collect_from_js_endpoints(js_result: dict) -> list:
    """Extract from js_endpoints module."""
    entries = []
    for url in js_result.get("endpoints", []) or []:
        entries.append({
            "url": url,
            "method": "GET",
            "source": "js_endpoint",
            "confidence": "medium",
        })
    return entries


def _collect_from_path_discovery(pd_result: dict, target: str) -> list:
    """Extract from path_discovery module."""
    entries = []
    for p in pd_result.get("real_paths", []) or []:
        url = p.get("url") if isinstance(p, dict) else None
        if not url:
            continue
        entries.append({
            "url": url,
            "method": "GET",
            "source": "path_discovery",
            "status": p.get("status") if isinstance(p, dict) else None,
            "confidence": "high",
        })
    return entries


def _collect_from_robots(client, target: str) -> list:
    """Fetch robots.txt + sitemap.xml and extract paths."""
    from urllib.parse import urlparse
    entries = []
    p = urlparse(target)
    base = f"{p.scheme}://{p.netloc}"

    # robots.txt
    try:
        r = client.scan_request(base + "/robots.txt")
        if r and r.status == 200 and r.text:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and len(path) > 1:
                        entries.append({
                            "url": urljoin(base, path),
                            "method": "GET",
                            "source": "robots.txt",
                            "confidence": "high",
                        })
    except Exception:
        pass

    # sitemap.xml
    try:
        r = client.scan_request(base + "/sitemap.xml")
        if r and r.status == 200 and r.text:
            urls = re.findall(r"<loc>([^<]+)</loc>", r.text)
            for u in urls[:50]:  # cap
                entries.append({
                    "url": u.strip(),
                    "method": "GET",
                    "source": "sitemap",
                    "confidence": "high",
                })
    except Exception:
        pass

    return entries


def _collect_from_openapi(client, target: str) -> list:
    """Check for OpenAPI/Swagger and extract paths."""
    from urllib.parse import urlparse
    entries = []
    p = urlparse(target)
    base = f"{p.scheme}://{p.netloc}"

    for path in ["/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs",
                 "/v3/api-docs", "/swagger/v1/swagger.json"]:
        try:
            r = client.scan_request(base + path)
            if not r or r.status != 200:
                continue
            if not (r.text and r.text.strip().startswith("{")):
                continue
            import json as _json
            try:
                spec = _json.loads(r.text)
            except Exception:
                continue

            paths = spec.get("paths", {})
            for api_path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                for method, meta in methods.items():
                    if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        continue
                    full = urljoin(base, api_path)
                    params = []
                    if isinstance(meta, dict):
                        for prm in meta.get("parameters", []) or []:
                            if isinstance(prm, dict) and prm.get("name"):
                                params.append(prm["name"])
                    entries.append({
                        "url": full,
                        "method": method.upper(),
                        "source": f"openapi:{path}",
                        "params": params,
                        "confidence": "high",
                    })
            log.info(f"  OpenAPI spec found: {path} ({len(paths)} paths)")
            break
        except Exception:
            continue

    return entries


# ============================================================
# Main
# ============================================================
def run(client, config, crawl_result=None):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info(f"Endpoint catalog on {target}")

    entries = []

    # 1. Crawler
    crawl = crawl_result or config.get("_crawl_result", {}) or {}
    entries.extend(_collect_from_crawl(crawl, target))

    # 2. JS endpoints
    js_eps = config.get("_js_endpoints", {}) or {}
    entries.extend(_collect_from_js_endpoints(js_eps))

    # 3. Path discovery
    pd = config.get("_path_discovery", {}) or {}
    # also try module_results (nested)
    if not pd:
        mr = config.get("module_results", {}) if isinstance(config, dict) else {}
    entries.extend(_collect_from_path_discovery(pd, target))

    # 4. robots.txt + sitemap
    entries.extend(_collect_from_robots(client, target))

    # 5. OpenAPI/Swagger
    entries.extend(_collect_from_openapi(client, target))

    # ============================================================
    # Deduplicate + classify + describe
    # ============================================================
    seen = {}
    for e in entries:
        url = e.get("url", "").strip()
        if not url or len(url) > 500:
            continue
        if is_static_resource(url):
            continue

        # Normalize: strip fragment
        if "#" in url:
            url = url.split("#")[0]
        if not url:
            continue

        key = url
        if key not in seen:
            e["url"] = url
            e["type"] = _classify_type(url, e.get("source", ""))
            e["data_type"] = _detect_data_type(url)
            e["params"] = e.get("params") or _extract_params(url)
            e["description"] = _describe(e)
            seen[key] = e
        else:
            # Merge params
            existing = seen[key]
            for p in e.get("params", []) or []:
                if p and p not in existing.get("params", []):
                    existing.setdefault("params", []).append(p)
            existing["description"] = _describe(existing)

    catalog = sorted(seen.values(), key=lambda x: (x.get("type", "z"), x["url"]))

    # Save for downstream + reports
    config["_endpoint_catalog"] = catalog

    # Count by type
    by_type = {}
    for e in catalog:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1

    log.info(f"  ✓ Catalog: {len(catalog)} unique endpoints")
    for t, n in sorted(by_type.items()):
        log.info(f"    {t}: {n}")

    return {
        "target": target,
        "total": len(catalog),
        "by_type": by_type,
        "endpoints": catalog,
    }
