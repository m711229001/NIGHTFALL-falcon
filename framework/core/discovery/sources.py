"""Discovery sources - robots, sitemap, HTML, JS, well-known probes."""
import re
from urllib.parse import urljoin
from core.logger import get_logger

log = get_logger("discovery.sources")


_HTML_LINK_RE = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)
_HTML_SRC_RE = re.compile(r"""src=["']([^"']+)["']""", re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"""<form[^>]*action=["']([^"']*)["']""", re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r"""<form[^>]*method=["']([^"']*)["']""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"""<input[^>]*name=["']([^"']+)["']""", re.IGNORECASE)
_META_REFRESH_RE = re.compile(
    r"""<meta[^>]*http-equiv=["']refresh["'][^>]*content=["']([^"']+)["']""",
    re.IGNORECASE,
)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_JS_PATH_RE = re.compile(
    r"""["'](/(?:api|v\d+|graphql|admin|internal|user|auth)[^"']*?)["']""",
    re.IGNORECASE,
)
_JS_FETCH_RE = re.compile(r"""fetch\s*\(\s*["']([^"']+)["']""", re.IGNORECASE)
_JS_AXIOS_RE = re.compile(r"""axios\.[a-z]+\s*\(\s*["']([^"']+)["']""", re.IGNORECASE)
_JS_URL_RE = re.compile(
    r"""(?:url|endpoint|baseURL)\s*[:=]\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def fetch_robots(client, base_url):
    result = {"paths": [], "sitemaps": [], "raw": ""}
    url = urljoin(base_url, "/robots.txt")
    resp = client.get(url)
    if not resp or resp.status != 200 or not resp.content:
        return result
    try:
        text = resp.content.decode("utf-8", errors="ignore")
    except Exception:
        return result
    result["raw"] = text[:5000]
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("disallow:") or low.startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                result["paths"].append(path)
        elif low.startswith("sitemap:"):
            sm = line.split(":", 1)[1].strip()
            if sm.startswith("http"):
                result["sitemaps"].append(sm)
    return result


def fetch_sitemap(client, sitemap_url, depth=0):
    if depth > 2:
        return []
    urls = []
    resp = client.get(sitemap_url)
    if not resp or resp.status != 200 or not resp.content:
        return urls
    try:
        text = resp.content.decode("utf-8", errors="ignore")
    except Exception:
        return urls
    locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.IGNORECASE)
    for loc in locs:
        if loc.endswith(".xml") or loc.endswith(".xml.gz"):
            urls.extend(fetch_sitemap(client, loc, depth + 1))
        else:
            urls.append(loc)
    return urls


def parse_html(content, base_url):
    out = {"links": [], "forms": [], "js_files": [], "comments": [], "meta_refresh": []}
    if not content:
        return out
    try:
        html = content.decode("utf-8", errors="ignore")
    except Exception:
        return out

    for m in _HTML_LINK_RE.finditer(html):
        href = m.group(1).strip()
        if href and not href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            out["links"].append(urljoin(base_url, href))

    for m in _HTML_SRC_RE.finditer(html):
        src = m.group(1).strip()
        if src and (src.endswith(".js") or ".js?" in src):
            out["js_files"].append(urljoin(base_url, src))

    for form_match in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.DOTALL | re.IGNORECASE):
        form_tag = form_match.group(0)[:500]
        action_m = _FORM_ACTION_RE.search(form_tag)
        method_m = _FORM_METHOD_RE.search(form_tag)
        action = action_m.group(1) if action_m else ""
        method = (method_m.group(1) if method_m else "GET").upper()
        inputs = [m.group(1) for m in _INPUT_NAME_RE.finditer(form_match.group(1))]
        out["forms"].append({
            "action": urljoin(base_url, action) if action else base_url,
            "method": method,
            "inputs": inputs,
        })

    for m in _META_REFRESH_RE.finditer(html):
        content_attr = m.group(1)
        url_m = re.search(r"url=([^;]+)", content_attr, re.IGNORECASE)
        if url_m:
            out["meta_refresh"].append(urljoin(base_url, url_m.group(1).strip()))

    for m in _COMMENT_RE.finditer(html):
        comment = m.group(1).strip()
        if len(comment) > 3000:
            continue
        for url_m in re.finditer(r"https?://[^\s<>\"']+", comment):
            out["comments"].append(url_m.group(0))

    return out


def parse_js(content, base_url):
    out = {"paths": [], "fetch_calls": [], "axios_calls": [], "base_urls": []}
    if not content:
        return out
    try:
        js = content.decode("utf-8", errors="ignore")
    except Exception:
        return out
    for m in _JS_PATH_RE.finditer(js):
        out["paths"].append(urljoin(base_url, m.group(1)))
    for m in _JS_FETCH_RE.finditer(js):
        out["fetch_calls"].append(urljoin(base_url, m.group(1)))
    for m in _JS_AXIOS_RE.finditer(js):
        out["axios_calls"].append(urljoin(base_url, m.group(1)))
    for m in _JS_URL_RE.finditer(js):
        out["base_urls"].append(m.group(1))
    return out


WELL_KNOWN = (
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/security.txt",
    "/manifest.json",
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
)


def probe_well_known(client, base_url, catchall=None):
    hits = []
    for path in WELL_KNOWN:
        url = urljoin(base_url, path)
        try:
            resp = client.get(url, timeout=4)
        except Exception:
            resp = None
        if not resp or resp.status == 0:
            continue
        if catchall and catchall.is_catchall(resp.status, resp.content):
            continue
        if resp.status in (200, 401, 403):
            hits.append({
                "url": url,
                "status": resp.status,
                "size": len(resp.content or b""),
            })
    return hits
