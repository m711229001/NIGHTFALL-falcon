"""Historical URL sources - Wayback, Common Crawl, AlienVault OTX."""
import json
from urllib.parse import urlparse, quote
from core.logger import get_logger

log = get_logger("discovery.history")

DEFAULT_TIMEOUT = 12
UA = "FalconMAG/2.0 (+recon; passive)"
_SESSION = None


def _get_session():
    global _SESSION
    if _SESSION is None:
        import requests
        _SESSION = requests.Session()
        _SESSION.headers.update({"User-Agent": UA, "Accept": "application/json"})
        _SESSION.verify = False
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass
    return _SESSION


def _safe_get(url, timeout=DEFAULT_TIMEOUT):
    try:
        s = _get_session()
        r = s.get(url, timeout=timeout, allow_redirects=True)
        if r.status_code != 200:
            return None
        return r
    except Exception as e:
        log.debug("  [history] http error: " + str(e)[:80])
        return None


def _extract_domain(target):
    try:
        p = urlparse(target)
        return (p.hostname or "").lower()
    except Exception:
        return ""


def fetch_wayback(domain, limit=500, timeout=DEFAULT_TIMEOUT):
    out = []
    if not domain:
        return out
    api = "http://web.archive.org/cdx/search/cdx"
    qs = ("url=" + quote(domain + "/*") +
          "&output=json&fl=original&collapse=urlkey&limit=" + str(limit) +
          "&filter=statuscode:200&filter=mimetype:text/html")
    r = _safe_get(api + "?" + qs, timeout=timeout)
    if not r:
        log.info("  [wayback] no response")
        return out
    try:
        data = r.json()
        if not data or len(data) < 2:
            return out
        for row in data[1:]:
            if row and row[0]:
                out.append(row[0])
    except Exception as e:
        log.debug("  [wayback] parse: " + str(e)[:80])
    log.info("  [wayback] " + str(len(out)) + " URLs")
    return out


def fetch_commoncrawl(domain, limit=500, timeout=DEFAULT_TIMEOUT):
    out = []
    if not domain:
        return out
    indices = [
        "CC-MAIN-2024-51", "CC-MAIN-2024-38", "CC-MAIN-2024-33",
        "CC-MAIN-2024-22", "CC-MAIN-2024-10",
    ]
    for idx in indices:
        api = "https://index.commoncrawl.org/" + idx + "-index"
        qs = "url=" + quote(domain + "/*") + "&output=json&limit=" + str(limit)
        r = _safe_get(api + "?" + qs, timeout=timeout)
        if not r:
            continue
        try:
            for line in r.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    u = obj.get("url")
                    if u:
                        out.append(u)
                except Exception:
                    continue
            if out:
                log.info("  [commoncrawl] " + str(len(out)) + " URLs (" + idx + ")")
                return out
        except Exception:
            continue
    if not out:
        log.info("  [commoncrawl] no URLs found")
    return out


def fetch_otx(domain, limit=500, timeout=DEFAULT_TIMEOUT):
    out = []
    if not domain:
        return out
    api = "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/url_list"
    qs = "?limit=" + str(min(limit, 500)) + "&page=1"
    r = _safe_get(api + qs, timeout=timeout)
    if not r:
        log.info("  [otx] no response")
        return out
    try:
        data = r.json()
        for item in (data.get("url_list") or []):
            u = item.get("url")
            if u:
                out.append(u)
    except Exception as e:
        log.debug("  [otx] parse: " + str(e)[:80])
    log.info("  [otx] " + str(len(out)) + " URLs")
    return out


# ============================================================
# Dangerous URL filter - ADDED 2026-09-20
# ============================================================
DANGEROUS_EXTENSIONS = (
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz",
    ".exe", ".dmg", ".msi", ".deb", ".rpm", ".apk", ".ipa",
    ".mp4", ".mp3", ".avi", ".mov", ".mkv", ".wav", ".flac",
    ".iso", ".img", ".bin", ".jar", ".war", ".ear",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)

DANGEROUS_PATH_PATTERNS = (
    "/delay/", "/sleep/", "/wait/", "/slow/",
    "/bytes/", "/stream/", "/drip/", "/range/",
    "/status/", "/redirect-to", "/absolute-redirect/",
    "/relative-redirect/", "/links/", "/image/",
)

DANGEROUS_QUERY_PATTERNS = (
    "?timeout=", "&timeout=", "?delay=", "&delay=",
    "?sleep=", "&sleep=", "?wait=", "&wait=",
    "?size=", "&size=", "?bytes=", "&bytes=",
)


def is_dangerous_url(url):
    """Filter URLs that cause slow responses or huge downloads."""
    if not url:
        return True
    low = url.lower()
    # Extensions
    for ext in DANGEROUS_EXTENSIONS:
        if low.endswith(ext) or (ext + "?") in low:
            return True
    # Path patterns
    for pat in DANGEROUS_PATH_PATTERNS:
        if pat in low:
            return True
    # Query patterns
    for pat in DANGEROUS_QUERY_PATTERNS:
        if pat in low:
            return True
    return False


def fetch_all_historical(target, limit=500, timeout=DEFAULT_TIMEOUT):
    domain = _extract_domain(target)
    if not domain:
        return []
    log.info("  Historical recon for: " + domain)
    merged = []
    merged.extend(fetch_wayback(domain, limit=limit, timeout=timeout))
    merged.extend(fetch_commoncrawl(domain, limit=limit, timeout=timeout))
    merged.extend(fetch_otx(domain, limit=limit, timeout=timeout))
    seen = set()
    out = []
    filtered = 0
    for u in merged:
        if not u or not u.startswith(("http://", "https://")):
            continue
        if is_dangerous_url(u):
            filtered += 1
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    log.info("  Historical total: " + str(len(out)) + " unique URLs ("
             + str(filtered) + " dangerous filtered)")
    return out
