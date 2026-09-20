"""Advanced JS analysis - LinkFinder + SecretFinder patterns."""
import re
from urllib.parse import urljoin
from core.logger import get_logger

log = get_logger("discovery.js_analysis")

MAX_JS_SIZE = 2_000_000

VENDOR_JS_KEYWORDS = (
    "swagger", "redoc", "openapi", "bundle", "vendor", "polyfill",
    "jquery", "react", "vue", "angular", "lodash", "moment",
    "chart", "d3", "three", "leaflet", "mapbox", "monaco",
    "codemirror", "tinymce", "ckeditor", "quill",
    "bootstrap", "tailwind", "bulma", "foundation",
    "google-analytics", "gtag", "gtm", "analytics",
    "facebook", "twitter", "linkedin",
    "recaptcha", "hcaptcha", "turnstile",
    "stripe", "paypal", "checkout",
)


def is_vendor_js(url):
    """Skip secrets from vendor/library JS files."""
    if not url:
        return False
    low = url.lower()
    return any(kw in low for kw in VENDOR_JS_KEYWORDS)


# LinkFinder-style patterns
RE_LINK_1 = re.compile(r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?|#][^"|']{0,}|)))(?:"|')""")
RE_LINK_2 = re.compile(r"""(?:"|')((?:https?:)?//[^"'\s]+)(?:"|')""")
RE_PATH = re.compile(r"""(?:"|')(/[a-zA-Z0-9_\-./]{2,}(?:\?[^"'\s]*)?)(?:"|')""")

# Secret patterns
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret": re.compile(r"(?i)aws.{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]"),
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "github_token": re.compile(r"(?i)github.{0,20}?['\"]((ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})['\"]"),
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    "stripe_key": re.compile(r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,99}"),
    "sendgrid": re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    "mailgun": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "twilio": re.compile(r"SK[0-9a-fA-F]{32}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "private_key": re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY"),
    "firebase": re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
    "heroku": re.compile(r"(?i)heroku.{0,20}?['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z_\-]{16,64})['\"]"),
    "generic_password": re.compile(r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^\"']{4,64})['\"]"),
    "s3_bucket": re.compile(r"[a-z0-9.\-]+\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com"),
    "internal_ip": re.compile(r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b"),
    "email": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
}


def extract_links(js_text, base_url):
    if not js_text:
        return []
    found = set()
    for m in RE_LINK_1.finditer(js_text):
        for g in m.groups():
            if g:
                found.add(g)
    for m in RE_PATH.finditer(js_text):
        found.add(m.group(1))

    out = []
    for raw in found:
        raw = raw.strip()
        if len(raw) < 2 or len(raw) > 500:
            continue
        try:
            if raw.startswith(("http://", "https://")):
                out.append(raw)
            elif raw.startswith("//"):
                out.append("https:" + raw)
            elif raw.startswith("/"):
                out.append(urljoin(base_url, raw))
            elif "." in raw and "/" in raw:
                out.append(urljoin(base_url, raw))
        except Exception:
            continue
    return out


def extract_secrets(js_text, js_url=""):
    if not js_text:
        return []
    if js_url and is_vendor_js(js_url):
        return []
    out = []
    for name, pattern in SECRET_PATTERNS.items():
        try:
            for m in pattern.finditer(js_text):
                val = m.group(0)
                if len(val) > 200:
                    continue
                out.append({
                    "type": name,
                    "value": val[:120],
                    "start": m.start(),
                })
        except Exception:
            continue
    # Deduplicate by value
    seen = set()
    uniq = []
    for item in out:
        k = (item["type"], item["value"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(item)
    return uniq


def analyze_js(js_text, base_url):
    if not js_text:
        return {"links": [], "secrets": []}
    return {
        "links": extract_links(js_text, base_url),
        "secrets": extract_secrets(js_text, js_url=base_url),
    }
