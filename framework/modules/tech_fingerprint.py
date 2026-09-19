"""Falcon MAG - Technology Fingerprint Scanner (v2 - Fixed FP)

Detects modern frameworks to enable smart module routing.
FIXED 2026-09-19:
  - Removed false positives from generic headers (server, x-powered-by).
  - Now only checks:
    * specific headers (x-nextjs-cache, cf-ray, ...)
    * powered_by VALUES (x-powered-by: wordpress)
    * server VALUES (server: nginx)
    * body regexes
    * cookies
"""
import re
from core.logger import get_logger

log = get_logger("tech_fingerprint")

SIGNATURES = {
    # ============================================================
    # Frontend Frameworks
    # ============================================================
    "Next.js": {
        # Specific headers ONLY (not generic)
        "headers": ["x-nextjs-cache", "x-nextjs-prerender", "x-nextjs-stale-time"],
        "body": [
            r'<script\s+id="__NEXT_DATA__"',
            r'/_next/static/',
            r'/_next/image',
            r'self\.__next_f\.push',
        ],
        "powered_by_values": ["next.js"],
    },
    "React": {
        "body": [
            r'data-reactroot',
            r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
            r'react\.production\.min\.js',
        ],
    },
    "React RSC": {
        "body": [
            r'self\.__next_f\.push',
            r'text/x-component',
        ],
    },
    "Vue.js": {
        "body": [r'data-v-[a-f0-9]{8}', r'vue\.runtime', r'__vue__', r'v-cloak'],
    },
    "Angular": {
        "body": [r'ng-version=', r'ng-app', r'angular(\.min)?\.js'],
    },
    "Svelte": {
        "body": [r'class="svelte-', r'__svelte'],
    },
    "Astro": {
        "body": [r'astro-island', r'data-astro-'],
    },

    # ============================================================
    # APIs
    # ============================================================
    "GraphQL": {
        "headers": ["x-graphql-duration", "x-apollo-operation-name"],
        "body": [r'"__schema"', r'graphql-ws', r'graphiql'],
    },

    # ============================================================
    # CMS
    # ============================================================
    "WordPress": {
        "body": [r'/wp-content/', r'/wp-includes/', r'wp-json', r'wp-emoji'],
        "powered_by_values": ["wordpress"],
    },
    "Drupal": {
        "headers": ["x-drupal-cache", "x-generator"],
        "body": [r'drupal-settings-json'],
    },
    "Joomla": {
        "body": [r'/components/com_', r'joomla!', r'option=com_'],
    },

    # ============================================================
    # Backend
    # ============================================================
    "Laravel": {
        "cookies": ["laravel_session", "xsrf-token"],
    },
    "Django": {
        "cookies": ["csrftoken", "sessionid"],
        "body": [r'csrfmiddlewaretoken'],
    },
    "Express/Node": {
        "body": [r'connect\.sid'],
        "powered_by_values": ["express"],
    },
    "ASP.NET": {
        "headers": ["x-aspnet-version", "x-aspnetmvc-version"],
        "body": [r'__viewstate', r'__eventvalidation'],
        "cookies": ["asp.net_sessionid", "aspnetcore.antiforgery"],
    },
    "PHP": {
        "cookies": ["phpsessid"],
        "powered_by_values": ["php"],
    },
    "Ruby on Rails": {
        "headers": ["x-runtime", "x-request-id"],
        "cookies": ["_rails_session", "_session_id"],
    },
    "Flask": {
        "server_values": ["werkzeug"],
        "powered_by_values": ["werkzeug"],
    },
    "Spring Boot": {
        "body": [r'whitelabel error page'],
        "cookies": ["jsessionid"],
    },

    # ============================================================
    # Infra / CDN
    # ============================================================
    "Nginx": {
        "server_values": ["nginx"],
    },
    "Apache": {
        "server_values": ["apache"],
    },
    "IIS": {
        "server_values": ["microsoft-iis", "microsoft-httpapi"],
    },
    "Caddy": {
        "server_values": ["caddy"],
    },
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"],
        "server_values": ["cloudfront"],
    },
    "Vercel": {
        "headers": ["x-vercel-id", "x-vercel-cache"],
        "server_values": ["vercel"],
    },
    "Netlify": {
        "headers": ["x-nf-request-id"],
    },
    "Fastly": {
        "headers": ["x-served-by", "x-fastly-request-id"],
        "server_values": ["fastly"],
    },
    "GitHub Pages": {
        "headers": ["x-github-request-id"],
        "server_values": ["github.com"],
    },
}


def _safe_headers(response):
    try:
        return {k.lower(): str(v).lower() for k, v in response.headers.items()}
    except Exception:
        return {}


def _safe_cookies(response):
    out = []
    try:
        for c in response.cookies:
            if c.name:
                out.append(c.name.lower())
    except Exception:
        pass
    return out


def _match_response(html, headers, cookies):
    """Return list of (tech, [evidence]) tuples. FIXED to avoid FPs."""
    server = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()
    detected = []

    for tech, rules in SIGNATURES.items():
        evidence = []

        # 1) Specific headers (like x-nextjs-cache, cf-ray)
        for h in rules.get("headers", []):
            if h in headers:
                evidence.append(f"header:{h}")

        # 2) powered_by VALUES (x-powered-by: wordpress)
        for pb in rules.get("powered_by_values", []):
            if pb in powered_by:
                evidence.append(f"x-powered-by:{pb}")

        # 3) server VALUES (server: nginx)
        for sv in rules.get("server_values", []):
            if sv in server:
                evidence.append(f"server:{sv}")

        # 4) body regexes
        for pattern in rules.get("body", []):
            try:
                if re.search(pattern, html, re.IGNORECASE):
                    evidence.append(f"body:{pattern[:50]}")
                    break
            except Exception:
                continue

        # 5) cookies
        for ck in rules.get("cookies", []):
            if ck in cookies:
                evidence.append(f"cookie:{ck}")

        if evidence:
            detected.append((tech, evidence))

    return detected


def run(config=None, client=None, **kwargs):
    if not client:
        return {"error": "no client", "technologies": []}

    target = (config.get("target") or "").rstrip("/")
    if not target:
        return {"error": "no target", "technologies": []}

    log.info(f"🔍 Tech fingerprint on {target}")

    result = {
        "target": target,
        "technologies": [],
        "evidence": {},
        "server": None,
        "powered_by": None,
    }

    try:
        r = client.get(target, timeout=15)
    except Exception as e:
        log.error(f"  ✗ fetch failed: {e}")
        return {"error": str(e), "technologies": []}

    html = r.text or ""
    headers = _safe_headers(r)
    cookies = _safe_cookies(r)

    result["server"] = headers.get("server")
    result["powered_by"] = headers.get("x-powered-by")

    detected = _match_response(html, headers, cookies)

    for tech, evidence in detected:
        result["technologies"].append(tech)
        result["evidence"][tech] = evidence

    if result["technologies"]:
        log.info(f"  ✓ Detected: {', '.join(result['technologies'])}")
    else:
        log.info("  ℹ No known technology detected")

    return result