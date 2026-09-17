"""Falcon MAG Framework - Fingerprint Module
Real HTTP-based fingerprinting. No hardcoded data."""

from core.logger import get_logger

log = get_logger("fingerprint")


SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
]

# Signatures are matched against REAL server responses
TECH_SIGNATURES = {
    "WordPress": ["/wp-content/", "/wp-includes/", "/wp-json/"],
    "Drupal": ["/sites/default/", "drupal.js", "Drupal.settings"],
    "Joomla": ["/components/com_", "/modules/mod_", "Joomla!"],
    "Magento": ["/skin/frontend/", "Magento"],
    "Shopify": ["cdn.shopify.com", "shopify.theme"],
    "Wix": ["wix.com", "wixstatic.com"],
    "React": ["react", "_reactrootcontainer", "react-dom"],
    "Angular": ["ng-version", "ng-app", "angular.js"],
    "Vue.js": ["vue.js", "vue.min.js", "__vue__"],
    "Next.js": ["__next_data__", "_next/static", "/_next/"],
    "Nuxt.js": ["__nuxt__", "_nuxt/"],
    "Svelte": ["svelte", "__svelte"],
    "jQuery": ["jquery.js", "jquery.min.js", "jquery-"],
    "Bootstrap": ["bootstrap.js", "bootstrap.css", "bootstrap.min."],
    "Tailwind": ["tailwind", "tailwindcss"],
    "Nginx": ["server: nginx"],
    "Apache": ["server: apache"],
    "IIS": ["server: microsoft-iis"],
    "Cloudflare": ["cf-ray", "cloudflare"],
    "AWS": ["x-amz-", "aws"],
    "Google": ["x-cloud-trace", "google", "gws"],
    "Express": ["x-powered-by: express"],
    "PHP": ["x-powered-by: php", "phpsessid"],
    "ASP.NET": ["x-aspnet-version", "asp.net", "aspnet"],
    "Django": ["csrftoken", "django"],
    "Flask": ["werkzeug", "flask"],
    "Ruby on Rails": ["x-powered-by: phusion", "rails"],
    "Laravel": ["laravel_session", "laravel"],
    "Spring": ["jsessionid", "spring"],
    "Tomcat": ["tomcat", "jsessionid"],
}


def run(client, config) -> dict:
    """Run fingerprint on the target. Returns REAL data only."""
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info(f"🔍 Fingerprinting {target}")

    result = {
        "target": target,
        "status": None,
        "server": None,
        "powered_by": None,
        "technologies": [],
        "missing_headers": [],
        "present_headers": {},
        "cookies": [],
        "redirects": [],
    }

    resp = client.scan_request(target)
    if not resp or resp.status == 0:
        log.warning(f"  ✗ Target unreachable: {resp.error if resp else 'no response'}")
        result["error"] = resp.error if resp else "no response"
        return result

    result["status"] = resp.status
    result["server"] = resp.headers.get("Server") or resp.headers.get("server")
    result["powered_by"] = resp.headers.get("X-Powered-By") or resp.headers.get("x-powered-by")
    result["redirects"] = resp.redirects

    # --- Real detection from headers ---
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    header_str = " ".join(f"{k}: {v}" for k, v in headers_lower.items()).lower()

    # --- Real detection from body ---
    body_lower = resp.text.lower() if resp.text else ""

    for tech, sigs in TECH_SIGNATURES.items():
        for sig in sigs:
            sig_lower = sig.lower()
            if sig_lower in header_str or sig_lower in body_lower:
                if tech not in result["technologies"]:
                    result["technologies"].append(tech)
                break

    # --- Security headers ---
    for h in SECURITY_HEADERS:
        val = resp.headers.get(h) or resp.headers.get(h.title())
        if val:
            result["present_headers"][h] = val
        else:
            result["missing_headers"].append(h)

    # --- Cookies (real) ---
    for cookie in resp.headers.get("Set-Cookie", "").split(","):
        if not cookie.strip():
            continue
        parts = cookie.split(";")
        name = parts[0].split("=")[0].strip() if parts else ""
        if not name:
            continue
        cookie_data = {"name": name}
        cookie_lower = cookie.lower()
        cookie_data["secure"] = "secure" in cookie_lower
        cookie_data["httponly"] = "httponly" in cookie_lower
        if "samesite=" in cookie_lower:
            idx = cookie_lower.find("samesite=")
            cookie_data["samesite"] = cookie[idx + 9:].split(";")[0].strip()
        else:
            cookie_data["samesite"] = None
        result["cookies"].append(cookie_data)

    log.info(f"  ✓ Status: {result['status']}")
    log.info(f"  ✓ Server: {result['server']}")
    log.info(f"  ✓ Technologies: {result['technologies']}")
    log.info(f"  ✓ Missing headers: {len(result['missing_headers'])}")

    return result