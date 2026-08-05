"""
Technology stack and WAF fingerprinting engine.

Detects:
1. Web servers (Apache, nginx, IIS, etc.)
2. Frameworks (Rails, Django, Laravel, Express, Spring, etc.)
3. Programming languages
4. CMS platforms (WordPress, Drupal, Joomla)
5. JavaScript libraries and versions
6. CDN/WAF presence
"""
from __future__ import annotations

import re
from typing import Any

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── Fingerprint Corpus ──────────────────────────────────────────────────────

HEADER_FINGERPRINTS: dict[str, list[tuple[str, re.Pattern, str]]] = {
    "server": [
        ("server", re.compile(r"Apache/?(\S*)", re.I), "Apache"),
        ("server", re.compile(r"nginx/?(\S*)", re.I), "nginx"),
        ("server", re.compile(r"Microsoft-IIS/?(\S*)", re.I), "IIS"),
        ("server", re.compile(r"LiteSpeed", re.I), "LiteSpeed"),
        ("server", re.compile(r"openresty/?(\S*)", re.I), "OpenResty"),
        ("server", re.compile(r"Caddy", re.I), "Caddy"),
        ("server", re.compile(r"gunicorn", re.I), "Gunicorn"),
        ("server", re.compile(r"uvicorn", re.I), "Uvicorn"),
    ],
    "framework": [
        ("x-powered-by", re.compile(r"PHP/?(\S*)", re.I), "PHP"),
        ("x-powered-by", re.compile(r"ASP\.NET", re.I), "ASP.NET"),
        ("x-powered-by", re.compile(r"Express", re.I), "Express.js"),
        ("x-powered-by", re.compile(r"Next\.js", re.I), "Next.js"),
        ("x-powered-by", re.compile(r"Servlet", re.I), "Java Servlet"),
    ],
}

BODY_FINGERPRINTS: list[tuple[re.Pattern, str, str]] = [
    # Frameworks
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django", "framework"),
    (re.compile(r"__RequestVerificationToken", re.I), "ASP.NET MVC", "framework"),
    (re.compile(r'content="Rails"', re.I), "Ruby on Rails", "framework"),
    (re.compile(r"laravel_session|Laravel", re.I), "Laravel", "framework"),
    (re.compile(r"Spring|JSESSIONID", re.I), "Spring", "framework"),
    (re.compile(r"__next|_next/static", re.I), "Next.js", "framework"),
    (re.compile(r"nuxt|__nuxt", re.I), "Nuxt.js", "framework"),

    # CMS
    (re.compile(r"wp-content|wp-includes|WordPress", re.I), "WordPress", "cms"),
    (re.compile(r"Drupal|sites/default/files", re.I), "Drupal", "cms"),
    (re.compile(r"/components/com_", re.I), "Joomla", "cms"),
    (re.compile(r"Magento|mage/cookies", re.I), "Magento", "cms"),
    (re.compile(r"Shopify", re.I), "Shopify", "cms"),

    # JS Libraries
    (re.compile(r"jquery[.-](\d+\.\d+\.?\d*)", re.I), "jQuery", "js-lib"),
    (re.compile(r"react(?:\.production|\.development|DOM)", re.I), "React", "js-lib"),
    (re.compile(r"angular(?:\.min)?\.js|ng-version", re.I), "Angular", "js-lib"),
    (re.compile(r"vue(?:\.min)?\.js|Vue\.config", re.I), "Vue.js", "js-lib"),
    (re.compile(r"bootstrap[.-](\d+\.\d+\.?\d*)", re.I), "Bootstrap", "js-lib"),
]

# Well-known paths for technology detection
PROBE_PATHS: list[tuple[str, re.Pattern, str, str]] = [
    ("/robots.txt", re.compile(r"Disallow:", re.I), "robots.txt", "misc"),
    ("/sitemap.xml", re.compile(r"<urlset", re.I), "sitemap.xml", "misc"),
    ("/.git/HEAD", re.compile(r"ref: refs/", re.I), "Git Repository Exposed", "security"),
    ("/.env", re.compile(r"(DB_|APP_|SECRET|KEY)", re.I), "Environment File Exposed", "security"),
    ("/.DS_Store", re.compile(rb"Bud1".decode(errors="replace")), ".DS_Store Exposed", "security"),
    ("/wp-login.php", re.compile(r"wp-login|WordPress", re.I), "WordPress", "cms"),
    ("/administrator/", re.compile(r"Joomla", re.I), "Joomla", "cms"),
    ("/user/login", re.compile(r"Drupal", re.I), "Drupal", "cms"),
    ("/api/v1", re.compile(r"(api|version|endpoints)", re.I), "API v1", "api"),
    ("/api/v2", re.compile(r"(api|version|endpoints)", re.I), "API v2", "api"),
    ("/graphql", re.compile(r"(query|mutation|__schema)", re.I), "GraphQL", "api"),
    ("/swagger.json", re.compile(r"swagger|openapi", re.I), "Swagger/OpenAPI", "api"),
    ("/openapi.json", re.compile(r"openapi|paths", re.I), "OpenAPI", "api"),
]


class Fingerprinter:
    """Technology stack fingerprinting engine."""

    def __init__(self, pool, scope):
        self.pool = pool
        self.scope = scope
        self.results: dict[str, Any] = {
            "server": [],
            "framework": [],
            "cms": [],
            "js_lib": [],
            "api": [],
            "security": [],
            "misc": [],
            "headers": {},
        }

    async def fingerprint(self, url: str) -> dict[str, Any]:
        """Run the full fingerprinting pipeline.

        Returns a dict categorized by technology type.
        """
        logger.info("fingerprint_start", url=url)

        # Phase 1: Passive — analyze headers and body of the main page
        ev = await self.pool.send("GET", url)
        self._analyze_headers(ev)
        self._analyze_body(ev.response_body)

        # Phase 2: Active — probe well-known paths
        await self._probe_paths(url)

        # Phase 3: Interesting headers for security analysis
        self._security_headers(ev)

        logger.info(
            "fingerprint_complete",
            server=self.results["server"],
            framework=self.results["framework"],
            cms=self.results["cms"],
        )

        return self.results

    def _analyze_headers(self, ev: Evidence) -> None:
        """Extract technology info from response headers."""
        for category, patterns in HEADER_FINGERPRINTS.items():
            for header_name, pattern, tech_name in patterns:
                header_value = ev.response_headers.get(header_name, "")
                match = pattern.search(header_value)
                if match:
                    version = match.group(1) if match.lastindex else ""
                    entry = {"name": tech_name, "version": version, "source": "header"}
                    if entry not in self.results[category]:
                        self.results[category].append(entry)

        # Store raw security-relevant headers
        security_headers = [
            "x-frame-options", "x-content-type-options", "x-xss-protection",
            "content-security-policy", "strict-transport-security",
            "access-control-allow-origin", "permissions-policy",
            "referrer-policy",
        ]
        for h in security_headers:
            val = ev.response_headers.get(h, "")
            if val:
                self.results["headers"][h] = val

    def _analyze_body(self, body: str) -> None:
        """Extract technology info from response body."""
        for pattern, tech_name, category in BODY_FINGERPRINTS:
            match = pattern.search(body)
            if match:
                version = match.group(1) if match.lastindex else ""
                key = category.replace("-", "_")
                entry = {"name": tech_name, "version": version, "source": "body"}
                if key not in self.results:
                    self.results[key] = []
                if entry not in self.results[key]:
                    self.results[key].append(entry)

    async def _probe_paths(self, base_url: str) -> None:
        """Probe well-known paths for technology detection."""
        from urllib.parse import urljoin

        for path, pattern, tech_name, category in PROBE_PATHS:
            probe_url = urljoin(base_url, path)
            try:
                ev = await self.pool.send("GET", probe_url)
                if ev.response_status == 200 and pattern.search(ev.response_body):
                    entry = {"name": tech_name, "path": path, "source": "probe"}
                    if entry not in self.results.get(category, []):
                        if category not in self.results:
                            self.results[category] = []
                        self.results[category].append(entry)

                    # Security findings
                    if category == "security":
                        logger.warning(
                            "sensitive_file_exposed",
                            path=path,
                            tech=tech_name,
                            url=probe_url,
                        )
            except Exception:
                continue

    def _security_headers(self, ev: Evidence) -> None:
        """Check for missing security headers."""
        missing = []
        important_headers = {
            "x-frame-options": "Clickjacking protection",
            "x-content-type-options": "MIME sniffing protection",
            "content-security-policy": "XSS/injection protection",
            "strict-transport-security": "HTTPS enforcement",
            "x-xss-protection": "Reflected XSS protection (legacy)",
        }

        for header, description in important_headers.items():
            if header not in (h.lower() for h in ev.response_headers):
                missing.append({"header": header, "description": description})

        if missing:
            self.results["missing_security_headers"] = missing
