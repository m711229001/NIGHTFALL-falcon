"""
JavaScript bundle endpoint and secret extraction engine.

Mines JS files for:
1. API endpoints (absolute and relative URLs)
2. Secrets and credentials (API keys, tokens, passwords)
3. Interesting strings (emails, IPs, domains)
4. GraphQL queries/mutations
5. WebSocket endpoints
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

import structlog

logger = structlog.get_logger(__name__)


# ── Extraction Patterns ─────────────────────────────────────────────────────

# API endpoints in JS
ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/api/[a-zA-Z0-9/_\-{}:.]+)["\']'),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_\-{}:.]+)["\']'),
    re.compile(r'["\'](https?://[^"\']+/api/[^"\']+)["\']'),
    re.compile(r'fetch\(["\']([^"\']+)["\']'),
    re.compile(r'axios\.[a-z]+\(["\']([^"\']+)["\']'),
    re.compile(r'\.get\(["\']([^"\']+)["\']'),
    re.compile(r'\.post\(["\']([^"\']+)["\']'),
    re.compile(r'\.put\(["\']([^"\']+)["\']'),
    re.compile(r'\.delete\(["\']([^"\']+)["\']'),
    re.compile(r'\.patch\(["\']([^"\']+)["\']'),
    re.compile(r'url:\s*["\']([^"\']+)["\']'),
    re.compile(r'endpoint:\s*["\']([^"\']+)["\']'),
    re.compile(r'baseURL:\s*["\']([^"\']+)["\']'),
    re.compile(r'XMLHttpRequest.*\.open\(["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']'),
]

# Secrets and credentials
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("AWS Secret Key", re.compile(r'["\']([0-9a-zA-Z/+]{40})["\']')),
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z_-]{35}')),
    ("Google OAuth Token", re.compile(r'ya29\.[0-9A-Za-z_-]+')),
    ("GitHub Token", re.compile(r'(gh[pousr]_[A-Za-z0-9_]{36,255})')),
    ("Slack Token", re.compile(r'xox[baprs]-[0-9a-zA-Z-]+')),
    ("Stripe Key", re.compile(r'(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}')),
    ("Twilio SID", re.compile(r'AC[0-9a-f]{32}')),
    ("SendGrid Key", re.compile(r'SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}')),
    ("Generic API Key", re.compile(r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{16,})["\']', re.I)),
    ("Generic Secret", re.compile(r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.I)),
    ("Generic Token", re.compile(r'["\']?token["\']?\s*[:=]\s*["\']([^"\']{16,})["\']', re.I)),
    ("Generic Password", re.compile(r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', re.I)),
    ("Private Key", re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----')),
    ("JWT", re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')),
    ("Basic Auth", re.compile(r'Basic\s+[A-Za-z0-9+/=]{10,}')),
    ("Bearer Token", re.compile(r'Bearer\s+[A-Za-z0-9._-]{10,}')),
]

# GraphQL patterns
GRAPHQL_PATTERNS = [
    re.compile(r'(?:query|mutation)\s+\w+\s*\{', re.I),
    re.compile(r'gql`[^`]+`', re.I),
    re.compile(r'["\']\s*(query|mutation)\s+\w+', re.I),
]

# WebSocket endpoints
WS_PATTERNS = [
    re.compile(r'["\']wss?://[^"\']+["\']'),
    re.compile(r'WebSocket\(["\']([^"\']+)["\']'),
    re.compile(r'io\(["\']([^"\']+)["\']'),  # Socket.IO
]

# Interesting strings
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
DOMAIN_PATTERN = re.compile(r'["\'](https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']')


class JSMiner:
    """JavaScript bundle analysis engine."""

    def __init__(self, pool, scope):
        self.pool = pool
        self.scope = scope
        self.endpoints: list[dict] = []
        self.secrets: list[dict] = []
        self.graphql_ops: list[str] = []
        self.websockets: list[str] = []
        self.emails: set[str] = set()
        self.ips: set[str] = set()
        self.domains: set[str] = set()

    async def mine(self, js_urls: list[str], base_url: str = "") -> dict[str, Any]:
        """Analyze JS files for endpoints, secrets, and interesting strings.

        Args:
            js_urls: List of JS file URLs to analyze.
            base_url: Base URL for resolving relative paths.

        Returns:
            Dict with discovered endpoints, secrets, etc.
        """
        logger.info("js_mining_start", num_files=len(js_urls))

        for js_url in js_urls[:100]:  # cap for performance
            try:
                ev = await self.pool.send("GET", js_url)
                if ev.response_status == 200 and ev.response_body:
                    self._analyze_js(ev.response_body, js_url, base_url)
            except Exception as exc:
                logger.debug("js_fetch_error", url=js_url, error=str(exc))

        results = {
            "endpoints": self.endpoints,
            "secrets": self.secrets,
            "graphql_operations": self.graphql_ops,
            "websockets": self.websockets,
            "emails": list(self.emails),
            "internal_ips": list(self.ips),
            "domains": list(self.domains),
        }

        logger.info(
            "js_mining_complete",
            endpoints=len(self.endpoints),
            secrets=len(self.secrets),
            graphql=len(self.graphql_ops),
        )

        return results

    def _analyze_js(self, content: str, source_url: str, base_url: str) -> None:
        """Analyze a single JS file."""

        # ── Endpoints ────────────────────────────────────────────────────
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip("\"'")

                # Resolve relative URLs
                if endpoint.startswith("/"):
                    endpoint = urljoin(base_url, endpoint)
                elif not endpoint.startswith("http"):
                    continue  # skip non-URL strings

                entry = {
                    "url": endpoint,
                    "source": source_url,
                    "context": content[max(0, match.start() - 50):match.end() + 50],
                }
                if entry not in self.endpoints:
                    self.endpoints.append(entry)

        # ── Secrets ──────────────────────────────────────────────────────
        for secret_type, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                secret_value = match.group(1) if match.lastindex else match.group(0)

                # Filter out common false positives
                if len(secret_value) < 8:
                    continue
                if secret_value in ("undefined", "null", "true", "false"):
                    continue

                entry = {
                    "type": secret_type,
                    "value": secret_value[:50] + "..." if len(secret_value) > 50 else secret_value,
                    "source": source_url,
                    "context": content[max(0, match.start() - 30):match.end() + 30],
                }
                self.secrets.append(entry)
                logger.warning("secret_found", type=secret_type, source=source_url)

        # ── GraphQL ──────────────────────────────────────────────────────
        for pattern in GRAPHQL_PATTERNS:
            for match in pattern.finditer(content):
                op = content[match.start():match.start() + 200]
                if op not in self.graphql_ops:
                    self.graphql_ops.append(op)

        # ── WebSockets ───────────────────────────────────────────────────
        for pattern in WS_PATTERNS:
            for match in pattern.finditer(content):
                ws_url = match.group(1) if match.lastindex else match.group(0)
                ws_url = ws_url.strip("\"'")
                if ws_url not in self.websockets:
                    self.websockets.append(ws_url)

        # ── Emails, IPs, Domains ─────────────────────────────────────────
        self.emails.update(EMAIL_PATTERN.findall(content)[:20])
        self.ips.update(IP_PATTERN.findall(content)[:20])
        self.domains.update(m.strip("\"'") for m in DOMAIN_PATTERN.findall(content)[:20])
