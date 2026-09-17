"""
Playwright-based async web crawler for NIGHTFALL.

Features:
1. JS-rendered page crawling (SPA support via Playwright)
2. Form extraction with input type analysis
3. Link discovery from HTML, JS, and sitemaps
4. Parameter discovery from forms, URLs, and JS
5. Respects scope guard
6. Deduplication of URLs
"""
from __future__ import annotations

import re
from collections import deque
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── URL/Link Extraction Patterns ────────────────────────────────────────────

LINK_PATTERNS = [
    re.compile(r'href=["\']([^"\'#]+)["\']', re.I),
    re.compile(r'src=["\']([^"\']+)["\']', re.I),
    re.compile(r'action=["\']([^"\']+)["\']', re.I),
    re.compile(r'data-url=["\']([^"\']+)["\']', re.I),
    re.compile(r'window\.location\s*=\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'location\.href\s*=\s*["\']([^"\']+)["\']', re.I),
]

FORM_PATTERN = re.compile(
    r'<form[^>]*>(.*?)</form>', re.I | re.S
)

FORM_ATTRS = re.compile(
    r'<form[^>]*(?:action=["\']([^"\']*)["\'])?[^>]*(?:method=["\']([^"\']*)["\'])?[^>]*>',
    re.I,
)

INPUT_PATTERN = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']*)["\'])?[^>]*>',
    re.I,
)

SELECT_PATTERN = re.compile(
    r'<select[^>]*name=["\']([^"\']+)["\']', re.I
)

TEXTAREA_PATTERN = re.compile(
    r'<textarea[^>]*name=["\']([^"\']+)["\']', re.I
)


class Endpoint:
    """Discovered endpoint with parameters."""
    def __init__(self, url: str, method: str = "GET", params: dict | None = None,
                 source: str = "crawl"):
        self.url = url
        self.method = method
        self.params = params or {}
        self.source = source
        self.content_type = ""

    def __repr__(self):
        return f"Endpoint({self.method} {self.url}, params={list(self.params.keys())})"


class Crawler:
    """Async web crawler that discovers endpoints, forms, and parameters.

    Uses httpx for fast crawling and optionally Playwright for JS-rendered pages.
    """

    def __init__(self, pool, scope, config):
        self.pool = pool
        self.scope = scope
        self.max_depth = config.crawler.max_depth
        self.max_pages = config.crawler.max_pages
        self.user_agent = config.crawler.user_agent
        self.headless = config.crawler.headless

        self.visited: set[str] = set()
        self.endpoints: list[Endpoint] = []
        self.forms: list[dict] = []
        self.js_files: list[str] = []
        self.params_discovered: dict[str, set] = {}  # url -> set of param names

    async def crawl(self, seed_url: str) -> list[Endpoint]:
        """BFS crawl starting from seed_url.

        Returns:
            List of discovered Endpoint objects.
        """
        logger.info("crawler_start", seed=seed_url, max_depth=self.max_depth)

        queue: deque[tuple[str, int]] = deque([(seed_url, 0)])
        self.visited.add(self._normalize_url(seed_url))

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            try:
                ev = await self.pool.send("GET", url)
            except Exception as exc:
                logger.debug("crawl_error", url=url, error=str(exc))
                continue

            if ev.response_status == 0:
                continue

            body = ev.response_body
            content_type = ev.response_headers.get("content-type", "")

            # Skip non-HTML responses
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                # But still record JS files
                if "javascript" in content_type or url.endswith(".js"):
                    self.js_files.append(url)
                continue

            # ── Extract links ────────────────────────────────────────────
            new_urls = self._extract_links(body, url)
            for new_url in new_urls:
                normalized = self._normalize_url(new_url)
                if normalized not in self.visited:
                    try:
                        await self.scope.assert_allowed(new_url)
                        self.visited.add(normalized)
                        queue.append((new_url, depth + 1))
                    except Exception:
                        pass  # out of scope

            # ── Extract forms ────────────────────────────────────────────
            self._extract_forms(body, url)

            # ── Extract JS files ─────────────────────────────────────────
            for js_match in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I):
                js_url = urljoin(url, js_match.group(1))
                if js_url not in self.js_files:
                    self.js_files.append(js_url)

            # ── Extract URL parameters ───────────────────────────────────
            self._extract_url_params(url)

            # Register as endpoint
            self.endpoints.append(Endpoint(url, "GET"))

        logger.info(
            "crawler_complete",
            pages_visited=len(self.visited),
            endpoints=len(self.endpoints),
            forms=len(self.forms),
            js_files=len(self.js_files),
        )

        return self.endpoints

    def _extract_links(self, body: str, base_url: str) -> list[str]:
        """Extract all links from HTML body."""
        links = []
        for pattern in LINK_PATTERNS:
            for match in pattern.findall(body):
                url = urljoin(base_url, match.strip())
                # Filter out non-HTTP links
                if url.startswith(("http://", "https://")):
                    links.append(url)
        return links

    def _extract_forms(self, body: str, base_url: str) -> None:
        """Extract forms and their input fields."""
        for form_match in FORM_PATTERN.finditer(body):
            form_html = form_match.group(0)

            # Get form attributes
            attrs = FORM_ATTRS.search(form_html)
            action = attrs.group(1) if attrs and attrs.group(1) else base_url
            method = (attrs.group(2) or "GET").upper() if attrs else "GET"

            action_url = urljoin(base_url, action)

            # Get inputs
            params = {}
            for name, input_type in INPUT_PATTERN.findall(form_html):
                params[name] = input_type or "text"
            for name in SELECT_PATTERN.findall(form_html):
                params[name] = "select"
            for name in TEXTAREA_PATTERN.findall(form_html):
                params[name] = "textarea"

            form_info = {
                "action": action_url,
                "method": method,
                "params": params,
                "source_url": base_url,
            }
            self.forms.append(form_info)

            # Also register as endpoint
            self.endpoints.append(Endpoint(
                action_url,
                method,
                {k: "test" for k in params},
                source="form",
            ))

    def _extract_url_params(self, url: str) -> None:
        """Extract query parameters from a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base not in self.params_discovered:
                self.params_discovered[base] = set()
            self.params_discovered[base].update(params.keys())

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        # Remove fragment, normalize path
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        # Keep query params for uniqueness but sort them
        if parsed.query:
            params = sorted(parse_qs(parsed.query).keys())
            normalized += "?" + "&".join(f"{k}=" for k in params)
        return normalized.lower().rstrip("/")

    async def crawl_with_playwright(self, seed_url: str) -> list[Endpoint]:
        """Crawl JS-rendered pages using Playwright.

        Falls back to httpx crawl if Playwright is not available.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("playwright_not_available", msg="Falling back to httpx crawl")
            return await self.crawl(seed_url)

        logger.info("playwright_crawl_start", seed=seed_url)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            page = await browser.new_page(user_agent=self.user_agent)

            try:
                await page.goto(seed_url, wait_until="networkidle", timeout=30000)
                content = await page.content()

                # Extract links from rendered DOM
                links = await page.evaluate("""
                    () => {
                        const links = [];
                        document.querySelectorAll('a[href]').forEach(a => links.push(a.href));
                        document.querySelectorAll('form[action]').forEach(f => links.push(f.action));
                        return links;
                    }
                """)

                for link in links:
                    if link.startswith(("http://", "https://")):
                        try:
                            await self.scope.assert_allowed(link)
                            normalized = self._normalize_url(link)
                            if normalized not in self.visited:
                                self.visited.add(normalized)
                                self.endpoints.append(Endpoint(link, "GET", source="playwright"))
                        except Exception:
                            pass

                # Also run the regular extraction on the rendered HTML
                self._extract_forms(content, seed_url)

            except Exception as exc:
                logger.warning("playwright_error", error=str(exc))
            finally:
                await browser.close()

        # Continue with regular httpx crawl for the rest
        return await self.crawl(seed_url)
