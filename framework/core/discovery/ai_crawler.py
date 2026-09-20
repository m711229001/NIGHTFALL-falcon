"""AI Crawler Agent - Playwright + AI planning for dynamic flows.

Fills forms, follows multi-step flows, discovers endpoints
that a static crawler cannot see.
"""
import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

from core.logger import get_logger

log = get_logger("discovery.ai_crawler")

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False


SYSTEM_PROMPT = """You are an expert web application reconnaissance agent.
Your job: analyze the HTML of a page and decide the best actions to discover
hidden functionality.

Focus on:
- Forms that submit sensitive data (login, register, search, upload)
- Links leading to admin/API/debug pages
- Buttons that trigger dynamic loads (SPA routes)
- Elements with data attributes that hint at API endpoints

Return ONLY valid JSON with this schema:
{
  "actions": [
    {"type": "click", "selector": "CSS selector", "reason": "why"},
    {"type": "fill", "selector": "CSS selector", "value": "test value", "reason": "why"},
    {"type": "submit", "selector": "form CSS selector", "reason": "why"},
    {"type": "goto", "url": "full URL", "reason": "why"}
  ],
  "notes": "short analysis"
}

Maximum 5 actions. Prefer diverse exploration over repetition.
"""


class AICrawler:
    def __init__(self, base_url, ai_client=None, max_steps=10, timeout=15000):
        self.base_url = base_url.rstrip("/")
        self.ai_client = ai_client
        self.max_steps = max_steps
        self.timeout = timeout
        self.discovered_urls = set()
        self.discovered_forms = []
        self.interactions = []

    async def run(self):
        if not HAS_PLAYWRIGHT:
            log.warning("Playwright not available - AI crawler disabled")
            return self._empty_result()

        if not self.ai_client:
            log.warning("No AI client - AI crawler disabled")
            return self._empty_result()

        log.info("AI Crawler starting on " + self.base_url)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Falcon-MAG/2.0",
            )
            page = await context.new_page()

            # Capture XHR / fetch
            async def on_request(req):
                if req.resource_type in ("xhr", "fetch"):
                    try:
                        self.discovered_urls.add(req.url)
                    except Exception:
                        pass

            page.on("request", on_request)

            try:
                await page.goto(self.base_url, timeout=self.timeout, wait_until="domcontentloaded")
                await page.wait_for_timeout(1500)
            except Exception as e:
                log.warning("  Initial goto failed: " + str(e)[:100])
                await browser.close()
                return self._empty_result()

            # Main loop
            for step in range(self.max_steps):
                log.info("  Step " + str(step + 1) + "/" + str(self.max_steps))

                # 1. Capture all current links
                try:
                    links = await page.eval_on_selector_all(
                        "a[href]",
                        "els => els.map(e => e.href).filter(h => h && h.startsWith('http'))"
                    )
                    for l in links:
                        self.discovered_urls.add(l)
                except Exception:
                    pass

                # 2. Capture forms
                try:
                    forms = await page.eval_on_selector_all(
                        "form",
                        """els => els.map(f => ({
                            action: f.action || '',
                            method: (f.method || 'GET').toUpperCase(),
                            inputs: Array.from(f.querySelectorAll('input,textarea,select'))
                                .map(i => ({name: i.name || '', type: i.type || ''}))
                                .filter(i => i.name)
                        }))"""
                    )
                    for f in forms:
                        self.discovered_forms.append(f)
                except Exception:
                    pass

                # 3. Ask AI for next action
                html = await self._get_page_html(page)
                if not html:
                    break

                action = await self._ai_decide(html, step)
                if not action:
                    log.info("  No AI action - stopping")
                    break

                # 4. Execute action
                executed = await self._execute_action(page, action)
                self.interactions.append({
                    "step": step + 1,
                    "action": action,
                    "executed": executed,
                })

                if not executed:
                    continue

                await page.wait_for_timeout(1500)

                # 5. Check if URL changed (SPA route)
                current = page.url
                if current and current != self.base_url:
                    self.discovered_urls.add(current)

            await browser.close()

        result = {
            "discovered_urls": sorted(self.discovered_urls),
            "discovered_forms": self.discovered_forms,
            "interactions": self.interactions,
            "steps_executed": len(self.interactions),
        }
        log.info("AI Crawler done: "
                 + str(len(result["discovered_urls"])) + " URLs, "
                 + str(len(result["discovered_forms"])) + " forms")
        return result

    async def _get_page_html(self, page):
        try:
            html = await page.content()
            return html[:30000]
        except Exception:
            return ""

    async def _ai_decide(self, html, step):
        if not self.ai_client:
            return None
        try:
            prompt = (
                "Step " + str(step + 1) + " of " + str(self.max_steps) + "\n"
                "Current URL: " + self.base_url + "\n"
                "Already discovered: " + str(len(self.discovered_urls)) + " URLs\n"
                "Already interacted: " + str(len(self.interactions)) + " times\n\n"
                "HTML (first 30000 chars):\n" + html
            )
            text = self.ai_client.generate_from_active(
                user_prompt=prompt,
                system_prompt=SYSTEM_PROMPT,
                json_mode=True,
            )
            if not text:
                return None
            parsed = self._extract_json(text)
            actions = parsed.get("actions", []) if isinstance(parsed, dict) else []
            if not actions:
                return None
            return actions[0]
        except Exception as e:
            log.debug("  AI decide failed: " + str(e)[:100])
            return None

    async def _execute_action(self, page, action):
        if not isinstance(action, dict):
            return False
        atype = action.get("type", "").lower()
        selector = action.get("selector", "")
        try:
            if atype == "click" and selector:
                await page.click(selector, timeout=5000)
                log.info("    [click] " + selector[:60])
                return True
            elif atype == "fill" and selector:
                value = action.get("value", "test")
                await page.fill(selector, value, timeout=5000)
                log.info("    [fill]  " + selector[:60] + " = " + value[:30])
                return True
            elif atype == "submit" and selector:
                await page.eval_on_selector(selector, "f => f.submit()")
                log.info("    [submit] " + selector[:60])
                return True
            elif atype == "goto" and action.get("url"):
                url = urljoin(self.base_url, action["url"])
                await page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
                log.info("    [goto]  " + url[:80])
                return True
        except Exception as e:
            log.debug("    action failed: " + str(e)[:100])
            return False
        return False

    @staticmethod
    def _extract_json(text):
        if not text:
            return {}
        try:
            return json.loads(text)
        except Exception:
            pass
        start = text.find("{")
        if start < 0:
            return {}
        depth = 0
        for i in range(start, len(text)):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except Exception:
                        return {}
        return {}

    def _empty_result(self):
        return {
            "discovered_urls": [],
            "discovered_forms": [],
            "interactions": [],
            "steps_executed": 0,
        }


def run_ai_crawler(base_url, ai_client=None, max_steps=10):
    """Sync wrapper for AICrawler.run()."""
    if not HAS_PLAYWRIGHT:
        return {"error": "playwright not installed"}
    crawler = AICrawler(base_url, ai_client=ai_client, max_steps=max_steps)
    try:
        return asyncio.run(crawler.run())
    except Exception as e:
        log.error("AI crawler failed: " + str(e)[:200])
        return {"error": str(e)}
