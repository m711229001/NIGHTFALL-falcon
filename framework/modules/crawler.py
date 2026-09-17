"""Falcon MAG Framework - Crawler Module
Real crawling using Playwright (Chromium)."""

import asyncio
from urllib.parse import urljoin, urlparse
from core.logger import get_logger

log = get_logger("crawler")


async def _crawl_async(client, config):
    """Async Playwright crawl."""
    from playwright.async_api import async_playwright

    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    scan_cfg = config.get("scan", {})
    max_depth = scan_cfg.get("max_depth", 3)
    max_pages = scan_cfg.get("max_pages", 100)
    timeout = scan_cfg.get("timeout", 15) * 1000
    user_agent = scan_cfg.get("user_agent", "FalconMAG/1.0")

    visited = set()
    to_visit = [(target, 0)]
    pages = []
    forms = []
    js_files = set()
    xhr_requests = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=user_agent,
            ignore_https_errors=True,
        )
        page = await context.new_page()

        async def on_request(req):
            if req.resource_type in ("xhr", "fetch"):
                xhr_requests.append({
                    "method": req.method,
                    "url": req.url,
                    "type": req.resource_type,
                })

        page.on("request", on_request)

        while to_visit and len(visited) < max_pages:
            url, depth = to_visit.pop(0)
            if url in visited or depth > max_depth:
                continue
            if not client.in_scope(url):
                continue

            visited.add(url)
            log.info(f"  🌐 [{depth}] {url[:80]}")

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                await page.wait_for_timeout(1000)
            except Exception as e:
                log.warning(f"    ✗ Failed: {str(e)[:80]}")
                continue

            # --- Extract links ---
            try:
                links = await page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.href).filter(h => h && !h.startsWith('javascript:') && !h.startsWith('mailto:') && !h.startsWith('tel:'))"
                )
                for link in links:
                    full = urljoin(url, link)
                    if client.in_scope(full) and full not in visited:
                        to_visit.append((full, depth + 1))
            except Exception:
                links = []

            # --- Extract forms ---
            try:
                page_forms = await page.eval_on_selector_all(
                    "form",
                    """els => els.map(f => ({
                        action: f.action || '',
                        method: (f.method || 'GET').toUpperCase(),
                        inputs: Array.from(f.querySelectorAll('input,textarea,select'))
                            .map(i => ({
                                name: i.name || '',
                                type: i.type || '',
                                value: (i.type === 'password' ? '' : (i.value || ''))
                            }))
                            .filter(i => i.name)
                    }))"""
                )
                for f in page_forms:
                    f["source_page"] = url
                    forms.append(f)
            except Exception:
                page_forms = []

            # --- Extract JS files ---
            try:
                scripts = await page.eval_on_selector_all(
                    "script[src]",
                    "els => els.map(e => e.src).filter(s => s)"
                )
                js_files.update(scripts)
            except Exception:
                scripts = []

            # --- Get page title ---
            try:
                title = await page.title()
            except Exception:
                title = ""

            pages.append({
                "url": url,
                "depth": depth,
                "title": title,
                "links_count": len(links) if links else 0,
                "forms_count": len(page_forms) if page_forms else 0,
                "scripts_count": len(scripts) if scripts else 0,
            })

        await browser.close()

    return {
        "pages": pages,
        "total_pages": len(pages),
        "forms": forms,
        "js_files": sorted(js_files),
        "xhr_requests": xhr_requests,
        "visited": sorted(visited),
    }


def run(client, config) -> dict:
    """Run crawler synchronously."""
    target = config.get("target", "")
    log.info(f"🕷️  Crawling {target}")

    try:
        result = asyncio.run(_crawl_async(client, config))
    except Exception as e:
        log.error(f"  ✗ Crawler failed: {e}")
        return {
            "error": str(e),
            "pages": [], "total_pages": 0,
            "forms": [], "js_files": [], "xhr_requests": [],
        }

    log.info(f"  ✓ Pages: {result.get('total_pages', 0)}")
    log.info(f"  ✓ Forms: {len(result.get('forms', []))}")
    log.info(f"  ✓ JS files: {len(result.get('js_files', []))}")
    log.info(f"  ✓ XHR: {len(result.get('xhr_requests', []))}")

    return result