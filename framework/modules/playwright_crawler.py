"""Falcon MAG Framework - Playwright Deep Crawler

Deep-crawls SPA/JS-heavy sites with a real headless browser:
  - Waits for networkidle
  - Extracts internal links
  - Extracts forms + actions
  - Captures XHR/fetch requests
  - Collects JS file URLs
  - Saves findings
"""

from urllib.parse import urljoin, urlparse
from core.logger import get_logger

log = get_logger("pw_crawl")


def _same_origin(url, base):
    try:
        a = urlparse(url); b = urlparse(base)
        return a.scheme in ("http", "https") and a.netloc == b.netloc
    except Exception:
        return False


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.warning("  Playwright not installed")
        return {"target": target, "pages": [], "error": "playwright not installed"}

    log.info("Deep crawling (Playwright) " + target)

    max_pages = int(config.get("scan", {}).get("max_pages", 50))
    max_depth = int(config.get("scan", {}).get("max_depth", 3))

    result = {
        "target": target,
        "url": target,
        "pages": [],
        "forms": [],
        "js_files": [],
        "xhr": [],
    }

    visited = set()
    to_visit = [(target, 0)]

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()

            xhr_log = []
            page.on("request", lambda req: xhr_log.append({"url": req.url, "method": req.method}) if req.resource_type in ("xhr", "fetch") else None)

            while to_visit and len(visited) < max_pages:
                url, depth = to_visit.pop(0)
                if url in visited or depth > max_depth:
                    continue
                visited.add(url)
                try:
                    page.goto(url, wait_until="load", timeout=30000)
                except Exception as e:
                    log.debug("  goto failed: " + str(e))
                    continue

                html = page.content()
                result["pages"].append({"url": url, "depth": depth})

                # Extract links
                links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for link in links:
                    if link not in visited and _same_origin(link, target):
                        to_visit.append((link, depth + 1))

                # Extract forms
                forms = page.eval_on_selector_all("form", "els => els.map(f => ({action: f.action, method: f.method, fields: Array.from(f.elements).map(e => e.name).filter(Boolean)}))")
                for f in forms:
                    result["forms"].append(f)

                # Extract JS
                scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                for s in scripts:
                    if s not in result["js_files"]:
                        result["js_files"].append(s)

            result["xhr"] = xhr_log[:200]
            browser.close()
    except Exception as e:
        log.error("  Playwright error: " + str(e))
        result["error"] = str(e)

    log.info("  Pages: " + str(len(result["pages"])))
    log.info("  Forms: " + str(len(result["forms"])))
    log.info("  JS files: " + str(len(result["js_files"])))
    log.info("  XHR: " + str(len(result["xhr"])))

    return result