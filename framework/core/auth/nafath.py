"""Falcon MAG - Nafath (Saudi National SSO) login handler.

Generic: works on Qiwa, Absher, Tawakkalna, Yakeen, and any portal
that exposes a Nafath button. You can override the button selector.

IMPORTANT FIX (2026-09-18):
  - Old logic used `success_url_contains = host_of(url)` which is ALWAYS
    true on the login page itself (URL = https://host/login contains "host").
    This caused the browser to close ~3s after clicking the Nafath button,
    before the user could complete approval on their phone.
  - New behavior:
      * --wait 0  -> OPEN-ENDED interactive mode: keeps browser open until
                     the user presses ENTER in the terminal.
      * --wait N  -> wait N seconds, but the "success" check is smarter:
                     a) URL no longer contains the original login path, AND
                     b) URL is on the same host, AND
                     c) some cookie appeared OR URL path changed.
      * We also auto-detect "path changed from /login" as success.
"""
from pathlib import Path
from urllib.parse import urlparse

from core.logger import get_logger
from core.auth import register, save_profile
from core.auth.browser import (
    open_browser,
    wait_for_url_contains,
    find_first_visible,
    host_of,
)

log = get_logger("auth.nafath")


DEFAULT_NAFATH_SELECTORS = [
    '[data-testid="loginComponentnafathButton"]',
    '[data-testid*="nafath" i]',
    '[data-testid*="Nafath" i]',
    'button[data-testid*="nafath" i]',
    'button:has-text("Nafath")',
    'button:has-text("نفاذ")',
    'button:has-text("النفاذ الوطني")',
    'a:has-text("Nafath")',
    'a:has-text("نفاذ")',
    '[aria-label*="Nafath" i]',
    '[aria-label*="نفاذ"]',
    '[role="button"]:has-text("Nafath")',
    '[role="button"]:has-text("نفاذ")',
]


def _path_of(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return "/"


def _looks_like_login_path(path: str) -> bool:
    p = (path or "").lower()
    return any(k in p for k in ("/login", "/signin", "/sign-in", "/auth", "/sso"))


@register("nafath")
def login_nafath(
    url: str,
    profile: str = "nafath",
    nafath_selector: str = None,
    success_url_contains: str = None,
    headless: bool = False,
    wait_seconds: int = 240,
    **kwargs,
) -> Path:
    """Open page, click Nafath button, wait for phone approval.

    wait_seconds == 0  ->  open-ended interactive mode (press ENTER to save).
    wait_seconds >  0  ->  auto-wait up to N seconds, with smarter success check.
    """
    host = host_of(url)
    initial_path = _path_of(url)

    interactive = (wait_seconds == 0)

    log.info(f"  [nafath] Opening {url}")
    log.info(f"  [nafath] Host: {host} | Initial path: {initial_path}")
    if interactive:
        log.info("  [nafath] Mode: INTERACTIVE (open-ended, press ENTER in terminal to save)")
    else:
        log.info(f"  [nafath] Mode: AUTO (wait up to {wait_seconds}s)")

    with open_browser(headless=headless) as (_, context, page):
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        try:
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass
        page.wait_for_timeout(2000)
        try:
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        except Exception:
            pass
        page.wait_for_timeout(1500)

        # ---- Find and click the Nafath button ----
        selectors = [nafath_selector] if nafath_selector else DEFAULT_NAFATH_SELECTORS
        found = find_first_visible(page, selectors, timeout_each=4000)

        if found:
            log.info(f"  [nafath] Clicking button: {found}")
            try:
                page.click(found)
            except Exception as e:
                log.warning(f"  [nafath] Normal click failed: {e}, trying JS click")
                try:
                    page.evaluate(
                        "(sel) => { const el = document.querySelector(sel); if (el) el.click(); }",
                        found,
                    )
                except Exception as e2:
                    raise RuntimeError(f"Both click methods failed: {e2}")
        else:
            log.warning("  [nafath] No selector matched. Trying JS text-based search...")
            clicked = page.evaluate("""() => {
                const keywords = ["nafath", "نفاذ", "النفاذ الوطني"];
                const all = document.querySelectorAll("button, a, div[role=button], span[role=button]");
                for (const el of all) {
                    const t = (el.innerText || el.textContent || "").toLowerCase();
                    for (const k of keywords) {
                        if (t.includes(k)) {
                            el.scrollIntoView({block: "center"});
                            el.click();
                            return el.tagName + ":" + t.slice(0, 40);
                        }
                    }
                }
                return null;
            }""")
            if not clicked:
                log.error("  [nafath] JS search found nothing. Saving screenshot...")
                try:
                    page.screenshot(path="nafath_debug.png", full_page=True)
                    log.error("  [nafath] Screenshot: nafath_debug.png")
                except Exception:
                    pass
                raise RuntimeError("Nafath button not found. See nafath_debug.png")
            log.info(f"  [nafath] JS click succeeded on: {clicked}")

        log.info("  [nafath] Approve the request on your phone (Nafath app).")

        # ============================================================
        # Wait strategy
        # ============================================================
        if interactive:
            # ---- OPEN-ENDED: wait for ENTER ----
            log.info("")
            log.info("  ┌──────────────────────────────────────────────────────────┐")
            log.info("  │  Nafath approval required on your phone.                │")
            log.info("  │  Complete it in the Nafath app.                          │")
            log.info("  │  When DONE, return to this terminal and press ENTER.     │")
            log.info("  │  (Ctrl+C to abort)                                       │")
            log.info("  └──────────────────────────────────────────────────────────┘")
            log.info("")
            try:
                input("  >>> Press ENTER here when you have finished logging in... ")
            except (EOFError, KeyboardInterrupt):
                log.warning("  [nafath] Interrupted by user; saving current cookies anyway.")
        else:
            # ---- AUTO: smarter success detection ----
            # We consider success when ALL of the following are true:
            #   1. URL still on same host (didn't navigate away)
            #   2. Path is NOT a login-like path anymore
            #   3. Either cookies appeared or path differs from initial_path
            import time
            deadline = time.time() + wait_seconds
            last_log = 0.0
            ok = False

            # Optional explicit override from CLI (e.g. --success-url /dashboard)
            explicit_contains = success_url_contains

            while time.time() < deadline:
                time.sleep(2.0)
                try:
                    cur_url = page.url or ""
                except Exception:
                    continue

                cur_host = host_of(cur_url)
                cur_path = _path_of(cur_url)

                # Success signal #1: explicit substring matched
                if explicit_contains and explicit_contains in cur_url:
                    log.info(f"  [nafath] Success (explicit match: {explicit_contains})")
                    ok = True
                    break

                # Success signal #2: path changed away from login
                if (cur_host == host) and (cur_path != initial_path) and not _looks_like_login_path(cur_path):
                    log.info(f"  [nafath] Success (navigated to: {cur_path})")
                    ok = True
                    break

                # Heartbeat log
                if time.time() - last_log >= 10:
                    remaining = int(deadline - time.time())
                    log.info(f"  [wait] ... {remaining}s left | host={cur_host} path={cur_path}")
                    last_log = time.time()

            if not ok:
                log.warning("  [nafath] Timed out; saving cookies anyway.")
            else:
                page.wait_for_timeout(3000)

        # ---- Capture cookies ----
        cookies = context.cookies()
        log.info(f"  [nafath] Captured {len(cookies)} cookies")

    return save_profile(profile, url, cookies, provider="nafath")