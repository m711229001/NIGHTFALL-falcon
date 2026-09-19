"""Falcon MAG - Shared Playwright browser helpers."""
import time
from contextlib import contextmanager
from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("auth.browser")


@contextmanager
def open_browser(headless: bool = False, ignore_https: bool = True):
    """Yield (browser, context, page). Auto-closes on exit."""
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=headless)
    context = browser.new_context(ignore_https_errors=ignore_https)
    page = context.new_page()
    try:
        yield browser, context, page
    finally:
        try:
            browser.close()
        except Exception:
            pass
        try:
            pw.stop()
        except Exception:
            pass


def wait_for_url_contains(page, substring: str, timeout: int = 240,
                          poll: float = 2.0, heartbeat: float = 10.0) -> bool:
    """Wait until page.url contains substring. Returns True if matched."""
    deadline = time.time() + timeout
    last = 0.0
    while time.time() < deadline:
        time.sleep(poll)
        try:
            cur = page.url or ""
        except Exception:
            continue
        if substring in cur:
            return True
        if time.time() - last >= heartbeat:
            remaining = int(deadline - time.time())
            log.info(f"  [wait] ... {remaining}s left | {cur[:90]}")
            last = time.time()
    return False


def path_of(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return "/"


def _looks_like_login_path(path: str) -> bool:
    p = (path or "").lower()
    return any(k in p for k in (
        "/login", "/signin", "/sign-in", "/auth",
        "/sso", "/oauth", "/authorize", "/callback",
    ))


def wait_for_login_success(
    page,
    initial_url: str,
    timeout: int = 240,
    explicit_contains: str = None,
    poll: float = 2.0,
    heartbeat: float = 10.0,
):
    """Smarter login-success detection (FIXED 2026-09-18).

    Prevents the old bug where `wait_for_url_contains(page, host)` matched
    immediately because the hostname is always in every URL on that host.

    Returns (ok: bool, final_url: str).

    Success criteria (any):
      1. explicit_contains is provided AND appears in current URL.
      2. Host stayed the same AND path changed from initial AND current path
         is NOT a login-like path.
    """
    host = host_of(initial_url)
    initial_path = path_of(initial_url)

    deadline = time.time() + timeout
    last_log = 0.0
    last_url = initial_url

    while time.time() < deadline:
        time.sleep(poll)
        try:
            cur_url = page.url or ""
        except Exception:
            continue
        last_url = cur_url

        # Criterion 1: explicit
        if explicit_contains and explicit_contains in cur_url:
            return True, cur_url

        # Criterion 2: host same + path changed away from login
        cur_host = host_of(cur_url)
        cur_path = path_of(cur_url)
        if (cur_host == host) and (cur_path != initial_path) and not _looks_like_login_path(cur_path):
            return True, cur_url

        if time.time() - last_log >= heartbeat:
            remaining = int(deadline - time.time())
            log.info(f"  [wait] ... {remaining}s left | host={cur_host} path={cur_path}")
            last_log = time.time()

    return False, last_url


def wait_for_selector_safe(page, selector: str, timeout: int = 10000) -> bool:
    """Return True if selector appears, False otherwise (no exception)."""
    try:
        page.wait_for_selector(selector, timeout=timeout)
        return True
    except Exception:
        return False


def find_first_visible(page, selectors: list, timeout_each: int = 1500):
    """Try a list of selectors, return the first that is clickable."""
    for sel in selectors:
        try:
            page.wait_for_selector(sel, timeout=timeout_each)
            el = page.query_selector(sel)
            if el and el.is_visible():
                return sel
        except Exception:
            continue
    return None


def same_host(a: str, b: str) -> bool:
    try:
        return urlparse(a).hostname == urlparse(b).hostname
    except Exception:
        return False


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""