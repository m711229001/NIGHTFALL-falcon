"""Falcon MAG - OAuth2 / OIDC / social login handler.

Generic: clicks a "Sign in with X" button, then waits for the user
to complete the flow manually. Works with Google, GitHub, Microsoft,
Apple, Okta, Auth0, etc.

FIXED 2026-09-18: uses `wait_for_login_success`; supports --wait 0.
"""
from pathlib import Path
from core.logger import get_logger
from core.auth import register, save_profile
from core.auth.browser import (
    open_browser,
    wait_for_login_success,
    find_first_visible,
)

log = get_logger("auth.oauth")


DEFAULT_OAUTH_BUTTONS = [
    'button:has-text("Sign in with Google")',
    'button:has-text("Continue with Google")',
    'a:has-text("Sign in with Google")',
    'button:has-text("Sign in with GitHub")',
    'button:has-text("Continue with GitHub")',
    'button:has-text("Sign in with Microsoft")',
    'button:has-text("Continue with Microsoft")',
    'button:has-text("Sign in with Apple")',
    '[aria-label*="Google" i]',
    '[aria-label*="GitHub" i]',
    '[aria-label*="Microsoft" i]',
]


@register("oauth")
def login_oauth(
    url: str,
    profile: str = "oauth",
    button_selector: str = None,
    success_url_contains: str = None,
    headless: bool = False,
    wait_seconds: int = 240,
    **kwargs,
) -> Path:
    """Click the OAuth provider button, then wait for the callback."""
    interactive = (wait_seconds == 0)

    log.info(f"  [oauth] Opening {url}")
    if interactive:
        log.info("  [oauth] Mode: INTERACTIVE (press ENTER in terminal to save)")

    with open_browser(headless=headless) as (_, context, page):
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1500)

        selectors = [button_selector] if button_selector else DEFAULT_OAUTH_BUTTONS
        found = find_first_visible(page, selectors, timeout_each=2000)

        if not found:
            log.error("  [oauth] No OAuth button found.")
            raise RuntimeError("OAuth button not found. Pass --button-selector.")

        log.info(f"  [oauth] Clicking: {found}")
        page.click(found)

        if interactive:
            log.info("")
            log.info("  ┌──────────────────────────────────────────────────────────┐")
            log.info("  │  Complete the OAuth login in the browser window.        │")
            log.info("  │  When DONE, return here and press ENTER to save.        │")
            log.info("  │  (Ctrl+C to abort)                                       │")
            log.info("  └──────────────────────────────────────────────────────────┘")
            log.info("")
            try:
                input("  >>> Press ENTER here when you have finished logging in... ")
            except (EOFError, KeyboardInterrupt):
                log.warning("  [oauth] Interrupted; saving current cookies anyway.")
        else:
            ok, final_url = wait_for_login_success(
                page, url,
                timeout=wait_seconds,
                explicit_contains=success_url_contains,
            )
            if not ok:
                log.warning("  [oauth] Timed out; saving cookies anyway.")
            else:
                log.info(f"  [oauth] Success at: {final_url}")
                page.wait_for_timeout(3000)

        cookies = context.cookies()
        log.info(f"  [oauth] Captured {len(cookies)} cookies")

    return save_profile(profile, url, cookies, provider="oauth")