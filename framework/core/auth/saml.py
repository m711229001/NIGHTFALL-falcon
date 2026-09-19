"""Falcon MAG - SAML SSO handler.

SAML flows typically start at /sso/login or similar and redirect to
the IdP. Since SAML forms are dynamic, we rely on the user completing
the flow interactively in a visible browser.

FIXED 2026-09-18: uses `wait_for_login_success` to avoid false positives
(success no longer detected while still on the login page).
Supports --wait 0 (open-ended interactive: press ENTER to save).
"""
from pathlib import Path
from core.logger import get_logger
from core.auth import register, save_profile
from core.auth.browser import (
    open_browser,
    wait_for_login_success,
)

log = get_logger("auth.saml")


@register("saml")
def login_saml(
    url: str,
    profile: str = "saml",
    success_url_contains: str = None,
    headless: bool = False,
    wait_seconds: int = 300,
    **kwargs,
) -> Path:
    """Open URL and wait for the user to complete the SAML flow."""
    interactive = (wait_seconds == 0)

    log.info(f"  [saml] Opening {url}")
    log.info(f"  [saml] Complete the SSO login in the visible browser.")
    if interactive:
        log.info("  [saml] Mode: INTERACTIVE (press ENTER in terminal to save)")
    else:
        log.info(f"  [saml] Mode: AUTO (wait up to {wait_seconds}s)")

    with open_browser(headless=headless) as (_, context, page):
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1500)

        if interactive:
            log.info("")
            log.info("  ┌──────────────────────────────────────────────────────────┐")
            log.info("  │  Complete the SSO / SAML login in the browser.          │")
            log.info("  │  When DONE, return here and press ENTER to save.        │")
            log.info("  │  (Ctrl+C to abort)                                       │")
            log.info("  └──────────────────────────────────────────────────────────┘")
            log.info("")
            try:
                input("  >>> Press ENTER here when you have finished logging in... ")
            except (EOFError, KeyboardInterrupt):
                log.warning("  [saml] Interrupted; saving current cookies anyway.")
        else:
            ok, final_url = wait_for_login_success(
                page, url,
                timeout=wait_seconds,
                explicit_contains=success_url_contains,
            )
            if not ok:
                log.warning("  [saml] Timed out; saving cookies anyway.")
            else:
                log.info(f"  [saml] Success at: {final_url}")
                page.wait_for_timeout(3000)

        cookies = context.cookies()
        log.info(f"  [saml] Captured {len(cookies)} cookies")

    return save_profile(profile, url, cookies, provider="saml")