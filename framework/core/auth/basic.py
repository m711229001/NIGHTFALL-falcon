"""Falcon MAG - Basic auth (username/password + OTP + TOTP).

FIXED 2026-09-18: uses `wait_for_login_success`; supports --wait 0.
"""
from pathlib import Path
from core.logger import get_logger
from core.auth import register, save_profile
from core.auth.browser import (
    open_browser,
    wait_for_login_success,
    wait_for_url_contains,
)

log = get_logger("auth.basic")


DEFAULT_USER_SELECTORS = [
    'input[type="email"]',
    'input[name*="user" i]',
    'input[name*="email" i]',
    'input[id*="user" i]',
    'input[id*="email" i]',
    'input[name="username"]',
    'input[name="login"]',
]

DEFAULT_PASS_SELECTORS = [
    'input[type="password"]',
    'input[name*="pass" i]',
    'input[id*="pass" i]',
]

DEFAULT_SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button:has-text("Log in")',
    'button:has-text("Sign in")',
    'button:has-text("Login")',
    'button:has-text("تسجيل الدخول")',
    'button:has-text("دخول")',
]


def _try_selector(page, selectors, action, value=None, label=""):
    """Try selectors in order; perform action on the first match."""
    for sel in selectors:
        try:
            page.wait_for_selector(sel, timeout=2000)
            el = page.query_selector(sel)
            if not el or not el.is_visible():
                continue
            if action == "fill":
                el.fill(value)
            elif action == "click":
                el.click()
            log.info(f"  [basic] {label} via {sel}")
            return sel
        except Exception:
            continue
    log.warning(f"  [basic] could not {action} for {label}")
    return None


@register("basic")
def login_basic(
    url: str,
    username: str = None,
    password: str = None,
    profile: str = "default",
    totp_secret: str = None,
    otp_selector: str = None,
    otp_wait_seconds: int = 180,
    user_selector: str = None,
    pass_selector: str = None,
    submit_selector: str = None,
    success_url_contains: str = None,
    headless: bool = False,
    wait_seconds: int = 240,
    **kwargs,
) -> Path:
    """Login via username + password (+ optional TOTP or manual OTP)."""
    if not username or not password:
        raise ValueError("basic auth requires --username and --password")

    interactive = (wait_seconds == 0)

    log.info(f"  [basic] Logging in to {url}")
    if interactive:
        log.info("  [basic] Mode: INTERACTIVE (press ENTER after login to save)")

    with open_browser(headless=headless) as (_, context, page):
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1000)

        # ---- Step 1: username ----
        filled_user = _try_selector(
            page,
            [user_selector] if user_selector else DEFAULT_USER_SELECTORS,
            "fill", username, "username",
        )

        pw_present_now = False
        try:
            pw_present_now = bool(page.query_selector('input[type="password"]'))
        except Exception:
            pass

        if filled_user and not pw_present_now:
            log.info("  [basic] multi-page flow: submitting username first")
            _try_selector(
                page,
                [submit_selector] if submit_selector else DEFAULT_SUBMIT_SELECTORS,
                "click", label="next",
            )
            try:
                page.wait_for_selector('input[type="password"]', timeout=15000)
                page.wait_for_timeout(800)
            except Exception:
                log.warning("  [basic] password field did not appear after username submit")

        # ---- Step 2: password ----
        _try_selector(
            page,
            [pass_selector] if pass_selector else DEFAULT_PASS_SELECTORS,
            "fill", password, "password",
        )
        _try_selector(
            page,
            [submit_selector] if submit_selector else DEFAULT_SUBMIT_SELECTORS,
            "click", label="submit",
        )

        page.wait_for_timeout(2000)

        # ---- Step 3: TOTP / OTP ----
        if totp_secret:
            try:
                from core.auth_totp import generate_totp
                code = generate_totp(totp_secret)
                log.info(f"  [basic] TOTP code: {code}")
            except Exception as e:
                log.warning(f"  [basic] TOTP failed: {e}")
                code = None

            if code:
                otp_inputs = [
                    'input[name*="otp" i]',
                    'input[name*="code" i]',
                    'input[autocomplete="one-time-code"]',
                    'input[type="tel"]',
                    'input[type="text"][maxlength="6"]',
                ]
                _try_selector(page, otp_inputs, "fill", code, "otp")
                page.keyboard.press("Enter")
                page.wait_for_timeout(2000)

        elif otp_selector:
            log.info(f"  [basic] Waiting up to {otp_wait_seconds}s for manual OTP in {otp_selector}")
            try:
                page.wait_for_selector(otp_selector, timeout=otp_wait_seconds * 1000)
                log.info("  [basic] OTP field appeared. Please enter the code in the browser.")
                if not interactive:
                    wait_for_url_contains(page, success_url_contains or "", timeout=otp_wait_seconds)
            except Exception:
                pass

        # ---- Step 4: wait strategy ----
        if interactive:
            log.info("")
            log.info("  ┌──────────────────────────────────────────────────────────┐")
            log.info("  │  Complete any remaining steps (OTP, MFA, consent).      │")
            log.info("  │  When DONE, return here and press ENTER to save.        │")
            log.info("  │  (Ctrl+C to abort)                                       │")
            log.info("  └──────────────────────────────────────────────────────────┘")
            log.info("")
            try:
                input("  >>> Press ENTER here when you have finished logging in... ")
            except (EOFError, KeyboardInterrupt):
                log.warning("  [basic] Interrupted; saving current cookies anyway.")
        else:
            ok, final_url = wait_for_login_success(
                page, url,
                timeout=wait_seconds,
                explicit_contains=success_url_contains,
            )
            if not ok:
                log.warning("  [basic] Timed out waiting for redirect; saving anyway.")
            else:
                log.info(f"  [basic] Success at: {final_url}")

        cookies = context.cookies()
        log.info(f"  [basic] Captured {len(cookies)} cookies")

    return save_profile(profile, url, cookies, provider="basic")