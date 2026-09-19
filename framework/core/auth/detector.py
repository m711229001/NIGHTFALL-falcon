"""Falcon MAG - Login type detector.

Opens the page and looks for well-known markers:
  - data-testid="...nafath..."
  - <button>Sign in with Google/GitHub/...
  - SAML meta tags
  - password field + username field
"""
from core.logger import get_logger
from core.auth.browser import open_browser

log = get_logger("auth.detector")

SAML_MARKERS = [
    'samlrequest', 'samlresponse', 'urn:oasis:names:tc:saml',
    'okta', 'onelogin', 'auth0', 'adfs',
]

OAUTH_MARKERS = [
    'sign in with google', 'sign in with github', 'sign in with microsoft',
    'continue with google', 'continue with github', 'continue with microsoft',
    'login with google', 'login with github', 'login with microsoft',
    'sign in with apple', 'sign in with facebook', 'sign in with twitter',
    'sign in with linkedin', 'sign in with okta', 'sign in with azure',
]


def detect_auth_type(url: str, headless: bool = True) -> str:
    """Open URL, inspect content, return suggested auth type.

    Returns one of: nafath | saml | oauth | basic
    """
    try:
        with open_browser(headless=headless) as (_, _, page):
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(1500)

            html_raw = page.content()
            html = html_raw.lower()
            try:
                text = (page.inner_text("body") or "").lower()
            except Exception:
                text = ""
            combined = html + "\n" + text

            # 1) Nafath
            if 'nafath' in combined or 'نفاذ' in html_raw or 'النفاذ الوطني' in html_raw:
                log.info("  [detector] found Nafath markers")
                return "nafath"

            # 2) SAML
            for marker in SAML_MARKERS:
                if marker in combined:
                    log.info(f"  [detector] found SAML marker: {marker}")
                    return "saml"

            # 3) OAuth / social
            for marker in OAUTH_MARKERS:
                if marker in combined:
                    log.info(f"  [detector] found OAuth marker: {marker}")
                    return "oauth"

            # 4) Basic
            has_pw = bool(page.query_selector('input[type="password"]'))
            has_user = bool(
                page.query_selector('input[type="email"]')
                or page.query_selector('input[name*="user" i]')
                or page.query_selector('input[id*="user" i]')
                or page.query_selector('input[name*="email" i]')
            )
            if has_pw and has_user:
                log.info("  [detector] found username + password fields")
                return "basic"

            log.warning("  [detector] unknown page layout, defaulting to basic")
            return "basic"

    except Exception as e:
        log.error(f"  [detector] failed: {e}")
        return "basic"