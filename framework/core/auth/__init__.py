"""Falcon MAG - Generic Authentication Module

Supports:
  - basic   : username/password (+ optional TOTP + manual OTP wait)
  - oauth   : OAuth2 / OIDC / "Sign in with X" buttons
  - saml    : SAML SSO
  - nafath  : Saudi National SSO (Qiwa/Absher/Tawakkalna family)
  - auto    : detect the login type from the page

Every auth method returns a Path to a JSON profile containing cookies.
"""
from pathlib import Path
from core.logger import get_logger

log = get_logger("auth")

# Registry: name -> callable
_REGISTRY = {}


def register(name):
    """Decorator to register an auth handler."""
    def deco(fn):
        _REGISTRY[name] = fn
        return fn
    return deco


def available() -> list:
    """Return list of registered auth handlers."""
    # Lazy import to trigger registration
    try:
        from core.auth import basic  # noqa: F401
    except ImportError:
        pass
    try:
        from core.auth import nafath  # noqa: F401
    except ImportError:
        pass
    try:
        from core.auth import oauth  # noqa: F401
    except ImportError:
        pass
    try:
        from core.auth import saml  # noqa: F401
    except ImportError:
        pass
    return sorted(_REGISTRY.keys())


def get(name: str):
    """Return a handler by name."""
    available()  # ensure registration
    return _REGISTRY.get(name)


def login(
    auth_type: str,
    url: str,
    profile: str = "default",
    headless: bool = False,
    wait_seconds: int = 240,
    **kwargs,
) -> Path:
    """Unified login dispatcher.

    Args:
        auth_type: basic | oauth | saml | nafath | auto
        url:       Login page URL
        profile:   Profile name to save
        headless:  Hide browser (not recommended for OTP/Nafath)
        wait_seconds: How long to wait for manual approval
        **kwargs:  Passed to the handler (username, password, totp_secret,
                   button_selector, success_url_contains, ...)
    """
    if auth_type == "auto":
        from core.auth.detector import detect_auth_type
        detected = detect_auth_type(url, headless=headless)
        log.info(f"  [auth] auto-detected: {detected}")
        auth_type = detected

    handler = get(auth_type)
    if not handler:
        raise ValueError(
            f"Unknown auth type: {auth_type}. "
            f"Available: {', '.join(available())}"
        )

    log.info(f"  [auth] Using handler: {auth_type}")
    return handler(
        url=url,
        profile=profile,
        headless=headless,
        wait_seconds=wait_seconds,
        **kwargs,
    )


def save_profile(profile: str, url: str, cookies: list, provider: str) -> Path:
    """Shared helper: save cookies to profiles/<name>.json."""
    import json, time
    p = Path("profiles")
    p.mkdir(parents=True, exist_ok=True)
    path = p / f"{profile}.json"
    data = {
        "profile": profile,
        "login_url": url,
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "provider": provider,
        "cookies": cookies,
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path