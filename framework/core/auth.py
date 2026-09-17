"""Falcon MAG Framework - Authentication Support

Provides:
  - Form-based login (POST username/password)
  - JSON API login
  - Bearer token
  - Manual cookie injection
  - Session persistence
"""

from urllib.parse import urljoin, urlparse
from core.logger import get_logger

log = get_logger("auth")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class AuthSession:
    """Authentication session manager."""

    def __init__(self, login_url: str, username: str = "",
                 password: str = "", method: str = "POST",
                 username_field: str = "", password_field: str = "",
                 bearer_token: str = "", manual_cookie: str = "",
                 extra_fields: dict = None, json_mode: bool = False):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.method = method.upper()
        self.username_field = username_field
        self.password_field = password_field
        self.bearer_token = bearer_token
        self.manual_cookie = manual_cookie
        self.extra_fields = extra_fields or {}
        self.json_mode = json_mode
        self.logged_in = False
        self.cookies = {}

    def _detect_form_fields(self, client):
        """Fetch login page and detect username/password field names."""
        if not BS4_AVAILABLE:
            return False
        try:
            resp = client.get(self.login_url)
            if not resp or resp.status == 0:
                return False

            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                inputs = form.find_all("input")
                user_cands = []
                pass_cands = []

                for inp in inputs:
                    name = inp.get("name", "")
                    itype = inp.get("type", "").lower()
                    nl = name.lower()

                    if itype == "password" or "pass" in nl:
                        pass_cands.append(name)
                    elif itype in ("text", "email") or "user" in nl or "email" in nl or "login" in nl:
                        user_cands.append(name)

                if user_cands and pass_cands:
                    self.username_field = self.username_field or user_cands[0]
                    self.password_field = self.password_field or pass_cands[0]
                    log.info("  Detected fields: " + self.username_field + " / " + self.password_field)
                    return True

        except Exception as e:
            log.debug("Form detection failed: " + str(e))
        return False

    def login(self, client) -> bool:
        """Perform login. Returns True on success."""
        # Manual cookie (highest priority)
        if self.manual_cookie:
            log.info("Using manual cookie")
            for cookie in self.manual_cookie.split(";"):
                if "=" in cookie:
                    k, v = cookie.strip().split("=", 1)
                    client.session.cookies.set(k, v)
            self.logged_in = True
            log.info("  Cookie set: " + str(list(client.session.cookies.keys())))
            return True

        # Bearer token
        if self.bearer_token:
            log.info("Using bearer token")
            client.session.headers["Authorization"] = "Bearer " + self.bearer_token
            self.logged_in = True
            log.info("  Authorization header set")
            return True

        # Form-based requires login_url
        if not self.login_url:
            log.warning("No login_url provided")
            return False

        # Form-based
        if not self.username or not self.password:
            log.warning("No credentials provided")
            return False

        if not self.username_field or not self.password_field:
            self._detect_form_fields(client)

        self.username_field = self.username_field or "username"
        self.password_field = self.password_field or "password"

        payload = dict(self.extra_fields)
        payload[self.username_field] = self.username
        payload[self.password_field] = self.password

        log.info("Logging in to " + self.login_url)
        log.info("  Fields: " + self.username_field + " / " + self.password_field)

        try:
            if self.json_mode:
                resp = client.session.request(
                    self.method, self.login_url, json=payload,
                    allow_redirects=True, verify=False
                )
            else:
                resp = client.session.request(
                    self.method, self.login_url, data=payload,
                    allow_redirects=True, verify=False
                )

            if 200 <= resp.status_code < 400:
                self.logged_in = True
                self.cookies = dict(resp.cookies)
                log.info("  Login successful (HTTP " + str(resp.status_code) + ")")
                log.info("  Cookies: " + str(list(resp.cookies.keys())))
                return True
            else:
                log.warning("  Login failed (HTTP " + str(resp.status_code) + ")")
                return False

        except Exception as e:
            log.error("  Login error: " + str(e))
            return False


def load_auth_from_config(config) -> AuthSession:
    """Build AuthSession from config dict."""
    auth_cfg = config.get("auth", {}) or {}
    if not auth_cfg.get("enabled"):
        return None
    return AuthSession(
        login_url=auth_cfg.get("login_url", ""),
        username=auth_cfg.get("username", ""),
        password=auth_cfg.get("password", ""),
        method=auth_cfg.get("method", "POST"),
        username_field=auth_cfg.get("username_field", ""),
        password_field=auth_cfg.get("password_field", ""),
        bearer_token=auth_cfg.get("bearer_token", ""),
        manual_cookie=auth_cfg.get("cookie", ""),
        extra_fields=auth_cfg.get("extra_fields", {}),
        json_mode=auth_cfg.get("json", False),
    )