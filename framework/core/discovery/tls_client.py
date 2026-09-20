"""TLS impersonation client - bypasses Cloudflare/Akamai via JA3."""
from core.logger import get_logger

log = get_logger("tls_client")

try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except Exception:
    HAS_CURL_CFFI = False
    log.warning("curl_cffi not installed - TLS impersonation disabled")


IMPERSONATE_PROFILES = [
    "chrome124",
    "chrome120",
    "chrome119",
    "chrome116",
    "safari17_0",
    "firefox133",
    "edge101",
]


class TLSClient:
    """HTTP client with TLS fingerprint impersonation."""

    def __init__(self, profile="chrome124", timeout=15, proxy=None):
        self.profile = profile
        self.timeout = timeout
        self.proxy = proxy
        self._session = None
        if not HAS_CURL_CFFI:
            raise RuntimeError("curl_cffi not available")

    def _get_session(self):
        if self._session is None:
            self._session = curl_requests.Session(
                impersonate=self.profile,
                timeout=self.timeout,
                verify=False,
            )
            if self.proxy:
                self._session.proxies = {"http": self.proxy, "https": self.proxy}
        return self._session

    def get(self, url, **kwargs):
        try:
            s = self._get_session()
            r = s.get(url, **kwargs)
            return _Wrap(r)
        except Exception as e:
            log.debug("TLS GET failed: " + str(e)[:100])
            return None

    def post(self, url, **kwargs):
        try:
            s = self._get_session()
            r = s.post(url, **kwargs)
            return _Wrap(r)
        except Exception as e:
            log.debug("TLS POST failed: " + str(e)[:100])
            return None


class _Wrap:
    """Wrapper to mimic requests.Response interface."""
    def __init__(self, r):
        self._r = r
        self.status = r.status_code
        self.status_code = r.status_code
        self.headers = dict(r.headers)
        self.content = r.content
        self.text = r.text
        self.url = str(r.url)

    def json(self):
        return self._r.json()


def get_tls_client(profile="chrome124"):
    if not HAS_CURL_CFFI:
        return None
    try:
        return TLSClient(profile=profile)
    except Exception as e:
        log.debug("TLS client failed: " + str(e))
        return None
