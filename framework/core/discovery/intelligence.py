"""Intelligence layer - URL normalization, scoring, catch-all, dedup."""
import hashlib
import uuid
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode


class URLNormalizer:
    TRACKING_PARAMS = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "gclid", "fbclid", "msclkid", "mc_eid", "_ga", "ref", "source",
    }

    @classmethod
    def normalize(cls, url):
        try:
            p = urlparse(url)
        except Exception:
            return url
        scheme = (p.scheme or "http").lower()
        netloc = (p.netloc or "").lower()
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        elif netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]
        path = p.path or "/"
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        qs = [
            (k, v)
            for k, v in parse_qsl(p.query, keep_blank_values=True)
            if k.lower() not in cls.TRACKING_PARAMS
        ]
        qs.sort()
        return urlunparse((scheme, netloc, path, "", urlencode(qs), ""))


class ScoreRanker:
    HIGH_KW = (
        "admin", "api", "graphql", "swagger", "openapi", "debug",
        "backup", "config", "secret", "token", "auth",
        "login", "signin", "register", "upload", "download",
        "internal", "private", "test", "dev", "staging",
    )
    MED_KW = (
        "user", "account", "profile", "search", "query", "find",
        "list", "view", "edit", "update", "delete", "create",
    )
    STATIC_EXT = (
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".woff", ".woff2", ".svg", ".ttf", ".eot", ".mp4", ".webm",
    )
    DATA_EXT = (".json", ".xml", ".yaml", ".yml")

    @classmethod
    def score(cls, url, has_params=False, is_form=False):
        score = 1
        lower = url.lower()
        for kw in cls.HIGH_KW:
            if kw in lower:
                score += 10
                break
        else:
            for kw in cls.MED_KW:
                if kw in lower:
                    score += 5
                    break
        if any(lower.endswith(ext) for ext in cls.DATA_EXT):
            score += 3
        if has_params:
            score += 3
        if is_form:
            score += 5
        if "/api/" in lower or lower.endswith("/api"):
            score += 8
        if "/graphql" in lower:
            score += 8
        if any(lower.endswith(ext) for ext in cls.STATIC_EXT):
            score -= 50
        return score


class CatchAllDetector:
    def __init__(self, client, base_url, samples=6):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.samples = samples
        self.catch_all = False
        self.signature = None
        self.signature_body = None
        self._detected = False

    def detect(self):
        if self._detected:
            return self._result()
        responses = []
        for _ in range(self.samples):
            uid = uuid.uuid4().hex[:12]
            url = self.base_url + "/" + uid
            try:
                resp = self.client.get(url, timeout=6)
            except Exception:
                resp = None
            if not resp or resp.status == 0:
                continue
            body = resp.content or b""
            responses.append((resp.status, body))

        if len(responses) < 2:
            self._detected = True
            return self._result()

        # Check status codes: catch-all requires SAME status AND high body similarity
        statuses = [s for s, _ in responses]
        if len(set(statuses)) != 1:
            self._detected = True
            return self._result()

        # Only 200 OK counts as catch-all (not 404s)
        if statuses[0] != 200:
            self._detected = True
            return self._result()

        # Body similarity - require > 95% same content
        bodies = [b for _, b in responses]
        lens = [len(b) for b in bodies]
        if max(lens) == 0:
            self._detected = True
            return self._result()

        # Compare bodies: same length OR same md5
        same_len = len(set(lens)) == 1
        hashes = {hashlib.md5(b).hexdigest() for b in bodies}
        same_hash = len(hashes) == 1

        if same_hash and same_len:
            self.catch_all = True
            self.signature = (statuses[0], list(hashes)[0])
            self.signature_body = bodies[0]
        self._detected = True
        return self._result()

    def is_catchall(self, status, body):
        if not self.catch_all or not self.signature:
            return False
        h = hashlib.md5(body or b"").hexdigest()
        return (status, h) == self.signature

    def _result(self):
        return {
            "catch_all": self.catch_all,
            "signature": self.signature,
            "samples_tested": self.samples,
        }


class ScopeGuard:
    """Strict scope checking - only target domain and its subdomains."""

    def __init__(self, target):
        try:
            from urllib.parse import urlparse
            host = urlparse(target).hostname or ""
            self.base_host = host.lower()
            # Root domain (last 2 labels or 3 for .co.uk style)
            parts = self.base_host.split(".")
            self.root_host = ".".join(parts[-2:]) if len(parts) >= 2 else self.base_host
        except Exception:
            self.base_host = ""
            self.root_host = ""

    def in_scope(self, url):
        if not url or not self.base_host:
            return False
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return False
            host = (p.hostname or "").lower()
            if not host:
                return False
            # Exact match or subdomain match
            if host == self.base_host:
                return True
            if host == self.root_host:
                return True
            if host.endswith("." + self.root_host):
                return True
            return False
        except Exception:
            return False


class Deduplicator:
    def __init__(self, target=None):
        self._seen = set()
        self.guard = ScopeGuard(target) if target else None

    def add(self, url):
        if self.guard and not self.guard.in_scope(url):
            return False
        key = URLNormalizer.normalize(url)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def contains(self, url):
        if self.guard and not self.guard.in_scope(url):
            return True  # treat out-of-scope as "already seen" to skip
        return URLNormalizer.normalize(url) in self._seen

    def in_scope(self, url):
        if not self.guard:
            return True
        return self.guard.in_scope(url)

    def __len__(self):
        return len(self._seen)
