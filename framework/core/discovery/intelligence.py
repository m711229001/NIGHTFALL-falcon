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
        self._detected = False

    def detect(self):
        if self._detected:
            return self._result()
        hashes = {}
        for _ in range(self.samples):
            uid = uuid.uuid4().hex[:12]
            url = self.base_url + "/" + uid
            resp = self.client.get(url)
            if not resp or resp.status == 0:
                continue
            body = resp.content or b""
            h = hashlib.md5(body).hexdigest()
            hashes.setdefault((resp.status, h), []).append(url)
        if len(hashes) == 1:
            self.catch_all = True
            self.signature = list(hashes.keys())[0]
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


class Deduplicator:
    def __init__(self):
        self._seen = set()

    def add(self, url):
        key = URLNormalizer.normalize(url)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def contains(self, url):
        return URLNormalizer.normalize(url) in self._seen

    def __len__(self):
        return len(self._seen)
