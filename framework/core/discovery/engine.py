"""Discovery Engine - orchestrator."""
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin

from core.logger import get_logger
from .sources import (
    fetch_robots,
    fetch_sitemap,
    parse_html,
    parse_js,
    probe_well_known,
)
from .intelligence import (
    URLNormalizer,
    ScoreRanker,
    CatchAllDetector,
    Deduplicator,
)

log = get_logger("discovery")


@dataclass
class DiscoveryConfig:
    target: str
    max_pages: int = 50
    max_depth: int = 3
    budget_requests: int = 300
    use_browser: bool = False
    use_ai: bool = True
    ai_threshold_low: int = 3
    ai_threshold_high: int = 8


@dataclass
class DiscoveryResult:
    target: str
    endpoints: list = field(default_factory=list)
    params: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    js_files: list = field(default_factory=list)
    catchall_info: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    def summary(self):
        s = self.stats
        return (
            "Discovery of " + self.target + "\n"
            "  Endpoints: " + str(len(self.endpoints)) + "\n"
            "  Params: " + str(len(self.params)) + "\n"
            "  Forms: " + str(len(self.forms)) + "\n"
            "  JS files: " + str(len(self.js_files)) + "\n"
            "  Requests: " + str(s.get("requests", 0)) + "\n"
            "  Duration: " + ("%.1f" % s.get("duration", 0)) + "s\n"
            "  Catch-all: " + str(self.catchall_info.get("catch_all", False))
        )


class DiscoveryEngine:
    def __init__(self, client, config):
        self.client = client
        self.config = config
        self.normalizer = URLNormalizer()
        self.ranker = ScoreRanker()
        self.dedup = Deduplicator()
        self.catchall = None
        self.stats = {"requests": 0, "errors": 0}
        self._start = time.time()

    def discover(self):
        target = self.config.target.rstrip("/")
        log.info("Smart Discovery: " + target)

        log.info("  [1/5] Catch-all detection...")
        self.catchall = CatchAllDetector(self.client, target, samples=6)
        catchall_info = self.catchall.detect()
        if catchall_info["catch_all"]:
            log.warning("    Catch-all detected - filtering false positives")
        else:
            log.info("    No catch-all")

        log.info("  [2/5] Collecting seeds...")
        queue = self._collect_seeds(target)
        log.info("    " + str(len(queue)) + " seeds")

        log.info("  [3/5] Crawling (budget=" + str(self.config.budget_requests) + ")...")
        pages, forms, js_files = self._crawl(queue)
        log.info("    " + str(len(pages)) + " pages, "
                 + str(len(forms)) + " forms, "
                 + str(len(js_files)) + " JS files")

        log.info("  [4/5] Parsing JS files...")
        js_endpoints = self._parse_js_files(js_files)
        log.info("    " + str(len(js_endpoints)) + " JS-derived endpoints")

        log.info("  [5/5] Probing well-known paths...")
        well_known = probe_well_known(self.client, target, self.catchall)
        log.info("    " + str(len(well_known)) + " well-known hits")

        result = self._build_result(
            target=target,
            pages=pages,
            forms=forms,
            js_files=js_files,
            js_endpoints=js_endpoints,
            well_known=well_known,
            catchall_info=catchall_info,
        )
        result.stats["duration"] = time.time() - self._start
        result.stats["requests"] = self.stats["requests"]
        result.stats["errors"] = self.stats["errors"]
        return result

    def _collect_seeds(self, target):
        seeds = [(target, 0)]
        robots = fetch_robots(self.client, target)
        self.stats["requests"] += 1
        for path in robots["paths"]:
            seeds.append((urljoin(target + "/", path.lstrip("/")), 1))
        for sm in robots["sitemaps"]:
            for u in fetch_sitemap(self.client, sm)[:100]:
                seeds.append((u, 1))

        seen = set()
        out = []
        for url, depth in seeds:
            key = self.normalizer.normalize(url)
            if key in seen:
                continue
            seen.add(key)
            out.append((url, depth))
        return out

    def _crawl(self, queue):
        pages = []
        forms = []
        js_files = set()
        visited = 0

        while queue:
            if visited >= self.config.max_pages:
                break
            if self.stats["requests"] >= self.config.budget_requests:
                log.warning("    Budget exhausted")
                break

            url, depth = queue.pop(0)
            if depth > self.config.max_depth:
                continue
            if not self.dedup.add(url):
                continue

            resp = self.client.get(url)
            self.stats["requests"] += 1
            if not resp or resp.status == 0:
                self.stats["errors"] += 1
                continue

            if self.catchall and self.catchall.is_catchall(resp.status, resp.content):
                continue

            content = resp.content or b""
            parsed = parse_html(content, url)

            pages.append({
                "url": url,
                "status": resp.status,
                "size": len(content),
                "depth": depth,
            })

            for form in parsed["forms"]:
                form["source_page"] = url
                forms.append(form)

            for js in parsed["js_files"]:
                js_files.add(js)

            for link in parsed["links"]:
                if not self._in_scope(link):
                    continue
                if not self.dedup.contains(link):
                    queue.append((link, depth + 1))

            for mr in parsed["meta_refresh"]:
                if self._in_scope(mr) and not self.dedup.contains(mr):
                    queue.append((mr, depth + 1))

            visited += 1

        return pages, forms, sorted(js_files)

    def _parse_js_files(self, js_urls):
        results = []
        for js_url in js_urls[:30]:
            if self.stats["requests"] >= self.config.budget_requests:
                break
            resp = self.client.get(js_url)
            self.stats["requests"] += 1
            if not resp or resp.status != 200 or not resp.content:
                continue
            parsed = parse_js(resp.content, js_url)
            results.extend(parsed["paths"])
            results.extend(parsed["fetch_calls"])
            results.extend(parsed["axios_calls"])

        out = []
        seen = set()
        for u in results:
            k = self.normalizer.normalize(u)
            if k in seen:
                continue
            seen.add(k)
            out.append(u)
        return out

    def _in_scope(self, url):
        try:
            return self.client.in_scope(url)
        except Exception:
            return False

    def _build_result(self, target, pages, forms, js_files, js_endpoints,
                      well_known, catchall_info):
        endpoints = []

        for p in pages:
            score = self.ranker.score(p["url"], has_params="?" in p["url"])
            endpoints.append({
                "url": p["url"],
                "status": p["status"],
                "source": "crawl",
                "depth": p["depth"],
                "score": score,
            })

        for u in js_endpoints:
            endpoints.append({
                "url": u,
                "status": None,
                "source": "js",
                "depth": None,
                "score": self.ranker.score(u),
            })

        for wk in well_known:
            endpoints.append({
                "url": wk["url"],
                "status": wk["status"],
                "source": "well-known",
                "depth": None,
                "score": self.ranker.score(wk["url"]) + 15,
            })

        endpoints.sort(key=lambda x: x["score"], reverse=True)

        params = []
        seen_params = set()
        for e in endpoints:
            q = urlparse(e["url"]).query
            if not q:
                continue
            for pair in q.split("&"):
                if "=" in pair:
                    name = pair.split("=", 1)[0]
                    if name and name not in seen_params:
                        seen_params.add(name)
                        params.append({
                            "name": name,
                            "source": e["source"],
                            "url": e["url"],
                        })
        for f in forms:
            for inp in f.get("inputs", []):
                if inp and inp not in seen_params:
                    seen_params.add(inp)
                    params.append({
                        "name": inp,
                        "source": "form",
                        "url": f.get("action", ""),
                    })

        return DiscoveryResult(
            target=target,
            endpoints=endpoints,
            params=params,
            forms=forms,
            js_files=js_files,
            catchall_info=catchall_info,
            stats={},
        )


def discover(client, config):
    engine = DiscoveryEngine(client, config)
    return engine.discover()
