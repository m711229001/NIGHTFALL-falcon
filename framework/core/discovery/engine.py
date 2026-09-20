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
from .sources_history import fetch_all_historical
from .js_analysis import analyze_js
from .intelligence import (
    URLNormalizer,
    ScoreRanker,
    CatchAllDetector,
    Deduplicator,
    ScopeGuard,
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
        self.dedup = Deduplicator(target=config.target)
        self.scope = ScopeGuard(config.target)
        self.catchall = None
        self.stats = {"requests": 0, "errors": 0}
        self._js_secrets = []
        self._start = time.time()

    def discover(self):
        target = self.config.target.rstrip("/")
        log.info("Smart Discovery: " + target)

        log.info("  [1/5] Catch-all detection...")
        self.catchall = CatchAllDetector(self.client, target, samples=3)
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

        # AI Crawler Agent (optional) - dynamic flow discovery
        if self.config.use_ai and getattr(self.config, "use_ai_crawler", False):
            log.info("  [5b/6] AI Crawler Agent...")
            try:
                from .ai_crawler import run_ai_crawler
                from core.ai_client import UniversalAIClient
                ai_client = UniversalAIClient()
                crawler_result = run_ai_crawler(
                    target,
                    ai_client=ai_client,
                    max_steps=getattr(self.config, "ai_crawler_steps", 5),
                )
                if crawler_result and crawler_result.get("discovered_urls"):
                    existing = {e["url"] for e in result.endpoints}
                    added = 0
                    for u in crawler_result["discovered_urls"]:
                        if not self.scope.in_scope(u):
                            continue
                        if u in existing:
                            continue
                        result.endpoints.append({
                            "url": u,
                            "status": None,
                            "source": "ai-crawler",
                            "depth": None,
                            "score": self.ranker.score(u) + 5,
                        })
                        added += 1
                    for form in crawler_result.get("discovered_forms", []):
                        if isinstance(form, dict):
                            result.forms.append(form)
                    result.endpoints.sort(key=lambda x: x["score"], reverse=True)
                    log.info("    AI crawler: +" + str(added) + " URLs")
            except Exception as e:
                log.debug("    AI crawler skipped: " + str(e))

        # AI Advisor (optional) - evaluate ambiguous endpoints
        if self.config.use_ai and len(result.endpoints) >= 10:
            log.info("  [6/6] AI Advisor on ambiguous URLs...")
            try:
                from .ai_advisor import AIAdvisor
                advisor = AIAdvisor()
                suggestions = advisor.evaluate_batch(
                    [e["url"] for e in result.endpoints[:30]],
                    self.config,
                )
                if suggestions:
                    existing = {e["url"] for e in result.endpoints}
                    for s in suggestions:
                        if not self.scope.in_scope(s["url"]):
                            continue
                        if s["url"] not in existing:
                            result.endpoints.append({
                                "url": s["url"],
                                "status": None,
                                "source": "ai",
                                "depth": None,
                                "score": s.get("score", 10),
                                "reason": s.get("reason", ""),
                            })
                    result.endpoints.sort(
                        key=lambda x: x["score"], reverse=True
                    )
                    log.info("    AI suggested " + str(len(suggestions)) + " extra URLs")
                else:
                    log.info("    AI: no additional suggestions")
            except Exception as e:
                log.debug("    AI Advisor skipped: " + str(e))
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

        # Historical passive recon (Wayback + CommonCrawl + OTX)
        try:
            log.info("    Fetching historical URLs...")
            hist = fetch_all_historical(target, limit=300)
            from .sources_history import is_dangerous_url
            added = 0
            skipped = 0
            for u in hist[:300]:
                if not self.scope.in_scope(u):
                    continue
                if is_dangerous_url(u):
                    skipped += 1
                    continue
                seeds.append((u, 1))
                added += 1
            log.info("    +" + str(added) + " historical seeds ("
                     + str(skipped) + " skipped)")
        except Exception as e:
            log.debug("    history failed: " + str(e))

        seen = set()
        out = []
        for url, depth in seeds:
            if not self.scope.in_scope(url):
                continue
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

            try:
                resp = self.client.get(url, timeout=8)
            except Exception:
                resp = None
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
                # Normalize to prevent duplicate analysis
                norm_js = self.normalizer.normalize(js)
                # Rebuild URL from normalized
                try:
                    from urllib.parse import urlparse as _up, urlunparse as _uu
                    p = _up(norm_js)
                    # Force https for safety
                    clean = _uu(("https", p.netloc, p.path, "", "", ""))
                    js_files.add(clean)
                except Exception:
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
        # Dedup normalized URLs
        seen_js = set()
        for js_url in js_urls[:30]:
            if self.stats["requests"] >= self.config.budget_requests:
                break
            # Normalize to avoid re-fetching same file
            norm = self.normalizer.normalize(js_url)
            if norm in seen_js:
                continue
            seen_js.add(norm)
            # Skip vendor / huge files by PATH only (more precise)
            try:
                from urllib.parse import urlparse as _up
                path_low = _up(js_url).path.lower()
            except Exception:
                path_low = js_url.lower()
            if any(kw in path_low for kw in ("swagger", "bundle", "vendor", "polyfill", "chunk-vendors")):
                continue
            try:
                resp = self.client.get(js_url, timeout=8)
            except Exception:
                resp = None
            self.stats["requests"] += 1
            if not resp or resp.status != 200 or not resp.content:
                continue
            if len(resp.content) > 500_000:
                log.debug("    skip large JS: " + js_url[-60:])
                continue
            parsed = parse_js(resp.content, js_url)
            results.extend(parsed["paths"])
            results.extend(parsed["fetch_calls"])
            results.extend(parsed["axios_calls"])

            # Advanced LinkFinder + SecretFinder
            try:
                if len(resp.content) <= 2_000_000:
                    js_text = resp.content.decode("utf-8", errors="ignore")
                    adv = analyze_js(js_text, js_url)
                    results.extend(adv["links"])
                    if adv["secrets"]:
                        for s in adv["secrets"]:
                            s["source_js"] = js_url
                            self._js_secrets.append(s)
                        log.info("    [secrets] +" + str(len(adv["secrets"])) + " in " + js_url[-50:])
            except Exception as e:
                log.debug("    advanced JS failed: " + str(e))

        out = []
        seen = set()
        for u in results:
            if not self.scope.in_scope(u):
                continue
            k = self.normalizer.normalize(u)
            if k in seen:
                continue
            seen.add(k)
            out.append(u)
        return out

    def _in_scope(self, url):
        # 1. Strict local scope check FIRST
        if not self.scope.in_scope(url):
            return False
        # 2. Fall back to client's check if available
        try:
            return self.client.in_scope(url)
        except Exception:
            return True

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
            if not self.scope.in_scope(wk["url"]):
                continue
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

        result = DiscoveryResult(
            target=target,
            endpoints=endpoints,
            params=params,
            forms=forms,
            js_files=js_files,
            catchall_info=catchall_info,
            stats={},
        )
        try:
            result.js_secrets = self._js_secrets
        except Exception:
            pass
        return result


def discover(client, config):
    engine = DiscoveryEngine(client, config)
    return engine.discover()
