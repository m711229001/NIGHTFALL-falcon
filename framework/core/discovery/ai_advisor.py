"""AI Advisor - evaluates ambiguous URLs (placeholder)."""
import json
from core.logger import get_logger

log = get_logger("discovery.ai")


class AIAdvisor:
    def __init__(self):
        self._client = None

    def _get_ai_client(self):
        if self._client is None:
            from core.ai_client import UniversalAIClient
            self._client = UniversalAIClient()
        return self._client

    def evaluate_batch(self, urls, config):
        if not urls:
            return []
        try:
            from .intelligence import ScoreRanker
            ranker = ScoreRanker()
            ambiguous = []
            for u in urls:
                s = ranker.score(u)
                if config.ai_threshold_low <= s <= config.ai_threshold_high:
                    ambiguous.append((u, s))
        except Exception:
            return []

        if not ambiguous:
            return []

        listing = "\n".join("- " + u + " (score " + str(s) + ")" for u, s in ambiguous[:10])
        prompt = (
            "You are a bug bounty recon assistant. For each URL below, "
            "decide if it deserves deep crawling. "
            "Reply ONLY with JSON: {results: [{url, crawl, reason}]}\n\n"
            "URLs:\n" + listing
        )
        system = "You decide crawl-worthiness. Output strict JSON only."

        try:
            client = self._get_ai_client()
            text = client.generate_from_active(
                user_prompt=prompt,
                system_prompt=system,
                json_mode=True,
            )
            if not text:
                return []
            parsed = self._extract_json(text)
            results = parsed.get("results", []) if isinstance(parsed, dict) else []
            out = []
            for item in results:
                if item.get("crawl"):
                    out.append({
                        "url": item.get("url", ""),
                        "score": 10,
                        "reason": item.get("reason", ""),
                    })
            return out
        except Exception as e:
            log.debug("AI advisor failed: " + str(e))
            return []

    @staticmethod
    def _extract_json(text):
        if not text:
            return {}
        try:
            return json.loads(text)
        except Exception:
            pass
        start = text.find("{")
        if start < 0:
            return {}
        depth = 0
        for i in range(start, len(text)):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except Exception:
                        return {}
        return {}
