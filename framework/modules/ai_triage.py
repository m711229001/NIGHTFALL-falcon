"""Falcon MAG Framework - AI Triage

Scores each finding on 4 dimensions:
  - exploitability_score  (0-100)
  - bugbounty_worthy      (yes/no)
  - real_cvss             (0-10)
  - publish_priority      (1-10)

Uses the active AI provider to make a smart judgment.
"""
import json
from core.logger import get_logger
from core.ai_analyzer import (
    _is_available,
    _call_deepseek,
    _extract_json,
)

log = get_logger("ai_triage")


TRIAGE_SYSTEM_PROMPT = """You are a senior bug bounty triager (HackerOne, Bugcrowd, Synack).

Given a security finding, decide:
1. Is it EXPLOITABLE in practice? (not theoretical)
2. Would a bug bounty program accept it? (in scope, impactful)
3. What's the REAL CVSS score after verification?
4. Priority: 1 (urgent) to 10 (low)

Return JSON ONLY:
{
  "exploitability_score": 0-100,
  "bugbounty_worthy": true/false,
  "real_cvss": 0.0-10.0,
  "publish_priority": 1-10,
  "reason": "concise 1-2 line explanation",
  "category": "confirmed_vuln | theoretical | config | info | false_positive"
}

Guidelines:
- Static-file findings (CSS/JS/image URLs) → false_positive
- Missing header without exploit → config (bugbounty_worthy: false)
- Reflected XSS with proof → confirmed_vuln (exploitability: 70-95)
- DOM XSS static match (no proof) → theoretical (exploitability: 20-40)
- SQLi with real delay (5s+) → confirmed_vuln (exploitability: 85-100)
- Time-based SQLi single-shot → theoretical
- Open ports on production → config (unless dangerous like 3306)
- CORS misconfig with credentials → confirmed (if Origin reflected)

Be strict. Reject noise.
"""


def _triage_one(finding: dict) -> dict:
    """Score one finding."""
    # Build a compact prompt
    f_info = {
        "title": finding.get("title", "")[:150],
        "category": finding.get("category", ""),
        "severity": finding.get("severity", "info"),
        "url": finding.get("url", "")[:200],
        "param": finding.get("param", "")[:50],
        "payload": str(finding.get("payload", ""))[:200],
        "evidence": str(finding.get("evidence", ""))[:300],
    }

    prompt = (
        "Finding details:\n"
        + json.dumps(f_info, ensure_ascii=False, indent=2)
        + "\n\nReturn JSON only."
    )

    response = _call_deepseek(
        TRIAGE_SYSTEM_PROMPT,
        prompt,
        timeout=60,
        max_tokens=800,
        json_mode=True,
    )

    if not response:
        return _default_triage(finding)

    data = _extract_json(response)
    if not data:
        return _default_triage(finding)

    return {
        "exploitability_score": int(data.get("exploitability_score", 50)),
        "bugbounty_worthy": bool(data.get("bugbounty_worthy", False)),
        "real_cvss": float(data.get("real_cvss", 0)),
        "publish_priority": int(data.get("publish_priority", 5)),
        "reason": data.get("reason", "")[:300],
        "category": data.get("category", "unknown"),
    }


def _default_triage(finding: dict) -> dict:
    """Fallback scoring without AI."""
    sev = (finding.get("severity") or "info").lower()
    map_score = {
        "critical": (85, True, 9.0, 1),
        "high":     (70, True, 7.5, 3),
        "medium":   (45, False, 5.0, 6),
        "low":      (25, False, 3.0, 8),
        "info":     (10, False, 1.0, 10),
    }
    score, worthy, cvss, prio = map_score.get(sev, (10, False, 1.0, 10))
    return {
        "exploitability_score": score,
        "bugbounty_worthy": worthy,
        "real_cvss": cvss,
        "publish_priority": prio,
        "reason": "Default heuristic (AI unavailable)",
        "category": "theoretical",
    }


def run(client, config, findings=None, max_findings=30):
    """Run AI Triage on findings list."""
    if not _is_available():
        log.warning("AI not available — using heuristic triage")

    findings = findings or config.get("_ai_enriched") or config.get("findings") or []
    if not findings:
        log.info("AI Triage: no findings to triage")
        return {"triaged": 0, "items": []}

    # Take top N by severity (skip info)
    to_triage = [f for f in findings if (f.get("severity") or "info").lower() != "info"]
    to_triage = to_triage[:max_findings]

    log.info(f"AI Triage: scoring {len(to_triage)} findings...")

    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = []

    def _work(f):
        try:
            triage = _triage_one(f)
            return {**f, "_triage": triage}
        except Exception as e:
            return {**f, "_triage": _default_triage(f)}

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_work, f) for f in to_triage]
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            results.append(r)
            t = r.get("_triage", {})
            log.info(f"  [{i}/{len(to_triage)}] {t.get('category','?')[:15]:15s} | "
                     f"expl={t.get('exploitability_score',0):3d} | "
                     f"bb={'Y' if t.get('bugbounty_worthy') else 'N'} | "
                     f"{r.get('title','')[:50]}")

    # Sort by exploitability desc
    results.sort(key=lambda x: -x.get("_triage", {}).get("exploitability_score", 0))

    log.info(f"AI Triage complete: {len(results)} scored")
    return {
        "triaged": len(results),
        "items": results,
    }
