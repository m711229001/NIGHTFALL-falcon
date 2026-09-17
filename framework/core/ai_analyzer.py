"""Falcon MAG Framework - AI Analyzer (DeepSeek)

Analyzes scan findings with DeepSeek AI. For each finding, generates:
  - Arabic explanation (what, why)
  - Attack walkthrough (step-by-step exploitation)
  - Working PoC code (Python / curl / Bash / HTML)
  - CVSS score + vector
  - Remediation with code snippets
  - Priority score

Also generates Arabic Executive Summary for the whole scan.
"""

import os
import json
import time
from typing import List, Dict, Optional
from core.logger import get_logger

log = get_logger("ai")

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"


# ============================================================
# Configuration
# ============================================================
def _get_api_key() -> str:
    """Get DeepSeek API key from env or config.yaml."""
    key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if key:
        return key
    try:
        import yaml
        with open("config.yaml", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return (cfg.get("ai", {}).get("deepseek_api_key", "") or "").strip()
    except Exception:
        return ""


def _is_available() -> bool:
    return HTTPX_AVAILABLE and bool(_get_api_key())


# ============================================================
# DeepSeek API call
# ============================================================
def _call_deepseek(system_prompt: str, user_prompt: str,
                   timeout: int = 120, max_tokens: int = 4000) -> Optional[str]:
    """Send prompt to DeepSeek and return response."""
    api_key = _get_api_key()
    if not api_key:
        log.warning("No DeepSeek API key")
        return None

    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.3,
        "max_tokens": max_tokens,
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(DEEPSEEK_API_URL, headers=headers, json=payload)
            if resp.status_code != 200:
                log.warning("DeepSeek API error: " + str(resp.status_code))
                log.debug("Response: " + resp.text[:500])
                return None
            data = resp.json()
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        log.warning("DeepSeek call failed: " + str(e))
        return None


def _extract_json(text: str) -> Optional[dict]:
    """Extract JSON object from AI response (handles markdown fences)."""
    if not text:
        return None
    # Remove markdown code fences
    text = text.strip()
    if text.startswith("```"):
        # Remove first line
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)

    # Find first { and last }
    start = text.find("{")
    end = text.rfind("}") + 1
    if start < 0 or end <= start:
        return None

    try:
        return json.loads(text[start:end])
    except Exception:
        return None


# ============================================================
# Finding analysis
# ============================================================
SYSTEM_PROMPT = """أنت خبير أمن سيبراني محترف (OSCP, OSWE, Bug Bounty Hunter).
مهمتك: تحليل ثغرة أمنية واحدة وإرجاع JSON بالعربية.

يجب أن تُرجع JSON فقط، بدون أي نص قبله أو بعده، بالصيغة:
{
  "poc_url": "الرابط الكامل مع الحمولة (injected_url) — يجب أن يكون جاهزاً للنسخ واللصق في المتصفح أو curl",
  "explanation_ar": "شرح تفصيلي بالعربية: ما هي الثغرة، لماذا تحدث، لماذا خطيرة",
  "attack_walkthrough_ar": "شرح خطوة بخطوة لكيفية استغلال الثغرة بنجاح (نقاط مرقمة)",
  "poc_code": "كود PoC كامل جاهز للتنفيذ (Python مفضّل). يجب أن يستخدم `poc_url` مباشرة كـ TARGET. ضع الكود داخل ```python ... ```.",
  "poc_language": "python",
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "severity": "high",
  "remediation_ar": "الإصلاح بالتفصيل مع كود أمثلة",
  "remediation_code": "```python ... ``` كود الإصلاح",
  "priority": 1,
  "references": ["https://owasp.org/...", "https://cve.mitre.org/..."]
}

القواعد الصارمة:
- poc_url: انسخ injected_url حرفياً من المُدخل. لا تعدّل عليه.
- poc_code: الكود يجب أن يستخدم poc_url أعلاه مباشرة. لا تضع "example.com" أو "TARGET = 'https://example.com'". استخدم الرابط الكامل الحقيقي.
- مثال على PoC URL: https://target.com/api?url=https://evil.com
- مثال على كود صحيح:
  ```python
  import requests
  POC_URL = "https://target.com/api?url=https://evil.com"
  r = requests.get(POC_URL, verify=False)
  print(r.status_code)
  print(r.text[:500])

القواعد:
- explanation_ar: 3-5 أسطر
- attack_walkthrough_ar: 5-10 نقاط مرقمة
- poc_code: كود Python كامل (imports + main) قابل للتشغيل
- cvss_score: رقم من 0.0 إلى 10.0
- severity: critical / high / medium / low / info
- priority: 1 (الأعلى) إلى 10
- references: 2-4 روابط
"""


def analyze_finding(finding: dict) -> dict:
    """Enrich one finding with AI analysis."""
    title = finding.get("title", "")
    category = finding.get("category", "")
    url = finding.get("url", "")
    original_url = finding.get("original_url", url)
    injected_url = finding.get("injected_url", "") or finding.get("test_url", "") or url
    param = finding.get("param", "")
    payload = finding.get("payload", "")
    evidence = finding.get("evidence", "")
    severity = finding.get("severity", "info")

    user_prompt = (
        "حلل الثغرة التالية وأرجع JSON:\n\n"
        "**التفاصيل:**\n"
        "- العنوان: " + title + "\n"
        "- التصنيف: " + category + "\n"
        "- الخطورة المبدئية: " + severity + "\n"
        "- **رابط PoC الكامل (استخدمه في الكود!):** " + injected_url + "\n"
        "- الرابط الأصلي: " + original_url + "\n"
        "- الباراميتر: " + str(param) + "\n"
        "- الحمولة: " + str(payload)[:300] + "\n"
        "- الدليل: " + str(evidence)[:500] + "\n\n"
        "**مهم جداً:**\n"
        "1. في حقل `ai_poc_code`، استخدم **رابط PoC الكامل** أعلاه (مع الباراميتر والحمولة) كـ TARGET_URL في الكود.\n"
        "2. أضف تعليقاً في الكود يشرح كل سطر.\n"
        "3. اجعل الكود قابلاً للتشغيل مباشرة (copy-paste-run) بدون تعديلات.\n"
        "4. أضف حقل `poc_url` في JSON يحتوي على الرابط الكامل.\n"
    )

    response = _call_deepseek(SYSTEM_PROMPT, user_prompt, timeout=180, max_tokens=4000)
    if not response:
        return finding

    ai_data = _extract_json(response)
    if not ai_data:
        log.debug("Could not extract JSON from AI response")
        return finding
    # Enrich finding
    finding["ai_poc_url"] = ai_data.get("poc_url", "") or finding.get("injected_url", "")
    finding["ai_explanation_ar"] = ai_data.get("explanation_ar", "")
    finding["ai_attack_walkthrough_ar"] = ai_data.get("attack_walkthrough_ar", "")
    finding["ai_poc_code"] = ai_data.get("poc_code", "")
    finding["ai_poc_language"] = ai_data.get("poc_language", "python")

    # Enrich finding
    finding["ai_explanation_ar"] = ai_data.get("explanation_ar", "")
    finding["ai_attack_walkthrough_ar"] = ai_data.get("attack_walkthrough_ar", "")
    finding["ai_poc_code"] = ai_data.get("poc_code", "")
    finding["ai_poc_language"] = ai_data.get("poc_language", "python")
    finding["ai_cvss_score"] = ai_data.get("cvss_score", 0)
    finding["ai_cvss_vector"] = ai_data.get("cvss_vector", "")
    finding["ai_severity"] = ai_data.get("severity", severity)
    finding["ai_remediation_ar"] = ai_data.get("remediation_ar", "")
    finding["ai_remediation_code"] = ai_data.get("remediation_code", "")
    finding["ai_priority"] = ai_data.get("priority", 99)
    finding["ai_references"] = ai_data.get("references", [])
    finding["ai_analyzed"] = True

    return finding


# ============================================================
# Batch analysis
# ============================================================
def analyze_all_findings(findings: List[dict],
                         max_findings: int = 20,
                         skip_info: bool = True) -> List[dict]:
    """Analyze all findings. Skips info/low severity by default."""
    if not _is_available():
        log.warning("AI not available")
        return findings

    # Filter by severity
    to_analyze = []
    for i, f in enumerate(findings):
        sev = f.get("severity", "info")
        if skip_info and sev in ("info", "low"):
            continue
        to_analyze.append((i, f))

    if not to_analyze:
        log.info("No findings to analyze (all info/low)")
        return findings

    to_analyze = to_analyze[:max_findings]

    log.info("AI analyzing " + str(len(to_analyze)) + " findings...")

    for n, (idx, f) in enumerate(to_analyze, 1):
        title = f.get("title", "")[:70]
        log.info("  [" + str(n) + "/" + str(len(to_analyze)) + "] " + title)
        try:
            enriched = analyze_finding(f)
            findings[idx] = enriched
        except Exception as e:
            log.warning("  Failed: " + str(e))
        time.sleep(0.3)

    analyzed_count = sum(1 for f in findings if f.get("ai_analyzed"))
    log.info("AI analysis complete: " + str(analyzed_count) + " findings enriched")

    return findings


# ============================================================
# Executive summary
# ============================================================
def generate_executive_summary(results: dict, findings: List[dict]) -> str:
    """Generate Arabic executive summary."""
    if not _is_available():
        return ""

    target = results.get("target", "")
    total = len(findings)
    by_sev = {}
    for f in findings:
        sev = f.get("severity", "info")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    # Collect top 5 finding titles
    top_titles = []
    for f in findings:
        if f.get("severity") in ("critical", "high"):
            top_titles.append("- " + f.get("title", "")[:80])
        if len(top_titles) >= 5:
            break

    prompt = (
        "الهدف: " + target + "\n"
        "إجمالي الثغرات: " + str(total) + "\n"
        "حرجة: " + str(by_sev.get("critical", 0)) + "\n"
        "عالية: " + str(by_sev.get("high", 0)) + "\n"
        "متوسطة: " + str(by_sev.get("medium", 0)) + "\n"
        "منخفضة: " + str(by_sev.get("low", 0)) + "\n"
        "معلوماتية: " + str(by_sev.get("info", 0)) + "\n\n"
        "أهم الثغرات:\n" + "\n".join(top_titles) + "\n\n"
        "اكتب ملخصاً تنفيذياً احترافياً بالعربي في 5-7 أسطر يشمل:\n"
        "1. الوضع العام\n"
        "2. أهم 3 مخاطر\n"
        "3. أهم 3 توصيات فورية\n"
        "4. تقييم عام (خطير/متوسط/منخفض)"
    )

    return _call_deepseek(
        "أنت خبير أمن سيبراني. اكتب بالعربية الفصحى المهنية. أسلوب تقارير احترافية.",
        prompt,
        timeout=120,
        max_tokens=1500,
    ) or ""


# ============================================================
# CLI test
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Falcon MAG - AI Analyzer Test")
    print("=" * 60)
    print("API key present:", bool(_get_api_key()))
    print("AI available:", _is_available())
    print()

    if not _is_available():
        print("Set DEEPSEEK_API_KEY env var first.")
        raise SystemExit(1)

    test = {
        "title": "CORS Misconfiguration",
        "category": "CORS",
        "url": "https://example.com/api/user",
        "param": "Origin",
        "payload": "https://evil.com",
        "evidence": "Access-Control-Allow-Origin: https://evil.com, Access-Control-Allow-Credentials: true",
        "severity": "high",
    }

    print("Analyzing test finding...")
    result = analyze_finding(test)
    print()
    print(json.dumps(result, indent=2, ensure_ascii=False))