"""Falcon MAG Framework - AI Analyzer (Multi-provider)

Analyzes scan findings with the active AI provider (DeepSeek / OpenAI / Claude / Gemini / etc.).

For each finding, generates:
  - Arabic explanation (what, why)
  - Attack walkthrough (step-by-step exploitation)
  - Working PoC code (Python / curl / Bash / HTML)
  - CVSS score + vector
  - Remediation with code snippets
  - Priority score

Also generates Arabic Executive Summary for the whole scan.

UPDATED 2026-09-19:
  - Provider config from ai_config_store (encrypted, set via /v2/ai-settings)
  - Legacy fallback: DEEPSEEK_API_KEY env var, config.yaml
  - Uses provider's model + base_url
  - json_mode support (response_format) for guaranteed JSON output
  - SYSTEM_PROMPT uses ''' instead of ``` to avoid Python triple-quote collision
"""

import os
import json
import time
from typing import List, Dict, Optional
from core.logger import get_logger

# ADDED 2026-09-19: AI config store integration
try:
    from core.ai_config_store import get_ai_config
    AI_CONFIG_STORE_AVAILABLE = True
except ImportError:
    AI_CONFIG_STORE_AVAILABLE = False

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
def _get_active_provider() -> Optional[Dict]:
    """
    Get active AI provider config (key, model, base_url).

    Priority:
      1. ai_config_store (encrypted store - set via UI)
      2. DEEPSEEK_API_KEY env var (legacy)
      3. config.yaml (legacy)

    Returns dict with: name, api_key, model, base_url
    """
    # 1. AI Config Store (new - preferred)
    if AI_CONFIG_STORE_AVAILABLE:
        try:
            active = get_ai_config().get_active_provider()
            if active and active.get("api_key"):
                return active
        except Exception as e:
            log.debug("ai_config_store read failed: " + str(e))

    # 2. Legacy: env var
    key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if key:
        return {
            "name": "deepseek",
            "api_key": key,
            "model": DEEPSEEK_MODEL,
            "base_url": DEEPSEEK_API_URL.replace("/chat/completions", ""),
        }

    # 3. Legacy: config.yaml
    try:
        import yaml
        with open("config.yaml", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        key = (cfg.get("ai", {}).get("deepseek_api_key", "") or "").strip()
        if key:
            return {
                "name": "deepseek",
                "api_key": key,
                "model": cfg.get("ai", {}).get("model", DEEPSEEK_MODEL),
                "base_url": cfg.get("ai", {}).get(
                    "base_url",
                    DEEPSEEK_API_URL.replace("/chat/completions", ""),
                ),
            }
    except Exception:
        pass

    return None


def _get_api_key() -> str:
    """Legacy shim - returns just the API key."""
    provider = _get_active_provider()
    return provider["api_key"] if provider else ""


def _is_available() -> bool:
    """AI is usable only if httpx is importable AND a provider key exists."""
    if not HTTPX_AVAILABLE:
        return False
    provider = _get_active_provider()
    return bool(provider and provider.get("api_key"))


# ============================================================
# DeepSeek API call
# ============================================================
def _build_chat_url(base_url: str) -> str:
    """Normalize base_url into a full /chat/completions URL."""
    base_url = (base_url or "").rstrip("/")
    if not base_url:
        return DEEPSEEK_API_URL
    if base_url.endswith("/chat/completions"):
        return base_url
    return base_url + "/chat/completions"


def _call_deepseek(system_prompt: str, user_prompt: str,
                   timeout: int = 120, max_tokens: int = 4000,
                   json_mode: bool = False) -> Optional[str]:
    """Send prompt to the active AI provider and return response."""
    provider = _get_active_provider()
    if not provider or not provider.get("api_key"):
        log.warning("No AI provider configured (check /v2/ai-settings)")
        return None

    api_key = provider["api_key"]
    model = provider.get("model") or DEEPSEEK_MODEL
    api_url = _build_chat_url(provider.get("base_url") or "")

    log.debug("AI call: provider=" + str(provider.get("name")) + " model=" + str(model))

    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.3,
        "max_tokens": max_tokens,
    }
    # DeepSeek supports JSON mode; use it when requested.
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(api_url, headers=headers, json=payload)
            if resp.status_code != 200:
                log.warning("AI API error: " + str(resp.status_code))
                log.debug("Response: " + resp.text[:500])
                return None
            data = resp.json()
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        log.warning("AI call failed: " + str(e))
        return None


def _extract_json(text: str) -> Optional[dict]:
    """Extract JSON object from AI response (handles markdown fences + nested braces)."""
    if not text:
        return None

    text = text.strip()

    # Strip markdown code fences (starts with triple-backtick)
    if text.startswith("`" * 3):
        lines = text.split("\n")
        if lines[0].startswith("`" * 3):
            lines = lines[1:]
        if lines and lines[-1].strip() == "`" * 3:
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    # Try direct parse first
    try:
        return json.loads(text)
    except Exception:
        pass

    # Find balanced JSON object (handles braces inside strings)
    start = text.find("{")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escape = False
    end = -1

    for i in range(start, len(text)):
        ch = text[i]

        if escape:
            escape = False
            continue

        if ch == "\\":
            escape = True
            continue

        if ch == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break

    if end <= start:
        return None

    try:
        return json.loads(text[start:end])
    except Exception:
        return None


# ============================================================
# Finding analysis
# ============================================================
# NOTE: We use ''' (single quotes) inside the prompt for code fences
# to avoid breaking the outer """ (double-quote) Python string.
SYSTEM_PROMPT = """أنت خبير أمن سيبراني محترف (OSCP, OSWE, Bug Bounty Hunter).
مهمتك: تحليل ثغرة أمنية واحدة وإرجاع JSON بالعربية.

يجب أن تُرجع JSON فقط، بدون أي نص قبله أو بعده، بالصيغة:
{
  "poc_url": "الرابط الكامل مع الحمولة (injected_url) — جاهز للنسخ واللصق",
  "explanation_ar": "شرح تفصيلي بالعربية: ما هي الثغرة، لماذا تحدث، لماذا خطيرة",
  "attack_walkthrough_ar": "شرح خطوة بخطوة لكيفية استغلال الثغرة (نقاط مرقمة)",
  "poc_code": "كود PoC كامل جاهز للتنفيذ (Python مفضّل) يستخدم poc_url مباشرة",
  "poc_language": "python",
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "severity": "high",
  "remediation_ar": "الإصلاح بالتفصيل مع كود أمثلة",
  "remediation_code": "كود الإصلاح",
  "priority": 1,
  "references": ["https://owasp.org/...", "https://cve.mitre.org/..."]
}

القواعد الصارمة:
- poc_url: انسخ injected_url حرفياً من المُدخل. لا تعدّل عليه.
- poc_code: الكود يجب أن يستخدم poc_url أعلاه مباشرة. لا تضع example.com.
- مثال على PoC URL: https://target.com/api?url=https://evil.com
- مثال على كود صحيح:
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

أعد JSON فقط.
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
        "1. في حقل poc_code، استخدم **رابط PoC الكامل** أعلاه كـ TARGET_URL في الكود.\n"
        "2. أضف تعليقاً في الكود يشرح كل سطر.\n"
        "3. اجعل الكود قابلاً للتشغيل مباشرة (copy-paste-run).\n"
        "4. أضف حقل poc_url في JSON يحتوي على الرابط الكامل.\n"
    )

    response = _call_deepseek(
        SYSTEM_PROMPT, user_prompt,
        timeout=180, max_tokens=4000,
        json_mode=True,
    )
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
        print("Set AI provider at /v2/ai-settings or via DEEPSEEK_API_KEY env.")
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