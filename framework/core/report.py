"""Falcon MAG Framework - Report Generator (JSON + Markdown + Excel)"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

FRAMEWORK_DIR = Path(__file__).resolve().parent.parent


# ============================================================
# Findings extraction
# ============================================================
def _get_module_result(results: dict, module_name: str) -> dict:
    """Get a module's result from either flat or nested (module_results) structure."""
    # Try nested first (actual cli.py structure)
    mr = results.get("module_results")
    if isinstance(mr, dict) and module_name in mr:
        val = mr[module_name]
        if isinstance(val, dict):
            return val
    # Fallback: flat (legacy)
    val = results.get(module_name)
    if isinstance(val, dict):
        return val
    return {}


def extract_findings(results: dict) -> List[dict]:
    """Extract all findings from all modules into a unified list.

    Every finding gets these unified keys:
      - url           : the primary URL shown in reports (injected URL if available)
      - original_url  : the clean URL without payload
      - injected_url  : the URL with payload (PoC)
      - param         : parameter name (if applicable)
      - payload       : the actual payload used (if applicable)
      - evidence      : textual proof
    """
    findings = []

    # ----------------------------------------------------------
    # Helper: pick the best URL to show (injected > test_url > url)
    # ----------------------------------------------------------
    def _pick_urls(v: dict) -> tuple:
        original = v.get("url", "") or v.get("original_url", "")
        injected = (v.get("injected_url")
                    or v.get("test_url")
                    or v.get("poc_url")
                    or original)
        primary = injected or original
        return primary, original, injected

    # ==========================================================
    # XSS
    # ==========================================================
    for v in _get_module_result(results, "xss_scanner").get("vulnerable", []):
        primary, original, injected = _pick_urls(v)
        findings.append({
            "severity": "high",
            "title": f"Reflected XSS in '{v.get('param', '')}'",
            "description": (f"Parameter '{v.get('param')}' reflects user input "
                            f"without encoding in context '{v.get('context_type', 'html')}'."),
            "evidence": (f"Payload: {v.get('payload')}\n"
                         f"Context type: {v.get('context_type', 'N/A')}\n"
                         f"Before: {v.get('context_before', '')[:120]}\n"
                         f"After:  {v.get('context_after', '')[:120]}"),
            "url": primary,
            "original_url": original,
            "injected_url": injected,
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "XSS",
        })

    # ==========================================================
    # SQLi
    # ==========================================================
    for v in _get_module_result(results, "sqli_scanner").get("vulnerable", []):
        primary, original, injected = _pick_urls(v)
        findings.append({
            "severity": "critical",
            "title": f"SQL Injection in '{v.get('param', '')}' ({v.get('type', '')})",
            "description": f"Parameter '{v.get('param')}' is vulnerable to SQL injection.",
            "evidence": (f"Payload: {v.get('payload')}\n"
                         f"Type: {v.get('type')}\n"
                         f"DB Error: {v.get('db_error', 'N/A')}\n"
                         f"Delay: {v.get('delay_ms', 'N/A')} ms"),
            "url": primary,
            "original_url": original,
            "injected_url": injected,
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "SQLi",
        })

    # ==========================================================
    # NoSQL
    # ==========================================================
    for v in _get_module_result(results, "nosql_scanner").get("vulnerable", []):
        primary, original, injected = _pick_urls(v)
        findings.append({
            "severity": "high",
            "title": f"NoSQL Injection in '{v.get('param', '')}'",
            "description": "NoSQL operator injection detected.",
            "evidence": (f"Payload: {v.get('payload')}\n"
                         f"Operator: {v.get('operator', 'N/A')}"),
            "url": primary,
            "original_url": original,
            "injected_url": injected,
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "NoSQL",
        })

    # ==========================================================
    # CSRF
    # ==========================================================
    csrf = _get_module_result(results, "csrf_checker")
    for form in csrf.get("vulnerable_forms", []):
        action = form.get("action", "")
        findings.append({
            "severity": "medium",
            "title": "CSRF: Missing anti-CSRF token in form",
            "description": f"Form at {action} has no anti-CSRF token.",
            "evidence": (f"Action: {action}\n"
                         f"Method: {form.get('method')}\n"
                         f"Fields: {', '.join(form.get('fields', []) or [])}"),
            "url": action,
            "original_url": action,
            "injected_url": action,
            "param": "",
            "payload": "",
            "category": "CSRF",
        })

    # ==========================================================
    # Clickjacking
    # ==========================================================
    cj = _get_module_result(results, "clickjacking")
    if cj.get("vulnerable"):
        url = cj.get("url", results.get("target", ""))
        findings.append({
            "severity": "medium",
            "title": "Clickjacking: missing X-Frame-Options / CSP frame-ancestors",
            "description": "Page can be embedded in an iframe.",
            "evidence": (f"X-Frame-Options: {cj.get('x_frame_options', 'MISSING')}\n"
                         f"CSP: {cj.get('csp', 'MISSING')}\n"
                         f"Status: {cj.get('status', 'N/A')}"),
            "url": url,
            "original_url": url,
            "injected_url": url,
            "param": "",
            "payload": "",
            "category": "Clickjacking",
        })

    # Cookies - vulnerable is a LIST of findings
    for v in _get_module_result(results, "cookies_checker").get("vulnerable", []):
        url = v.get("url", results.get("target", ""))
        findings.append({
            "severity": v.get("severity", "low"),
            "title": "Insecure cookie: " + v.get("param", ""),
            "description": v.get("description", "Cookie missing security flags"),
            "evidence": "Cookie: " + v.get("param", ""),
            "url": url,
            "original_url": v.get("original_url", url),
            "injected_url": v.get("injected_url", url),
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "Cookies",
        })

    # Rate Limit - vulnerable is a LIST of findings
    for v in _get_module_result(results, "rate_limit_test").get("vulnerable", []):
        url = v.get("url", results.get("target", ""))
        findings.append({
            "severity": v.get("severity", "low"),
            "title": "No rate limiting detected",
            "description": v.get("description", "Server does not enforce rate limits"),
            "evidence": "No 429 responses received",
            "url": url,
            "original_url": v.get("original_url", url),
            "injected_url": v.get("injected_url", url),
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "RateLimit",
        })

    # DOM XSS - vulnerable is a LIST of findings
    for v in _get_module_result(results, "dom_xss_scanner").get("vulnerable", []):
        url = v.get("url", results.get("target", ""))
        findings.append({
            "severity": v.get("severity", "high"),
            "title": "DOM XSS risk: " + v.get("param", ""),
            "description": v.get("description", "Potential DOM XSS"),
            "evidence": v.get("evidence", ""),
            "url": url,
            "original_url": v.get("original_url", url),
            "injected_url": v.get("injected_url", url),
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "DOM-XSS",
        })

    # ==========================================================
    # CORS - vulnerable is a LIST of findings
    cors = _get_module_result(results, "cors_checker")
    cors_vuln = cors.get("vulnerable", [])
    if isinstance(cors_vuln, dict):
        cors_vuln = [cors_vuln]
    for v in cors_vuln:
        url = v.get("url", results.get("target", ""))
        findings.append({
            "severity": v.get("severity", "high"),
            "title": "CORS Misconfiguration",
            "description": v.get("description", "Origin reflected with credentials"),
            "evidence": (
                "Evil Origin: " + str(v.get("evil_origin", "")) + "\n"
                + "ACAO: " + str(v.get("acao", "")) + "\n"
                + "ACAC: " + str(v.get("acac", ""))
            ),
            "url": url,
            "original_url": v.get("original_url", url),
            "injected_url": v.get("injected_url", url),
            "param": v.get("param", "Origin"),
            "payload": v.get("payload", ""),
            "category": "CORS",
        })

    # ==========================================================
    # JS Secrets
    # ==========================================================
    for s in _get_module_result(results, "js_analyzer").get("secrets", []):
        file_url = s.get("file", "")
        findings.append({
            "severity": "high",
            "title": f"Hardcoded secret in JS: {s.get('type')}",
            "description": f"Secret found in {file_url}",
            "evidence": (f"Type: {s.get('type')}\n"
                         f"Value preview: {s.get('value', '')[:120]}"),
            "url": file_url,
            "original_url": file_url,
            "injected_url": file_url,
            "param": "",
            "payload": s.get("value", "")[:120],
            "category": "Secrets",
        })

    # ==========================================================
    # Missing Security Headers (Info)
    # ==========================================================
    fp = _get_module_result(results, "fingerprint")
    for h in fp.get("missing_headers", []):
        url = fp.get("target", results.get("target", ""))
        findings.append({
            "severity": "low",
            "title": f"Missing security header: {h}",
            "description": f"The HTTP response is missing the '{h}' header.",
            "evidence": f"Header '{h}' not present in response",
            "url": url,
            "original_url": url,
            "injected_url": url,
            "param": "",
            "payload": "",
            "category": "Headers",
        })

    # ==========================================================
    # TLS weak protocols
    # ==========================================================
    tls = _get_module_result(results, "tls_checker")
    for proto in tls.get("weak_protocols", []):
        url = tls.get("target", results.get("target", ""))
        findings.append({
            "severity": "medium",
            "title": f"Weak TLS protocol: {proto}",
            "description": f"Server supports deprecated protocol {proto}.",
            "evidence": (f"Protocol: {proto}\n"
                         f"Host: {tls.get('host', '')}:{tls.get('port', '')}"),
            "url": url,
            "original_url": url,
            "injected_url": url,
            "param": "",
            "payload": "",
            "category": "TLS",
        })

    # ==========================================================
    # Open ports
    # ==========================================================
    for port in _get_module_result(results, "port_scanner").get("open_ports", []):
        host = results.get("target", "")
        sev = "info"
        if port.get("port") in (22, 3306, 5432, 6379, 27017):
            sev = "medium"
        findings.append({
            "severity": sev,
            "title": f"Open port: {port.get('port')} ({port.get('service', '')})",
            "description": f"Port {port.get('port')} is open on {host}.",
            "evidence": (f"Service: {port.get('service', '')}\n"
                         f"Version: {port.get('version', '')}\n"
                         f"Banner: {port.get('banner', '')[:120]}"),
            "url": f"{host}:{port.get('port')}",
            "original_url": host,
            "injected_url": f"{host}:{port.get('port')}",
            "param": "",
            "payload": "",
            "category": "Ports",
        })

    # ==========================================================
    # Open Redirect
    # ==========================================================
    for v in _get_module_result(results, "open_redirect").get("vulnerable", []):
        primary, original, injected = _pick_urls(v)
        findings.append({
            "severity": "medium",
            "title": f"Open Redirect in '{v.get('param', '')}'",
            "description": "Parameter redirects to attacker-controlled URL.",
            "evidence": (f"Payload: {v.get('payload')}\n"
                         f"Redirect to: {v.get('redirect_to', '')}"),
            "url": primary,
            "original_url": original,
            "injected_url": injected,
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "OpenRedirect",
        })

    # ==========================================================
    # Path Traversal
    # ==========================================================
    for v in _get_module_result(results, "path_traversal").get("vulnerable", []):
        primary, original, injected = _pick_urls(v)
        findings.append({
            "severity": "high",
            "title": f"Path Traversal in '{v.get('param', '')}'",
            "description": "Parameter is vulnerable to path traversal.",
            "evidence": (f"Payload: {v.get('payload')}\n"
                         f"Signature: {v.get('signature', '')}"),
            "url": primary,
            "original_url": original,
            "injected_url": injected,
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "PathTraversal",
        })

    # ==========================================================
    # SSRF
    # ==========================================================
    for v in _get_module_result(results, "ssrf_scanner").get("vulnerable", []):
        primary, original, injected = _pick_urls(v)
        findings.append({
            "severity": "high",
            "title": f"SSRF in '{v.get('param', '')}'",
            "description": "Parameter allows server-side request forgery.",
            "evidence": (f"Payload: {v.get('payload')}\n"
                         f"Evidence: {v.get('evidence', '')}"),
            "url": primary,
            "original_url": original,
            "injected_url": injected,
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "SSRF",
        })

    # ==========================================================
    # IDOR
    # ==========================================================
    for v in _get_module_result(results, "idor_scanner").get("vulnerable", []):
        primary, original, injected = _pick_urls(v)
        findings.append({
            "severity": "high",
            "title": f"Potential IDOR in '{v.get('param', '')}'",
            "description": "Parameter may expose other users' data.",
            "evidence": (f"Original ID: {v.get('original_id')}\n"
                         f"Tested ID: {v.get('tested_id')}\n"
                         f"Similarity: {v.get('similarity', 'N/A')}"),
            "url": primary,
            "original_url": original,
            "injected_url": injected,
            "param": v.get("param", ""),
            "payload": str(v.get("tested_id", "")),
            "category": "IDOR",
        })

    # ==========================================================
    # Prototype Pollution
    # ==========================================================
    for v in _get_module_result(results, "prototype_pollution").get("vulnerable", []):
        primary, original, injected = _pick_urls(v)
        findings.append({
            "severity": "high",
            "title": f"Prototype Pollution in '{v.get('param', '')}'",
            "description": "Parameter pollutes Object.prototype.",
            "evidence": (f"Payload: {v.get('payload')}\n"
                         f"Evidence: {v.get('evidence', '')}"),
            "url": primary,
            "original_url": original,
            "injected_url": injected,
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "category": "PrototypePollution",
        })

    # ==========================================================
    # HTTP Methods
    # ==========================================================
    for m in _get_module_result(results, "http_methods").get("dangerous", []):
        url = results.get("target", "")
        findings.append({
            "severity": "medium",
            "title": f"Dangerous HTTP method enabled: {m.get('method', '')}",
            "description": f"Server responds to {m.get('method', '')}.",
            "evidence": (f"Method: {m.get('method')}\n"
                         f"Status: {m.get('status')}"),
            "url": url,
            "original_url": url,
            "injected_url": url,
            "param": "",
            "payload": m.get("method", ""),
            "category": "HTTPMethods",
        })

    # ==========================================================
    # Cookies
    # ==========================================================
    for c in _get_module_result(results, "cookies_checker").get("insecure", []):
        url = results.get("target", "")
        missing = ", ".join(c.get("missing_flags", []))
        findings.append({
            "severity": "low",
            "title": f"Insecure cookie: {c.get('name', '')}",
            "description": f"Cookie missing: {missing}",
            "evidence": (f"Name: {c.get('name')}\n"
                         f"Missing flags: {missing}\n"
                         f"Value preview: {str(c.get('value', ''))[:60]}"),
            "url": url,
            "original_url": url,
            "injected_url": url,
            "param": c.get("name", ""),
            "payload": "",
            "category": "Cookies",
        })

    # ==========================================================
    # Subdomains found
    # ==========================================================
    for s in _get_module_result(results, "subdomain_enum").get("found", []):
        url = results.get("target", "")
        findings.append({
            "severity": "info",
            "title": f"Subdomain discovered: {s}",
            "description": "Subdomain found via enumeration.",
            "evidence": f"Subdomain: {s}",
            "url": url,
            "original_url": url,
            "injected_url": f"https://{s}",
            "param": "",
            "payload": "",
            "category": "Subdomains",
        })

    # ==========================================================
    # CVEs
    # ==========================================================
    for cve in _get_module_result(results, "cve_lookup").get("cves", []):
        url = results.get("target", "")
        findings.append({
            "severity": cve.get("severity", "info"),
            "title": f"{cve.get('id', 'CVE')}: {cve.get('tech', '')}",
            "description": cve.get("description", ""),
            "evidence": (f"CVSS: {cve.get('cvss', 'N/A')}\n"
                         f"Reference: {cve.get('url', '')}"),
            "url": cve.get("url", url),
            "original_url": url,
            "injected_url": cve.get("url", url),
            "param": "",
            "payload": "",
            "category": "CVE",
        })

    # ==========================================================
    # Path discovery (real paths only)
    # ==========================================================
    for p in _get_module_result(results, "path_discovery").get("real_paths", []):
        if p.get("status") in (200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 500):
            full_url = p.get("url") or (results.get("target", "").rstrip("/") + p.get("path", ""))
            findings.append({
                "severity": "info",
                "title": f"Interesting path: {p.get('path')} ({p.get('status')})",
                "description": f"Path returned HTTP {p.get('status')}",
                "evidence": (f"Status: {p.get('status')}\n"
                             f"Size: {p.get('size')} bytes\n"
                             f"Type: {p.get('type', 'other')}"),
                "url": full_url,
                "original_url": results.get("target", ""),
                "injected_url": full_url,
                "param": "",
                "payload": "",
                "category": "Paths",
            })

    # ==========================================================
    # Merge AI enrichment (if present)
    # ==========================================================
    ai_enriched = results.get("_ai_enriched", [])
    if ai_enriched:
        # Build a lookup keyed by injected_url (most reliable)
        # Fallback to (url, param) if injected_url missing
        ai_map = {}
        for ai_f in ai_enriched:
            key = ai_f.get("injected_url") or ai_f.get("test_url") or ai_f.get("url", "")
            param = ai_f.get("param", "")
            ai_map[(key, param)] = ai_f
            # Also key by (url, param) for safety
            url_key = ai_f.get("url", "")
            if url_key and url_key != key:
                ai_map[(url_key, param)] = ai_f
        # Merge into findings
        for f in findings:
            key = f.get("injected_url") or f.get("url", "")
            param = f.get("param", "")
            ai_f = ai_map.get((key, param))
            if not ai_f:
                # Try with original_url
                orig = f.get("original_url", "")
                ai_f = ai_map.get((orig, param))
            if not ai_f:
                # Try with url only
                u = f.get("url", "")
                ai_f = ai_map.get((u, param))
            if ai_f:
                f["ai_poc_url"] = ai_f.get("ai_poc_url", "")
                f["ai_explanation_ar"] = ai_f.get("ai_explanation_ar", "")
                f["ai_attack_walkthrough_ar"] = ai_f.get("ai_attack_walkthrough_ar", "")
                f["ai_poc_code"] = ai_f.get("ai_poc_code", "")
                f["ai_remediation_ar"] = ai_f.get("ai_remediation_ar", "")
                f["ai_remediation_code"] = ai_f.get("ai_remediation_code", "")
                f["ai_cvss_score"] = ai_f.get("ai_cvss_score", 0)
                f["ai_cvss_vector"] = ai_f.get("ai_cvss_vector", "")
                f["ai_severity"] = ai_f.get("ai_severity", f.get("severity", "info"))
                f["ai_priority"] = ai_f.get("ai_priority", 99)
                f["ai_references"] = ai_f.get("ai_references", [])
                f["ai_analyzed"] = True

    return findings


# ============================================================
# JSON
# ============================================================
def save_json(results: dict, base_path: str) -> str:
    path = base_path + ".json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    return path


# ============================================================
# Markdown

# ============================================================
# Markdown (AI-enhanced Arabic)

# ============================================================
# Markdown (AI-enhanced Arabic)
# ============================================================
def save_markdown(results: dict, findings: List[dict], base_path: str,
                  target: str) -> str:
    """Generate an Arabic-AI-enhanced Markdown report."""
    path = base_path + ".md"
    lines = []

    # === Header ===
    lines.append("# 🦅 Falcon MAG — تقرير تقييم أمني\n")
    lines.append(f"- **الهدف:** `{target}`")
    lines.append(f"- **التاريخ:** {results.get('timestamp', '')}")
    lines.append(f"- **المدة:** {results.get('duration', 0)}s")
    lines.append(f"- **عدد الطلبات:** {results.get('http_requests_count', 0)}")
    lines.append(f"- **الوحدات المشغّلة:** {', '.join(results.get('modules_run', []))}")
    lines.append("")
    lines.append("---\n")

    # === AI Executive Summary ===
    ai_summary = results.get("_ai_summary", "")
    if ai_summary:
        lines.append("## 📋 الملخص التنفيذي (AI)\n")
        lines.append(ai_summary)
        lines.append("\n---\n")

    # === Summary by severity ===
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    lines.append("## 📊 ملخص الثغرات\n")
    if not findings:
        lines.append("لم يتم تأكيد أي ثغرات.\n")
    else:
        lines.append(f"**إجمالي الثغرات: {len(findings)}**\n")
        sev_ar = {
            "critical": "🔴 حرجة",
            "high": "🟠 عالية",
            "medium": "🟡 متوسطة",
            "low": "🟢 منخفضة",
            "info": "🔵 معلوماتية",
        }
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_sev:
                lines.append(f"- {sev_ar[sev]}: {by_sev[sev]}")
        lines.append("")

    lines.append("---\n")
    lines.append("## 🔍 الثغرات\n")

    # === Findings ===
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").upper()
        title = f.get("title", "")
        category = f.get("category", "N/A")

        lines.append(f"### {i}. [{sev}] {title}\n")
        lines.append(f"**التصنيف:** {category}\n")

        # --- CVSS + Priority (from AI) ---
        cvss = f.get("ai_cvss_score", 0)
        cvss_vec = f.get("ai_cvss_vector", "")
        priority = f.get("ai_priority", "")
        if cvss:
            lines.append(f"**🎯 CVSS:** {cvss}")
            if cvss_vec:
                lines.append(f"  \n**Vector:** `{cvss_vec}`")
            if priority != "":
                lines.append(f"  \n**⚠️ الأولوية:** {priority}")
            lines.append("")

        # --- PoC URL ---
        poc_url = f.get("ai_poc_url", "") or f.get("injected_url", "") or f.get("url", "")
        original = f.get("original_url") or f.get("url", "")

        if poc_url:
            lines.append("**🔗 رابط PoC (انسخه في المتصفح):**\n")
            lines.append(f"```\n{poc_url}\n```\n")
            if original and original != poc_url:
                lines.append(f"**الرابط الأصلي:** `{original}`\n")

        # --- Param + Payload ---
        if f.get("param"):
            lines.append(f"**📌 الباراميتر:** `{f['param']}`\n")
        if f.get("payload"):
            payload = str(f["payload"]).replace("`", "\\`")
            lines.append(f"**💉 الحمولة:** `{payload}`\n")

        # --- AI Explanation ---
        ai_explanation = f.get("ai_explanation_ar", "")
        if ai_explanation:
            lines.append("**📝 الشرح:**\n")
            lines.append(ai_explanation)
            lines.append("")

        # --- AI Attack Walkthrough ---
        ai_walk = f.get("ai_attack_walkthrough_ar", "")
        if ai_walk:
            lines.append("**🎬 خطوات الاستغلال:**\n")
            lines.append(ai_walk)
            lines.append("")

        # --- AI PoC Code ---
        ai_poc = f.get("ai_poc_code", "")
        if ai_poc:
            lines.append("**💻 كود PoC (جاهز للتنفيذ):**\n")
            # ai_poc usually already wrapped in ```python ... ```
            lines.append(ai_poc)
            lines.append("")

        # --- AI Remediation ---
        ai_rem = f.get("ai_remediation_ar", "")
        if ai_rem:
            lines.append("**🛠️ الإصلاح:**\n")
            lines.append(ai_rem)
            lines.append("")

        # --- AI Remediation Code ---
        ai_rem_code = f.get("ai_remediation_code", "")
        if ai_rem_code:
            lines.append("**🛠️ كود الإصلاح:**\n")
            lines.append(ai_rem_code)
            lines.append("")

        # --- AI References ---
        ai_refs = f.get("ai_references", []) or []
        if ai_refs:
            lines.append("**📚 المراجع:**\n")
            for ref in ai_refs:
                lines.append(f"- {ref}")
            lines.append("")

        # --- Fallback: description + evidence ---
        if not ai_explanation:
            lines.append(f"**الوصف:**\n{f.get('description', '')}\n")
        if f.get("evidence"):
            lines.append("**🔬 الدليل:**\n")
            lines.append(f"```\n{f.get('evidence', '')}\n```\n")

        lines.append("---\n")

    # === Appendix ===
    lines.append("## 📎 ملحق\n")
    lines.append("### بصمة الهدف\n")
    fp = _get_module_result(results, "fingerprint")
    lines.append(f"- **Server:** `{fp.get('server', 'N/A')}`")
    lines.append(f"- **Powered By:** `{fp.get('powered_by', 'N/A')}`")
    lines.append(f"- **Technologies:** {', '.join(fp.get('technologies', []))}")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def save_excel(results: dict, findings: List[dict], base_path: str,
               target: str) -> str:
    """Generate an Excel report."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.utils import get_column_letter
    except ImportError:
        return ""

    path = base_path + ".xlsx"
    wb = Workbook()

    # ----- Sheet 1: Summary -----
    ws = wb.active
    ws.title = "Summary"
    ws.sheet_view.rightToLeft = True

    title_font = Font(name="Segoe UI", size=16, bold=True, color="DC2626")
    header_font = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
    normal = Font(name="Segoe UI", size=10)
    header_fill = PatternFill("solid", fgColor="0A0014")

    ws["A1"] = "Falcon MAG - Security Report"
    ws["A1"].font = title_font
    ws.merge_cells("A1:B1")

    # severity counter
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    rows = [
        ("Target", target),
        ("Generated", results.get("timestamp", "")),
        ("Duration (s)", results.get("duration", 0)),
        ("Requests", results.get("http_requests_count", 0)),
        ("Total Findings", len(findings)),
        ("", ""),
        ("🔴 Critical", sev_counts["critical"]),
        ("🟠 High", sev_counts["high"]),
        ("🟡 Medium", sev_counts["medium"]),
        ("🟢 Low", sev_counts["low"]),
        ("🔵 Info", sev_counts["info"]),
    ]
    for i, (k, v) in enumerate(rows, 3):
        ws.cell(i, 1, k).font = Font(name="Segoe UI", size=10, bold=True)
        ws.cell(i, 2, str(v)).font = normal

    ws.column_dimensions["A"].width = 20
    ws.column_dimensions["B"].width = 60

    # ----- Sheet 2: Findings -----
    ws2 = wb.create_sheet("Findings")
    ws2.sheet_view.rightToLeft = True

    headers = ["#", "Severity", "Category", "Title",
               "Injected URL (PoC)", "Original URL", "Param", "Payload", "Evidence"]
    for c, h in enumerate(headers, 1):
        cell = ws2.cell(1, c, h)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    # Severity colors
    sev_colors = {
        "critical": "DC2626",
        "high":     "EA580C",
        "medium":   "CA8A04",
        "low":      "16A34A",
        "info":     "2563EB",
    }

    for i, f in enumerate(findings, 1):
        row = i + 1

        ws2.cell(row, 1, i).font = normal

        sev_cell = ws2.cell(row, 2, f["severity"])
        sev_cell.font = Font(name="Segoe UI", size=10, bold=True,
                             color=sev_colors.get(f["severity"], "000000"))
        sev_cell.alignment = Alignment(horizontal="center", vertical="center")

        ws2.cell(row, 3, f.get("category", "")).font = normal
        ws2.cell(row, 4, f["title"]).font = normal

        # Injected URL (highlighted)
        injected = f.get("injected_url") or f.get("url", "")
        url_cell = ws2.cell(row, 5, injected)
        url_cell.font = Font(name="Consolas", size=9, color="0563C1", underline="single")
        url_cell.alignment = Alignment(wrap_text=True, vertical="top")

        # Original URL
        orig_cell = ws2.cell(row, 6, f.get("original_url", ""))
        orig_cell.font = Font(name="Consolas", size=9, color="666666")
        orig_cell.alignment = Alignment(wrap_text=True, vertical="top")

        # Param
        ws2.cell(row, 7, f.get("param", "")).font = Font(name="Consolas", size=9)

        # Payload
        pay_cell = ws2.cell(row, 8, str(f.get("payload", ""))[:200])
        pay_cell.font = Font(name="Consolas", size=9, color="DC2626")
        pay_cell.alignment = Alignment(wrap_text=True, vertical="top")

        # Evidence
        ev_cell = ws2.cell(row, 9, f.get("evidence", "")[:500])
        ev_cell.font = normal
        ev_cell.alignment = Alignment(wrap_text=True, vertical="top")

        # Row height
        ws2.row_dimensions[row].height = 42

    widths = [5, 11, 14, 45, 60, 45, 12, 30, 50]
    for c, w in enumerate(widths, 1):
        ws2.column_dimensions[get_column_letter(c)].width = w

    ws2.freeze_panes = "A2"
    if findings:
        ws2.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{len(findings) + 1}"

    wb.save(path)
    return path


# ============================================================
# Main entry
# ============================================================
def generate_reports(results: dict, config: dict) -> Dict[str, str]:
    """Generate all requested report formats."""
    output_dir = Path(config.get("output", {}).get("directory", "output/"))
    if not output_dir.is_absolute():
        output_dir = FRAMEWORK_DIR / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = str(output_dir / f"scan_{ts}")

    # Reuse AI-enriched findings if present, otherwise extract fresh
    if results.get("_ai_enriched"):
        findings = results["_ai_enriched"]
        results["findings"] = findings
    else:
        findings = extract_findings(results)
        results["findings"] = findings

    target = config.get("target", "")
    paths = {}

    fmt = config.get("output", {}).get("format", "all")

    if fmt in ("json", "all"):
        paths["json"] = save_json(results, base)
    if fmt in ("md", "all"):
        paths["md"] = save_markdown(results, findings, base, target)
    if fmt in ("excel", "all"):
        p = save_excel(results, findings, base, target)
        if p:
            paths["excel"] = p

    return paths