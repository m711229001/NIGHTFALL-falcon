"""Falcon MAG Framework - JS Secrets Scanner

Detects hardcoded secrets in JavaScript files:
  - AWS keys (AKIA...)
  - Google API keys (AIza...)
  - Stripe keys (sk_live_, pk_live_)
  - GitHub tokens (ghp_, gho_)
  - Generic API keys, tokens, passwords
  - Private keys (BEGIN RSA PRIVATE KEY)
"""

import re
from urllib.parse import urljoin
from core.logger import get_logger

log = get_logger("js_secrets")

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("AWS Secret Key", re.compile(r'aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]', re.I)),
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("Google OAuth", re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com')),
    ("Stripe Live Secret", re.compile(r'sk_live_[0-9a-zA-Z]{24,}')),
    ("Stripe Live Public", re.compile(r'pk_live_[0-9a-zA-Z]{24,}')),
    ("Stripe Test Secret", re.compile(r'sk_test_[0-9a-zA-Z]{24,}')),
    ("GitHub Token", re.compile(r'gh[pousr]_[0-9A-Za-z]{36,}')),
    ("GitLab Token", re.compile(r'glpat-[0-9A-Za-z\-_]{20,}')),
    ("Slack Token", re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}')),
    ("Twilio SID", re.compile(r'AC[a-z0-9]{32}')),
    ("SendGrid", re.compile(r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}')),
    ("Private Key", re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')),
    ("JWT Token", re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')),
    ("Generic API Key", re.compile(r'(?:api[_-]?key|apikey)[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9_\-]{16,})[\'"]', re.I)),
    ("Generic Secret", re.compile(r'(?:secret|password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9_\-!@#$%^&*]{8,})[\'"]', re.I)),
    ("Bearer Token", re.compile(r'[Bb]earer\s+[a-zA-Z0-9_\-\.]{20,}')),
]


def _scan_text(text):
    """Return list of (type, value) found."""
    found = []
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            # For patterns with capture groups, prefer group(1)
            if match.groups():
                value = match.group(1) or match.group(0)
            # Skip obvious placeholders
            lower = value.lower()
            if any(p in lower for p in ("example", "xxx", "your_", "placeholder", "changeme", "test123")):
                continue
            found.append((name, value[:200]))
    return found


def run(client, config, crawl_result=None):
    """Scan JS files for hardcoded secrets."""
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info("JS secrets scan on " + target)

    result = {
        "target": target,
        "url": target,
        "tested": 0,
        "secrets": [],
        "js_files": [],
        "vulnerable": [],
    }

    # Collect JS files from various sources
    js_files = set()

    crawl = crawl_result or config.get("_crawl_result", {}) or {}
    for f in crawl.get("js_files", []) or []:
        if isinstance(f, str):
            js_files.add(f)
        elif isinstance(f, dict) and "url" in f:
            js_files.add(f["url"])

    js_data = config.get("_js_analyzer", {}) or {}
    for f in js_data.get("files", []) or []:
        if isinstance(f, str):
            js_files.add(f)
        elif isinstance(f, dict) and "url" in f:
            js_files.add(f["url"])

    # Fallback: extract from HTML
    if not js_files:
        resp = client.get(target)
        if resp and resp.status == 200:
            html_js = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text)
            for src in html_js:
                js_files.add(urljoin(target, src))

    if not js_files:
        log.info("  No JS files found")
        return result

    log.info("  Scanning " + str(len(js_files)) + " JS files")

    seen = set()
    for js_url in list(js_files)[:30]:
        result["tested"] += 1
        resp = client.get(js_url)
        if not resp or resp.status != 200:
            continue
        result["js_files"].append(js_url)
        found = _scan_text(resp.text)
        for name, value in found:
            key = (name, value[:50])
            if key in seen:
                continue
            seen.add(key)
            log.warning("  SECRET: " + name + " in " + js_url)
            result["secrets"].append({
                "type": name,
                "value": value,
                "file": js_url,
            })
            result["vulnerable"].append({
                "url": target,
                "original_url": target,
                "injected_url": js_url,
                "param": name,
                "payload": value,
                "severity": "high",
                "description": "Hardcoded " + name + " in JS",
            })

    if not result["secrets"]:
        log.info("  No secrets found")
    else:
        log.warning("  Found " + str(len(result["secrets"])) + " potential secrets")

    return result