"""Falcon MAG Framework - DOM-based XSS Scanner (static analysis)

Analyzes JS files for dangerous sinks and sources:
  - Sinks: innerHTML, outerHTML, document.write, eval, setTimeout, location
  - Sources: location.hash, location.search, document.referrer
Flags files where a source flows into a sink (heuristic).
"""

import re
from urllib.parse import urljoin
from core.logger import get_logger

log = get_logger("dom_xss")

SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "insertAdjacentHTML", "location.href", "location.assign",
    "location.replace", "element.innerHTML", ".html(",
]

SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.URL", "document.documentURI", "document.referrer",
    "window.name", "postMessage",
]


def _find_hits(text):
    """Return list of (sink, source, snippet)."""
    hits = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        for sink in SINKS:
            if sink in line:
                # Look at nearby lines for a source
                context = "\n".join(lines[max(0,i-2):i+3])
                for source in SOURCES:
                    if source in context:
                        hits.append((sink, source, line.strip()[:200]))
                        break
                break
    return hits


def run(client, config, crawl_result=None):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info("DOM XSS static analysis on " + target)

    result = {
        "target": target,
        "url": target,
        "tested": 0,
        "js_files": [],
        "vulnerable": [],
    }

    js_files = set()
    crawl = crawl_result or config.get("_crawl_result", {}) or {}
    for f in crawl.get("js_files", []) or []:
        if isinstance(f, str):
            js_files.add(f)
        elif isinstance(f, dict) and "url" in f:
            js_files.add(f["url"])

    if not js_files:
        resp = client.get(target)
        if resp and resp.status == 200:
            html_js = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text)
            for src in html_js:
                js_files.add(urljoin(target, src))

    if not js_files:
        log.info("  No JS files to analyze")
        return result

    for js_url in list(js_files)[:20]:
        result["tested"] += 1
        resp = client.get(js_url)
        if not resp or resp.status != 200:
            continue
        result["js_files"].append(js_url)
        hits = _find_hits(resp.text)
        for sink, source, snippet in hits[:3]:  # cap
            log.warning("  DOM XSS risk in " + js_url + ": " + sink + " <- " + source)
            result["vulnerable"].append({
                "url": target,
                "original_url": target,
                "injected_url": js_url,
                "param": source,
                "payload": sink,
                "severity": "high",
                "description": "Potential DOM XSS: " + source + " flows to " + sink,
                "evidence": snippet,
            })

    if not result["vulnerable"]:
        log.info("  No obvious DOM XSS sinks detected")
    return result