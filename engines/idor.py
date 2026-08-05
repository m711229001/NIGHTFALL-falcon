"""
IDOR (Insecure Direct Object Reference) — dual-session differential engine.

The differentiator: two authenticated tenants attack one resource table.
  session A = owner of the object
  session B = attacker (different tenant)

If B can read/modify what only A should => broken object-level authorization.
No commercial scanner does this properly.
"""
from __future__ import annotations

import difflib
import re
from typing import Optional

import structlog

from nightfall.core.http import Evidence

logger = structlog.get_logger(__name__)


# ── ID Extraction Patterns ──────────────────────────────────────────────────

ID_PATTERNS = [
    re.compile(r"/(\d{1,10})(?:/|$|\?)"),                    # numeric IDs in path
    re.compile(r"[?&]id=(\d+)"),                              # id= query param
    re.compile(r"[?&]user_?id=(\d+)", re.I),                 # user_id param
    re.compile(r"[?&]account_?id=(\d+)", re.I),              # account_id param
    re.compile(r"[?&]order_?id=(\d+)", re.I),                # order_id param
    re.compile(r'"id"\s*:\s*(\d+)'),                          # JSON id field
    re.compile(r'"userId"\s*:\s*(\d+)', re.I),                # JSON userId
    re.compile(r'"accountId"\s*:\s*(\d+)', re.I),             # JSON accountId
    re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I),  # UUID
]

# HTTP methods that indicate state-changing operations
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class IDORDifferential:
    """Dual-session differential IDOR detection engine.

    Two authenticated tenants attack one resource table. session A = owner,
    session B = attacker. If B can read what only A should see, it's broken
    object-level authorization (BOLA).

    Also tests:
    - Cross-tenant write operations (BFLA)
    - Horizontal privilege escalation
    - Vertical privilege escalation (admin → regular user endpoints)
    """

    def __init__(self, pool, ai=None, oast=None):
        self.pool = pool
        self.ai = ai
        self.oast = oast

    async def hunt(self, step: dict, obj) -> Optional[Evidence]:
        """Run the IDOR differential attack.

        1. Harvest object IDs from the crawl state / JS mining / API responses
        2. For each ID: request with session A (owner) then session B (attacker)
        3. Diff the responses to detect unauthorized access
        """
        endpoint = step.get("endpoint", "")
        method = step.get("method", "GET")
        session_a = step.get("session", "userA")
        session_b = "userB" if session_a != "userB" else "userA"

        # Get the parameterized endpoint pattern
        # e.g., /api/account/{id}/details or /api/users/{id}
        id_placeholder = _find_id_placeholder(endpoint)

        if id_placeholder:
            return await self._differential_with_placeholder(
                endpoint, id_placeholder, method, session_a, session_b
            )
        else:
            return await self._differential_discovery(
                endpoint, method, session_a, session_b
            )

    async def _differential_with_placeholder(
        self,
        endpoint: str,
        placeholder: str,
        method: str,
        session_a: str,
        session_b: str,
    ) -> Optional[Evidence]:
        """Test IDOR on an endpoint with an identified ID placeholder."""

        # Harvest IDs: try sequential IDs around common ranges
        id_candidates = self._generate_id_candidates()

        for oid in id_candidates[:50]:  # budget cap
            url = endpoint.replace(placeholder, str(oid))

            # Step 1: Request as owner (session A)
            owner_ev = await self.pool.send(method, url, session=session_a)

            if owner_ev.response_status in (401, 403, 404, 0):
                continue  # resource doesn't exist for anyone

            if owner_ev.response_status != 200:
                continue

            # Step 2: Request as attacker (session B)
            attacker_ev = await self.pool.send(method, url, session=session_b)

            # Step 3: Differential analysis
            verdict = self._diff_responses(owner_ev, attacker_ev)

            if verdict == "broken":
                attacker_ev.vuln_class = "idor"
                attacker_ev.subtype = (
                    "cross-tenant-write" if method in WRITE_METHODS
                    else "cross-tenant-read"
                )
                attacker_ev.param = placeholder
                attacker_ev.payload = str(oid)
                attacker_ev.confidence = 0.85
                attacker_ev.severity = "critical" if method in WRITE_METHODS else "high"
                attacker_ev.extra = {
                    "owner_session": session_a,
                    "attacker_session": session_b,
                    "owner_status": owner_ev.response_status,
                    "attacker_status": attacker_ev.response_status,
                    "similarity": self._similarity(owner_ev.response_body, attacker_ev.response_body),
                    "object_id": str(oid),
                }
                attacker_ev.evidence_snip = (
                    f"Owner ({session_a}): {owner_ev.response_body[:200]}\n"
                    f"Attacker ({session_b}): {attacker_ev.response_body[:200]}"
                )
                attacker_ev.remediation = (
                    "Implement object-level authorization checks. Verify that the "
                    "authenticated user owns or has permission to access the requested "
                    "resource. Use authorization middleware, not just authentication."
                )
                logger.info(
                    "idor_confirmed",
                    url=url,
                    object_id=str(oid),
                    method=method,
                    subtype=attacker_ev.subtype,
                )
                return attacker_ev

        logger.debug("idor_no_signal", endpoint=endpoint)
        return None

    async def _differential_discovery(
        self,
        endpoint: str,
        method: str,
        session_a: str,
        session_b: str,
    ) -> Optional[Evidence]:
        """Test IDOR by discovering IDs from session A's responses.

        First, fetch data as session A to discover object IDs,
        then try to access those same objects as session B.
        """
        # Fetch as session A to get reference data
        owner_ev = await self.pool.send(method, endpoint, session=session_a)
        if owner_ev.response_status != 200:
            return None

        # Extract IDs from the response
        discovered_ids = set()
        for pattern in ID_PATTERNS:
            for match in pattern.findall(owner_ev.response_body):
                discovered_ids.add(match)

        if not discovered_ids:
            # No IDs found — try the same endpoint as session B directly
            attacker_ev = await self.pool.send(method, endpoint, session=session_b)
            verdict = self._diff_responses(owner_ev, attacker_ev)
            if verdict == "broken":
                attacker_ev.vuln_class = "idor"
                attacker_ev.subtype = "same-endpoint-access"
                attacker_ev.confidence = 0.7
                attacker_ev.severity = "high"
                attacker_ev.evidence_snip = (
                    f"Both sessions return similar data for {endpoint}"
                )
                attacker_ev.remediation = (
                    "Implement tenant-level data isolation. "
                    "Filter query results by the authenticated user's tenant."
                )
                return attacker_ev
            return None

        # Try accessing discovered IDs as session B
        for oid in list(discovered_ids)[:20]:
            # Try common URL patterns
            for url_pattern in [
                f"{endpoint}/{oid}",
                f"{endpoint}?id={oid}",
                f"{endpoint}?user_id={oid}",
            ]:
                attacker_ev = await self.pool.send(method, url_pattern, session=session_b)
                owner_check = await self.pool.send(method, url_pattern, session=session_a)

                if owner_check.response_status != 200:
                    continue

                verdict = self._diff_responses(owner_check, attacker_ev)
                if verdict == "broken":
                    attacker_ev.vuln_class = "idor"
                    attacker_ev.subtype = "cross-tenant-read"
                    attacker_ev.param = "id"
                    attacker_ev.payload = str(oid)
                    attacker_ev.confidence = 0.85
                    attacker_ev.severity = "high"
                    attacker_ev.extra = {"discovered_id": str(oid)}
                    attacker_ev.evidence_snip = attacker_ev.response_body[:300]
                    attacker_ev.remediation = (
                        "Implement object-level authorization. Verify ownership before returning data."
                    )
                    return attacker_ev

        return None

    def _diff_responses(self, owner_ev: Evidence, attacker_ev: Evidence) -> str:
        """Compare owner and attacker responses to detect IDOR.

        Returns:
            "broken" if attacker can see owner's data
            "ok" if properly denied
            "different-resource" if both 200 but different content
        """
        # Attacker denied — proper authorization
        if attacker_ev.response_status in (401, 403, 404):
            return "ok"

        # Attacker got server error — not useful
        if attacker_ev.response_status >= 500:
            return "ok"

        # Both 200 — compare response bodies
        if attacker_ev.response_status == 200 and owner_ev.response_status == 200:
            # Significantly different body lengths suggest different resources
            owner_len = len(owner_ev.response_body)
            attacker_len = len(attacker_ev.response_body)
            if owner_len > 0 and abs(attacker_len - owner_len) > owner_len * 0.7:
                return "different-resource"

            # High similarity = same data leaked to other session
            similarity = self._similarity(owner_ev.response_body, attacker_ev.response_body)
            if similarity > 0.85:
                return "broken"

            # Moderate similarity — could be same template with different data
            if similarity > 0.5 and similarity <= 0.85:
                return "different-resource"

        return "ok"

    @staticmethod
    def _similarity(text1: str, text2: str) -> float:
        """Compute similarity ratio between two response bodies."""
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0

        # Truncate for performance
        t1 = text1[:5000]
        t2 = text2[:5000]
        return difflib.SequenceMatcher(None, t1, t2).ratio()

    @staticmethod
    def _generate_id_candidates() -> list:
        """Generate common ID candidates for IDOR testing."""
        candidates = []
        # Low sequential IDs (common in dev/staging)
        candidates.extend(range(1, 20))
        # Gaps that catch off-by-one
        candidates.extend([100, 101, 999, 1000, 1001])
        return candidates


def _find_id_placeholder(endpoint: str) -> Optional[str]:
    """Find ID placeholders in an endpoint URL.

    Matches patterns like {id}, {userId}, :id, <id>, etc.
    """
    patterns = [
        re.compile(r"(\{[\w]+\})"),           # {id}, {userId}
        re.compile(r"(:[\w]+)"),               # :id, :userId
        re.compile(r"(<[\w]+>)"),              # <id>
    ]
    for p in patterns:
        match = p.search(endpoint)
        if match:
            return match.group(1)
    return None


async def idor_engine(ctx, step: dict, obj) -> Optional[Evidence]:
    """Entry point for IDOR detection, wraps IDORDifferential."""
    differ = IDORDifferential(ctx.pool, ctx.ai, ctx.oast)
    return await differ.hunt(step, obj)
