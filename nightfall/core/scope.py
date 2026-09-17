"""
Scope enforcement — the ONLY restriction in NIGHTFALL.

Scope is enforced at the worker level: no request leaves the box without
passing this guard. Every other capability is unrestricted.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


class OutOfScope(Exception):
    """Raised when a request target is not in the declared scope."""


class ScopeGuard:
    """Worker-enforced scope gate.

    Every outbound request passes through `assert_allowed` before being sent.
    This is the operational safety boundary — it keeps the tool pointed only
    at the targets the operator declared.

    Args:
        allow_hosts: Hostnames (or wildcard-stripped domains) that are in scope.
                     e.g. ["staging.example.com", "api.example.com"]
        deny_hosts:  Hostnames explicitly denied even if they match allow.
        allow_private: If True, allows requests to RFC1918 / loopback IPs.
                       Enable only for internal network pentests.
    """

    def __init__(
        self,
        allow_hosts: list[str],
        deny_hosts: tuple[str, ...] | list[str] = (),
        allow_private: bool = False,
    ):
        # Normalize: strip leading "*." for wildcard matching
        self.allow = {h.lower().lstrip("*.") for h in allow_hosts}
        self.deny = {h.lower() for h in deny_hosts}
        self.allow_private = allow_private

        logger.info(
            "scope_guard_initialized",
            allow=sorted(self.allow),
            deny=sorted(self.deny),
            allow_private=allow_private,
        )

    def _host_matches(self, host: str, patterns: set[str]) -> bool:
        """Check if host matches any pattern (exact or suffix match)."""
        for pattern in patterns:
            if host == pattern or host.endswith("." + pattern):
                return True
        return False

    async def assert_allowed(self, url: str) -> None:
        """Validate that a URL is within the declared scope.

        Performs:
        1. Deny-list check (takes priority)
        2. Allow-list check
        3. DNS re-resolution to kill DNS-rebinding attacks on our own egress
        4. Private IP check (blocks RFC1918 unless allow_private=True)

        Raises:
            OutOfScope: If the URL target is not in scope.
        """
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if not host:
            raise OutOfScope(f"no hostname in URL: {url}")

        # 1. Deny-list takes priority
        if self._host_matches(host, self.deny):
            logger.warning("scope_denied", host=host, reason="deny-listed")
            raise OutOfScope(f"deny-listed: {host}")

        # 2. Allow-list check
        if not self._host_matches(host, self.allow):
            logger.warning("scope_denied", host=host, reason="not in scope")
            raise OutOfScope(f"not in scope: {host}")

        # 3. Re-resolve at request time — kills DNS-rebinding of our own egress
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            logger.warning("scope_denied", host=host, reason="unresolvable")
            raise OutOfScope(f"unresolvable: {host}")

        # 4. Private IP check
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise OutOfScope(f"invalid IP resolution: {host} -> {ip}")

        if (addr.is_private or addr.is_loopback or addr.is_link_local) and not self.allow_private:
            logger.warning(
                "scope_denied",
                host=host,
                ip=ip,
                reason="private egress target",
            )
            raise OutOfScope(f"private egress target: {host} -> {ip}")

        logger.debug("scope_allowed", host=host, ip=ip)

    @classmethod
    def from_config(cls, cfg) -> "ScopeGuard":
        """Build a ScopeGuard from a NightfallConfig instance."""
        return cls(
            allow_hosts=cfg.targets,
            deny_hosts=cfg.deny_hosts,
            allow_private=cfg.allow_private,
        )
