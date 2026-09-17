"""
Self-hosted OAST (Out-of-Band Application Security Testing) callback server.

interactsh-class infrastructure: wildcard DNS responder + HTTP callback catcher.
Every OOB payload embeds a unique nonce subdomain; callbacks are correlated
back to the test that spawned them.

Architecture:
  - DNS server (dnslib): responds to *.{domain} with the OAST server IP
  - HTTP server (FastAPI/uvicorn): catches GET/POST callbacks at /{nonce}
  - Nonce registry: tracks pending nonces and records hits

Usage:
  oast = OAST(domain="o.nightfall.local", server_ip="10.0.0.5")
  await oast.start()
  nonce = oast.nonce()
  # ... inject f"{nonce}.{oast.domain}" into payload ...
  if await oast.poll(nonce, timeout=8):
      print("OOB callback confirmed!")
"""
from __future__ import annotations

import asyncio
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class CallbackRecord:
    """A single OOB callback event."""
    nonce: str
    callback_type: str  # "dns" | "http"
    source_ip: str = ""
    data: str = ""
    timestamp: float = 0.0


class OAST:
    """Self-hosted Out-of-Band Application Security Testing server.

    Provides wildcard DNS + HTTP callback catching for blind vulnerability
    detection (blind SQLi, blind XXE, SSRF, etc.).

    Args:
        domain: The wildcard DNS zone you control (e.g. "o.nightfall.local").
        server_ip: The IP address of this OAST server (for DNS A records).
        dns_port: Port for the DNS listener.
        http_port: Port for the HTTP callback catcher.
        poll_timeout: Default timeout (seconds) when polling for callbacks.
    """

    def __init__(
        self,
        domain: str = "o.nightfall.local",
        server_ip: str = "127.0.0.1",
        dns_port: int = 5353,
        http_port: int = 8089,
        poll_timeout: int = 8,
    ):
        self.domain = domain.lower().rstrip(".")
        self.server_ip = server_ip
        self.dns_port = dns_port
        self.http_port = http_port
        self.poll_timeout = poll_timeout

        # Nonce tracking
        self._pending: dict[str, float] = {}  # nonce -> created_at
        self._callbacks: dict[str, list[CallbackRecord]] = defaultdict(list)
        self._dns_hits: dict[str, str] = {}  # fqdn -> source_ip

        # Server tasks
        self._dns_task: Optional[asyncio.Task] = None
        self._http_task: Optional[asyncio.Task] = None
        self._running = False

    def nonce(self) -> str:
        """Generate a unique nonce for an OOB payload.

        Returns:
            A random 16-char hex string to use as the subdomain prefix.
        """
        n = secrets.token_hex(8)
        self._pending[n] = time.monotonic()
        logger.debug("oast_nonce_created", nonce=n)
        return n

    def nonce_domain(self, nonce: str) -> str:
        """Build the full FQDN for a nonce: {nonce}.{domain}"""
        return f"{nonce}.{self.domain}"

    def record_dns_hit(self, fqdn: str, source_ip: str = "") -> None:
        """Record a DNS lookup hit (called by the DNS server handler)."""
        fqdn = fqdn.lower().rstrip(".")
        # Extract nonce from subdomain
        if fqdn.endswith("." + self.domain):
            parts = fqdn[: -(len(self.domain) + 1)].split(".")
            nonce = parts[-1] if parts else ""
            if nonce and nonce in self._pending:
                record = CallbackRecord(
                    nonce=nonce,
                    callback_type="dns",
                    source_ip=source_ip,
                    data=fqdn,
                    timestamp=time.monotonic(),
                )
                self._callbacks[nonce].append(record)
                self._dns_hits[fqdn] = source_ip
                logger.info("oast_dns_hit", nonce=nonce, fqdn=fqdn, source=source_ip)

    def record_http_hit(self, nonce: str, source_ip: str = "", data: str = "") -> None:
        """Record an HTTP callback hit (called by the HTTP server handler)."""
        if nonce in self._pending:
            record = CallbackRecord(
                nonce=nonce,
                callback_type="http",
                source_ip=source_ip,
                data=data,
                timestamp=time.monotonic(),
            )
            self._callbacks[nonce].append(record)
            logger.info("oast_http_hit", nonce=nonce, source=source_ip)

    def has_callback(self, nonce: str) -> bool:
        """Check if any callback has been received for this nonce."""
        return len(self._callbacks.get(nonce, [])) > 0

    async def poll(self, nonce: str, timeout: float | None = None) -> bool:
        """Wait for the first DNS or HTTP callback proving the target
        resolved/fetched our server.

        Args:
            nonce: The nonce to wait for.
            timeout: Max seconds to wait (default: self.poll_timeout).

        Returns:
            True if a callback was received, False if timeout.
        """
        timeout = timeout or self.poll_timeout
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            if self.has_callback(nonce):
                return True
            await asyncio.sleep(0.25)

        logger.debug("oast_poll_timeout", nonce=nonce, timeout=timeout)
        return False

    async def poll_http(self, nonce: str, timeout: float | None = None) -> bool:
        """Wait specifically for an HTTP callback (e.g. external DTD fetch)."""
        timeout = timeout or self.poll_timeout
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            callbacks = self._callbacks.get(nonce, [])
            if any(c.callback_type == "http" for c in callbacks):
                return True
            await asyncio.sleep(0.25)
        return False

    def get_callbacks(self, nonce: str) -> list[CallbackRecord]:
        """Get all callback records for a nonce."""
        return self._callbacks.get(nonce, [])

    async def recycle(self, nonce: str | None) -> None:
        """Remove a nonce from the pending set (finding confirmed)."""
        if nonce and nonce in self._pending:
            del self._pending[nonce]
            logger.debug("oast_nonce_recycled", nonce=nonce)

    # ── DNS Server ───────────────────────────────────────────────────────────

    async def _run_dns_server(self) -> None:
        """Wildcard DNS responder: any *.{domain} query → self.server_ip.

        Uses dnslib for DNS packet parsing/building and asyncio UDP transport.
        """
        try:
            from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE
        except ImportError:
            logger.error("dnslib not installed — OAST DNS server disabled")
            return

        class DNSProtocol(asyncio.DatagramProtocol):
            def __init__(self, oast: OAST):
                self.oast = oast

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                try:
                    request = DNSRecord.parse(data)
                    qname = str(request.q.qname).lower().rstrip(".")
                    qtype = QTYPE[request.q.qtype]

                    reply = request.reply()

                    if qname.endswith(self.oast.domain) or qname == self.oast.domain:
                        # Record the hit
                        self.oast.record_dns_hit(qname, source_ip=addr[0])
                        # Respond with our server IP for A queries
                        if qtype == "A":
                            reply.add_answer(
                                RR(qname, QTYPE.A, rdata=A(self.oast.server_ip), ttl=60)
                            )

                    self.transport.sendto(reply.pack(), addr)
                except Exception as e:
                    logger.error("dns_parse_error", error=str(e), source=addr)

        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DNSProtocol(self),
            local_addr=(self.server_ip if self.server_ip != "0.0.0.0" else "0.0.0.0", self.dns_port),
        )
        logger.info("oast_dns_started", port=self.dns_port, domain=self.domain)

        try:
            while self._running:
                await asyncio.sleep(1)
        finally:
            transport.close()

    # ── HTTP Server ──────────────────────────────────────────────────────────

    async def _run_http_server(self) -> None:
        """HTTP callback catcher: logs any request to /{nonce}."""
        try:
            from fastapi import FastAPI, Request
            import uvicorn
        except ImportError:
            logger.error("fastapi/uvicorn not installed — OAST HTTP server disabled")
            return

        app = FastAPI(docs_url=None, redoc_url=None)

        @app.api_route("/{nonce}", methods=["GET", "POST", "PUT", "DELETE"])
        async def callback_handler(nonce: str, request: Request):
            body = (await request.body()).decode("utf-8", errors="replace")[:1000]
            self.record_http_hit(
                nonce=nonce,
                source_ip=request.client.host if request.client else "",
                data=body,
            )
            return {"status": "ok"}

        @app.get("/health")
        async def health():
            return {
                "status": "running",
                "domain": self.domain,
                "pending_nonces": len(self._pending),
                "total_callbacks": sum(len(v) for v in self._callbacks.values()),
            }

        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=self.http_port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        logger.info("oast_http_started", port=self.http_port)
        await server.serve()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start both DNS and HTTP OAST servers as background tasks."""
        self._running = True
        self._dns_task = asyncio.create_task(self._run_dns_server())
        self._http_task = asyncio.create_task(self._run_http_server())
        logger.info(
            "oast_started",
            domain=self.domain,
            dns_port=self.dns_port,
            http_port=self.http_port,
        )

    async def stop(self) -> None:
        """Stop both servers."""
        self._running = False
        if self._dns_task:
            self._dns_task.cancel()
        if self._http_task:
            self._http_task.cancel()
        logger.info("oast_stopped")

    @classmethod
    def from_config(cls, cfg) -> "OAST":
        """Build an OAST instance from a NightfallConfig."""
        return cls(
            domain=cfg.oast.domain,
            server_ip=cfg.oast.server,
            dns_port=cfg.oast.dns_port,
            http_port=cfg.oast.http_port,
            poll_timeout=cfg.oast.poll_timeout,
        )
