"""
SQLite persistence layer for NIGHTFALL.

Stores findings, objectives, OAST callbacks, and campaign state.
Deduplication via unique dedup_key on findings.
Provides a snapshot() method for feeding world state to the planner LLM.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

import aiosqlite
import structlog

logger = structlog.get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    param TEXT DEFAULT '',
    vuln_class TEXT NOT NULL,
    subtype TEXT DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    confidence REAL NOT NULL DEFAULT 0.0,
    payload TEXT DEFAULT '',
    evidence_snip TEXT DEFAULT '',
    request_har TEXT DEFAULT '',
    response_har TEXT DEFAULT '',
    ai_reason TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    dedup_key TEXT UNIQUE,
    extra_json TEXT DEFAULT '{}',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS objectives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phase TEXT NOT NULL,
    endpoint TEXT DEFAULT '',
    vuln_class TEXT DEFAULT '',
    session_name TEXT DEFAULT 'default',
    priority REAL DEFAULT 0.5,
    budget INTEGER DEFAULT 40,
    state TEXT NOT NULL DEFAULT 'pending',
    context_json TEXT DEFAULT '{}',
    created_at REAL NOT NULL,
    completed_at REAL
);

CREATE TABLE IF NOT EXISTS callbacks (
    nonce TEXT PRIMARY KEY,
    objective_id INTEGER,
    callback_type TEXT DEFAULT 'dns',
    source_ip TEXT DEFAULT '',
    data TEXT DEFAULT '',
    created_at REAL NOT NULL,
    received_at REAL
);

CREATE TABLE IF NOT EXISTS evidence_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    session_name TEXT DEFAULT 'default',
    request_body TEXT DEFAULT '',
    response_status INTEGER DEFAULT 0,
    response_body_snip TEXT DEFAULT '',
    latency_ms REAL DEFAULT 0.0,
    oob_nonce TEXT DEFAULT '',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS campaign (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_class ON findings(vuln_class);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(dedup_key);
CREATE INDEX IF NOT EXISTS idx_objectives_state ON objectives(state);
CREATE INDEX IF NOT EXISTS idx_callbacks_nonce ON callbacks(nonce);
"""


class Database:
    """Async SQLite database for NIGHTFALL campaign persistence."""

    def __init__(self, db_path: str | Path = "nightfall.db"):
        self.db_path = str(db_path)
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """Open the database and create tables if needed."""
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()
        logger.info("database_connected", path=self.db_path)

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            logger.info("database_closed")

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn

    # ── Findings ─────────────────────────────────────────────────────────────

    async def add_finding(self, verdict: dict, evidence: Any) -> Optional[int]:
        """Persist a triaged finding with deduplication.

        Args:
            verdict: Triage output dict with severity, class, confidence, reason.
            evidence: Evidence dataclass from the detection engine.

        Returns:
            Finding ID if inserted, None if duplicate.
        """
        now = time.time()
        dedup_key = f"{evidence.url}|{verdict.get('class', '')}|{getattr(evidence, 'param', '')}"

        try:
            cursor = await self.conn.execute(
                """INSERT INTO findings
                   (target, url, method, param, vuln_class, subtype, severity,
                    confidence, payload, evidence_snip, request_har, response_har,
                    ai_reason, remediation, dedup_key, extra_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    urlparse_host(evidence.url),
                    evidence.url,
                    evidence.method,
                    getattr(evidence, "param", ""),
                    verdict.get("class", "unknown"),
                    verdict.get("subtype", ""),
                    verdict.get("severity", "info"),
                    verdict.get("confidence", 0.0),
                    getattr(evidence, "payload", ""),
                    evidence.response_body[:2000] if hasattr(evidence, "response_body") else "",
                    json.dumps(getattr(evidence, "request_headers", {})),
                    str(evidence.response_status),
                    verdict.get("reason", ""),
                    verdict.get("remediation", ""),
                    dedup_key,
                    json.dumps(verdict.get("extra", {})),
                    now,
                    now,
                ),
            )
            await self.conn.commit()
            logger.info(
                "finding_added",
                id=cursor.lastrowid,
                vuln_class=verdict.get("class"),
                severity=verdict.get("severity"),
                url=evidence.url,
            )
            return cursor.lastrowid
        except aiosqlite.IntegrityError:
            logger.debug("finding_duplicate", dedup_key=dedup_key)
            return None

    async def get_findings(
        self, vuln_class: str | None = None, severity: str | None = None
    ) -> list[dict]:
        """Retrieve findings, optionally filtered."""
        query = "SELECT * FROM findings WHERE 1=1"
        params: list = []
        if vuln_class:
            query += " AND vuln_class = ?"
            params.append(vuln_class)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY confidence DESC, created_at DESC"

        async with self.conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def count_findings(self) -> int:
        async with self.conn.execute("SELECT COUNT(*) FROM findings") as c:
            row = await c.fetchone()
            return row[0] if row else 0

    # ── Objectives ───────────────────────────────────────────────────────────

    async def add_objective(self, obj: dict) -> int:
        now = time.time()
        cursor = await self.conn.execute(
            """INSERT INTO objectives
               (phase, endpoint, vuln_class, session_name, priority, budget,
                context_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                obj.get("phase", "DETECTION"),
                obj.get("endpoint", ""),
                obj.get("vuln_class", ""),
                obj.get("session", "default"),
                obj.get("priority", 0.5),
                obj.get("budget", 40),
                json.dumps(obj.get("context", {})),
                now,
            ),
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def update_objective_state(self, obj_id: int, state: str) -> None:
        now = time.time()
        await self.conn.execute(
            "UPDATE objectives SET state = ?, completed_at = ? WHERE id = ?",
            (state, now if state in ("completed", "failed") else None, obj_id),
        )
        await self.conn.commit()

    # ── Callbacks (OAST) ─────────────────────────────────────────────────────

    async def register_nonce(self, nonce: str, objective_id: int | None = None) -> None:
        await self.conn.execute(
            "INSERT OR IGNORE INTO callbacks (nonce, objective_id, created_at) VALUES (?, ?, ?)",
            (nonce, objective_id, time.time()),
        )
        await self.conn.commit()

    async def record_callback(
        self, nonce: str, callback_type: str = "dns", source_ip: str = "", data: str = ""
    ) -> None:
        await self.conn.execute(
            """UPDATE callbacks
               SET callback_type = ?, source_ip = ?, data = ?, received_at = ?
               WHERE nonce = ?""",
            (callback_type, source_ip, data, time.time(), nonce),
        )
        await self.conn.commit()
        logger.info("oast_callback_recorded", nonce=nonce, type=callback_type, source=source_ip)

    async def has_callback(self, nonce: str) -> bool:
        async with self.conn.execute(
            "SELECT received_at FROM callbacks WHERE nonce = ?", (nonce,)
        ) as c:
            row = await c.fetchone()
            return row is not None and row["received_at"] is not None

    # ── Evidence Log ─────────────────────────────────────────────────────────

    async def log_evidence(self, ev: Any) -> None:
        await self.conn.execute(
            """INSERT INTO evidence_log
               (url, method, session_name, request_body, response_status,
                response_body_snip, latency_ms, oob_nonce, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ev.url,
                ev.method,
                ev.session,
                ev.request_body[:2000],
                ev.response_status,
                ev.response_body[:2000],
                ev.latency_ms,
                ev.oob_nonce or "",
                time.time(),
            ),
        )
        await self.conn.commit()

    # ── Campaign State ───────────────────────────────────────────────────────

    async def set_campaign(self, key: str, value: str) -> None:
        await self.conn.execute(
            "INSERT OR REPLACE INTO campaign (key, value) VALUES (?, ?)",
            (key, value),
        )
        await self.conn.commit()

    async def get_campaign(self, key: str, default: str = "") -> str:
        async with self.conn.execute(
            "SELECT value FROM campaign WHERE key = ?", (key,)
        ) as c:
            row = await c.fetchone()
            return row["value"] if row else default

    # ── Snapshot (for planner LLM context) ───────────────────────────────────

    async def snapshot(self) -> dict:
        """Build a world-state snapshot for the planner LLM.

        Returns a dict with:
        - findings_summary: list of {class, severity, url, confidence}
        - total_findings: int
        - pending_objectives: int
        - frozen_waf_chains: list (from campaign state)
        - fingerprints: dict (from campaign state)
        """
        findings = await self.get_findings()
        findings_summary = [
            {
                "class": f["vuln_class"],
                "severity": f["severity"],
                "url": f["url"],
                "confidence": f["confidence"],
                "param": f["param"],
            }
            for f in findings[:50]  # cap for context window
        ]

        async with self.conn.execute(
            "SELECT COUNT(*) FROM objectives WHERE state = 'pending'"
        ) as c:
            row = await c.fetchone()
            pending = row[0] if row else 0

        frozen_raw = await self.get_campaign("frozen_waf_chains", "[]")
        fingerprints_raw = await self.get_campaign("fingerprints", "{}")

        return {
            "findings_summary": findings_summary,
            "total_findings": len(findings),
            "pending_objectives": pending,
            "frozen_waf_chains": json.loads(frozen_raw),
            "fingerprints": json.loads(fingerprints_raw),
        }

    async def finalize_report(self) -> list[dict]:
        """Fetch all open findings for final report generation."""
        return await self.get_findings()


def urlparse_host(url: str) -> str:
    """Extract hostname from URL."""
    from urllib.parse import urlparse
    return urlparse(url).hostname or "unknown"
