"""
NIGHTFALL Orchestrator — the agentic core.

observe → reason → plan → act → triage → persist

This is the brain that ties everything together. It maintains a priority
queue of objectives, dispatches them to the planner LLM, routes steps
to detection engines, triages findings, and spawns new objectives based
on discoveries. The loop runs until the budget is exhausted or all
objectives are complete.

Budget-aware: every request costs against the hard cap. The planner sees
the remaining budget and adjusts its strategy accordingly.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import structlog

from nightfall.ai.client import ModelClient
from nightfall.ai.planner import plan
from nightfall.ai.triage import triage
from nightfall.bypass.freeze import ChainFreezer
from nightfall.bypass.waf import WAFBypasser
from nightfall.config import NightfallConfig
from nightfall.core.db import Database
from nightfall.core.http import Evidence, HttpPool
from nightfall.core.oast import OAST
from nightfall.core.ratelimit import RateLimiter
from nightfall.core.scope import ScopeGuard

logger = structlog.get_logger(__name__)


# ── Data Models ──────────────────────────────────────────────────────────────

class Phase(Enum):
    RECON = 0
    DISCOVERY = 1
    DETECTION = 2
    EXPLOIT = 3


@dataclass
class Objective:
    """A single unit of work for the agent."""
    phase: Phase
    endpoint: str = ""
    vuln_class: str = ""
    session: str = "default"
    priority: float = 0.5
    budget: int = 40
    context: dict = field(default_factory=dict)
    id: int = 0

    def __lt__(self, other):
        return self.priority > other.priority  # higher priority first


# ── Engine Registry ──────────────────────────────────────────────────────────

async def _dispatch_engine(ctx: "EngineContext", payload_class: str, step: dict, obj: Objective) -> Optional[Evidence]:
    """Route a step to the matching detection engine."""
    from nightfall.engines.sqli import sqli_engine, sqlmap_bridge
    from nightfall.engines.xss import xss_engine
    from nightfall.engines.csrf import csrf_engine
    from nightfall.engines.xxe import xxe_engine
    from nightfall.engines.ssrf import ssrf_engine
    from nightfall.engines.idor import idor_engine
    from nightfall.engines.jwt import jwt_engine
    from nightfall.engines.authn import authn_engine
    from nightfall.engines.session import session_engine

    engines = {
        "sqli": sqli_engine,
        "xss": xss_engine,
        "csrf": csrf_engine,
        "xxe": xxe_engine,
        "ssrf": ssrf_engine,
        "idor": idor_engine,
        "jwt": jwt_engine,
        "authn": authn_engine,
        "auth": authn_engine,
        "session": session_engine,
        "sqlmap": sqlmap_bridge,
    }

    engine_fn = engines.get(payload_class)
    if engine_fn:
        try:
            return await engine_fn(ctx, step, obj)
        except Exception as exc:
            logger.error("engine_error", engine=payload_class, error=str(exc), url=step.get("endpoint", ""))
            return None

    logger.warning("unknown_engine", payload_class=payload_class)
    return None


@dataclass
class EngineContext:
    """Context passed to every detection engine."""
    pool: HttpPool
    ai: ModelClient
    oast: Optional[OAST]
    db: Database
    config: NightfallConfig
    freezer: ChainFreezer
    waf: Optional[WAFBypasser]
    exploit_mode: str = "off"
    creds: dict = field(default_factory=dict)


# ── Orchestrator ─────────────────────────────────────────────────────────────

class Orchestrator:
    """The agentic core of NIGHTFALL.

    Maintains a priority queue of objectives, dispatches them to the planner
    LLM, routes planned steps to detection engines, triages findings, and
    spawns new objectives based on discoveries.
    """

    def __init__(self, cfg: NightfallConfig, ai: ModelClient, pool: HttpPool,
                 oast: Optional[OAST], db: Database, scope: ScopeGuard):
        self.cfg = cfg
        self.ai = ai
        self.pool = pool
        self.oast = oast
        self.db = db
        self.scope = scope

        self.queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.seq = 0
        self.budget = cfg.total_requests
        self.freezer = ChainFreezer()
        self.waf = WAFBypasser(pool)

        self.ctx = EngineContext(
            pool=pool,
            ai=ai,
            oast=oast,
            db=db,
            config=cfg,
            freezer=self.freezer,
            waf=self.waf,
            exploit_mode=cfg.exploit_mode,
        )

        # Stats
        self._start_time = 0.0
        self._findings_count = 0
        self._objectives_completed = 0
        self._steps_executed = 0

    async def seed(self, seed_url: str) -> None:
        """Seed the objective queue with initial RECON and DISCOVERY phases."""
        logger.info("orchestrator_seeding", seed_url=seed_url)

        for phase in (Phase.RECON, Phase.DISCOVERY):
            obj = Objective(
                phase=phase,
                endpoint=seed_url,
                priority=1.0,
                budget=min(200, self.budget // 4),
            )
            await self._enqueue(obj)

    async def run(self, seed_url: str) -> dict:
        """Run the full agentic loop.

        Flow: seed → (dequeue → plan → execute steps → triage → persist → spawn) → report

        Returns:
            Campaign summary dict.
        """
        self._start_time = time.monotonic()
        logger.info("orchestrator_start", seed_url=seed_url, budget=self.budget)

        # Seed initial objectives
        await self.seed(seed_url)

        # Phase 0: WAF detection
        waf_type = await self.waf.identify(seed_url)
        if waf_type:
            await self.db.set_campaign("waf", waf_type)
            logger.info("waf_identified", type=waf_type)

        # Phase 0.5: Fingerprint & crawl (run before the agent loop for state)
        await self._run_recon(seed_url)

        # Main agent loop
        while self.budget > 0 and not self.queue.empty():
            try:
                _, _, obj = await asyncio.wait_for(self.queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                break

            logger.info(
                "objective_start",
                phase=obj.phase.name,
                endpoint=obj.endpoint,
                vuln_class=obj.vuln_class,
                budget_left=self.budget,
            )

            # Get world state for the planner
            state = await self.db.snapshot()
            state["frozen_waf_chains"] = self.freezer.frozen_chains
            state["waf_type"] = self.waf.detected_waf

            # Ask the LLM to plan
            plan_result = await plan(self.ai, obj, state, self.budget)

            # Execute planned steps
            for step in plan_result.get("steps", []):
                if self.budget <= 0:
                    logger.warning("budget_exhausted")
                    break

                action = step.get("action", "request")

                if action == "stop":
                    break
                elif action == "spawn":
                    self._spawn_from_step(step, obj)
                    continue
                elif action == "analyze":
                    continue  # analysis is done by the planner
                elif action == "request":
                    # Execute the step
                    ev = await self._execute_step(step, obj)
                    self.budget -= step.get("budget_cost", 1)
                    self._steps_executed += 1

                    if ev is None:
                        continue

                    # Triage: only the LLM decides if evidence is a finding
                    payload_class = step.get("payload_class", "none")
                    if payload_class != "none" and ev.response_status > 0:
                        verdict = await triage(self.ai, ev, payload_class)

                        if verdict.get("accepted"):
                            # Persist the finding
                            await self.db.add_finding(verdict, ev)
                            self._findings_count += 1

                            if ev.oob_nonce and self.oast:
                                await self.oast.recycle(ev.oob_nonce)

                            # Exploit confirmation mode
                            if self.cfg.exploit_mode == "confirm":
                                await self._exploit_confirm(verdict, ev)

                            # Agentic pivot: finding → new attack angle
                            self._spawn_from_finding(verdict, ev, obj)

                            logger.info(
                                "finding_confirmed",
                                vuln_class=verdict.get("class"),
                                severity=verdict.get("severity"),
                                confidence=verdict.get("confidence"),
                                url=ev.url,
                            )

            # Spawn new objectives from the plan
            for new_obj_spec in plan_result.get("new_objectives", []):
                self._spawn_from_step(new_obj_spec, obj)

            self._objectives_completed += 1

        # Finalize
        elapsed = time.monotonic() - self._start_time
        summary = {
            "elapsed_seconds": round(elapsed, 1),
            "budget_used": self.cfg.total_requests - self.budget,
            "budget_remaining": self.budget,
            "findings": self._findings_count,
            "objectives_completed": self._objectives_completed,
            "steps_executed": self._steps_executed,
            "waf": self.waf.detected_waf,
            "frozen_chains": self.freezer.frozen_chains,
        }

        logger.info("orchestrator_complete", **summary)
        return summary

    async def _execute_step(self, step: dict, obj: Objective) -> Optional[Evidence]:
        """Execute a single planned step."""
        payload_class = step.get("payload_class", "none")
        method = step.get("method", "GET")
        endpoint = step.get("endpoint", obj.endpoint)
        params = step.get("params", {})
        body = step.get("body", "")
        content_type = step.get("content_type", "")
        session = step.get("session", obj.session)

        # If the payload class has an engine, route to it
        if payload_class and payload_class != "none":
            return await _dispatch_engine(self.ctx, payload_class, step, obj)

        # Plain request (recon/discovery)
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type

        return await self.pool.send(
            method, endpoint,
            params=params if params else None,
            data=body if body and not content_type.startswith("application/json") else None,
            json_payload=body if body and content_type.startswith("application/json") else None,
            headers=headers if headers else None,
            session=session,
        )

    async def _run_recon(self, seed_url: str) -> None:
        """Run the initial reconnaissance phase (fingerprint + crawl + JS mining)."""
        from nightfall.recon.crawler import Crawler
        from nightfall.recon.fingerprint import Fingerprinter
        from nightfall.recon.js_mining import JSMiner

        # Fingerprint
        fp = Fingerprinter(self.pool, self.scope)
        fingerprints = await fp.fingerprint(seed_url)
        await self.db.set_campaign("fingerprints", json.dumps(fingerprints, default=str))

        # Crawl
        crawler = Crawler(self.pool, self.scope, self.cfg)
        endpoints = await crawler.crawl(seed_url)

        # JS mining
        if crawler.js_files:
            miner = JSMiner(self.pool, self.scope)
            js_results = await miner.mine(crawler.js_files, seed_url)
            await self.db.set_campaign("js_mining", json.dumps(js_results, default=str))

            # Add JS-discovered endpoints to the crawl results
            for ep_info in js_results.get("endpoints", []):
                from nightfall.recon.crawler import Endpoint
                endpoints.append(Endpoint(ep_info["url"], "GET", source="js-mining"))

        # Spawn DETECTION objectives for discovered endpoints
        for ep in endpoints[:100]:  # cap
            for vuln_class in ("sqli", "xss", "ssrf", "xxe"):
                detect_obj = Objective(
                    phase=Phase.DETECTION,
                    endpoint=ep.url,
                    vuln_class=vuln_class,
                    session="default",
                    priority=0.6,
                    budget=min(30, self.budget // 20),
                    context={"params": ep.params, "source": ep.source},
                )
                await self._enqueue(detect_obj)

            # IDOR for endpoints with ID-like parameters
            if any(p in str(ep.params).lower() or p in ep.url.lower()
                   for p in ("id", "user", "account", "order")):
                idor_obj = Objective(
                    phase=Phase.DETECTION,
                    endpoint=ep.url,
                    vuln_class="idor",
                    session="userA",
                    priority=0.7,
                    budget=min(50, self.budget // 10),
                )
                await self._enqueue(idor_obj)

        # Session and auth checks (once per campaign)
        for check in ("session", "authn", "jwt", "csrf"):
            check_obj = Objective(
                phase=Phase.DETECTION,
                endpoint=seed_url,
                vuln_class=check,
                priority=0.5,
                budget=min(20, self.budget // 20),
            )
            await self._enqueue(check_obj)

        # WAF bypass chain synthesis if WAF detected
        if self.waf.detected_waf:
            for vc in ("sqli", "xss"):
                chain = await self.waf.break_chain(seed_url, vc)
                if chain:
                    self.freezer.freeze(vc, chain[0])

        logger.info(
            "recon_complete",
            endpoints=len(endpoints),
            fingerprints=len(fingerprints.get("server", [])),
        )

    def _spawn_from_step(self, spec: dict, parent: Objective) -> None:
        """Spawn a new objective from a plan step or new_objectives entry."""
        phase_str = spec.get("phase", "DETECTION")
        try:
            phase = Phase[phase_str]
        except KeyError:
            phase = Phase.DETECTION

        obj = Objective(
            phase=phase,
            endpoint=spec.get("endpoint", parent.endpoint),
            vuln_class=spec.get("vuln_class", ""),
            session=spec.get("session", parent.session),
            priority=spec.get("priority", 0.5),
            budget=spec.get("budget", 30),
            context={
                "parent": parent.endpoint,
                "frozen_waf": self.freezer.frozen_chains,
            },
        )
        asyncio.create_task(self._enqueue(obj))

    def _spawn_from_finding(self, verdict: dict, ev: Evidence, parent: Objective) -> None:
        """Agentic pivot: finding → new attack angle."""
        vuln_class = verdict.get("class", "")

        # SQLi confirmed → try UNION extraction + OOB
        if vuln_class == "sqli" and verdict.get("subtype") != "sqlmap-confirmed":
            self._spawn_from_step({
                "phase": "EXPLOIT",
                "vuln_class": "sqli",
                "endpoint": ev.url,
                "priority": 0.95,
                "budget": 50,
            }, parent)

        # XSS confirmed → try stored XSS on related endpoints
        if vuln_class == "xss" and verdict.get("subtype") == "reflected":
            self._spawn_from_step({
                "phase": "DETECTION",
                "vuln_class": "xss",
                "endpoint": ev.url,
                "priority": 0.8,
            }, parent)

        # SSRF confirmed → try file read + cloud pivot
        if vuln_class == "ssrf":
            self._spawn_from_step({
                "phase": "EXPLOIT",
                "vuln_class": "ssrf",
                "endpoint": ev.url,
                "priority": 0.9,
                "budget": 30,
            }, parent)

    async def _exploit_confirm(self, verdict: dict, ev: Evidence) -> None:
        """Exploit confirmation: prove impact with evidence capture.

        Only runs in exploit_mode='confirm'. Escalates confirmed findings
        to proof-of-impact actions.
        """
        vuln_class = verdict.get("class", "")
        logger.info("exploit_confirm", vuln_class=vuln_class, url=ev.url)

        if vuln_class == "sqli":
            # Try sqlmap for extraction
            step = {"endpoint": ev.url, "params": {"q": ev.payload}}
            from nightfall.engines.sqli import sqlmap_bridge
            result = await sqlmap_bridge(self.ctx, step, Objective(Phase.EXPLOIT))
            if result:
                await self.db.add_finding(
                    {"accepted": True, "severity": "critical", "class": "sqli",
                     "confidence": 0.95, "reason": "sqlmap confirmed exploitation"},
                    result,
                )

    async def _enqueue(self, obj: Objective) -> None:
        """Add an objective to the priority queue."""
        obj.id = self.seq
        self.seq += 1
        await self.queue.put((-obj.priority, self.seq, obj))
