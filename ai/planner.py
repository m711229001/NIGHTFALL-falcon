"""
Agentic planner — the reasoning brain of NIGHTFALL.

The planner receives the current world state (findings, fingerprints, frozen
WAF chains) and the current objective, then produces a JSON plan with:
  - rationale: why this plan makes sense
  - steps: ordered list of actions (request, analyze, spawn, stop)
  - new_objectives: attack angles to explore next

The plan runs through the strongest reasoning model available, with extended
thinking enabled for maximum deliberation depth.
"""
from __future__ import annotations

import json
from typing import Any

import structlog

from nightfall.ai.client import ModelClient

logger = structlog.get_logger(__name__)


# ── System Prompt — the agentic brain instructions ──────────────────────────

PLANNER_SYSTEM = """You are the reasoning engine of NIGHTFALL, an autonomous
penetration testing agent. You plan actions; the tool executes them. You never
invent evidence. You are a professional performing authorized security testing.

Rules:
1. Always return valid JSON matching the requested schema. No prose outside JSON.
2. Think about the objective in stages: recon -> discovery -> detection -> exploitation.
3. Prefer low-volume, high-signal probes. You have a hard request budget per objective.
4. When a finding is confirmed, spawn a follow-up objective to (a) exploit-proof it
   or (b) pivot to a related attack class (e.g. SQLi found -> also try UNION-based
   data extraction and OOB SQLi).
5. If a payload family keeps failing (no reflection, no timing delta), abandon it —
   do not burn budget. Recommend a different vector or move on.
6. Take account of the WAF state: if bypass chains are frozen, reuse them in payloads.
7. Never propose requests outside the scope enforced by the tool.
8. For RECON phase: focus on crawling, fingerprinting, and endpoint discovery.
9. For DISCOVERY phase: enumerate parameters, forms, API endpoints.
10. For DETECTION phase: test specific vulnerability classes with targeted payloads.
11. For EXPLOIT phase: prove impact with minimal additional requests.

Payload class identifiers: sqli, xss, csrf, xxe, ssrf, idor, jwt, authn, session, cmdi, deser

Expected signal types: reflection, timing, error, oob, status_diff, body_diff, header_diff"""


# ── Plan Schema ──────────────────────────────────────────────────────────────

PLAN_SCHEMA = """{
  "rationale": "concise reasoning for this plan",
  "steps": [
    {
      "action": "request|analyze|spawn|stop",
      "method": "GET|POST|PUT|DELETE|PATCH",
      "endpoint": "absolute or relative URL",
      "params": {"name": "value"},
      "body": "optional request body",
      "content_type": "application/x-www-form-urlencoded|application/json|application/xml|multipart/form-data",
      "session": "default|userA|userB",
      "payload_class": "sqli|xss|csrf|xxe|ssrf|idor|jwt|authn|session|none",
      "expected_signal": "reflection|timing|error|oob|status_diff|body_diff",
      "budget_cost": 1,
      "note": "optional context for this step"
    }
  ],
  "new_objectives": [
    {
      "phase": "RECON|DISCOVERY|DETECTION|EXPLOIT",
      "vuln_class": "sqli|xss|...",
      "endpoint": "...",
      "priority": 0.0-1.0,
      "budget": 40,
      "note": "why this objective matters"
    }
  ]
}"""


async def plan(
    ai: ModelClient,
    objective: Any,
    state: dict,
    budget_left: int,
) -> dict:
    """Generate an action plan for the current objective.

    Args:
        ai: The configured ModelClient instance.
        objective: Current Objective dataclass (phase, endpoint, vuln_class, etc.)
        state: World state snapshot from the database.
        budget_left: Remaining request budget for the entire campaign.

    Returns:
        Parsed plan dict with 'rationale', 'steps', and 'new_objectives'.
    """
    # Serialize objective for the prompt
    obj_dict = {
        "phase": objective.phase.value if hasattr(objective.phase, "value") else str(objective.phase),
        "endpoint": objective.endpoint,
        "vuln_class": objective.vuln_class,
        "session": objective.session,
        "priority": objective.priority,
        "budget": objective.budget,
        "context": objective.context,
    }

    # Truncate state to fit context window
    state_str = json.dumps(state, default=str, indent=None)
    if len(state_str) > 12000:
        state_str = state_str[:12000] + "...(truncated)"

    prompt = f"""WORLD STATE (JSON):
{state_str}

CURRENT OBJECTIVE:
{json.dumps(obj_dict, default=str, indent=2)}

REMAINING REQUEST BUDGET: {budget_left}

PHASE: {obj_dict['phase']}

Return JSON ONLY matching this schema:
{PLAN_SCHEMA}"""

    logger.info(
        "planner_invoked",
        phase=obj_dict["phase"],
        endpoint=objective.endpoint,
        vuln_class=objective.vuln_class,
        budget_left=budget_left,
    )

    result = await ai.think(PLANNER_SYSTEM, prompt)

    # Validate structure
    if "error" in result and len(result) == 1:
        logger.error("planner_error", error=result["error"][:500])
        return {"rationale": "planner error", "steps": [], "new_objectives": []}

    # Ensure required keys
    result.setdefault("rationale", "")
    result.setdefault("steps", [])
    result.setdefault("new_objectives", [])

    # Validate steps
    valid_steps = []
    for step in result["steps"]:
        if not isinstance(step, dict):
            continue
        step.setdefault("action", "request")
        step.setdefault("method", "GET")
        step.setdefault("endpoint", objective.endpoint or "")
        step.setdefault("params", {})
        step.setdefault("body", "")
        step.setdefault("content_type", "")
        step.setdefault("session", "default")
        step.setdefault("payload_class", "none")
        step.setdefault("expected_signal", "")
        step.setdefault("budget_cost", 1)
        valid_steps.append(step)
    result["steps"] = valid_steps

    logger.info(
        "planner_result",
        rationale=result["rationale"][:200],
        num_steps=len(result["steps"]),
        num_new_objectives=len(result["new_objectives"]),
    )

    return result
