"""
Provider-agnostic LLM client with extended thinking support.

The tool doesn't care which model you plug in — it flips on extended thinking
and routes the hard decisions (planning, triage, payload synthesis) to the
strongest reasoning model you have access to. One config line changes the brain.

Supports:
  - Anthropic (native Messages API)
  - OpenAI-compatible (GPT, vLLM, Ollama, Together, etc.)
  - Custom endpoints (any /chat/completions or /messages compatible server)
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

import httpx
import structlog

from nightfall.config import AIConfig

logger = structlog.get_logger(__name__)


class ModelClient:
    """Provider-agnostic reasoning model client.

    Routes planning, triage, and payload synthesis calls to the configured
    LLM endpoint. Automatically enables extended thinking (reasoning tokens)
    when configured.

    Args:
        cfg: AIConfig section from the NIGHTFALL configuration.
    """

    def __init__(self, cfg: AIConfig):
        self.provider = cfg.provider
        self.base_url = cfg.base_url.rstrip("/")
        self.model = cfg.model
        self.thinking = cfg.thinking
        self.thinking_budget = cfg.thinking_budget
        self.max_tokens = cfg.max_tokens
        self.api_key = cfg.resolved_api_key
        self.temperature = cfg.temperature

        # Audit log — every reasoning call is recorded
        self._audit_log: list[dict] = []

        logger.info(
            "model_client_initialized",
            provider=self.provider,
            model=self.model,
            thinking=self.thinking,
            base_url=self.base_url,
        )

    async def think(
        self,
        system: str,
        prompt: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict:
        """Send a reasoning request to the configured LLM.

        The extended thinking flag activates deliberative mode for plan/triage
        calls — reasoning tokens are generated but stripped from the final answer.

        Args:
            system: System prompt (role instructions).
            prompt: User prompt (the actual question/task).
            temperature: Override default temperature.
            max_tokens: Override default max tokens.

        Returns:
            Parsed JSON dict from the model response. Falls back to
            {"error": "<raw text>"} if JSON parsing fails.
        """
        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens or self.max_tokens
        start = time.monotonic()

        try:
            if self.provider == "anthropic":
                result = await self._call_anthropic(system, prompt, temp, tokens)
            else:
                result = await self._call_openai_compat(system, prompt, temp, tokens)

            elapsed = round(time.monotonic() - start, 2)

            # Log for audit trail
            self._audit_log.append({
                "timestamp": time.time(),
                "elapsed_s": elapsed,
                "system_snip": system[:200],
                "prompt_snip": prompt[:500],
                "result_snip": str(result)[:500],
            })

            logger.info(
                "model_think_complete",
                elapsed_s=elapsed,
                result_keys=list(result.keys()) if isinstance(result, dict) else "non-dict",
            )
            return result

        except Exception as exc:
            elapsed = round(time.monotonic() - start, 2)
            logger.error("model_think_error", error=str(exc), elapsed_s=elapsed)
            return {"error": str(exc)}

    async def _call_anthropic(
        self, system: str, prompt: str, temperature: float, max_tokens: int
    ) -> dict:
        """Call the Anthropic Messages API with optional extended thinking."""
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "user", "content": prompt},
            ],
        }

        # System prompt handling for Anthropic
        payload["system"] = system

        # Extended thinking configuration
        if self.thinking == "extended":
            payload["thinking"] = {
                "type": "enabled",
                "budget_tokens": self.thinking_budget,
            }
            # Anthropic requires temperature=1 with extended thinking,
            # or we omit temperature entirely
        else:
            payload["temperature"] = temperature

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/messages",
                headers=headers,
                json=payload,
                timeout=180.0,
            )
            response.raise_for_status()

        body = response.json()

        # Extract text from content blocks, stripping thinking blocks
        text = ""
        thinking_text = ""
        for block in body.get("content", []):
            if block.get("type") == "thinking":
                thinking_text += block.get("thinking", "")
            elif block.get("type") == "text":
                text += block.get("text", "")

        if thinking_text:
            logger.debug("model_thinking_trace", thinking_snip=thinking_text[:500])

        return self._parse_json(text)

    async def _call_openai_compat(
        self, system: str, prompt: str, temperature: float, max_tokens: int
    ) -> dict:
        """Call an OpenAI-compatible /chat/completions endpoint."""
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=180.0,
            )
            response.raise_for_status()

        body = response.json()
        text = body["choices"][0]["message"]["content"]
        return self._parse_json(text)

    @staticmethod
    def _parse_json(text: str) -> dict:
        """Extract JSON from model response text.

        Handles cases where the model wraps JSON in markdown code fences
        or includes prose before/after the JSON object.
        """
        text = text.strip()

        # Try direct parse first
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass

        # Strip markdown code fences
        if "```json" in text:
            text = text.split("```json", 1)[1]
            if "```" in text:
                text = text.split("```", 1)[0]
            try:
                return json.loads(text.strip())
            except (json.JSONDecodeError, ValueError):
                pass

        if "```" in text:
            parts = text.split("```")
            if len(parts) >= 3:
                try:
                    return json.loads(parts[1].strip())
                except (json.JSONDecodeError, ValueError):
                    pass

        # Find the first { ... } block
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            return json.loads(text[start:end])
        except (ValueError, json.JSONDecodeError):
            pass

        # Last resort
        return {"error": text[:2000]}

    @property
    def audit_log(self) -> list[dict]:
        return self._audit_log

    @classmethod
    def from_config(cls, cfg) -> "ModelClient":
        """Build a ModelClient from a NightfallConfig."""
        return cls(cfg.ai)
