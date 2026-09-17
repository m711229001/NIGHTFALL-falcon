"""
NIGHTFALL configuration model.

Pydantic-based config with YAML loading and environment variable interpolation.
Every component reads from a single Config instance — no scattered magic strings.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, Field, field_validator


# ── Sub-models ───────────────────────────────────────────────────────────────

class AIConfig(BaseModel):
    provider: Literal["anthropic", "openai", "custom"] = "anthropic"
    base_url: str = "https://api.anthropic.com/v1"
    model: str = "claude-sonnet-4-20250514"
    thinking: Literal["extended", "off"] = "extended"
    thinking_budget: int = 4096
    max_tokens: int = 8192
    api_key: str = ""
    temperature: float = 0.1

    @property
    def resolved_api_key(self) -> str:
        """Prefer MODEL_API_KEY env var over config file."""
        return os.environ.get("MODEL_API_KEY", "") or self.api_key


class SessionConfig(BaseModel):
    cookies: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)


class OASTConfig(BaseModel):
    enabled: bool = True
    domain: str = "o.nightfall.local"
    server: str = "0.0.0.0"
    dns_port: int = 5353
    http_port: int = 8089
    poll_timeout: int = 8


class CrawlerConfig(BaseModel):
    max_depth: int = 5
    max_pages: int = 500
    respect_robots: bool = False
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 NIGHTFALL/1.0"
    )
    headless: bool = True


class ReportConfig(BaseModel):
    output_dir: str = "reports"
    formats: List[str] = Field(default_factory=lambda: ["markdown", "sarif"])
    include_evidence: bool = True
    include_remediation: bool = True


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str = "nightfall.log"
    structured: bool = True


# ── Root Config ──────────────────────────────────────────────────────────────

class NightfallConfig(BaseModel):
    """Root configuration model for the entire NIGHTFALL platform."""

    targets: List[str] = Field(default_factory=list)
    deny_hosts: List[str] = Field(default_factory=list)
    allow_private: bool = False

    total_requests: int = 10000
    workers: int = 8
    rate_limit_per_host: float = 30.0
    burst: int = 5

    proxy: Optional[str] = None
    exploit_mode: Literal["off", "confirm"] = "confirm"
    destructive: bool = False

    ai: AIConfig = Field(default_factory=AIConfig)
    sessions: Dict[str, SessionConfig] = Field(default_factory=dict)
    oast: OASTConfig = Field(default_factory=OASTConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("targets")
    @classmethod
    def targets_not_empty(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one target host must be specified")
        return v

    @field_validator("proxy", mode="before")
    @classmethod
    def empty_proxy_to_none(cls, v: Any) -> Optional[str]:
        if v == "" or v is None:
            return None
        return v


# ── Loader ───────────────────────────────────────────────────────────────────

def _interpolate_env(data: Any) -> Any:
    """Recursively replace ${ENV_VAR} patterns with environment values."""
    if isinstance(data, str):
        import re
        def _sub(m: re.Match) -> str:
            return os.environ.get(m.group(1), m.group(0))
        return re.sub(r"\$\{(\w+)\}", _sub, data)
    elif isinstance(data, dict):
        return {k: _interpolate_env(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_interpolate_env(i) for i in data]
    return data


def load_config(path: str | Path) -> NightfallConfig:
    """Load config from a YAML file with environment variable interpolation."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raw = {}

    raw = _interpolate_env(raw)

    # Normalize sessions: YAML maps to Dict[str, SessionConfig]
    if "sessions" in raw and isinstance(raw["sessions"], dict):
        for name, sess in raw["sessions"].items():
            if isinstance(sess, dict):
                raw["sessions"][name] = SessionConfig(**sess)

    return NightfallConfig(**raw)


def default_config() -> NightfallConfig:
    """Return a config instance with sensible defaults (no file needed)."""
    return NightfallConfig(
        targets=["localhost"],
        sessions={"default": SessionConfig()},
    )
