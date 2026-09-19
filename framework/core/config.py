"""Falcon MAG Framework - Configuration Loader"""
import yaml
from pathlib import Path
from urllib.parse import urlparse


FRAMEWORK_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = FRAMEWORK_DIR / "config.yaml"


def load_config(path=None) -> dict:
    """Load config from YAML file."""
    path = Path(path) if path else DEFAULT_CONFIG
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def apply_target(config: dict, target: str) -> dict:
    """Apply target URL to config, auto-deriving scope."""
    config["target"] = target
    host = urlparse(target).hostname
    if host:
        config["scope"] = [host]
    return config


def apply_modules(config: dict, modules_str) -> dict:
    """Enable only the given modules (accepts list or comma-separated string)."""
    if isinstance(modules_str, (list, tuple)):
        enabled = {str(m).strip() for m in modules_str if str(m).strip()}
    else:
        enabled = {m.strip() for m in str(modules_str).split(",") if m.strip()}
    for k in config.get("modules", {}):
        config["modules"][k] = k in enabled
    return config


def enable_all_modules(config: dict) -> dict:
    for k in config.get("modules", {}):
        config["modules"][k] = True
    return config


def disable_all_modules(config: dict) -> dict:
    for k in config.get("modules", {}):
        config["modules"][k] = False
    return config


def get_enabled_modules(config: dict) -> list:
    return [k for k, v in config.get("modules", {}).items() if v]


def get_wordlist(config: dict, name: str) -> Path:
    """Get full path to a wordlist."""
    rel = config.get("wordlists", {}).get(name, "")
    if not rel:
        return None
    p = Path(rel)
    if not p.is_absolute():
        p = FRAMEWORK_DIR / p
    return p