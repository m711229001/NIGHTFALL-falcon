"""Falcon MAG - Cookie Loader (JSON + Netscape formats)"""
import json
from pathlib import Path
from typing import Optional

from core.logger import get_logger

log = get_logger("cookie_loader")


def load_cookie_json(path: str) -> Optional[str]:
    """Load cookies from a JSON file (Playwright storage_state or simple list).

    Supported formats:
    1. Playwright storage_state: {"cookies": [{"name":..., "value":...}, ...]}
    2. Simple list: [{"name":..., "value":...}, ...]
    3. Simple dict: {"session": "abc", "csrftoken": "xyz"}
    """
    p = Path(path)
    if not p.exists():
        log.error(f"Cookie file not found: {path}")
        return None

    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.error(f"Failed to parse JSON: {e}")
        return None

    # Format 1: Playwright storage_state
    if isinstance(data, dict) and "cookies" in data:
        cookies = data["cookies"]
        return _cookies_list_to_str(cookies)

    # Format 2: Simple list
    if isinstance(data, list):
        return _cookies_list_to_str(data)

    # Format 3: Simple dict
    if isinstance(data, dict):
        return _cookies_dict_to_str(data)

    log.error("Unknown cookie JSON format")
    return None


def load_cookie_netscape(path: str) -> Optional[str]:
    """Load cookies from a Netscape format file (curl/wget/Burp style).

    Format: domain<TAB>flag<TAB>path<TAB>secure<TAB>expiry<TAB>name<TAB>value
    Lines starting with '#' are comments.
    """
    p = Path(path)
    if not p.exists():
        log.error(f"Cookie file not found: {path}")
        return None

    cookies = []
    try:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    name = parts[5].strip()
                    value = parts[6].strip()
                    if name:
                        cookies.append(f"{name}={value}")
    except Exception as e:
        log.error(f"Failed to parse Netscape cookies: {e}")
        return None

    if not cookies:
        log.error("No valid cookies found in Netscape file")
        return None

    log.info(f"Loaded {len(cookies)} cookies from Netscape file")
    return "; ".join(cookies)


def auto_load_cookie_file(path: str) -> Optional[str]:
    """Auto-detect format (JSON or Netscape) and load cookies."""
    p = Path(path)
    if not p.exists():
        log.error(f"Cookie file not found: {path}")
        return None

    # Try JSON first
    try:
        with open(p, "r", encoding="utf-8") as f:
            first = f.read(1).strip()
        if first in ("{", "["):
            log.info("Detected JSON format")
            return load_cookie_json(path)
        else:
            log.info("Detected Netscape/text format")
            return load_cookie_netscape(path)
    except Exception as e:
        log.error(f"Auto-detect failed: {e}")
        return None


# ============================================================
# Internal helpers
# ============================================================

def _cookies_list_to_str(cookies: list) -> Optional[str]:
    """Convert list of cookie dicts to 'name=value; ...' string."""
    parts = []
    for c in cookies:
        if not isinstance(c, dict):
            continue
        name = c.get("name")
        value = c.get("value")
        if name and value is not None:
            parts.append(f"{name}={value}")
    if not parts:
        return None
    log.info(f"Loaded {len(parts)} cookies from JSON list")
    return "; ".join(parts)


def _cookies_dict_to_str(cookies: dict) -> Optional[str]:
    """Convert simple dict {name: value} to 'name=value; ...' string."""
    parts = [f"{k}={v}" for k, v in cookies.items() if v is not None]
    if not parts:
        return None
    log.info(f"Loaded {len(parts)} cookies from JSON dict")
    return "; ".join(parts)