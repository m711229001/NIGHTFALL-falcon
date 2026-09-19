"""Profile management for Falcon MAG."""
import json
from pathlib import Path
from typing import Optional, List


PROFILES_DIR = Path(__file__).resolve().parent.parent.parent / "profiles"


def load_profile(name: str) -> Optional[dict]:
    """Load a profile by name (JSON)."""
    if not name:
        return None
    safe_name = Path(name).name
    path = PROFILES_DIR / f"{safe_name}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def list_profiles() -> List[str]:
    """List all saved profile names (without .json extension)."""
    if not PROFILES_DIR.exists():
        return []
    return sorted(p.stem for p in PROFILES_DIR.glob("*.json"))


def save_profile(name: str, data: dict) -> Optional[Path]:
    """Save a profile to disk."""
    if not name:
        return None
    safe_name = Path(name).name
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    path = PROFILES_DIR / f"{safe_name}.json"
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return path
    except Exception:
        return None


def delete_profile(name: str) -> bool:
    """Delete a profile. Returns True if deleted."""
    if not name:
        return False
    safe_name = Path(name).name
    path = PROFILES_DIR / f"{safe_name}.json"
    if path.exists():
        try:
            path.unlink()
            return True
        except Exception:
            return False
    return False