"""
Falcon MAG — AI Config Store
=============================
مخزن إعدادات AI مشفّر + hot reload

Features:
  - تشفير API keys بـ Fernet (AES-128 in CBC + HMAC-SHA256)
  - حفظ في framework/config/ai_config.json
  - دعم عدة مزودين + تبديل سريع
  - Auto-reload عند تغيير الملف
  - Master key من .env (AI_MASTER_KEY) أو توليد تلقائي

Usage:
    from core.ai_config_store import get_ai_config

    cfg = get_ai_config()
    provider = cfg.get_active_provider()   # {"name": "deepseek", "key": "...", "model": "..."}
"""

from __future__ import annotations

import base64
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.logger import get_logger

log = get_logger("ai_config_store")


# ============================================================
# Constants
# ============================================================

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
CONFIG_FILE = CONFIG_DIR / "ai_config.json"
MASTER_KEY_FILE = CONFIG_DIR / ".ai_master_key"

# مزودون معروفون — يُستخدمون كقوالب في الواجهة
KNOWN_PROVIDERS: dict[str, dict[str, Any]] = {
    "deepseek": {
        "label": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "docs_url": "https://platform.deepseek.com/api_keys",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
    },
    "openai": {
        "label": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o3-mini", "o1-mini"],
        "docs_url": "https://platform.openai.com/api-keys",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
    },
    "anthropic": {
        "label": "Anthropic Claude",
        "base_url": "https://api.anthropic.com/v1",
        "models": [
            "claude-sonnet-4-5-20250929",
            "claude-opus-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
        ],
        "docs_url": "https://console.anthropic.com/settings/keys",
        "auth_header": "x-api-key",
        "auth_prefix": "",
    },
    "gemini": {
        "label": "Google Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "models": ["gemini-2.0-flash-exp", "gemini-1.5-pro", "gemini-1.5-flash"],
        "docs_url": "https://aistudio.google.com/app/apikey",
        "auth_header": "x-goog-api-key",
        "auth_prefix": "",
    },
    "groq": {
        "label": "Groq",
        "base_url": "https://api.groq.com/openai/v1",
        "models": [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "mixtral-8x7b-32768",
        ],
        "docs_url": "https://console.groq.com/keys",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
    },
    "mistral": {
        "label": "Mistral AI",
        "base_url": "https://api.mistral.ai/v1",
        "models": ["mistral-large-latest", "mistral-small-latest", "codestral-latest"],
        "docs_url": "https://console.mistral.ai/api-keys/",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
    },
    "openrouter": {
        "label": "OpenRouter",
        "base_url": "https://openrouter.ai/api/v1",
        "models": [
            "anthropic/claude-3.5-sonnet",
            "openai/gpt-4o",
            "google/gemini-2.0-flash-exp:free",
            "meta-llama/llama-3.3-70b-instruct",
        ],
        "docs_url": "https://openrouter.ai/keys",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
    },
    "together": {
        "label": "Together AI",
        "base_url": "https://api.together.xyz/v1",
        "models": [
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "Qwen/Qwen2.5-72B-Instruct-Turbo",
            "mistralai/Mixtral-8x7B-Instruct-v0.1",
        ],
        "docs_url": "https://api.together.xyz/settings/api-keys",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
    },
    "ollama": {
        "label": "Ollama (Local)",
        "base_url": "http://host.docker.internal:11434/v1",
        "models": ["llama3.1:8b", "qwen2.5:7b", "mistral:7b", "codellama:13b"],
        "docs_url": "https://ollama.com/download",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "no_key_required": True,
    },
}

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "active_provider": None,
    "providers": {},  # name -> {"key_encrypted": "...", "model": "...", "base_url": "...", "updated_at": "..."}
    "updated_at": None,
}


# ============================================================
# Master Key Management
# ============================================================

def _get_or_create_master_key() -> bytes:
    """
    يحصل على Master Key من:
    1. متغير البيئة AI_MASTER_KEY
    2. ملف CONFIG_DIR/.ai_master_key
    3. يولّد مفتاحاً جديداً ويحفظه
    """
    # 1. من env
    env_key = os.getenv("AI_MASTER_KEY", "").strip()
    if env_key:
        try:
            return env_key.encode("utf-8") if len(env_key) == 44 else _derive_from_password(env_key)
        except Exception as e:
            log.warning(f"AI_MASTER_KEY invalid: {e}, falling back to file")

    # 2. من ملف
    if MASTER_KEY_FILE.exists():
        return MASTER_KEY_FILE.read_bytes().strip()

    # 3. توليد جديد
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    new_key = Fernet.generate_key()
    MASTER_KEY_FILE.write_bytes(new_key)
    try:
        os.chmod(MASTER_KEY_FILE, 0o600)
    except Exception:
        pass  # Windows قد لا يدعم chmod
    log.info(f"✓ Generated new AI master key at {MASTER_KEY_FILE}")
    return new_key


def _derive_from_password(password: str) -> bytes:
    """يشتق مفتاح Fernet من كلمة مرور نصية."""
    salt = b"falcon_mag_ai_salt_v1"  # ثابت — ليس مثالياً لكنه أفضل من plaintext
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key


# ============================================================
# AI Config Store
# ============================================================

class AIConfigStore:
    """
    مخزن إعدادات AI — thread-safe + hot reload.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._fernet: Optional[Fernet] = None
        self._config: dict[str, Any] = dict(DEFAULT_CONFIG)
        self._last_mtime: float = 0.0
        self._ensure_loaded()

    # --------------------------------------------------------
    # Encryption
    # --------------------------------------------------------

    @property
    def fernet(self) -> Fernet:
        if self._fernet is None:
            key = _get_or_create_master_key()
            self._fernet = Fernet(key)
        return self._fernet

    def _encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        token = self.fernet.encrypt(plaintext.encode("utf-8"))
        return token.decode("ascii")

    def _decrypt(self, token: str) -> str:
        if not token:
            return ""
        try:
            return self.fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken:
            log.error("✗ Failed to decrypt key — master key changed?")
            return ""
        except Exception as e:
            log.error(f"✗ Decrypt error: {e}")
            return ""

    # --------------------------------------------------------
    # Load / Save
    # --------------------------------------------------------

    def _ensure_loaded(self) -> None:
        """يحمّل الإعدادات من القرص + auto-reload إذا تغير الملف."""
        with self._lock:
            if not CONFIG_FILE.exists():
                self._config = dict(DEFAULT_CONFIG)
                self._last_mtime = 0.0
                return

            try:
                mtime = CONFIG_FILE.stat().st_mtime
                if mtime == self._last_mtime:
                    return  # لا تغيير
                with CONFIG_FILE.open("r", encoding="utf-8") as f:
                    self._config = json.load(f)
                self._last_mtime = mtime
            except Exception as e:
                log.error(f"✗ Failed to load ai_config.json: {e}")
                self._config = dict(DEFAULT_CONFIG)

    def _save(self) -> None:
        """يحفظ الإعدادات على القرص (atomic)."""
        with self._lock:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            self._config["updated_at"] = _now_iso()
            tmp = CONFIG_FILE.with_suffix(".json.tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
            tmp.replace(CONFIG_FILE)
            self._last_mtime = CONFIG_FILE.stat().st_mtime

    # --------------------------------------------------------
    # Public API — Read
    # --------------------------------------------------------

    def get_raw(self) -> dict[str, Any]:
        """يرجع النسخة الكاملة (بدون فك تشفير — آمن للـ API العام)."""
        self._ensure_loaded()
        with self._lock:
            return {
                "version": self._config.get("version", 1),
                "active_provider": self._config.get("active_provider"),
                "providers": {
                    name: {
                        "configured": bool(p.get("key_encrypted")) or bool(p.get("no_key")),
                        "model": p.get("model"),
                        "base_url": p.get("base_url"),
                        "updated_at": p.get("updated_at"),
                    }
                    for name, p in self._config.get("providers", {}).items()
                },
                "updated_at": self._config.get("updated_at"),
            }

    def get_active_provider(self) -> Optional[dict[str, Any]]:
        """
        يرجع المزود النشط مع المفتاح مفكوك التشفير.
        """
        self._ensure_loaded()
        with self._lock:
            name = self._config.get("active_provider")
            if not name:
                return None
            p = self._config.get("providers", {}).get(name)
            if not p:
                return None

            template = KNOWN_PROVIDERS.get(name, {})
            return {
                "name": name,
                "label": template.get("label", name),
                "api_key": self._decrypt(p.get("key_encrypted", "")),
                "model": p.get("model") or (template.get("models", [None])[0]),
                "base_url": p.get("base_url") or template.get("base_url", ""),
                "auth_header": template.get("auth_header", "Authorization"),
                "auth_prefix": template.get("auth_prefix", "Bearer "),
                "no_key_required": template.get("no_key_required", False),
            }

    # --------------------------------------------------------
    # Public API — Write
    # --------------------------------------------------------

    def set_provider(
        self,
        name: str,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
    ) -> dict[str, Any]:
        """يضبط مزوداً ويحفظه. يُفعّله تلقائياً إذا لم يوجد مزود نشط."""
        name = name.strip().lower()
        if not name:
            raise ValueError("Provider name is required")

        template = KNOWN_PROVIDERS.get(name, {})
        no_key = template.get("no_key_required", False)

        if not no_key and not api_key:
            raise ValueError(f"API key is required for provider '{name}'")

        with self._lock:
            self._ensure_loaded()
            providers = self._config.setdefault("providers", {})
            providers[name] = {
                "key_encrypted": self._encrypt(api_key) if api_key else "",
                "model": model or template.get("models", [""])[0],
                "base_url": base_url or template.get("base_url", ""),
                "no_key": no_key,
                "updated_at": _now_iso(),
            }
            # إذا لم يوجد مزود نشط، فعّل هذا
            if not self._config.get("active_provider"):
                self._config["active_provider"] = name
            self._save()

        log.info(f"✓ Provider '{name}' saved (model={model})")
        return self.get_raw()

    def activate(self, name: str) -> dict[str, Any]:
        """يفعّل مزوداً موجوداً."""
        name = name.strip().lower()
        with self._lock:
            self._ensure_loaded()
            providers = self._config.get("providers", {})
            if name not in providers:
                raise ValueError(f"Provider '{name}' not configured")
            self._config["active_provider"] = name
            self._save()
        log.info(f"✓ Activated provider '{name}'")
        return self.get_raw()

    def delete_provider(self, name: str) -> dict[str, Any]:
        """يحذف مزوداً. إذا كان النشط، يفرّغ التفعيل."""
        name = name.strip().lower()
        with self._lock:
            self._ensure_loaded()
            providers = self._config.get("providers", {})
            providers.pop(name, None)
            if self._config.get("active_provider") == name:
                self._config["active_provider"] = None
            self._save()
        log.info(f"✓ Deleted provider '{name}'")
        return self.get_raw()

    def clear_all(self) -> dict[str, Any]:
        """يمسح كل الإعدادات."""
        with self._lock:
            self._config = dict(DEFAULT_CONFIG)
            self._save()
        log.warning("⚠ All AI config cleared")
        return self.get_raw()


# ============================================================
# Helpers
# ============================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ============================================================
# Singleton
# ============================================================

_instance: Optional[AIConfigStore] = None
_instance_lock = threading.Lock()


def get_ai_config() -> AIConfigStore:
    """Singleton accessor."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = AIConfigStore()
    return _instance


# ============================================================
# CLI quick test
# ============================================================

if __name__ == "__main__":
    cfg = get_ai_config()
    print("Config file:", CONFIG_FILE)
    print("Master key file:", MASTER_KEY_FILE)
    print("Known providers:", ", ".join(KNOWN_PROVIDERS.keys()))
    print("Current state:")
    print(json.dumps(cfg.get_raw(), indent=2, ensure_ascii=False))