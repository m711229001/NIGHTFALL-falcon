"""
Falcon MAG — AI Provider Configuration API
==========================================
واجهة REST لإدارة مزوّدي AI مع تشفير المفاتيح.

Endpoints:
    GET    /api/ai/providers              → قائمة المزودين المعروفين + state
    GET    /api/ai/config                 → الإعدادات الحالية (بدون مفاتيح)
    POST   /api/ai/config                 → حفظ مزود
    POST   /api/ai/activate               → تفعيل مزود
    DELETE /api/ai/config/{provider}      → حذف مزود
    POST   /api/ai/test                   → اختبار الاتصال
    GET    /api/ai/models/{provider}      → موديلات مزود
    POST   /api/ai/clear                  → مسح كل الإعدادات

الأمان:
    - كل المسارات تتطلب JWT (عبر get_current_user من core.security)
    - api_key لا يُرجع أبداً — فقط configured: true/false
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

# ============================================================
# Bridge: framework/ ← backend/
# ============================================================
# WHY: 'core' exists in BOTH /app/core (backend) and /app/framework/core.
# sys.path insertion caused naming collision. We load by absolute path instead.
# ------------------------------------------------------------

_NIGHTFALL_DIR = os.getenv("NIGHTFALL_DIR", "/app")
_FRAMEWORK_DIR = Path(_NIGHTFALL_DIR) / "framework"
_AI_CONFIG_STORE = _FRAMEWORK_DIR / "core" / "ai_config_store.py"
_LOGGER_PATH = _FRAMEWORK_DIR / "core" / "logger.py"

if not _AI_CONFIG_STORE.exists():
    raise RuntimeError(
        f"Cannot find {_AI_CONFIG_STORE}. "
        f"Check NIGHTFALL_DIR env var and volume mounts."
    )

# --- Load framework/core/logger.py first (as 'falcon_core_logger') ---
if _LOGGER_PATH.exists():
    _logger_spec = importlib.util.spec_from_file_location(
        "falcon_core_logger", str(_LOGGER_PATH)
    )
    if _logger_spec and _logger_spec.loader:
        _logger_module = importlib.util.module_from_spec(_logger_spec)
        sys.modules["falcon_core_logger"] = _logger_module
        # Alias so ai_config_store's `from core.logger import get_logger` works
        sys.modules["core.logger"] = _logger_module
        _logger_spec.loader.exec_module(_logger_module)

# --- Load framework/core/ai_config_store.py (as 'falcon_ai_config_store') ---
_spec = importlib.util.spec_from_file_location(
    "falcon_ai_config_store", str(_AI_CONFIG_STORE)
)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"Cannot load {_AI_CONFIG_STORE}")

_ai_module = importlib.util.module_from_spec(_spec)
sys.modules["falcon_ai_config_store"] = _ai_module
_spec.loader.exec_module(_ai_module)

KNOWN_PROVIDERS = _ai_module.KNOWN_PROVIDERS
get_ai_config = _ai_module.get_ai_config


# ============================================================
# Auth dependency — من core.security (backend's core)
# ============================================================
try:
    from core.security import get_current_user  # type: ignore
except ImportError:
    # Fallback مؤقت — للتطوير فقط
    async def get_current_user():  # type: ignore
        return {"username": "dev"}


# ============================================================
# Router
# ============================================================

router = APIRouter(prefix="/api/ai", tags=["AI Config"])


# ============================================================
# Pydantic Models
# ============================================================

class ProviderConfigIn(BaseModel):
    provider: str = Field(..., min_length=1, max_length=64)
    api_key: str = Field(default="", max_length=512)
    model: str = Field(..., min_length=1, max_length=128)
    base_url: Optional[str] = Field(default=None, max_length=512)


class ActivateIn(BaseModel):
    provider: str = Field(..., min_length=1, max_length=64)


class TestIn(BaseModel):
    provider: Optional[str] = Field(
        default=None,
        description="إذا فارغ → يستخدم المزود النشط حالياً",
    )
    api_key: Optional[str] = Field(default=None, max_length=512)
    model: Optional[str] = Field(default=None, max_length=128)
    base_url: Optional[str] = Field(default=None, max_length=512)


# ============================================================
# Endpoints — Read
# ============================================================

@router.get("/providers")
async def list_providers(_user=Depends(get_current_user)) -> dict[str, Any]:
    """يرجع قائمة المزودين المعروفين + الحالة الحالية."""
    cfg = get_ai_config()
    state = cfg.get_raw()
    return {
        "known": KNOWN_PROVIDERS,
        "configured": state.get("providers", {}),
        "active_provider": state.get("active_provider"),
        "updated_at": state.get("updated_at"),
    }


@router.get("/config")
async def get_config(_user=Depends(get_current_user)) -> dict[str, Any]:
    """يرجع الإعدادات الحالية (بدون مفاتيح)."""
    cfg = get_ai_config()
    return cfg.get_raw()


@router.get("/models/{provider}")
async def get_models(
    provider: str,
    _user=Depends(get_current_user),
) -> dict[str, Any]:
    """يرجع قائمة الموديلات المعروفة لمزود."""
    provider = provider.strip().lower()
    if provider not in KNOWN_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown provider: {provider}",
        )
    tpl = KNOWN_PROVIDERS[provider]
    return {
        "provider": provider,
        "label": tpl.get("label"),
        "models": tpl.get("models", []),
        "base_url": tpl.get("base_url"),
        "docs_url": tpl.get("docs_url"),
    }


# ============================================================
# Endpoints — Write
# ============================================================

@router.post("/config")
async def save_provider(
    body: ProviderConfigIn,
    _user=Depends(get_current_user),
) -> dict[str, Any]:
    """يحفظ مزوداً ويشفّر المفتاح."""
    provider = body.provider.strip().lower()
    if provider not in KNOWN_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown provider: {provider}. "
                   f"Known: {', '.join(KNOWN_PROVIDERS.keys())}",
        )
    try:
        cfg = get_ai_config()
        result = cfg.set_provider(
            name=provider,
            api_key=body.api_key,
            model=body.model,
            base_url=body.base_url,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    return {
        "ok": True,
        "message": f"Provider '{provider}' saved",
        "config": result,
    }


@router.post("/activate")
async def activate_provider(
    body: ActivateIn,
    _user=Depends(get_current_user),
) -> dict[str, Any]:
    """يفعّل مزوداً مُعدّاً."""
    provider = body.provider.strip().lower()
    try:
        cfg = get_ai_config()
        result = cfg.activate(provider)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    return {
        "ok": True,
        "message": f"Provider '{provider}' activated",
        "config": result,
    }


@router.delete("/config/{provider}")
async def delete_provider(
    provider: str,
    _user=Depends(get_current_user),
) -> dict[str, Any]:
    """يحذف مزوداً."""
    provider = provider.strip().lower()
    cfg = get_ai_config()
    result = cfg.delete_provider(provider)
    return {
        "ok": True,
        "message": f"Provider '{provider}' deleted",
        "config": result,
    }


@router.post("/clear")
async def clear_all(_user=Depends(get_current_user)) -> dict[str, Any]:
    """يمسح كل إعدادات AI."""
    cfg = get_ai_config()
    result = cfg.clear_all()
    return {
        "ok": True,
        "message": "All AI config cleared",
        "config": result,
    }


# ============================================================
# Test Connection
# ============================================================

@router.post("/test")
async def test_connection(
    body: TestIn,
    _user=Depends(get_current_user),
) -> dict[str, Any]:
    """يختبر الاتصال بمزود AI."""
    cfg = get_ai_config()

    # 1. حل المزود
    if body.provider:
        provider_name = body.provider.strip().lower()
        if provider_name not in KNOWN_PROVIDERS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown provider: {provider_name}",
            )
        template = KNOWN_PROVIDERS[provider_name]
        saved = cfg.get_raw().get("providers", {}).get(provider_name, {})
        api_key = body.api_key or ""
        model = body.model or saved.get("model") or template["models"][0]
        base_url = body.base_url or saved.get("base_url") or template["base_url"]
    else:
        active = cfg.get_active_provider()
        if not active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No active provider configured",
            )
        provider_name = active["name"]
        template = KNOWN_PROVIDERS.get(provider_name, {})
        api_key = body.api_key or active["api_key"]
        model = body.model or active["model"]
        base_url = body.base_url or active["base_url"]

    # 2. تحقق المفتاح
    no_key = template.get("no_key_required", False)
    if not no_key and not api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"API key required for '{provider_name}'",
        )

    # 3. URL للاختبار
    url = base_url.rstrip("/") + "/models"
    headers = _build_headers(template, api_key)

    # 4. إرسال
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)
    except httpx.ConnectError as e:
        return {
            "ok": False,
            "provider": provider_name,
            "error": f"Connection failed: {e}",
        }
    except httpx.TimeoutException:
        return {
            "ok": False,
            "provider": provider_name,
            "error": "Timeout (15s)",
        }
    except Exception as e:
        return {
            "ok": False,
            "provider": provider_name,
            "error": f"Unexpected error: {e}",
        }

    # 5. تحليل
    if resp.status_code == 200:
        return {
            "ok": True,
            "provider": provider_name,
            "model": model,
            "status_code": resp.status_code,
            "message": "Connection successful ✓",
        }
    elif resp.status_code in (401, 403):
        return {
            "ok": False,
            "provider": provider_name,
            "status_code": resp.status_code,
            "error": "Authentication failed — check API key",
        }
    elif resp.status_code == 404:
        return {
            "ok": True,
            "provider": provider_name,
            "model": model,
            "status_code": resp.status_code,
            "message": "Reachable (models endpoint not supported)",
        }
    else:
        return {
            "ok": False,
            "provider": provider_name,
            "status_code": resp.status_code,
            "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
        }


# ============================================================
# Helpers
# ============================================================

def _build_headers(template: dict, api_key: str) -> dict[str, str]:
    """يبني headers المصادقة حسب المزود."""
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    auth_header = template.get("auth_header", "Authorization")
    auth_prefix = template.get("auth_prefix", "Bearer ")
    if api_key:
        headers[auth_header] = f"{auth_prefix}{api_key}"
    return headers