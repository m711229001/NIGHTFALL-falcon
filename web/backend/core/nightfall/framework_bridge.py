"""Falcon MAG — Framework Bridge

طبقة ربط بين nightfall_core (Async) و framework/ (Sync).

الهدف: إعادة استخدام المنطق المُختبَر من framework/modules/ بدون تكرار.

هذا الملف يوفر:
  1. sys.path setup للوصول إلى framework/.
  2. Re-exports للثوابت والدوال المساعدة من framework.
  3. Async wrappers عند الحاجة.

لا يحتوي على أي منطق سكان — فقط re-exports + helpers.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# ============================================================
# 1. Path Setup
# ============================================================
# framework_bridge.py موجود في:
#   web/backend/core/nightfall/framework_bridge.py
# framework/ موجود في:
#   <project_root>/framework/
#
# من هنا:
#   parent = core/nightfall/
#   parent.parent = core/
#   parent.parent.parent = backend/
#   parent.parent.parent.parent = web/
#   parent.parent.parent.parent.parent = project_root/

_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent.parent.parent.parent
_FRAMEWORK_DIR = _PROJECT_ROOT / "framework"

if not _FRAMEWORK_DIR.exists():
    raise RuntimeError(
        f"framework/ not found. Tried: {_FRAMEWORK_DIR}\n"
        f"Bridge file: {_THIS_FILE}"
    )

if str(_FRAMEWORK_DIR) not in sys.path:
    sys.path.insert(0, str(_FRAMEWORK_DIR))

# Metadata
FRAMEWORK_DIR = _FRAMEWORK_DIR
PROJECT_ROOT = _PROJECT_ROOT


# ============================================================
# 2. Framework Helpers — Re-exports
# ============================================================
# نستورد فقط الدوال المساعدة والثوابت، ليس حلقات التشغيل.
# عند استبدال كل دالة في nightfall_core، سنستورد المساعدات من هنا.

# ── XSS Scanner Helpers ──────────────────────────────────────
try:
    from modules.xss_scanner import (
        PAYLOADS as XSS_PAYLOADS,
        MARKER as XSS_MARKER,
        _verify_reflection as xss_verify_reflection,
        _find_context as xss_find_context,
        _inject_param as xss_inject_param,
    )
    HAS_XSS_HELPERS = True
except ImportError as e:
    HAS_XSS_HELPERS = False
    _xss_import_error = str(e)


# ── SQLi Scanner Helpers ─────────────────────────────────────
try:
    from modules.sqli_scanner import (
        ERROR_SIGNATURES as SQLI_ERROR_SIGNATURES,
        AUTH_BYPASS_PAYLOADS as SQLI_AUTH_BYPASS_PAYLOADS,
        ERROR_PAYLOADS as SQLI_ERROR_PAYLOADS,
        BOOLEAN_TRUE as SQLI_BOOLEAN_TRUE,
        BOOLEAN_FALSE as SQLI_BOOLEAN_FALSE,
        SLEEP_PAYLOADS as SQLI_SLEEP_PAYLOADS,
        _has_db_error as sqli_has_db_error,
        _looks_like_error as sqli_looks_like_error,
        _inject as sqli_inject,
        _body_replace as sqli_body_replace,
    )
    HAS_SQLI_HELPERS = True
except ImportError as e:
    HAS_SQLI_HELPERS = False
    _sqli_import_error = str(e)


# ── SSRF Scanner Helpers ─────────────────────────────────────
try:
    from modules.ssrf_scanner import (
        _inject as ssrf_inject,
    )
    HAS_SSRF_HELPERS = True
except ImportError as e:
    HAS_SSRF_HELPERS = False
    _ssrf_import_error = str(e)


# ── Open Redirect Helpers ────────────────────────────────────
try:
    from modules.open_redirect import (
        _inject as redirect_inject,
        _is_redirect_to_evil as redirect_is_evil,
    )
    HAS_REDIRECT_HELPERS = True
except ImportError as e:
    HAS_REDIRECT_HELPERS = False
    _redirect_import_error = str(e)


# ── CSRF Checker Helpers ─────────────────────────────────────
try:
    from modules.csrf_checker import (
        _has_csrf_token as csrf_has_token,
    )
    HAS_CSRF_HELPERS = True
except ImportError as e:
    HAS_CSRF_HELPERS = False
    _csrf_import_error = str(e)


# ── NoSQL Scanner Helpers ────────────────────────────────────
try:
    from modules.nosql_scanner import (
        _inject_raw as nosql_inject_raw,
    )
    HAS_NOSQL_HELPERS = True
except ImportError as e:
    HAS_NOSQL_HELPERS = False
    _nosql_import_error = str(e)


# ── IDOR Scanner Helpers ─────────────────────────────────────
try:
    from modules.idor_scanner import (
        _inject as idor_inject,
    )
    HAS_IDOR_HELPERS = True
except ImportError as e:
    HAS_IDOR_HELPERS = False
    _idor_import_error = str(e)


# ============================================================
# 3. Diagnostics
# ============================================================
def bridge_status() -> dict:
    """تشخيص حالة الـ bridge — مفيد للـ smoke testing."""
    return {
        "framework_dir": str(FRAMEWORK_DIR),
        "framework_exists": FRAMEWORK_DIR.exists(),
        "project_root": str(PROJECT_ROOT),
        "helpers": {
            "xss": HAS_XSS_HELPERS,
            "sqli": HAS_SQLI_HELPERS,
            "ssrf": HAS_SSRF_HELPERS,
            "redirect": HAS_REDIRECT_HELPERS,
            "csrf": HAS_CSRF_HELPERS,
            "nosql": HAS_NOSQL_HELPERS,
            "idor": HAS_IDOR_HELPERS,
        },
    }


__all__ = [
    "FRAMEWORK_DIR",
    "PROJECT_ROOT",
    "bridge_status",
    # XSS
    "XSS_PAYLOADS",
    "XSS_MARKER",
    "xss_verify_reflection",
    "xss_find_context",
    "xss_inject_param",
    # SQLi
    "SQLI_ERROR_SIGNATURES",
    "SQLI_AUTH_BYPASS_PAYLOADS",
    "SQLI_ERROR_PAYLOADS",
    "SQLI_BOOLEAN_TRUE",
    "SQLI_BOOLEAN_FALSE",
    "SQLI_SLEEP_PAYLOADS",
    "sqli_has_db_error",
    "sqli_looks_like_error",
    "sqli_inject",
    "sqli_body_replace",
    # SSRF
    "ssrf_inject",
    # Redirect
    "redirect_inject",
    "redirect_is_evil",
    # CSRF
    "csrf_has_token",
    # NoSQL
    "nosql_inject_raw",
    # IDOR
    "idor_inject",
]
