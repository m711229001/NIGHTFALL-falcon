"""Falcon MAG - Auth API v2 (Playwright via framework/cli.py)

Adds Playwright-based login endpoints:
  - POST /api/v2/auth/login      -> runs cli.py login (background)
  - GET  /api/v2/auth/types      -> list supported auth types
  - GET  /api/v2/auth/login/{id} -> login status
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, List
import time
import threading
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.security import get_current_user
from services import cli_runner

router = APIRouter(prefix="/api/v2/auth", tags=["auth-v2"])


# ============================================================
# Supported auth types (from framework/core/auth/__init__.py)
# ============================================================
AUTH_TYPES = [
    {"name": "auto",   "description": "Detect login type automatically"},
    {"name": "basic",  "description": "Username + password (+ TOTP)"},
    {"name": "oauth",  "description": "OAuth2 / OIDC / 'Sign in with X'"},
    {"name": "saml",   "description": "SAML 2.0 SSO"},
    {"name": "nafath", "description": "Saudi National SSO (Nafath)"},
]


class LoginRequest(BaseModel):
    url: str
    auth_type: str = "auto"
    profile: str = "default"
    username: Optional[str] = None
    password: Optional[str] = None
    totp_secret: Optional[str] = None
    button_selector: Optional[str] = None
    otp_selector: Optional[str] = None
    wait: int = Field(240, ge=30, le=1800)
    headless: bool = False
    success_url: Optional[str] = None
    timeout: int = Field(600, ge=60, le=3600)


@router.get("/types")
async def list_auth_types():
    """Public - list available auth handlers."""
    return {"auth_types": AUTH_TYPES}


@router.post("/login")
async def login_v2(
    req: LoginRequest,
    user: dict = Depends(get_current_user),
):
    """Start a Playwright login (background). Poll /login/{id} for status."""
    if req.auth_type not in {t["name"] for t in AUTH_TYPES}:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown auth_type: {req.auth_type}. "
                   f"Valid: {', '.join(t['name'] for t in AUTH_TYPES)}",
        )

    login_id = f"login_{int(time.time())}"
    args = cli_runner.build_login_args(
        url=req.url,
        auth_type=req.auth_type,
        username=req.username,
        password=req.password,
        totp_secret=req.totp_secret,
        button_selector=req.button_selector,
        otp_selector=req.otp_selector,
        profile=req.profile,
        wait=req.wait,
        headless=req.headless,
        success_url=req.success_url,
    )

    # Register + start in background
    from services.cli_runner import ScanState, _register
    state = ScanState(scan_id=login_id, target=req.url)
    _register(state)

    t = threading.Thread(
        target=cli_runner.run_login_sync,
        args=(login_id, args, req.timeout),
        daemon=True,
    )
    t.start()

    return {
        "status": "started",
        "login_id": login_id,
        "url": req.url,
        "auth_type": req.auth_type,
        "profile": req.profile,
    }


@router.get("/login/{login_id}")
async def login_status(
    login_id: str,
    tail: int = 200,
    user: dict = Depends(get_current_user),
):
    state = cli_runner.get_status(login_id, tail=tail)
    if not state:
        raise HTTPException(status_code=404, detail=f"Login not found: {login_id}")
    return state


@router.get("/login/{login_id}/log")
async def login_log(
    login_id: str,
    tail: int = 500,
    user: dict = Depends(get_current_user),
):
    lines = cli_runner.read_log(login_id, tail=tail)
# ============================================================
# Manual profile creation (ADDED 2026-09-18)
# ============================================================
from pydantic import BaseModel as _BM
from typing import Optional as _Opt, Dict as _Dict, Any as _Any
from pathlib import Path as _Path
import json as _json


class ManualProfileRequest(_BM):
    profile: str
    target_url: str = ""
    cookies: str = ""
    bearer_token: str = ""
    basic_auth: _Opt[_Dict[str, str]] = None
    headers: _Opt[_Dict[str, _Any]] = None
    user_agent: str = ""
    referer: str = ""
    csrf_token: str = ""


@router.post("/manual")
async def create_manual_profile(
    req: ManualProfileRequest,
    user: dict = Depends(get_current_user),
):
    """Create a login profile from manual credentials."""
    # Locate profiles dir
    if _Path("/app/framework/profiles").exists():
        profiles_dir = _Path("/app/framework/profiles")
    else:
        profiles_dir = cli_runner.PROFILES_DIR
    profiles_dir.mkdir(parents=True, exist_ok=True)

    # Parse cookies string into list of dicts
    cookies_list = []
    for pair in (req.cookies or "").split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        cookies_list.append({
            "name": k.strip(),
            "value": v.strip(),
            "domain": "",
            "path": "/",
        })

    # Build headers
    headers = dict(req.headers or {})
    if req.bearer_token:
        headers["Authorization"] = "Bearer " + req.bearer_token
    if req.user_agent:
        headers["User-Agent"] = req.user_agent
    if req.referer:
        headers["Referer"] = req.referer
    if req.csrf_token:
        headers["X-CSRF-Token"] = req.csrf_token

    # Basic auth
    if req.basic_auth:
        import base64
        raw = "%s:%s" % (req.basic_auth.get("username", ""), req.basic_auth.get("password", ""))
        headers["Authorization"] = "Basic " + base64.b64encode(raw.encode()).decode()

    profile_data = {
        "profile": req.profile,
        "login_url": req.target_url,
        "provider": "manual",
        "saved_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
        "cookies": cookies_list,
        "headers": headers,
        "bearer_token": req.bearer_token,
    }

    path = profiles_dir / ("%s.json" % req.profile)
    path.write_text(_json.dumps(profile_data, ensure_ascii=False, indent=2), encoding="utf-8")

    return {"status": "saved", "profile": req.profile, "path": str(path)}
    return {"login_id": login_id, "lines": lines, "count": len(lines)}