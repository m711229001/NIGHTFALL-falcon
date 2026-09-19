"""Falcon MAG - Profiles API v2

Exposes saved login profiles (created by `framework/cli.py login`).
Read-only for now — login itself goes through /api/v2/auth/login.
"""
from fastapi import APIRouter, HTTPException, Depends
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.security import get_current_user
from services import cli_runner

router = APIRouter(prefix="/api/v2/profiles", tags=["profiles-v2"])


@router.get("/list")
async def list_profiles(user: dict = Depends(get_current_user)):
    return {"profiles": cli_runner.list_profiles()}


@router.get("/{name}")
async def get_profile(name: str, user: dict = Depends(get_current_user)):
    p = cli_runner.get_profile(name)
    if not p:
        raise HTTPException(status_code=404, detail=f"Profile not found: {name}")
    # Don't leak cookies to the client — just metadata
    safe = {k: v for k, v in p.items() if k != "cookies"}
    safe["cookies_count"] = len(p.get("cookies", []))
    return safe