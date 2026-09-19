"""Falcon MAG - Scans API"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.security import get_current_user
from core import nightfall_db
from services import scanner_v3 as scanner

router = APIRouter(prefix="/api/scans", tags=["scans"])


class StartScanRequest(BaseModel):
    url: str
    budget: int = 100
    exploit: str = "off"
    # === Advanced Auth ===
    cookies: str = ""
    bearer_token: str = ""
    headers: dict = {}
    # === HTTP Method / Body ===
    method: str = "GET"
    post_data: str = ""
    post_json: str = ""
    # === Login ===
    login_url: str = ""
    username: str = ""
    password: str = ""
    sms_code: str = ""
    # === Network ===
    user_agent: str = ""
    proxy: str = ""


@router.post("/start")
async def start_scan(
    request: StartScanRequest,
    user: dict = Depends(get_current_user),
):
    """Start a new scan with optional auth fields."""
    from core.nightfall.nightfall_core import run_scan_v5
    import asyncio

    # Build kwargs for run_scan_v5
    kwargs = {
        "budget": request.budget,
        "exploit": request.exploit,
        "cookies": request.cookies,
        "bearer_token": request.bearer_token,
        "headers": request.headers or {},
        "method": request.method or "GET",
        "post_data": request.post_data or "",
        "post_json": request.post_json or "",
        "login_url": request.login_url or "",
        "username": request.username or "",
        "password": request.password or "",
        "sms_code": request.sms_code or "",
        "user_agent": request.user_agent or "",
        "proxy": request.proxy or "",
    }

    # Fire and forget (long-running)
    asyncio.create_task(run_scan_v5(request.url, **kwargs))

    return {
        "status": "started",
        "target": request.url,
        "message": "Scan started in background",
    }


@router.get("/status")
async def scan_status(user: dict = Depends(get_current_user)):
    return scanner.get_status()


@router.get("/log")
async def scan_log(lines: int = 200, user: dict = Depends(get_current_user)):
    return {"lines": scanner.get_log(lines)}


@router.post("/stop")
async def stop_scan(user: dict = Depends(get_current_user)):
    return scanner.stop_scan()


@router.get("/stats")
async def stats(user: dict = Depends(get_current_user)):
    return nightfall_db.get_stats()


@router.get("/list")
async def list_scans(limit: int = 50, user: dict = Depends(get_current_user)):
    return nightfall_db.get_scans(limit=limit)


@router.get("/{scan_id}")
async def get_scan(scan_id: int, user: dict = Depends(get_current_user)):
    scan = nightfall_db.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = nightfall_db.get_findings(scan_id=scan_id)
    return {"scan": scan, "findings": findings}
