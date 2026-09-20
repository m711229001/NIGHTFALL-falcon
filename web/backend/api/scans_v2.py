"""Falcon MAG - Scans API v2 (Framework CLI wrapper)

This module adds NEW endpoints that call `framework/cli.py` via subprocess.
The old `api/scans.py` (which uses core/nightfall/nightfall_core.py) is
NOT modified — both systems coexist side-by-side.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.security import get_current_user
from services import cli_runner

router = APIRouter(prefix="/api/v2/scans", tags=["scans-v2"])


# ============================================================
# Request model
# ============================================================
class StartScanV2Request(BaseModel):
    url: str

    # Modules
    modules: Optional[str] = None
    all_modules: bool = False

    # Auth
    profile: Optional[str] = None
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    bearer_token: Optional[str] = None
    cookie: Optional[str] = None
    cookie_file: Optional[str] = None
    cookies: Optional[str] = None
    totp_secret: Optional[str] = None

    # HTTP
    method: str = "GET"
    post_data: Optional[str] = None
    post_json: Optional[str] = None
    header: Optional[str] = None
    insecure: bool = False

    # Execution
    parallel: int = 1
    timeout: int = Field(3600, ge=60, le=14400)
    output: Optional[str] = None
    config: Optional[str] = None

    # AI
    no_ai: bool = False
    ai_max: int = 20


# ============================================================
# Endpoints
# ============================================================
@router.post("/start")
async def start_scan_v2(
    req: StartScanV2Request,
    user: dict = Depends(get_current_user),
):
    """Start a scan using framework/cli.py (background thread)."""
    try:
        state = cli_runner.start_scan(
            target=req.url,
            modules=req.modules,
            all_modules=req.all_modules,
            profile=req.profile,
            login_url=req.login_url,
            username=req.username,
            password=req.password,
            bearer_token=req.bearer_token,
            cookie=req.cookie,
            cookie_file=req.cookie_file,
            cookies=req.cookies,
            totp_secret=req.totp_secret,
            method=req.method,
            post_data=req.post_data,
            post_json=req.post_json,
            header=req.header,
            insecure=req.insecure,
            parallel=req.parallel,
            output=req.output,
            config=req.config,
            timeout=req.timeout,
            no_ai=req.no_ai,
            ai_max=req.ai_max,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {e}")

    return {
        "status": "started",
        "engine": "framework-cli",
        "scan_id": state.scan_id,
        "target": state.target,
        "started_at": state.started_at,
    }


@router.get("/status/{scan_id}")
async def get_status_v2(scan_id: str, user: dict = Depends(get_current_user)):
    state = cli_runner.get_status(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
    return state


@router.get("/log/{scan_id}")
async def get_log_v2(
    scan_id: str,
    tail: int = 500,
    user: dict = Depends(get_current_user),
):
    lines = cli_runner.read_log(scan_id, tail=tail)
    return {"scan_id": scan_id, "lines": lines, "count": len(lines)}


@router.post("/cancel/{scan_id}")
async def cancel_v2(scan_id: str, user: dict = Depends(get_current_user)):
    return cli_runner.cancel_scan(scan_id)


@router.get("/list")
async def list_v2(user: dict = Depends(get_current_user)):
    return {"scans": cli_runner.list_scans()}


@router.get("/ai/{scan_id}")
async def get_ai_analyses_v2(
    scan_id: str,
    user: dict = Depends(get_current_user),
):
    """Return AI analyses for a scan (from output JSON)."""
    analyses = cli_runner.get_ai_analyses(scan_id)
    if analyses is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scan not found or no AI data: {scan_id}",
        )
    return {"scan_id": scan_id, "analyses": analyses}



@router.post("/pause/{scan_id}")
async def pause_scan_v2(scan_id: str, user: dict = Depends(get_current_user)):
    return cli_runner.pause_scan(scan_id)


@router.post("/resume/{scan_id}")
async def resume_scan_v2(scan_id: str, user: dict = Depends(get_current_user)):
    return cli_runner.resume_scan(scan_id)


@router.get("/report/{scan_id}")
async def get_report_v2(scan_id: str, user: dict = Depends(get_current_user)):
    data = cli_runner.get_scan_report_data(scan_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No report data for scan: {scan_id}")
    return data


@router.get("/dashboard-stats")
async def dashboard_stats_v2(user: dict = Depends(get_current_user)):
    return cli_runner.get_dashboard_stats()


@router.get("/triage-latest")
async def get_triage_latest_v2(user: dict = Depends(get_current_user)):
    data = cli_runner.get_latest_triage()
    if data is None:
        return {"triaged": 0, "items": []}
    return data


@router.get("/links-latest")
async def get_links_latest_v2(user: dict = Depends(get_current_user)):
    """Return endpoint catalog from the most recent scan (no scan_id)."""
    data = cli_runner.get_latest_endpoint_catalog()
    if data is None:
        return {"scan_id": None, "target": "", "total": 0, "endpoints": []}
    return data


@router.get("/links/{scan_id}")
async def get_links_v2(scan_id: str, user: dict = Depends(get_current_user)):
    data = cli_runner.get_endpoint_catalog(scan_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No data for scan: {scan_id}")
    return data


@router.get("/diagnose")
async def diagnose_v2(user: dict = Depends(get_current_user)):
    """Check that framework/cli.py is reachable from inside the container."""
    return cli_runner.diagnose()
