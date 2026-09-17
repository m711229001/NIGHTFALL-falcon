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


@router.post("/start")
async def start_scan(req: StartScanRequest, user: dict = Depends(get_current_user)):
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    result = scanner.start_scan(req.url, req.budget, req.exploit)
    if "error" in result:
        raise HTTPException(status_code=409, detail=result["error"])
    return result


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
