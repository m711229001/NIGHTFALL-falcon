"""Falcon MAG - Findings API"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.security import get_current_user
from core import nightfall_db

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("")
async def list_findings(
    limit: int = 100,
    severity: Optional[str] = None,
    vuln_class: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    return nightfall_db.get_findings(limit=limit, severity=severity, vuln_class=vuln_class)


@router.get("/{finding_id}")
async def get_finding(finding_id: int, user: dict = Depends(get_current_user)):
    finding = nightfall_db.get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/objectives/list")
async def list_objectives(limit: int = 100, user: dict = Depends(get_current_user)):
    return nightfall_db.get_objectives(limit=limit)


@router.get("/campaign/info")
async def campaign_info(user: dict = Depends(get_current_user)):
    return nightfall_db.get_campaign()


@router.get("/callbacks/list")
async def list_callbacks(limit: int = 100, user: dict = Depends(get_current_user)):
    return nightfall_db.get_callbacks(limit=limit)


@router.get("/evidence/list")
async def list_evidence(limit: int = 100, user: dict = Depends(get_current_user)):
    return nightfall_db.get_evidence(limit=limit)
