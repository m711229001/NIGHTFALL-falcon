"""Falcon MAG - Reports API"""
from fastapi import APIRouter, HTTPException, Depends
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.security import get_current_user

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BACKEND_DIR.parent.parent / "web" / "backend" / "core" / "nightfall" / "reports"
NIGHTFALL_REPORTS = BACKEND_DIR / "reports"

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("")
async def list_reports(user: dict = Depends(get_current_user)):
    """List all report files."""
    reports = []
    seen = set()
    for d in [REPORTS_DIR, NIGHTFALL_REPORTS, BACKEND_DIR.parent.parent / "reports"]:
        if d.exists():
            for f in d.glob("*.md"):
                if str(f) not in seen:
                    seen.add(str(f))
                    reports.append({
                        "name": f.name,
                        "path": str(f),
                        "size": f.stat().st_size,
                        "modified": f.stat().st_mtime,
                        "type": "markdown",
                    })
            for f in d.glob("*.sarif"):
                if str(f) not in seen:
                    seen.add(str(f))
                    reports.append({
                        "name": f.name,
                        "path": str(f),
                        "size": f.stat().st_size,
                        "modified": f.stat().st_mtime,
                        "type": "sarif",
                    })
    reports.sort(key=lambda x: x["modified"], reverse=True)
    return reports


@router.get("/{name}")
async def get_report(name: str, user: dict = Depends(get_current_user)):
    """Get report content by name."""
    for d in [REPORTS_DIR, NIGHTFALL_REPORTS, BACKEND_DIR.parent.parent / "reports"]:
        f = d / name
        if f.exists() and f.is_file():
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                return {"name": name, "content": content, "size": f.stat().st_size}
            except Exception as exc:
                raise HTTPException(status_code=500, detail=str(exc))
    raise HTTPException(status_code=404, detail="Report not found")