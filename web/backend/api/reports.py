"""Falcon MAG - Reports API"""
from fastapi import APIRouter, HTTPException, Depends
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.security import get_current_user

BACKEND_DIR = Path(__file__).resolve().parent.parent

# Report directories (searched in order)
REPORT_DIRS = [
    BACKEND_DIR / "reports",                # web/backend/reports/
    BACKEND_DIR / "bug_bounty_reports",    # web/backend/bug_bounty_reports/
    BACKEND_DIR / "core" / "nightfall" / "reports",  # legacy
    BACKEND_DIR.parent / "reports",        # web/reports/
    BACKEND_DIR.parent.parent / "reports", # NIGHTFALL/reports/
]

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("")
async def list_reports():
    """List all report files across all report directories."""
    reports = []
    seen = set()

    for d in REPORT_DIRS:
        if not d.exists() or not d.is_dir():
            continue
        # .md files
        for f in d.glob("*.md"):
            if str(f) not in seen:
                seen.add(str(f))
                try:
                    st = f.stat()
                    reports.append({
                        "name": f.name,
                        "path": str(f),
                        "size": st.st_size,
                        "modified": st.st_mtime,
                        "type": "markdown",
                    })
                except Exception:
                    continue
        # .sarif files
        for f in d.glob("*.sarif"):
            if str(f) not in seen:
                seen.add(str(f))
                try:
                    st = f.stat()
                    reports.append({
                        "name": f.name,
                        "path": str(f),
                        "size": st.st_size,
                        "modified": st.st_mtime,
                        "type": "sarif",
                    })
                except Exception:
                    continue
        # .json files
        for f in d.glob("*.json"):
            if str(f) not in seen and "report" in f.name.lower():
                seen.add(str(f))
                try:
                    st = f.stat()
                    reports.append({
                        "name": f.name,
                        "path": str(f),
                        "size": st.st_size,
                        "modified": st.st_mtime,
                        "type": "json",
                    })
                except Exception:
                    continue

    reports.sort(key=lambda x: x.get("modified", 0), reverse=True)
    return reports


@router.get("/{name}")
async def get_report(name: str):
    """Get report content by name."""
    # Sanitize name — no path traversal
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid report name")

    for d in REPORT_DIRS:
        if not d.exists():
            continue
        f = d / name
        if f.exists() and f.is_file():
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                return {
                    "name": name,
                    "content": content,
                    "size": f.stat().st_size,
                    "type": "markdown" if name.endswith(".md") else (
                        "sarif" if name.endswith(".sarif") else "text"
                    ),
                }
            except Exception as exc:
                raise HTTPException(status_code=500, detail=str(exc))

    raise HTTPException(status_code=404, detail="Report not found: " + name)
