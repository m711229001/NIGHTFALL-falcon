"""Falcon MAG - FastAPI Backend Entry Point"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from core.config import settings
from api import auth, scans, findings, reports, export, sarif_export

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Falcon MAG - Autonomous AI VAPT Platform UI Backend",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(export.router)
app.include_router(sarif_export.router)


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "online",
        "docs": "/docs",
    }


@app.get("/api/health")
async def health():
    return {"status": "healthy"}
