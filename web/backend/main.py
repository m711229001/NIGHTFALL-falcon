"""Falcon MAG - FastAPI Backend Entry Point"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from core.config import settings
from api import auth, scans, findings, reports, export, sarif_export
# ADDED 2026-09-18: V2 APIs (framework/cli.py integration)
from api import scans_v2, profiles_v2, auth_v2, ai_config


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Falcon MAG - Autonomous AI VAPT Platform UI Backend",
)


# CORS — must be added BEFORE routers so preflight OPTIONS is handled.
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


# ============================================================
# V1 Routers (existing)
# ============================================================
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(export.router)
app.include_router(sarif_export.router)


# ============================================================
# V2 Routers (framework/cli.py integration)
# ADDED 2026-09-18
# ============================================================
app.include_router(scans_v2.router)
app.include_router(profiles_v2.router)
app.include_router(auth_v2.router)
app.include_router(ai_config.router)


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