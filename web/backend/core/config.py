"""Falcon MAG - Backend Configuration"""
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent

class Settings(BaseSettings):
    # App
    APP_NAME: str = "Falcon MAG"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Security
    SECRET_KEY: str = "falcon-mag-change-me-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Database
    DB_PATH: str = str(BASE_DIR / "nightfall.db")
    USERS_DB: str = str(BASE_DIR / "web" / "backend" / "users.db")

    # Paths
    REPORTS_DIR: str = str(BASE_DIR / "reports")
    NIGHTFALL_DIR: str = str(BASE_DIR)

    # CORS
    CORS_ORIGINS: list = ["http://localhost:5173", "http://localhost:5174", "http://localhost:3000", "http://localhost:8000", "http://127.0.0.1:5174"]

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()