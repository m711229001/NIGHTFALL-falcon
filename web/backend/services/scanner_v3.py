"""Falcon MAG - Scanner v3 (direct integration + proxy support)"""
import asyncio
import sys
import json
import threading
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

BACKEND_DIR = Path(__file__).resolve().parent.parent
NIGHTFALL_CORE_DIR = BACKEND_DIR / "core" / "nightfall"

sys.path.insert(0, str(NIGHTFALL_CORE_DIR))

SCAN_STATE_FILE = BACKEND_DIR / "current_scan.json"
LOG_FILE = BACKEND_DIR / "current_scan.log"

_scan_thread: Optional[threading.Thread] = None
_scan_running = False


def _run_scan_sync(url: str, budget: int, exploit: str, proxy: str = None):
    """Run scan synchronously in a thread, capturing all stdout to log file."""
    global _scan_running
    _scan_running = True

    try:
        log_handle = open(str(LOG_FILE), "w", encoding="utf-8", errors="replace")
    except Exception:
        log_handle = None

    original_stdout = sys.stdout
    original_stderr = sys.stderr

    # Set proxy env vars BEFORE importing nightfall_core
    # httpx respects HTTP_PROXY / HTTPS_PROXY automatically
    saved_env = {}
    if proxy:
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            saved_env[key] = os.environ.get(key)
        os.environ["HTTP_PROXY"] = proxy
        os.environ["HTTPS_PROXY"] = proxy
        os.environ["http_proxy"] = proxy
        os.environ["https_proxy"] = proxy

    def write_header(msg):
        if log_handle:
            try:
                log_handle.write(msg + "\n")
                log_handle.flush()
            except Exception:
                pass

    write_header(f"[info] scan_start target={url} budget={budget} exploit={exploit} proxy={proxy or 'none'}")

    try:
        if log_handle:
            sys.stdout = log_handle
            sys.stderr = log_handle

        from nightfall_core import run_scan_v5
        result = asyncio.run(run_scan_v5(url, budget=budget, exploit=exploit, multi_turn=True))

        state = {
            "status": "completed",
            "url": url,
            "budget": budget,
            "exploit": exploit,
            "proxy": proxy,
            "started_at": datetime.utcnow().isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
            "findings_count": result.get("findings_count", 0),
            "requests_used": result.get("budget_used", 0),
            "elapsed_seconds": result.get("elapsed_seconds", 0),
            "scan_id": result.get("scan_id"),
        }
        SCAN_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")

    except Exception as exc:
        state = {
            "status": "failed",
            "url": url,
            "budget": budget,
            "exploit": exploit,
            "proxy": proxy,
            "error": str(exc),
            "started_at": datetime.utcnow().isoformat(),
        }
        SCAN_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")

    finally:
        # Restore proxy env vars
        if proxy:
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                if saved_env.get(key) is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = saved_env[key]

        sys.stdout = original_stdout
        sys.stderr = original_stderr

        try:
            if SCAN_STATE_FILE.exists():
                final = json.loads(SCAN_STATE_FILE.read_text(encoding="utf-8"))
                write_header(f"[info] scan_{final.get('status', 'unknown')} findings={final.get('findings_count', 0)} requests={final.get('requests_used', 0)}")
        except Exception:
            pass

        if log_handle:
            try:
                log_handle.close()
            except Exception:
                pass

        _scan_running = False


def start_scan(url: str, budget: int = 100, exploit: str = "off", proxy: str = None) -> dict:
    """Start scan in background thread."""
    global _scan_thread, _scan_running
    if _scan_running:
        return {"error": "Scan already running"}

    try:
        LOG_FILE.write_text("", encoding="utf-8")
    except Exception:
        pass

    state = {
        "status": "running",
        "url": url,
        "budget": budget,
        "exploit": exploit,
        "proxy": proxy,
        "started_at": datetime.utcnow().isoformat(),
    }
    SCAN_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")

    _scan_thread = threading.Thread(
        target=_run_scan_sync,
        args=(url, budget, exploit, proxy),
        daemon=True,
    )
    _scan_thread.start()
    return state


def get_status() -> dict:
    if not SCAN_STATE_FILE.exists():
        return {"status": "idle"}
    try:
        return json.loads(SCAN_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"status": "idle"}


def get_log(lines: int = 200) -> list:
    if LOG_FILE.exists():
        try:
            content = LOG_FILE.read_text(encoding="utf-8", errors="replace")
            return content.splitlines()[-lines:]
        except Exception:
            pass
    return []


def stop_scan() -> dict:
    global _scan_running
    _scan_running = False
    if SCAN_STATE_FILE.exists():
        try:
            state = json.loads(SCAN_STATE_FILE.read_text(encoding="utf-8"))
            state["status"] = "stopped"
            SCAN_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
        except Exception:
            pass
    return {"status": "stopped"}