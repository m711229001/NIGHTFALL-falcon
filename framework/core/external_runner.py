"""Falcon MAG Framework - External Tool Runner

Safe subprocess wrapper for external security tools (nmap, testssl.sh, etc.)
Handles: timeout, stdout/stderr capture, error handling.
"""

import subprocess
import shutil
from core.logger import get_logger

log = get_logger("external")


def is_available(tool_name):
    """Check if a tool is available in PATH."""
    return shutil.which(tool_name) is not None


def run_tool(command, timeout=300, capture_stderr=True):
    """Run an external tool safely.

    Args:
        command: list of strings (e.g. ["nmap", "-sV", "example.com"])
        timeout: max seconds
        capture_stderr: whether to capture stderr

    Returns:
        dict {ok, stdout, stderr, returncode, error}
    """
    if not isinstance(command, list) or not command:
        return {"ok": False, "error": "invalid command"}

    tool = command[0]
    if not is_available(tool):
        return {
            "ok": False,
            "error": "tool not found: " + tool,
            "tool": tool,
        }

    log.info("  Running: " + " ".join(command))

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "ok": proc.returncode == 0,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "" if capture_stderr else "",
            "returncode": proc.returncode,
            "tool": tool,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout after " + str(timeout) + "s", "tool": tool}
    except Exception as e:
        return {"ok": False, "error": str(e), "tool": tool}