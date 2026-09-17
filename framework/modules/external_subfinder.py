"""Falcon MAG Framework - External subfinder wrapper"""

from urllib.parse import urlparse
from core.logger import get_logger
from core.external_runner import run_tool, is_available

log = get_logger("subfinder")


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    host = urlparse(target).hostname or ""
    if not host:
        return {"error": "No hostname"}

    if not is_available("subfinder"):
        log.warning("  subfinder not found in PATH")
        return {"target": target, "found": [], "error": "subfinder not installed"}

    log.info("subfinder on " + host)

    cmd = ["subfinder", "-d", host, "-silent"]
    r = run_tool(cmd, timeout=180)

    result = {"target": target, "base": host, "found": [], "raw": r.get("stdout", "")[:20000]}

    if r.get("stdout"):
        for line in r["stdout"].splitlines():
            line = line.strip()
            if line and "." in line:
                result["found"].append(line)

    if result["found"]:
        log.info("  Found " + str(len(result["found"])) + " subdomains")
        for s in result["found"][:10]:
            log.info("    " + s)
    else:
        log.info("  No subdomains found")

    return result