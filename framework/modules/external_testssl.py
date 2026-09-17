"""Falcon MAG Framework - External testssl.sh wrapper"""

from urllib.parse import urlparse
from core.logger import get_logger
from core.external_runner import run_tool, is_available

log = get_logger("testssl")


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return {"error": "No hostname"}

    if not is_available("testssl.sh"):
        log.warning("  testssl.sh not found in PATH")
        return {"target": target, "weak_protocols": [], "error": "testssl.sh not installed"}

    log.info("testssl.sh on " + host + ":" + str(port))

    cmd = ["testssl.sh", "--quiet", "--protocols", "--jsonfile-pretty", "-", host + ":" + str(port)]
    r = run_tool(cmd, timeout=300)

    result = {
        "target": target,
        "host": host,
        "port": port,
        "weak_protocols": [],
        "raw": (r.get("stdout") or "")[:50000],
    }

    # Heuristic parse
    out = result["raw"].lower()
    for proto in ["sslv2", "sslv3", "tlsv1 ", "tlsv1.0", "tlsv1.1"]:
        if proto in out and "offered" in out:
            pretty = proto.strip().upper()
            result["weak_protocols"].append(pretty)
            log.warning("  WEAK: " + pretty)

    if not result["weak_protocols"]:
        log.info("  No weak protocols reported")

    return result