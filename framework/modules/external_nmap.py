"""Falcon MAG Framework - External nmap wrapper"""

from urllib.parse import urlparse
from core.logger import get_logger
from core.external_runner import run_tool, is_available

log = get_logger("nmap")


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    host = urlparse(target).hostname or ""
    if not host:
        return {"error": "No hostname"}

    if not is_available("nmap"):
        log.warning("  nmap not found in PATH")
        return {"target": target, "open_ports": [], "error": "nmap not installed"}

    log.info("nmap scan on " + host)

    cmd = ["nmap", "-sV", "-T4", "--top-ports", "100", "-oX", "-", host]
    r = run_tool(cmd, timeout=180)

    result = {"target": target, "host": host, "open_ports": [], "raw_xml": ""}

    if not r.get("ok") and not r.get("stdout"):
        log.warning("  nmap failed: " + r.get("error", "unknown"))
        result["error"] = r.get("error", "nmap failed")
        return result

    result["raw_xml"] = (r.get("stdout") or "")[:50000]

    # Parse XML for open ports
    import re
    port_re = re.compile(r'<port protocol="([^"]+)" portid="(\d+)">.*?<state state="open".*?<service name="([^"]*)"(?:.*?product="([^"]*)")?(?:.*?version="([^"]*)")?', re.DOTALL)
    for m in port_re.finditer(result["raw_xml"]):
        proto, port, svc, prod, ver = m.groups()
        entry = {
            "port": int(port),
            "service": svc or "",
            "version": ((prod or "") + " " + (ver or "")).strip(),
            "banner": "",
        }
        result["open_ports"].append(entry)
        log.warning("  OPEN: " + port + "/" + proto + " " + entry["service"])

    if not result["open_ports"]:
        log.info("  No open ports found by nmap")

    return result