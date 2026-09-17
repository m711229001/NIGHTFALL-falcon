"""Falcon MAG Framework - Port Scanner"""

import socket
from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("port")

COMMON_PORTS = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
    (80, "http"), (110, "pop3"), (143, "imap"), (443, "https"),
    (445, "smb"), (3306, "mysql"), (3389, "rdp"), (5432, "postgres"),
    (6379, "redis"), (8080, "http-alt"), (8443, "https-alt"),
    (9200, "elasticsearch"), (27017, "mongodb"),
]


def _check(host, port, timeout=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((host, port))
        return result == 0
    except Exception:
        return False
    finally:
        s.close()


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    host = urlparse(target).hostname or ""
    if not host:
        return {"error": "No hostname"}
    log.info("Port scan on " + host)
    result = {"target": target, "host": host, "open_ports": [], "tested": 0}
    for port, service in COMMON_PORTS:
        result["tested"] += 1
        if _check(host, port):
            log.warning("  OPEN: " + str(port) + "/" + service)
            result["open_ports"].append({
                "port": port,
                "service": service,
                "version": "",
                "banner": "",
            })
    if not result["open_ports"]:
        log.info("  No open ports found (" + str(result["tested"]) + " tested)")
    return result