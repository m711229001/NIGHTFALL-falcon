"""Falcon MAG Framework - Subdomain Enumeration"""

import socket
from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("subdomain")

COMMON = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "blog", "shop", "app", "m", "mobile", "secure",
    "vpn", "cdn", "static", "assets", "media", "images", "files",
    "db", "mysql", "postgres", "redis", "mongo", "git", "gitlab",
    "jenkins", "ci", "docker", "k8s", "monitor", "grafana", "nagios",
]


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    parsed = urlparse(target)
    base = parsed.hostname or ""
    if not base:
        return {"error": "No hostname"}
    if base.startswith("www."):
        base = base[4:]
    log.info("Subdomain enum on " + base)
    result = {"target": target, "base": base, "tested": 0, "found": []}
    for sub in COMMON:
        host = sub + "." + base
        result["tested"] += 1
        ip = _resolve(host)
        if ip:
            log.info("  Found: " + host + " -> " + ip)
            result["found"].append(host)
    if not result["found"]:
        log.info("  No subdomains found (" + str(result["tested"]) + " tested)")
    return result