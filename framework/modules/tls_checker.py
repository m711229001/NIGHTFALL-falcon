"""Falcon MAG Framework - TLS Checker"""

import socket
import ssl
from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("tls")


def _test_protocol(host, port, proto_name):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if proto_name == "TLSv1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif proto_name == "TLSv1.1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        else:
            return False
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return {"error": "No hostname"}
    log.info("TLS check on " + host + ":" + str(port))
    result = {"target": target, "host": host, "port": port, "weak_protocols": [], "cert_info": {}}
    for proto in ["TLSv1", "TLSv1.1"]:
        if _test_protocol(host, port, proto):
            log.warning("  WEAK: " + proto + " supported")
            result["weak_protocols"].append(proto)
    if not result["weak_protocols"]:
        log.info("  No weak TLS protocols detected")
    return result