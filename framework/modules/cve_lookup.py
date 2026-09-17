"""Falcon MAG Framework - CVE Lookup (offline stub)"""

from core.logger import get_logger

log = get_logger("cve")

KNOWN_CVES = {
    "WordPress": [{"id": "CVE-2023-2982", "tech": "WordPress", "description": "Auth bypass", "severity": "high", "cvss": 9.8, "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-2982"}],
    "Drupal": [{"id": "CVE-2018-7600", "tech": "Drupal", "description": "Drupalgeddon2 RCE", "severity": "critical", "cvss": 9.8, "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"}],
    "jQuery": [{"id": "CVE-2020-11022", "tech": "jQuery", "description": "XSS in jQuery < 3.5.0", "severity": "medium", "cvss": 6.1, "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-11022"}],
    "Apache": [{"id": "CVE-2021-41773", "tech": "Apache HTTP Server", "description": "Path traversal in Apache 2.4.49", "severity": "critical", "cvss": 9.8, "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}],
    "Nginx": [{"id": "CVE-2019-20372", "tech": "Nginx", "description": "Request smuggling", "severity": "medium", "cvss": 5.3, "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-20372"}],
}


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}
    fp = config.get("_fingerprint", {}) or {}
    techs = fp.get("technologies", []) or []
    if not techs:
        log.info("No fingerprint data available for CVE lookup")
        return {"target": target, "cves": []}
    log.info("CVE lookup for: " + ", ".join(techs))
    result = {"target": target, "cves": []}
    for tech in techs:
        for key, cves in KNOWN_CVES.items():
            if key.lower() in tech.lower():
                for cve in cves:
                    result["cves"].append(cve)
                    log.warning("  " + cve["id"] + ": " + cve["description"][:60])
    if not result["cves"]:
        log.info("  No known CVEs for detected technologies")
    return result