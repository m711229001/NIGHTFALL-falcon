"""Falcon MAG Framework - External searchsploit wrapper"""

from core.logger import get_logger
from core.external_runner import run_tool, is_available

log = get_logger("searchsploit")


def run(client, config):
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    if not is_available("searchsploit"):
        log.warning("  searchsploit not found in PATH")
        return {"target": target, "cves": [], "error": "searchsploit not installed"}

    # Get fingerprints
    fp = config.get("_fingerprint", {}) or {}
    techs = fp.get("technologies", []) or []

    if not techs:
        log.info("  No technologies to search")
        return {"target": target, "cves": []}

    result = {"target": target, "cves": []}

    for tech in techs[:5]:
        log.info("  searchsploit for: " + tech)
        r = run_tool(["searchsploit", "--json", tech], timeout=60)
        if not r.get("ok"):
            continue
        raw = r.get("stdout", "")
        import json as _json
        try:
            data = _json.loads(raw)
        except Exception:
            continue
        for exp in (data.get("RESULTS_EXPLOIT") or [])[:5]:
            entry = {
                "id": exp.get("EDB-ID", "N/A"),
                "tech": tech,
                "description": exp.get("Title", ""),
                "severity": "high",
                "cvss": "N/A",
                "url": "https://www.exploit-db.com/exploits/" + str(exp.get("EDB-ID", "")),
            }
            result["cves"].append(entry)
            log.warning("  " + entry["id"] + ": " + entry["description"][:60])

    return result