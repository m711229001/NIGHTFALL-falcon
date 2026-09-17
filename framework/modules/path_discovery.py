"""Falcon MAG Framework - Path Discovery Module
Real brute-force of paths with catch-all detection. No hardcoded results."""

import hashlib
from urllib.parse import urljoin
from pathlib import Path
from core.logger import get_logger
from core.config import get_wordlist

log = get_logger("paths")


# Real interesting path classification
PATH_TYPES = {
    "admin_panel": ["admin", "administrator", "cpanel", "whm", "panel", "manage"],
    "critical_exposure": [".env", ".git", ".svn", ".htpasswd", ".netrc",
                          "secrets", "credentials", "backup.sql", "db.sql"],
    "sensitive_file": ["config", "settings", ".htaccess", "web.config",
                       "app.config", "dump", "backup"],
    "reconnaissance": ["robots.txt", "sitemap", "security.txt", ".well-known"],
    "api_doc": ["swagger", "openapi", "api-docs", "graphql", "api", "docs"],
    "debug": ["debug", "console", "phpinfo", "info.php", "test.php", "test",
              "server-status", "server-info"],
}


def _classify(path: str, status: int, size: int) -> str:
    """Classify a discovered path based on its name."""
    p_lower = path.lower()
    for ptype, keywords in PATH_TYPES.items():
        for kw in keywords:
            if kw in p_lower:
                return ptype
    return "other"


def _load_wordlist(config) -> list:
    """Load real wordlist from file."""
    wl_path = get_wordlist(config, "paths")
    if not wl_path or not Path(wl_path).exists():
        log.warning(f"  ✗ Wordlist not found: {wl_path}")
        return []
    with open(wl_path, encoding="utf-8", errors="replace") as f:
        words = [line.strip() for line in f
                 if line.strip() and not line.startswith("#")]
    log.info(f"  ✓ Loaded {len(words)} paths from wordlist")
    return words


def run(client, config) -> dict:
    """Run real path discovery."""
    target = config.get("target", "").rstrip("/")
    if not target:
        return {"error": "No target"}

    log.info(f"🛣️  Path Discovery on {target}")

    result = {
        "target": target,
        "tested": 0,
        "real_paths": [],
        "fake_paths": [],
        "catch_all_detected": False,
        "baseline": {},
        "unique_path": "",
        "unique_response": {},
    }

    # ---- Step 1: Baseline ----
    baseline = client.scan_request(target)
    if not baseline or baseline.status == 0:
        log.error("  ✗ Baseline request failed")
        return {"error": "baseline failed"}

    baseline_hash = hashlib.md5(baseline.content).hexdigest()
    baseline_size = len(baseline.content)
    baseline_status = baseline.status

    result["baseline"] = {
        "status": baseline_status,
        "size": baseline_size,
        "hash": baseline_hash,
    }
    log.info(f"  ✓ Baseline: HTTP {baseline_status}, {baseline_size} bytes")

    # ---- Step 2: Catch-all detection ----
    import uuid
    unique_path = f"/{uuid.uuid4().hex[:16]}"
    unique_resp = client.scan_request(urljoin(target, unique_path))

    if unique_resp and unique_resp.status == 0:
        log.warning("  ⚠ Unique-path request failed; assuming no catch-all")
    else:
        unique_hash = hashlib.md5(unique_resp.content).hexdigest()
        unique_size = len(unique_resp.content)

        result["unique_path"] = unique_path
        result["unique_response"] = {
            "status": unique_resp.status,
            "size": unique_size,
            "hash": unique_hash,
        }

        # Real catch-all: random path returns 200 with same content as index
        if (unique_resp.status == 200
                and unique_hash == baseline_hash):
            result["catch_all_detected"] = True
            log.warning(f"  ⚠ CATCH-ALL detected! Random path returns index content")

        log.info(f"  ℹ Random path: HTTP {unique_resp.status}, {unique_size} bytes")

    # ---- Step 3: Load wordlist ----
    words = _load_wordlist(config)
    if not words:
        return result

    # ---- Step 4: Test each path ----
    unique_hash = result["unique_response"].get("hash")
    unique_size = result["unique_response"].get("size", 0)

    for i, path in enumerate(words, 1):
        if client.config.get("scan", {}).get("max_paths"):
            if result["tested"] >= client.config["scan"]["max_paths"]:
                break

        url = urljoin(target + "/", path.lstrip("/"))
        try:
            resp = client.scan_request(url)
        except KeyboardInterrupt:
            log.warning("  ⚠ Path discovery interrupted by user")
            break
        except Exception as exc:
            log.debug(f"  ✗ Request error: {exc}")
            continue
        result["tested"] += 1
        if not resp:
            continue

        # Determine if real or fake
        entry = {
            "path": "/" + path.lstrip("/"),
            "url": url,
            "status": resp.status,
            "size": len(resp.content),
            "type": _classify(path, resp.status, len(resp.content)),
        }

        # Filter out non-interesting
        if resp.status in (404, 0):
            continue

        # Catch-all detection: same status + size as random path
        is_fake = False
        if result["catch_all_detected"]:
            resp_hash = hashlib.md5(resp.content).hexdigest()
            if resp_hash == unique_hash:
                is_fake = True
        elif unique_hash:
            resp_hash = hashlib.md5(resp.content).hexdigest()
            if resp_hash == unique_hash:
                is_fake = True

        if is_fake:
            result["fake_paths"].append(entry)
        elif resp.status in (200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 500):
            result["real_paths"].append(entry)
            log.info(f"  ✓ [{resp.status}] {entry['path']} ({entry['size']}B, {entry['type']})")

    log.info(f"  ✓ Tested: {result['tested']}")
    log.info(f"  ✓ Real: {len(result['real_paths'])}")
    log.info(f"  ✓ Fake (catch-all): {len(result['fake_paths'])}")

    return result