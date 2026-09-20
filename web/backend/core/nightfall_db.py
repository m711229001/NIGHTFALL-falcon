"""Falcon MAG - Falcon DB Reader (v2)"""
import sqlite3
from pathlib import Path
from typing import Optional

BACKEND_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BACKEND_DIR / "falcon.db"


def _conn():
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def get_scans(limit: int = 50):
    conn = _conn()
    if not conn:
        return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_scan_by_id(scan_id: int):
    conn = _conn()
    if not conn:
        return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cur.fetchone()
        if not row:
            return None
        scan = dict(row)
        # Parse ai_plan (which is a JSON string) and extract internal fields
        import json as _json
        waf_val = None
        hidden_val = []
        waf_info_val = None
        ai_plan_raw = scan.get("ai_plan")
        if ai_plan_raw:
            try:
                if isinstance(ai_plan_raw, str):
                    plan = _json.loads(ai_plan_raw)
                else:
                    plan = ai_plan_raw
                if isinstance(plan, dict):
                    waf_val = plan.pop("_waf", None)
                    hidden_val = plan.pop("_hidden_paths", []) or []
                    waf_info_val = plan.pop("_waf_info", None)
                    scan["ai_plan"] = plan
            except Exception:
                pass
        scan["waf"] = waf_val
        scan["hidden_paths"] = hidden_val
        scan["waf_info"] = waf_info_val
        # Also extract waf_info from ai_plan if not already extracted
        if not scan.get("waf_info") and isinstance(scan.get("ai_plan"), dict):
            scan["waf_info"] = scan["ai_plan"].get("_waf_info")
        return scan
    finally:
        conn.close()


def get_findings(limit: int = 200, severity: Optional[str] = None, vuln_class: Optional[str] = None, scan_id: Optional[int] = None):
    conn = _conn()
    if not conn:
        return []
    try:
        q = "SELECT * FROM findings WHERE 1=1"
        params = []
        if severity:
            q += " AND severity = ?"
            params.append(severity)
        if vuln_class:
            q += " AND vuln_class = ?"
            params.append(vuln_class)
        if scan_id:
            q += " AND scan_id = ?"
            params.append(scan_id)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        cur = conn.cursor()
        cur.execute(q, params)
        return [_expand_ai(dict(r)) for r in cur.fetchall()]
    finally:
        conn.close()


def _expand_ai(row: dict) -> dict:
    """If row has ai_data JSON, expand it into top-level keys."""
    import json as _json
    raw = row.pop("ai_data", None)
    if raw:
        try:
            ai = _json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(ai, dict):
                for k, v in ai.items():
                    row[k] = v
        except Exception:
            pass
    return row


def get_finding_by_id(finding_id: int):
    conn = _conn()
    if not conn:
        return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = cur.fetchone()
        return _expand_ai(dict(row)) if row else None
    finally:
        conn.close()


def get_objectives(limit: int = 100):
    """Alias for get_scans (for backward compat with old UI)."""
    return get_scans(limit=limit)


def get_campaign():
    """Return DB stats as campaign info."""
    return get_stats()


def get_callbacks(limit: int = 100):
    """No callbacks table in v2 yet - return empty list."""
    return []


def get_evidence(limit: int = 100):
    """No evidence table in v2 yet - return empty list."""
    return []


def get_stats():
    conn = _conn()
    if not conn:
        return {
            "scans": 0, "findings": 0, "objectives": 0, "callbacks": 0, "evidence": 0,
            "by_severity": {}, "by_class": {},
        }
    try:
        cur = conn.cursor()
        scans = cur.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        findings = cur.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        by_sev = dict(cur.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity").fetchall())
        by_class = dict(cur.execute("SELECT vuln_class, COUNT(*) FROM findings GROUP BY vuln_class").fetchall())
        return {
            "scans": scans,
            "findings": findings,
            "objectives": scans,  # alias
            "callbacks": 0,
            "evidence": 0,
            "by_severity": by_sev,
            "by_class": by_class,
        }
    finally:
        conn.close()