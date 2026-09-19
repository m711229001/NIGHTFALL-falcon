"""Falcon MAG - Framework CLI Runner

Executes `framework/cli.py` via subprocess with:
  - Streaming logs
  - Status tracking
  - Cancellation
  - JSON parsing
  - Timeout handling
  - Docker-aware paths
  - Persistence to falcon.db (ADDED 2026-09-18)
"""
import asyncio
import json
import os
import shutil
import signal
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

# ============================================================
# Path detection (works both native + Docker)
# ============================================================
BACKEND_DIR = Path(__file__).resolve().parent.parent  # web/backend/
if os.path.exists("/app/framework/cli.py"):
    FRAMEWORK_DIR = Path("/app/framework")
    NIGHTFALL_DIR = Path("/app")
    WORKDIR = Path("/app")
elif os.path.exists(BACKEND_DIR.parent.parent / "framework" / "cli.py"):
    FRAMEWORK_DIR = BACKEND_DIR.parent.parent / "framework"
    NIGHTFALL_DIR = BACKEND_DIR.parent.parent
    WORKDIR = NIGHTFALL_DIR
else:
    raise RuntimeError(
        f"Cannot locate framework/cli.py. Tried:\n"
        f"  - /app/framework/cli.py\n"
        f"  - {BACKEND_DIR.parent.parent / 'framework' / 'cli.py'}"
    )

CLI_PATH = FRAMEWORK_DIR / "cli.py"
PROFILES_DIR = FRAMEWORK_DIR / "profiles"
OUTPUT_DIR = FRAMEWORK_DIR / "output"
LOGS_DIR = BACKEND_DIR / "logs"

for d in (PROFILES_DIR, OUTPUT_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)


# ============================================================
# falcon.db path
# ============================================================
def _falcon_db_path() -> Optional[Path]:
    """Locate falcon.db (Docker: /app/falcon.db; native: web/backend/falcon.db)."""
    for p in (Path("/app/falcon.db"), BACKEND_DIR / "falcon.db", NIGHTFALL_DIR / "falcon.db"):
        if p.exists():
            return p
    return None


# ============================================================
# Python executable detection
# ============================================================
def _python_bin() -> str:
    """Return the python executable (venv-aware)."""
    if sys.executable and Path(sys.executable).exists():
        return sys.executable
    for candidate in ("python3", "python"):
        p = shutil.which(candidate)
        if p:
            return p
    raise RuntimeError("No python interpreter found")


# ============================================================
# Data classes
# ============================================================
@dataclass
class ScanState:
    """Live state of a running CLI scan."""
    scan_id: str
    target: str
    status: str = "pending"      # pending | running | done | error | cancelled | timeout
    started_at: str = ""
    finished_at: str = ""
    exit_code: Optional[int] = None
    pid: Optional[int] = None
    stdout_lines: List[str] = field(default_factory=list)
    stderr_lines: List[str] = field(default_factory=list)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    args: List[str] = field(default_factory=list)
    db_scan_id: Optional[int] = None   # ADDED: falcon.db row id

    def to_dict(self, tail: int = 200) -> dict:
        d = asdict(self)
        d["stdout_lines"] = self.stdout_lines[-tail:]
        d["stderr_lines"] = self.stderr_lines[-tail:]
        return d


# ============================================================
# Global registry (in-memory + persisted to disk)
# ============================================================
_REGISTRY: Dict[str, ScanState] = {}
_LOCK = threading.Lock()
_MAX_KEEP = 20


def _register(state: ScanState):
    with _LOCK:
        _REGISTRY[state.scan_id] = state
        if len(_REGISTRY) > _MAX_KEEP:
            oldest = sorted(_REGISTRY.values(), key=lambda s: s.started_at or "")
            for old in oldest[: len(_REGISTRY) - _MAX_KEEP]:
                _REGISTRY.pop(old.scan_id, None)


def _get(scan_id: str) -> Optional[ScanState]:
    with _LOCK:
        return _REGISTRY.get(scan_id)


def list_scans() -> List[dict]:
    with _LOCK:
        return [s.to_dict(tail=0) for s in _REGISTRY.values()]


# ============================================================
# Log persistence (per-scan .log file)
# ============================================================
def _log_path(scan_id: str) -> Path:
    return LOGS_DIR / f"{scan_id}.log"


def _append_log(scan_id: str, line: str):
    try:
        with open(_log_path(scan_id), "a", encoding="utf-8") as f:
            f.write(line.rstrip("\n") + "\n")
    except Exception:
        pass


def read_log(scan_id: str, tail: int = 500) -> List[str]:
    p = _log_path(scan_id)
    if not p.exists():
        return []
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-tail:]
    except Exception:
        return []


# ============================================================
# falcon.db integration (ADDED 2026-09-18)
# ============================================================
def _flatten_findings(result: dict, target: str) -> List[dict]:
    """Extract findings from framework CLI JSON result.

    Framework result shape:
      {
        "module_results": {
          "headers_check": {"findings": [{severity, title, description, evidence, url, category}, ...]},
          "xss_scanner":   {"vulnerable": [{url, param, payload, severity, ...}, ...]},
          "sqli_scanner":  {"vulnerable": [{"url", "param", "payload", "severity", ...}, ...]},
          ...
        },
        "findings": [ ...already-normalized findings... ]   # may be present
      }
    """
    out: List[dict] = []

    # 1) Top-level "findings" list (if framework already produced them)
    top = result.get("findings")
    if isinstance(top, list):
        for f in top:
            if isinstance(f, dict):
                out.append(f)

    # 2) Per-module findings/vulnerable arrays
    mod_results = result.get("module_results") or {}
    for mod_name, mod_data in mod_results.items():
        if not isinstance(mod_data, dict):
            continue

        # a) mod_data["findings"] (e.g. headers_check)
        for f in (mod_data.get("findings") or []):
            if isinstance(f, dict):
                f2 = dict(f)
                f2.setdefault("vuln_class", f2.get("category") or mod_name)
                f2.setdefault("subtype", f2.get("title"))
                f2.setdefault("url", f2.get("url") or target)
                out.append(f2)

        # b) mod_data["vulnerable"] (e.g. xss_scanner, sqli_scanner)
        for v in (mod_data.get("vulnerable") or []):
            if isinstance(v, dict):
                v2 = dict(v)
                v2.setdefault("vuln_class", v2.get("class") or mod_name)
                v2.setdefault("subtype", v2.get("type") or v2.get("param"))
                v2.setdefault("url", v2.get("injected_url") or v2.get("url") or target)
                out.append(v2)

    # 3) Normalize each finding to falcon.db findings schema
    normalized: List[dict] = []
    for f in out:
        normalized.append({
            "vuln_class": (f.get("vuln_class") or f.get("category") or f.get("class") or "unknown"),
            "subtype":    (f.get("subtype") or f.get("title") or f.get("type") or ""),
            "severity":   (f.get("severity") or "info").lower(),
            "url":        (f.get("url") or f.get("injected_url") or target),
            "param":      (f.get("param") or f.get("parameter") or ""),
            "payload":    (f.get("payload") or ""),
            "evidence":   (f.get("evidence") or f.get("description") or ""),
            "confidence": float(f.get("confidence") or 0.8),
        })
    return normalized


def _save_to_falcon_db(state: "ScanState") -> Optional[int]:
    """Insert a completed Framework scan + findings into falcon.db.

    Returns: scan_id (DB row id) or None on failure.
    Best-effort: never raises.
    """
    if state.status != "done" or not state.result:
        return None

    db_path = _falcon_db_path()
    if not db_path:
        print("[cli_runner] falcon.db not found; skipping persist", flush=True)
        return None

    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()

        # --- Compute basic metadata ---
        target = state.target or state.result.get("target") or ""
        now = time.time()

        # Best-effort started_at from ISO string
        try:
            started_ts = datetime.fromisoformat(state.started_at.replace("Z", "+00:00")).timestamp()
        except Exception:
            started_ts = now
        try:
            completed_ts = datetime.fromisoformat(state.finished_at.replace("Z", "+00:00")).timestamp()
        except Exception:
            completed_ts = now

        elapsed = max(0.0, completed_ts - started_ts)

        # --- Parse findings ---
        findings = _flatten_findings(state.result, target)

        # --- Insert scan row ---
        cur.execute(
            """
            INSERT INTO scans
              (target, budget, exploit, status, findings_count,
               requests_used, elapsed_seconds, ai_tokens, ai_plan,
               started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                0,                       # budget — framework CLI doesn't use it
                "off",                   # exploit mode
                "completed",             # falcon.db status enum
                len(findings),
                0,                       # requests_used (not tracked by framework)
                elapsed,
                0,                       # ai_tokens
                json.dumps({"engine": "framework-cli", "scan_id": state.scan_id}),
                started_ts,
                completed_ts,
            ),
        )
        db_scan_id = cur.lastrowid

        # --- Insert findings ---
        for f in findings:
            cur.execute(
                """
                INSERT INTO findings
                  (scan_id, vuln_class, subtype, severity, url, param,
                   payload, evidence, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    db_scan_id,
                    f["vuln_class"],
                    f["subtype"],
                    f["severity"],
                    f["url"],
                    f["param"],
                    f["payload"],
                    f["evidence"],
                    f["confidence"],
                    now,
                ),
            )

        conn.commit()
        conn.close()

        state.db_scan_id = db_scan_id
        print(
            f"[cli_runner] Saved to falcon.db: scan_id={db_scan_id}, "
            f"findings={len(findings)}",
            flush=True,
        )
        return db_scan_id

    except Exception as e:
        print(f"[cli_runner] save_to_falcon_db failed: {e}", flush=True)
        return None


# ============================================================
# Core: run CLI scan
# ============================================================
# ============================================================
# Reports bridge (ADDED 2026-09-18)
# ============================================================
def _write_finding_report(out_dir, db_scan_id, index, finding, target):
    vuln_class = (finding.get("vuln_class") or "unknown").lower().replace(" ", "_")
    filename = "scan_%s_finding_%s_%s.md" % (db_scan_id, index, vuln_class)
    path = out_dir / filename

    severity = (finding.get("severity") or "info").upper()
    subtype = finding.get("subtype") or ""
    url = finding.get("url") or target
    param = finding.get("param") or "-"
    payload = finding.get("payload") or "-"
    evidence = finding.get("evidence") or "-"

    md = "# Scan #%s - Finding #%s\n\n" % (db_scan_id, index)
    md += "**Severity:** %s\n" % severity
    md += "**Class:** %s\n" % vuln_class
    md += "**Subtype:** %s\n\n" % subtype
    md += "## Target\n\n`%s`\n\n" % target
    md += "## URL\n\n`%s`\n\n" % url
    md += "## Parameter\n\n`%s`\n\n" % param
    md += "## Payload\n\n```\n%s\n```\n\n" % payload
    md += "## Evidence\n\n%s\n\n" % evidence
    md += "---\n\n*Generated by Falcon MAG Framework CLI*\n"

    path.write_text(md, encoding="utf-8")
    return path


def _write_summary_report(out_dir, db_scan_id, target, findings, elapsed):
    path = out_dir / ("scan_%s_summary.md" % db_scan_id)

    counts = {}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        counts[s] = counts.get(s, 0) + 1

    severity_lines = "\n".join(
        "- **%s:** %s" % (s.upper(), n) for s, n in sorted(counts.items())
    ) or "- No findings"

    rows = []
    for i, f in enumerate(findings, 1):
        rows.append(
            "| %s | %s | %s | %s | `%s` |" % (
                i,
                (f.get("severity") or "info").upper(),
                f.get("vuln_class") or "-",
                f.get("subtype") or "-",
                f.get("url") or "-",
            )
        )
    table = "\n".join(rows) if rows else "| - | - | - | - | - |"

    md = "# Scan #%s - Summary\n\n" % db_scan_id
    md += "**Target:** `%s`\n" % target
    md += "**Duration:** %.2fs\n" % elapsed
    md += "**Total Findings:** %s\n\n" % len(findings)
    md += "## Severity Breakdown\n\n%s\n\n" % severity_lines
    md += "## Findings\n\n| # | Severity | Class | Subtype | URL |\n"
    md += "|---|----------|-------|---------|-----|\n"
    md += table + "\n\n---\n\n*Generated by Falcon MAG Framework CLI*\n"

    path.write_text(md, encoding="utf-8")
    return path




def _save_excel_export(state):
    """Generate an Excel (.xlsx) export for a completed scan (ADDED 2026-09-18).

    Output: web/backend/exports/falcon_scan_{db_id}_{timestamp}.xlsx
    Sheets: Summary, Findings
    """
    if state.status != "done" or not state.result:
        return None
    if not state.db_scan_id:
        return None

    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
    except Exception as e:
        print("[cli_runner] openpyxl not available: %s" % e, flush=True)
        return None

    # Locate exports dir
    targets = [BACKEND_DIR / "exports", Path("/app/exports")]
    out_dir = next((d for d in targets if d.exists()), None)
    if not out_dir:
        try:
            out_dir = targets[0]
            out_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print("[cli_runner] cannot create exports dir: %s" % e, flush=True)
            return None

    try:
        findings = _flatten_findings(state.result, state.target)

        wb = Workbook()

        # ---------------- Summary sheet ----------------
        ws = wb.active
        ws.title = "Summary"

        header_font = Font(bold=True, size=12, color="FFFFFF")
        header_fill = PatternFill("solid", fgColor="B91C1C")
        label_font = Font(bold=True)

        ws["A1"] = "Falcon MAG - Scan Summary"
        ws["A1"].font = Font(bold=True, size=14, color="B91C1C")
        ws.merge_cells("A1:B1")

        row = 3
        ws.cell(row=row, column=1, value="Scan ID (DB)").font = label_font
        ws.cell(row=row, column=2, value=state.db_scan_id)
        row += 1
        ws.cell(row=row, column=1, value="Framework Scan ID").font = label_font
        ws.cell(row=row, column=2, value=state.scan_id)
        row += 1
        ws.cell(row=row, column=1, value="Target").font = label_font
        ws.cell(row=row, column=2, value=state.target)
        row += 1
        ws.cell(row=row, column=1, value="Started At").font = label_font
        ws.cell(row=row, column=2, value=state.started_at)
        row += 1
        ws.cell(row=row, column=1, value="Finished At").font = label_font
        ws.cell(row=row, column=2, value=state.finished_at)
        row += 1
        ws.cell(row=row, column=1, value="Exit Code").font = label_font
        ws.cell(row=row, column=2, value=state.exit_code)
        row += 1
        ws.cell(row=row, column=1, value="Total Findings").font = label_font
        ws.cell(row=row, column=2, value=len(findings))

        # Severity breakdown
        row += 2
        ws.cell(row=row, column=1, value="Severity Breakdown").font = Font(bold=True, size=12)
        row += 1
        counts = {}
        for f in findings:
            s = (f.get("severity") or "info").upper()
            counts[s] = counts.get(s, 0) + 1
        for sev, n in sorted(counts.items()):
            ws.cell(row=row, column=1, value=sev).font = label_font
            ws.cell(row=row, column=2, value=n)
            row += 1

        ws.column_dimensions["A"].width = 25
        ws.column_dimensions["B"].width = 60

        # ---------------- Findings sheet ----------------
        ws2 = wb.create_sheet("Findings")
        headers = ["#", "Severity", "Class", "Subtype", "URL", "Param", "Payload", "Evidence", "Confidence"]
        for c, h in enumerate(headers, 1):
            cell = ws2.cell(row=1, column=c, value=h)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal="center")

        sev_colors = {
            "CRITICAL": "DC2626",
            "HIGH": "EA580C",
            "MEDIUM": "CA8A04",
            "LOW": "16A34A",
            "INFO": "0891B2",
        }

        for i, f in enumerate(findings, 1):
            sev = (f.get("severity") or "info").upper()
            row_values = [
                i,
                sev,
                f.get("vuln_class") or "-",
                f.get("subtype") or "-",
                f.get("url") or "-",
                f.get("param") or "-",
                f.get("payload") or "-",
                f.get("evidence") or "-",
                f.get("confidence") or 0.8,
            ]
            for c, v in enumerate(row_values, 1):
                cell = ws2.cell(row=i + 1, column=c, value=v)
                if c == 2 and sev in sev_colors:
                    cell.font = Font(bold=True, color=sev_colors[sev])

        # Column widths
        widths = [5, 12, 15, 30, 60, 15, 40, 60, 12]
        for c, w in enumerate(widths, 1):
            ws2.column_dimensions[chr(64 + c) if c <= 26 else "A"].width = w

        ws2.freeze_panes = "A2"

        # ---------------- Save ----------------
        import time as _time
        ts = int(_time.time())
        filename = "falcon_scan_%s_%s.xlsx" % (state.db_scan_id, ts)
        path = out_dir / filename
        wb.save(str(path))

        print("[cli_runner] Excel saved: %s (%s findings)" % (path, len(findings)), flush=True)
        return path

    except Exception as e:
        print("[cli_runner] save_excel_export failed: %s" % e, flush=True)
        return None


def _save_reports_to_backend(state):
    if state.status != "done" or not state.result:
        return
    if not state.db_scan_id:
        print("[cli_runner] no db_scan_id; skipping reports", flush=True)
        return

    targets = [
        BACKEND_DIR / "bug_bounty_reports",
        Path("/app/bug_bounty_reports"),
    ]
    out_dir = next((d for d in targets if d.exists()), None)
    if not out_dir:
        try:
            out_dir = targets[0]
            out_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print("[cli_runner] cannot create reports dir: %s" % e, flush=True)
            return

    try:
        findings = _flatten_findings(state.result, state.target)

        for i, f in enumerate(findings, 1):
            try:
                _write_finding_report(out_dir, state.db_scan_id, i, f, state.target)
            except Exception as e:
                print("[cli_runner] finding report %s failed: %s" % (i, e), flush=True)

        try:
            elapsed = 0.0
            try:
                s = datetime.fromisoformat(state.started_at.replace("Z", "+00:00"))
                e = datetime.fromisoformat(state.finished_at.replace("Z", "+00:00"))
                elapsed = (e - s).total_seconds()
            except Exception:
                pass
            _write_summary_report(out_dir, state.db_scan_id, state.target, findings, elapsed)
        except Exception as e:
            print("[cli_runner] summary report failed: %s" % e, flush=True)

        print("[cli_runner] Reports generated: scan_%s_* (%s findings) in %s" % (
            state.db_scan_id, len(findings), out_dir
        ), flush=True)

    except Exception as e:
        print("[cli_runner] save_reports_to_backend failed: %s" % e, flush=True)

def build_scan_args(
    target: str,
    modules: Optional[str] = None,
    all_modules: bool = False,
    output: Optional[str] = None,
    login_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    bearer_token: Optional[str] = None,
    cookie: Optional[str] = None,
    cookie_file: Optional[str] = None,
    cookies: Optional[str] = None,
    method: str = "GET",
    post_data: Optional[str] = None,
    post_json: Optional[str] = None,
    header: Optional[str] = None,
    parallel: int = 1,
    insecure: bool = False,
    profile: Optional[str] = None,
    totp_secret: Optional[str] = None,
    config: Optional[str] = None,
    json_out: bool = True,
    quiet: bool = True,
) -> List[str]:
    """Build the argv list for `python framework/cli.py scan ...`."""
    args = [
        _python_bin(), str(CLI_PATH),
        "scan", target,
        "--json",
    ]
    if quiet:
        args.append("--quiet")
    if modules:
        args += ["--modules", modules]
    if all_modules:
        args.append("--all")
    if config:
        args += ["--config", config]
    if output:
        args += ["--output", output]
    if login_url:
        args += ["--login-url", login_url]
    if username:
        args += ["--username", username]
    if password:
        args += ["--password", password]
    if bearer_token:
        args += ["--bearer-token", bearer_token]
    if cookie:
        args += ["--cookie", cookie]
    if cookie_file:
        args += ["--cookie-file", cookie_file]
    if cookies:
        args += ["--cookies", cookies]
    if method and method != "GET":
        args += ["--method", method]
    if post_data:
        args += ["--post-data", post_data]
    if post_json:
        args += ["--post-json", post_json]
    if header:
        args += ["--header", header]
    if parallel and parallel > 1:
        args += ["--parallel", str(parallel)]
    if insecure:
        args.append("--insecure")
    if profile:
        args += ["--profile", profile]
    if totp_secret:
        args += ["--totp-secret", totp_secret]
    return args


def run_scan_sync(
    scan_id: str,
    args: List[str],
    timeout: int = 3600,
) -> ScanState:
    """Blocking scan run — runs inside a thread."""
    state = _get(scan_id)
    if not state:
        raise RuntimeError(f"Unknown scan_id: {scan_id}")

    state.status = "running"
    state.started_at = datetime.now(timezone.utc).isoformat()
    state.args = args

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    try:
        import subprocess
        proc = subprocess.Popen(
            args,
            cwd=str(WORKDIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP
                if sys.platform == "win32" else 0
            ),
        )
        state.pid = proc.pid

        stdout_buf: List[str] = []
        start = time.time()

        def _read_stdout():
            for line in proc.stdout:  # type: ignore
                state.stdout_lines.append(line.rstrip("\n"))
                stdout_buf.append(line)
                _append_log(scan_id, line.rstrip("\n"))

        def _read_stderr():
            for line in proc.stderr:  # type: ignore
                state.stderr_lines.append(line.rstrip("\n"))
                _append_log(scan_id, "[stderr] " + line.rstrip("\n"))

        t_out = threading.Thread(target=_read_stdout, daemon=True)
        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=timeout)
        except Exception:
            state.status = "timeout"
            state.error = f"Timed out after {timeout}s"
            _terminate(proc)
            t_out.join(timeout=2)
            t_err.join(timeout=2)
            return state

        t_out.join(timeout=5)
        t_err.join(timeout=5)

        state.exit_code = proc.returncode
        state.finished_at = datetime.now(timezone.utc).isoformat()

        json_text = _extract_json("".join(stdout_buf))
        if json_text is not None:
            state.result = json_text

        if proc.returncode == 0:
            state.status = "done"
            # ADDED 2026-09-18: persist to falcon.db
            _save_to_falcon_db(state)
            # ADDED 2026-09-18: generate V1-format reports
            _save_reports_to_backend(state)
            # ADDED 2026-09-18: generate Excel export
            _save_excel_export(state)
            # ADDED 2026-09-18: generate V1-format reports
            _save_reports_to_backend(state)
        else:
            state.status = "error"
            state.error = (
                f"CLI exited with code {proc.returncode}. "
                f"stderr tail: {' | '.join(state.stderr_lines[-5:])}"
            )

    except FileNotFoundError as e:
        state.status = "error"
        state.error = f"CLI not found: {e}"
    except Exception as e:
        state.status = "error"
        state.error = f"{type(e).__name__}: {e}"
    finally:
        if not state.finished_at:
            state.finished_at = datetime.now(timezone.utc).isoformat()

    return state


def _extract_json(text: str) -> Optional[dict]:
    """Extract the last JSON object from CLI stdout."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    last_open = text.rfind("{")
    while last_open != -1:
        candidate = text[last_open:]
        try:
            return json.loads(candidate)
        except Exception:
            last_open = text.rfind("{", 0, last_open)
    return None


def _terminate(proc):
    """Cross-platform process kill."""
    try:
        if sys.platform == "win32":
            import subprocess
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
            )
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# ============================================================
# Async wrapper
# ============================================================
async def run_scan_async(
    scan_id: str,
    args: List[str],
    timeout: int = 3600,
) -> ScanState:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, run_scan_sync, scan_id, args, timeout)


def start_scan(
    target: str,
    scan_id: Optional[str] = None,
    timeout: int = 3600,
    **kwargs,
) -> ScanState:
    """Start a scan and return immediately (background thread)."""
    if not scan_id:
        scan_id = f"cli_{int(time.time())}_{os.getpid()}"

    state = ScanState(scan_id=scan_id, target=target)
    _register(state)

    args = build_scan_args(target=target, **kwargs)
    t = threading.Thread(
        target=run_scan_sync,
        args=(scan_id, args, timeout),
        daemon=True,
    )
    t.start()
    return state


def cancel_scan(scan_id: str) -> dict:
    """Cancel a running scan by id."""
    state = _get(scan_id)
    if not state:
        return {"status": "not_found", "scan_id": scan_id}
    if state.status != "running" or not state.pid:
        return {"status": "not_running", "scan_id": scan_id, "state": state.status}
    try:
        import subprocess
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(state.pid)],
                capture_output=True,
            )
        else:
            os.killpg(os.getpgid(state.pid), signal.SIGTERM)
        state.status = "cancelled"
        state.finished_at = datetime.now(timezone.utc).isoformat()
        return {"status": "cancelled", "scan_id": scan_id}
    except Exception as e:
        return {"status": "error", "scan_id": scan_id, "error": str(e)}


def get_status(scan_id: str, tail: int = 200) -> Optional[dict]:
    state = _get(scan_id)
    return state.to_dict(tail=tail) if state else None


# ============================================================
# Profiles (framework/profiles/*.json)
# ============================================================
def list_profiles() -> List[dict]:
    out = []
    if not PROFILES_DIR.exists():
        return out
    for p in sorted(PROFILES_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            out.append({
                "name": data.get("profile", p.stem),
                "login_url": data.get("login_url", ""),
                "provider": data.get("provider", ""),
                "saved_at": data.get("saved_at", ""),
                "cookies_count": len(data.get("cookies", [])),
                "file": str(p),
            })
        except Exception as e:
            out.append({"name": p.stem, "error": str(e), "file": str(p)})
    return out


def get_profile(name: str) -> Optional[dict]:
    p = PROFILES_DIR / f"{name}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


# ============================================================
# Login via CLI (Playwright)
# ============================================================
def build_login_args(
    url: str,
    auth_type: str = "auto",
    username: Optional[str] = None,
    password: Optional[str] = None,
    totp_secret: Optional[str] = None,
    button_selector: Optional[str] = None,
    otp_selector: Optional[str] = None,
    profile: str = "default",
    wait: int = 240,
    headless: bool = False,
    success_url: Optional[str] = None,
) -> List[str]:
    args = [
        _python_bin(), str(CLI_PATH),
        "login", url,
        "--auth-type", auth_type,
        "--profile", profile,
        "--wait", str(wait),
    ]
    if headless:
        args.append("--headless")
    if username:
        args += ["--username", username]
    if password:
        args += ["--password", password]
    if totp_secret:
        args += ["--totp-secret", totp_secret]
    if button_selector:
        args += ["--button-selector", button_selector]
    if otp_selector:
        args += ["--otp-selector", otp_selector]
    if success_url:
        args += ["--success-url", success_url]
    return args


def run_login_sync(
    login_id: str,
    args: List[str],
    timeout: int = 600,
) -> ScanState:
    return run_scan_sync(login_id, args, timeout=timeout)


# ============================================================
# Environment diagnostics
# ============================================================
def diagnose() -> dict:
    db = _falcon_db_path()
    return {
        "cli_path": str(CLI_PATH),
        "cli_exists": CLI_PATH.exists(),
        "framework_dir": str(FRAMEWORK_DIR),
        "nightfall_dir": str(NIGHTFALL_DIR),
        "workdir": str(WORKDIR),
        "python_bin": _python_bin(),
        "profiles_dir": str(PROFILES_DIR),
        "profiles_count": len(list(PROFILES_DIR.glob("*.json"))) if PROFILES_DIR.exists() else 0,
        "output_dir": str(OUTPUT_DIR),
        "logs_dir": str(LOGS_DIR),
        "registry_size": len(_REGISTRY),
        "falcon_db": str(db) if db else None,
        "falcon_db_exists": bool(db),
    }