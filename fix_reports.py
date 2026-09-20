# -*- coding: utf-8 -*-
from pathlib import Path

f = Path(r"C:\BugBounty\NIGHTFALL\web\backend\api\reports.py")
content = f.read_text(encoding="utf-8")

old_dirs = '''REPORT_DIRS = [
    BACKEND_DIR / "reports",                # web/backend/reports/
    BACKEND_DIR / "bug_bounty_reports",    # web/backend/bug_bounty_reports/
    BACKEND_DIR / "core" / "nightfall" / "reports",  # legacy
    BACKEND_DIR.parent / "reports",        # web/reports/
    BACKEND_DIR.parent.parent / "reports", # NIGHTFALL/reports/
]'''

new_dirs = '''REPORT_DIRS = [
    # Framework CLI reports (rich, AI-enhanced, Arabic)
    Path("/app/framework/output"),                        # Docker path
    BACKEND_DIR.parent.parent / "framework" / "output",   # Native path
    # Legacy backend reports (simple, no AI)
    BACKEND_DIR / "reports",                              # web/backend/reports/
    BACKEND_DIR / "bug_bounty_reports",                   # web/backend/bug_bounty_reports/
    BACKEND_DIR / "core" / "nightfall" / "reports",       # legacy
    BACKEND_DIR.parent / "reports",                       # web/reports/
    BACKEND_DIR.parent.parent / "reports",                # NIGHTFALL/reports/
]'''

if old_dirs not in content:
    print("[FAIL] REPORT_DIRS block not found")
    print("       File may have different indentation/format")
    raise SystemExit(1)

content = content.replace(old_dirs, new_dirs, 1)
f.write_text(content, encoding="utf-8")
print("[OK] reports.py updated - framework/output added first")
print()
print("Search order now:")
print("  1. /app/framework/output  ← NEW (rich reports)")
print("  2. web/backend/reports")
print("  3. web/backend/bug_bounty_reports")
print("  4. legacy paths...")
