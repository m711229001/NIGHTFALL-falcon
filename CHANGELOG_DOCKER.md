# CHANGELOG — Falcon MAG Platform

> Complete history of Docker, Framework, Modern Modules, and UI.
> **Rule:** No-Deletion — nothing was removed, only added or fixed.

---

## 2026-09-19 — Modern Modules Release 🎉

### Summary
Added 6 modern vulnerability modules (2024-2025), Arabic knowledge base
with PoC for Drawer UI, and comprehensive explanation system.

---

## Phase 1 — Docker Infrastructure ✅ (2026-09-18)

### Created
- `web/backend/requirements.txt` — complete dependency list (was missing)
- `web/backend/Dockerfile` — python:3.12-slim + Playwright + nmap + testssl + Xvfb + VNC
- `docker-compose.yml` — 3 ports (8888 API, 5900 VNC, 6080 noVNC)
- `web/backend/start-with-vnc.sh` — Xvfb + x11vnc + noVNC startup

### Verified
- `docker compose ps` → Up (healthy) with all 3 ports
- `curl http://localhost:8888/api/health` → `{"status":"healthy"}`

---

## Phase 2 — Framework CLI Integration ✅

### Created
- `web/backend/services/cli_runner.py` (~500 lines)
  - subprocess wrapper for `framework/cli.py`
  - ScanState + registry + live log streaming
  - `_save_to_falcon_db` — persist scans + findings
  - `_save_reports_to_backend` — V1-format reports
  - `_save_excel_export` — Excel export
  - `_save_ai_analysis` — DeepSeek analysis
- `web/backend/api/scans_v2.py` — 8 endpoints (start, status, log, cancel, list, diagnose, sarif, ai)
- `web/backend/api/profiles_v2.py` — 2 endpoints
- `web/backend/api/auth_v2.py` — 4 endpoints (types, login, status, log)

---

## Phase 3 — Frontend V2 ✅

### Pages
- `FrameworkScanV2.jsx` — Module picker (5 groups) + Modern preset + Auth + Live log
- `ProfilesV2.jsx` — Login profiles management
- `LoginV2.jsx` — Playwright login + VNC floating widget
- `FindingsV2.jsx` — All findings + filters + Drawer
- `ScanDetailsV2.jsx` — Scan detail view
- `DashboardV2.jsx` — KPIs + charts

### Components
- `VulnDetailDrawer.jsx` — Arabic explanation + PoC + CVSS/CWE

---

## Phase 4 — Interactive Auth + VNC ✅

### Root cause fixed
- `wait_for_url_contains(page, host)` matched immediately → browser closed after 3s
- New: `wait_for_login_success()` — smarter detection (host + path + cookies)

### Features
- `--wait 0` → open-ended interactive (press ENTER to save)
- Xvfb `:99` + x11vnc `:5900` + noVNC `:6080`
- VNC floating widget in LoginV2
- Verified with Nafath: 44 cookies, OAuth: 8, SAML: 7

---

## Phase 5 — 6 Modern Modules (2024-2025) ✅

### Framework modules added
| Module | Purpose |
|--------|---------|
| `tech_fingerprint` | Detect 25+ technologies (Next.js, React RSC, WordPress, Vercel) |
| `nextjs_middleware_bypass` | CVE-2025-29927 — bypass auth middleware |
| `rsc_data_leakage` | Detect leaked data in __NEXT_DATA__ / self.__next_f |
| `graphql_relay_idor` | Forge Global IDs (base64) — Bug Bounty Gold |
| `react2shell_rce` | CVE-2025-55182 — Flight protocol deserialization |
| `ssr_proto_pollution` | Prototype pollution in SSR context |

### Verified
- `tech_fingerprint` on vercel.com → detected Next.js + React RSC + Vercel (0 FPs)
- `nextjs_middleware_bypass` on test server → 5 bypasses detected
- All 6 modules ready in `framework/cli.py list` (38 total)

---

## Phase 6 — Arabic Knowledge Base ✅

### Files
- `web/frontend/src/v2/data/vulnKnowledge.js` (deprecated — replaced by inline KB)
- `web/frontend/src/v2/components/VulnDetailDrawer.jsx` — inline KB with:
  - SQL Injection, SSTI, XSS, DOM XSS, Headers, Path Traversal
  - What / How / Impact / Exploit steps / cURL / Python PoC / Tools
  - CVSS, CWE, References

### Features
- Copy button for every code block
- CVSS score with color (red ≥7, yellow ≥4, green <4)
- RTL-friendly layout
- ESC to close, click outside to close

---

## File Inventory

| Path | Type | Status |
|------|------|--------|
| `framework/modules/tech_fingerprint.py` | Module | ✅ |
| `framework/modules/nextjs_middleware_bypass.py` | Module | ✅ |
| `framework/modules/rsc_data_leakage.py` | Module | ✅ |
| `framework/modules/graphql_relay_idor.py` | Module | ✅ |
| `framework/modules/react2shell_rce.py` | Module | ✅ |
| `framework/modules/ssr_proto_pollution.py` | Module | ✅ |
| `web/backend/services/cli_runner.py` | Service | ✅ |
| `web/backend/api/scans_v2.py` | API | ✅ |
| `web/backend/api/profiles_v2.py` | API | ✅ |
| `web/backend/api/auth_v2.py` | API | ✅ |
| `web/frontend/src/api/clientV2.js` | API client | ✅ |
| `web/frontend/src/v2/pages/FrameworkScanV2.jsx` | Page | ✅ |
| `web/frontend/src/v2/pages/ProfilesV2.jsx` | Page | ✅ |
| `web/frontend/src/v2/pages/LoginV2.jsx` | Page | ✅ |
| `web/frontend/src/v2/pages/FindingsV2.jsx` | Page | ✅ |
| `web/frontend/src/v2/components/VulnDetailDrawer.jsx` | Component | ✅ |

---

## Verification Commands

```cmd
# Stack status
docker compose ps

# Framework modules
docker compose exec backend python /app/framework/cli.py list

# Test modern modules
docker compose exec backend python /app/framework/cli.py scan https://vercel.com --modules tech_fingerprint --json --quiet

# Latest findings
docker compose exec backend python -c "import sqlite3; c=sqlite3.connect('/app/falcon.db'); c.row_factory=sqlite3.Row; [print(dict(r)) for r in c.execute('SELECT id, vuln_class, severity, url FROM findings ORDER BY id DESC LIMIT 5')]"