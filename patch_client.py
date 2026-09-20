# -*- coding: utf-8 -*-
from pathlib import Path

f = Path(r"C:\BugBounty\NIGHTFALL\web\frontend\src\api\clientV2.js")
content = f.read_text(encoding="utf-8")

old_api = '''export const frameworkScanApi = {
  start:    (data)                => clientV2.post("/api/v2/scans/start", data),
  status:   (scanId)              => clientV2.get(`/api/v2/scans/status/${scanId}`),
  log:      (scanId, tail = 200)  => clientV2.get(`/api/v2/scans/log/${scanId}?tail=${tail}`),
  cancel:   (scanId)              => clientV2.post(`/api/v2/scans/cancel/${scanId}`),
  list:     ()                    => clientV2.get("/api/v2/scans/list"),
  diagnose: ()                    => clientV2.get("/api/v2/scans/diagnose"),
};'''

new_api = '''export const frameworkScanApi = {
  start:        (data)                => clientV2.post("/api/v2/scans/start", data),
  status:       (scanId)              => clientV2.get(`/api/v2/scans/status/${scanId}`),
  log:          (scanId, tail = 200)  => clientV2.get(`/api/v2/scans/log/${scanId}?tail=${tail}`),
  cancel:       (scanId)              => clientV2.post(`/api/v2/scans/cancel/${scanId}`),
  pause:        (scanId)              => clientV2.post(`/api/v2/scans/pause/${scanId}`),
  resume:       (scanId)              => clientV2.post(`/api/v2/scans/resume/${scanId}`),
  report:       (scanId)              => clientV2.get(`/api/v2/scans/report/${scanId}`),
  list:         ()                    => clientV2.get("/api/v2/scans/list"),
  diagnose:     ()                    => clientV2.get("/api/v2/scans/diagnose"),
};'''

if old_api in content:
    content = content.replace(old_api, new_api, 1)
    print("[OK] clientV2.js updated with pause/resume/report")
elif 'pause:        (scanId)' in content:
    print("[SKIP] already updated")
else:
    print("[FAIL] frameworkScanApi block not found")

f.write_text(content, encoding="utf-8")
print("=== Done ===")
