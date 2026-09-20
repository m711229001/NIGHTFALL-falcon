# -*- coding: utf-8 -*-
from pathlib import Path

f = Path(r"C:\BugBounty\NIGHTFALL\web\frontend\src\v2\pages\LiveMonitorV2.jsx")
content = f.read_text(encoding="utf-8")

# 1. Add state for pause/export
old_state = '  const stoppedRef = useRef(false)'
new_state = '''  const stoppedRef = useRef(false)
  const [isPaused, setIsPaused] = useState(false)
  const [exporting, setExporting] = useState(false)'''

if old_state in content:
    content = content.replace(old_state, new_state, 1)
    print("[OK] state added")

# 2. Add handlers after stopScan
old_stop = '''  const restart = () => {'''
new_stop = '''  const pauseScan = async () => {
    if (!scanId) return
    try {
      const r = await frameworkScanApi.pause(scanId)
      if (r.data?.status === "paused") setIsPaused(true)
    } catch { /* ignore */ }
  }

  const resumeScan = async () => {
    if (!scanId) return
    try {
      const r = await frameworkScanApi.resume(scanId)
      if (r.data?.status === "resumed") setIsPaused(false)
    } catch { /* ignore */ }
  }

  const exportReport = async () => {
    if (!scanId) return
    setExporting(true)
    try {
      const r = await frameworkScanApi.report(scanId)
      const data = r.data || {}
      // Download JSON
      const jsonBlob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json;charset=utf-8" })
      const jsonUrl = URL.createObjectURL(jsonBlob)
      const a1 = document.createElement("a")
      a1.href = jsonUrl
      a1.download = scanId + ".json"
      document.body.appendChild(a1); a1.click(); document.body.removeChild(a1)
      URL.revokeObjectURL(jsonUrl)
    } catch (e) {
      alert("Export failed: " + (e?.response?.data?.detail || e?.message || "unknown"))
    } finally {
      setExporting(false)
    }
  }

  const restart = () => {'''

if old_stop in content and 'pauseScan' not in content:
    content = content.replace(old_stop, new_stop, 1)
    print("[OK] handlers added")

# 3. Replace status area to include control buttons
old_status_area = '''              <button
                onClick={restart}
                className="p-2 rounded-md"
                style={{
                  background: "var(--bg-tertiary)",
                  color: "var(--text-primary)",
                  border: "1px solid var(--border-color)",
                  cursor: "pointer",
                }}
                title={t("common.refresh", "Refresh")}
              >
                <Icon name="refresh" size={16} />
              </button>
            </div>
          </div>'''

new_status_area = '''              <button
                onClick={restart}
                className="p-2 rounded-md"
                style={{
                  background: "var(--bg-tertiary)",
                  color: "var(--text-primary)",
                  border: "1px solid var(--border-color)",
                  cursor: "pointer",
                }}
                title={t("common.refresh", "Refresh")}
              >
                <Icon name="refresh" size={16} />
              </button>

              {/* Control buttons (ADDED 2026-09-20) */}
              {scanId && (
                <div className="flex gap-2">
                  {status?.status === "running" && !isPaused && (
                    <button onClick={pauseScan}
                      className="px-3 py-1.5 rounded-md text-xs font-bold flex items-center gap-1.5"
                      style={{
                        background: "rgba(234,179,8,0.15)",
                        color: "var(--accent-yellow)",
                        border: "1px solid var(--accent-yellow)",
                        cursor: "pointer",
                      }}
                      title="Pause scan">
                      <Icon name="pause" size={14} /> {isRtl ? "إيقاف مؤقت" : "Pause"}
                    </button>
                  )}
                  {isPaused && (
                    <button onClick={resumeScan}
                      className="px-3 py-1.5 rounded-md text-xs font-bold flex items-center gap-1.5"
                      style={{
                        background: "rgba(16,185,129,0.15)",
                        color: "var(--accent-green)",
                        border: "1px solid var(--accent-green)",
                        cursor: "pointer",
                      }}
                      title="Resume scan">
                      <Icon name="play" size={14} /> {isRtl ? "استئناف" : "Resume"}
                    </button>
                  )}
                  {(status?.status === "running" || status?.status === "paused") && (
                    <button onClick={stopScan}
                      className="px-3 py-1.5 rounded-md text-xs font-bold flex items-center gap-1.5"
                      style={{
                        background: "var(--accent-red-soft)",
                        color: "var(--accent-red)",
                        border: "1px solid var(--accent-red)",
                        cursor: "pointer",
                      }}
                      title="Stop scan permanently">
                      <Icon name="stop" size={14} /> {isRtl ? "إيقاف" : "Stop"}
                    </button>
                  )}
                  <button onClick={exportReport} disabled={exporting}
                    className="px-3 py-1.5 rounded-md text-xs font-bold flex items-center gap-1.5"
                    style={{
                      background: "var(--bg-tertiary)",
                      color: "var(--text-primary)",
                      border: "1px solid var(--border-color)",
                      cursor: exporting ? "wait" : "pointer",
                    }}
                    title="Export report as JSON">
                    <Icon name="download" size={14} />
                    {exporting ? "..." : (isRtl ? "تصدير" : "Export")}
                  </button>
                </div>
              )}
            </div>
          </div>'''

if old_status_area in content:
    content = content.replace(old_status_area, new_status_area, 1)
    print("[OK] control buttons added")
else:
    print("[FAIL] status area not found")

f.write_text(content, encoding="utf-8")
print()
print("=== Done ===")
