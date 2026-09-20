# -*- coding: utf-8 -*-
from pathlib import Path

f = Path(r"C:\BugBounty\NIGHTFALL\web\frontend\src\v2\pages\LiveMonitorV2.jsx")
content = f.read_text(encoding="utf-8")

# 1. Add progress bar + findings counters — insert before <div ref={logRef}> block
old_terminal = '''          <div
            className="rounded-2xl overflow-hidden"
            style={{
              background: "var(--bg-secondary)",
              border: "2px solid var(--border-color)",
            }}
          >'''

new_terminal = '''          {/* Progress + Live findings (ADDED 2026-09-20) */}
          {scanId && status && (
            <div className="rounded-xl p-4 space-y-3"
              style={{
                background: "var(--bg-secondary)",
                border: "1px solid var(--border-color)",
              }}>
              {/* Progress bar */}
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-xs font-bold" style={{ color: "var(--accent-cyan)" }}>
                    {isRtl ? "التقدم" : "Progress"}: {status.progress_percent || 0}%
                  </span>
                  <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                    {status.modules_done || 0} / {status.modules_total || "?"} modules
                    {status.current_module && " · " + status.current_module}
                  </span>
                </div>
                <div className="w-full h-2 rounded-full overflow-hidden"
                  style={{ background: "var(--bg-tertiary)" }}>
                  <div
                    className="h-full transition-all duration-500"
                    style={{
                      width: (status.progress_percent || 0) + "%",
                      background: "linear-gradient(90deg, var(--accent-cyan), var(--accent-green))",
                    }}
                  />
                </div>
              </div>

              {/* Live findings counters */}
              <div className="grid grid-cols-5 gap-2">
                {[
                  { key: "critical", label: isRtl ? "حرجة" : "Critical", color: "var(--sev-critical)" },
                  { key: "high",     label: isRtl ? "عالية" : "High",     color: "var(--sev-high)" },
                  { key: "medium",   label: isRtl ? "متوسطة" : "Medium",  color: "var(--sev-medium)" },
                  { key: "low",      label: isRtl ? "منخفضة" : "Low",    color: "var(--sev-low)" },
                  { key: "info",     label: isRtl ? "معلوماتية" : "Info",  color: "var(--sev-info)" },
                ].map(({ key, label, color }) => {
                  const count = (status.findings_live || {})[key] || 0
                  return (
                    <div key={key} className="rounded-lg p-2 text-center"
                      style={{
                        background: count > 0 ? "rgba(255,255,255,0.03)" : "transparent",
                        border: "1px solid " + (count > 0 ? color : "var(--border-color)"),
                      }}>
                      <div className="text-lg font-bold font-mono" style={{ color }}>
                        {count}
                      </div>
                      <div className="text-[9px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                        {label}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          <div
            className="rounded-2xl overflow-hidden"
            style={{
              background: "var(--bg-secondary)",
              border: "2px solid var(--border-color)",
            }}
          >'''

if old_terminal in content:
    content = content.replace(old_terminal, new_terminal, 1)
    print("[OK] Progress + findings UI added")
else:
    print("[FAIL] Terminal block not found")

f.write_text(content, encoding="utf-8")
print()
print("=== Done ===")
