/**
 * LiveMonitorV2 — Tactical Edition
 */
import { useEffect, useState, useRef } from "react"
import { useTranslation } from "react-i18next"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import client from "../../api/client"

export default function LiveMonitorV2() {
  const { t } = useTranslation()
  const [status, setStatus] = useState(null)
  const [lines, setLines] = useState([])
  const logRef = useRef(null)

  useEffect(() => {
    const poll = async () => {
      try {
        const [s, l] = await Promise.all([
          client.get("/api/scans/status"),
          client.get("/api/scans/log", { params: { lines: 200 } }),
        ])
        setStatus(s.data)
        setLines(l.data.lines || [])
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
      } catch { /* ignore */ }
    }
    poll()
    const id = setInterval(poll, 2000)
    return () => clearInterval(id)
  }, [])

  const statusColor =
    status?.status === "running" ? "var(--accent-yellow)" :
    status?.status === "completed" ? "var(--accent-green)" :
    status?.status === "stopped" ? "var(--text-muted)" :
    "var(--text-muted)"

  const stopScan = async () => {
    try { await client.post("/api/scans/stop") } catch {}
  }

  return (
    <div
      className="flex min-h-screen transition-colors"
      style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}
    >
      <TacticalSidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />

        <main className="flex-1 p-6 overflow-x-hidden space-y-4">
          <div className="flex justify-between items-center flex-wrap gap-3">
            <div>
              <h1
                className="text-3xl font-bold"
                style={{ color: "var(--accent-red)" }}
              >
                {t("live_monitor")}
              </h1>
              <p className="text-sm mt-1 font-mono" style={{ color: "var(--text-secondary)" }}>
                {status?.url || t("no_active_scan")}
              </p>
            </div>
            <div className="text-end">
              <div className="text-lg font-bold font-mono" style={{ color: statusColor }}>
                {status?.status?.toUpperCase() || t("status_idle")}
              </div>
              {status?.budget && (
                <div className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>
                  {t("budget_label")}: {status.budget}
                </div>
              )}
            </div>
          </div>

          <div
            className="rounded-2xl overflow-hidden"
            style={{
              background: "var(--bg-secondary)",
              border: "2px solid var(--border-color)",
            }}
          >
            {/* Terminal bar */}
            <div
              className="flex items-center gap-2 px-4 py-2"
              style={{
                background: "var(--bg-tertiary)",
                borderBottom: "1px solid var(--border-color)",
              }}
            >
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <span className="text-xs font-mono ms-2" style={{ color: "var(--text-muted)" }}>
                nightfall@falcon:~$
              </span>
            </div>

            {/* Log content */}
            <div
              ref={logRef}
              className="h-[600px] overflow-y-auto p-4 font-mono text-xs whitespace-pre-wrap"
              style={{
                background: "var(--bg-primary)",
                color: "var(--accent-green)",
              }}
            >
              {lines.length === 0 ? (
                <div style={{ color: "var(--text-muted)" }}>{t("waiting_scan")}</div>
              ) : (
                lines.map((line, i) => (
                  <div key={i} className="hover:bg-red-900/10 px-2 -mx-2">
                    {line}
                  </div>
                ))
              )}
            </div>
          </div>

          {status?.status === "running" && (
            <button
              onClick={stopScan}
              className="px-6 py-2 rounded-lg font-mono text-sm transition-colors"
              style={{
                background: "var(--kpi-red-bg)",
                color: "var(--accent-red)",
                border: "1px solid var(--kpi-red-border)",
              }}
            >
              [ {t("stop_scan_button")} ]
            </button>
          )}
        </main>
      </div>
    </div>
  )
}