# -*- coding: utf-8 -*-
from pathlib import Path

f = Path(r"C:\BugBounty\NIGHTFALL\web\frontend\src\v2\pages\LiveMonitorV2.jsx")

new_content = r'''/**
 * LiveMonitorV2 - Live view of framework scans (v2 endpoints)
 */
import { useEffect, useState, useRef } from "react"
import { useTranslation } from "react-i18next"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import { frameworkScanApi } from "../../api/clientV2"
import { Icon } from "../components/Icons"

export default function LiveMonitorV2() {
  const { t, i18n } = useTranslation()
  const isRtl = i18n.language === "ar"
  const [scanId, setScanId] = useState(null)
  const [status, setStatus] = useState(null)
  const [lines, setLines] = useState([])
  const [error, setError] = useState("")
  const logRef = useRef(null)
  const stoppedRef = useRef(false)

  // ---- 1) Find latest scan ONCE on mount ----
  useEffect(() => {
    let active = true
    const findLatest = async () => {
      try {
        const r = await frameworkScanApi.list()
        const scans = r.data?.scans || []
        if (!active) return
        if (scans.length === 0) {
          setError("no_scans_yet")
          return
        }
        // Sort by started_at desc
        const sorted = [...scans].sort((a, b) => {
          const da = a.started_at || ""
          const db = b.started_at || ""
          return db.localeCompare(da)
        })
        setScanId(sorted[0].scan_id)
      } catch (e) {
        if (active) setError(e?.message || "list_failed")
      }
    }
    findLatest()
    return () => { active = false }
  }, [])

  // ---- 2) Poll status + log every 2s ----
  useEffect(() => {
    if (!scanId) return
    if (stoppedRef.current) return

    let active = true

    const poll = async () => {
      try {
        const [sRes, lRes] = await Promise.all([
          frameworkScanApi.status(scanId),
          frameworkScanApi.log(scanId, 200),
        ])
        if (!active) return
        setStatus(sRes.data)
        setLines(lRes.data?.lines || [])
        if (logRef.current) {
          logRef.current.scrollTop = logRef.current.scrollHeight
        }
      } catch (e) {
        // silent - keep trying
      }
    }

    poll()
    const id = setInterval(poll, 2000)
    return () => { active = false; clearInterval(id) }
  }, [scanId])

  const statusColor =
    status?.status === "running"   ? "var(--accent-yellow)" :
    status?.status === "done"      ? "var(--accent-green)"  :
    status?.status === "error"     ? "var(--accent-red)"    :
    status?.status === "cancelled" ? "var(--text-muted)"    :
    "var(--text-muted)"

  const stopScan = async () => {
    if (!scanId) return
    stoppedRef.current = true
    try {
      await frameworkScanApi.cancel(scanId)
      setStatus((prev) => prev ? { ...prev, status: "cancelled" } : prev)
    } catch { /* ignore */ }
  }

  const restart = () => {
    stoppedRef.current = false
    setScanId(null)
    setStatus(null)
    setLines([])
    setError("")
    // Re-trigger the findLatest effect by navigation-free remount:
    window.location.reload()
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
                className="text-3xl font-bold flex items-center gap-3"
                style={{ color: "var(--accent-red)" }}
              >
                <Icon name="monitor" size={28} />
                {t("live_monitor", "Live Monitor")}
              </h1>
              <p className="text-sm mt-1 font-mono" style={{ color: "var(--text-secondary)" }}>
                {scanId ? scanId : t("no_active_scan", "No active scan")}
              </p>
            </div>

            <div className="flex items-center gap-3">
              <div className="text-end">
                <div className="text-lg font-bold font-mono" style={{ color: statusColor }}>
                  {(status?.status || "idle").toUpperCase()}
                </div>
                {scanId && (
                  <div className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>
                    {status?.target || ""}
                  </div>
                )}
              </div>
              <button
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
          </div>

          {error === "no_scans_yet" && (
            <div
              className="rounded-lg p-4 text-sm"
              style={{
                background: "var(--accent-yellow-soft)",
                border: "1px solid var(--accent-yellow)",
                color: "var(--accent-yellow)",
              }}
            >
              {t("live_monitor_no_scans", "No scans yet. Start a scan from Framework Scan page.")}
            </div>
          )}

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
                nightfall@falcon:~${scanId ? " " + scanId : ""}
              </span>
            </div>

            {/* Log content */}
            <div
              ref={logRef}
              dir="ltr"
              className="h-[600px] overflow-y-auto p-4 font-mono text-xs whitespace-pre-wrap"
              style={{
                background: "var(--bg-primary)",
                color: "var(--accent-green)",
              }}
            >
              {lines.length === 0 ? (
                <div style={{ color: "var(--text-muted)" }}>
                  {scanId
                    ? t("waiting_scan", "Waiting for scan output...")
                    : t("no_active_scan", "No active scan")}
                </div>
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
              className="px-6 py-2 rounded-lg font-mono text-sm transition-colors inline-flex items-center gap-2"
              style={{
                background: "var(--accent-red-soft)",
                color: "var(--accent-red)",
                border: "1px solid var(--accent-red)",
                cursor: "pointer",
              }}
            >
              <Icon name="stop" size={16} />
              {t("stop_scan_button", "STOP SCAN")}
            </button>
          )}
        </main>
      </div>
    </div>
  )
}
'''

f.write_text(new_content, encoding="utf-8")
print("[OK] LiveMonitorV2.jsx rewritten (uses v2 endpoints)")
print("     Path:", f)
print("     Size:", len(new_content), "chars")
