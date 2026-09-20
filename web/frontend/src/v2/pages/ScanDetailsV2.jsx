/**
 * ScanDetailsV2 — Tactical Edition
 */
import { useEffect, useState } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { useTranslation } from "react-i18next"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import VulnDetailDrawer from "../components/VulnDetailDrawer"
import client from "../../api/client"

const SEV_COLORS = {
  critical: "#EF4444",
  high:     "#F97316",
  medium:   "#FACC15",
  low:      "#10B981",
  info:     "#06B6D4",
}

export default function ScanDetailsV2() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [selectedFinding, setSelectedFinding] = useState(null)

  useEffect(() => {
    client.get(`/api/scans/${id}`)
      .then(r => { setData(r.data); setLoading(false) })
      .catch(() => setLoading(false))
  }, [id])

  const downloadFile = async (format) => {
    const token = localStorage.getItem("token")
    const url = `http://localhost:8888/api/scans/${id}/export/${format}${format === "sarif" ? "?download=true" : ""}`
    try {
      const res = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      if (!res.ok) return alert("Export failed")
      const blob = await res.blob()
      const blobUrl = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = blobUrl
      a.download = `scan_${id}.${format}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(blobUrl)
    } catch (e) {
      alert("Download error: " + e.message)
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen" style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
        <TacticalSidebar />
        <div className="flex-1 flex flex-col">
          <TopHeader />
          <div className="flex-1 flex items-center justify-center" style={{ color: "var(--text-muted)" }}>
            {t("loading")}
          </div>
        </div>
      </div>
    )
  }

  if (!data || !data.scan) {
    return (
      <div className="flex min-h-screen" style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
        <TacticalSidebar />
        <div className="flex-1 flex flex-col">
          <TopHeader />
          <div className="flex-1 flex flex-col items-center justify-center gap-4">
            <div style={{ color: "var(--accent-red)" }}>{t("scan_not_found")}</div>
            <button onClick={() => navigate("/v2/dashboard")} className="px-4 py-2 rounded"
              style={{ background: "var(--accent-red)", color: "white" }}>
              {t("back_to_dashboard")}
            </button>
          </div>
        </div>
      </div>
    )
  }

  const { scan, findings = [] } = data

  return (
    <div className="flex min-h-screen transition-colors" style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <TacticalSidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />
        <main className="flex-1 p-6 overflow-x-hidden space-y-4">
          <div className="flex justify-between items-center flex-wrap gap-2">
            <button onClick={() => navigate("/v2/dashboard")} className="text-sm"
              style={{ color: "var(--accent-yellow)" }}>
              ← {t("back_to_dashboard")}
            </button>
            <div className="flex gap-2">
              <button onClick={() => downloadFile("pdf")} className="px-4 py-2 rounded-lg text-sm font-mono"
                style={{ background: "var(--kpi-red-bg)", color: "var(--accent-red)", border: "1px solid var(--kpi-red-border)" }}>
                📄 {t("export_pdf")}
              </button>
              <button onClick={() => downloadFile("sarif")} className="px-4 py-2 rounded-lg text-sm font-mono"
                style={{ background: "rgba(168, 85, 247, 0.2)", color: "var(--accent-purple)", border: "1px solid var(--accent-purple)" }}>
                📊 {t("export_sarif")}
              </button>
            </div>
          </div>

          <div>
            <h1 className="text-3xl font-bold" style={{ color: "var(--accent-red)" }}>
              {t("scan_number")} #{scan.id}
            </h1>
            <p className="text-sm mt-1 font-mono truncate" style={{ color: "var(--text-secondary)" }}>
              {scan.target}
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="rounded-xl p-4" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
              <div className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>{t("status")}</div>
              <div className="text-xl font-bold mt-1" style={{ color: "var(--accent-green)" }}>
                {scan.status?.toUpperCase() || "—"}
              </div>
            </div>
            <div className="rounded-xl p-4" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
              <div className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>{t("findings")}</div>
              <div className="text-xl font-bold mt-1" style={{ color: "var(--accent-red)" }}>
                {scan.findings_count || findings.length}
              </div>
            </div>
            <div className="rounded-xl p-4" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
              <div className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>{t("requests")}</div>
              <div className="text-xl font-bold mt-1" style={{ color: "var(--accent-yellow)" }}>
                {scan.requests_used || 0}
              </div>
            </div>
            <div className="rounded-xl p-4" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
              <div className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>{t("duration_seconds")}</div>
              <div className="text-xl font-bold mt-1" style={{ color: "var(--accent-purple)" }}>
                {scan.elapsed_seconds || 0}s
              </div>
            </div>
          </div>

          <div className="rounded-2xl p-6" style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>
            <h2 className="text-lg font-bold mb-4 font-mono" style={{ color: "var(--accent-yellow)" }}>
              🎯 {t("findings")} ({findings.length})
            </h2>
            {findings.length === 0 ? (
              <p className="text-center py-8" style={{ color: "var(--text-muted)" }}>{t("no_vulns_in_scan")}</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-xs uppercase" style={{ color: "var(--text-muted)" }}>
                    <tr>
                      <th className="text-start py-2">{t("severity_col")}</th>
                      <th className="text-start py-2">{t("class_col")}</th>
                      <th className="text-start py-2">{t("url_col")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f, i) => {
                      const sev = (f.severity || "info").toLowerCase()
                      const color = SEV_COLORS[sev] || SEV_COLORS.info
                      return (
                        <tr key={i} onClick={() => setSelectedFinding(f)} style={{ borderTop: "1px solid var(--border-color)", cursor: "pointer" }}>
                          <td className="py-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                              style={{ color, border: `1px solid ${color}`, background: `${color}20` }}>
                              {sev}
                            </span>
                          </td>
                          <td className="py-2" style={{ color: "var(--accent-yellow)" }}>{f.vuln_class || f.category}</td>
                          <td className="py-2 font-mono text-xs truncate" style={{ color: "var(--accent-cyan)" }}>{f.url}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </main>
      </div>
      {selectedFinding && (
        <VulnDetailDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  )
}