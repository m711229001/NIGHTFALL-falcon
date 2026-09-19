/**
 * FindingsV2 — All findings across all scans.
 * UPDATED 2026-09-18:
 *   - Click any finding → opens VulnDetailDrawer with Arabic explanation.
 *   - Filter by severity, search, refresh.
 */
import { useState, useEffect, useMemo } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import VulnDetailDrawer from "../components/VulnDetailDrawer"
import client from "../../api/client"

const SEV_COLORS = {
  critical: "#dc2626",
  high:     "#ea580c",
  medium:   "#ca8a04",
  low:      "#16a34a",
  info:     "#0891b2",
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export default function FindingsV2() {
  const { t, i18n } = useTranslation()
  const isRtl = i18n.language === "ar"
  const navigate = useNavigate()

  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [selectedFinding, setSelectedFinding] = useState(null)

  // Filters
  const [sevFilter, setSevFilter] = useState("all")
  const [search, setSearch] = useState("")
  const [limit, setLimit] = useState(200)

  const load = async () => {
    setLoading(true)
    setError("")
    try {
      const res = await client.get(`/api/findings?limit=${limit}`)
      const data = Array.isArray(res.data) ? res.data : (res.data.findings || [])
      setFindings(data)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [limit])

  // Filtered + sorted
  const visible = useMemo(() => {
    let list = [...findings]
    if (sevFilter !== "all") {
      list = list.filter(f => (f.severity || "info").toLowerCase() === sevFilter)
    }
    if (search.trim()) {
      const q = search.trim().toLowerCase()
      list = list.filter(f =>
        (f.url || "").toLowerCase().includes(q) ||
        (f.vuln_class || "").toLowerCase().includes(q) ||
        (f.subtype || f.title || "").toLowerCase().includes(q) ||
        (f.param || "").toLowerCase().includes(q) ||
        (f.payload || "").toLowerCase().includes(q)
      )
    }
    list.sort((a, b) => {
      const sa = SEV_ORDER[(a.severity || "info").toLowerCase()] ?? 9
      const sb = SEV_ORDER[(b.severity || "info").toLowerCase()] ?? 9
      if (sa !== sb) return sa - sb
      return (b.id || 0) - (a.id || 0)
    })
    return list
  }, [findings, sevFilter, search])

  const counts = useMemo(() => {
    const c = { all: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) {
      const s = (f.severity || "info").toLowerCase()
      if (c[s] != null) c[s]++
    }
    return c
  }, [findings])

  return (
    <div className="flex min-h-screen transition-colors"
      style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <TacticalSidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />

        <main className="flex-1 p-6 overflow-x-hidden">
          <div className="max-w-7xl mx-auto space-y-5">

            {/* Header */}
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div>
                <h1 className="text-3xl font-bold mb-1" style={{ color: "var(--accent-red)" }}>
                  🎯 {isRtl ? "الثغرات" : "Findings"}
                </h1>
                <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  {isRtl
                    ? "كل الثغرات المكتشفة — اضغط على أي ثغرة لعرض الشرح الكامل"
                    : "All discovered findings — click any finding for full explanation"}
                </p>
              </div>
              <button onClick={load} disabled={loading}
                className="px-4 py-2 rounded-lg text-sm font-bold"
                style={{
                  background: "var(--bg-tertiary)",
                  color: "var(--text-primary)",
                  border: "1px solid var(--border-color)",
                  cursor: loading ? "wait" : "pointer",
                }}>
                ↻ {isRtl ? "تحديث" : "Refresh"}
              </button>
            </div>

            {/* KPI bar */}
            <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
              {[
                { k: "all",      label: isRtl ? "الكل" : "All",         color: "var(--accent-cyan)" },
                { k: "critical", label: isRtl ? "حرجة" : "Critical",    color: SEV_COLORS.critical },
                { k: "high",     label: isRtl ? "عالية" : "High",       color: SEV_COLORS.high },
                { k: "medium",   label: isRtl ? "متوسطة" : "Medium",    color: SEV_COLORS.medium },
                { k: "low",      label: isRtl ? "منخفضة" : "Low",       color: SEV_COLORS.low },
                { k: "info",     label: isRtl ? "معلوماتية" : "Info",   color: SEV_COLORS.info },
              ].map(({ k, label, color }) => (
                <button key={k} onClick={() => setSevFilter(k)}
                  className="rounded-lg p-2 text-center transition-all"
                  style={{
                    background: sevFilter === k ? "rgba(255,255,255,0.08)" : "var(--bg-secondary)",
                    border: sevFilter === k ? `2px solid ${color}` : "1px solid var(--border-color)",
                    cursor: "pointer",
                  }}>
                  <div className="text-2xl font-bold" style={{ color }}>
                    {counts[k] || 0}
                  </div>
                  <div className="text-[10px] uppercase tracking-wider"
                    style={{ color: "var(--text-muted)" }}>
                    {label}
                  </div>
                </button>
              ))}
            </div>

            {/* Search */}
            <div className="flex gap-2 flex-wrap">
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder={isRtl
                  ? "ابحث في URL، نوع الثغرة، المعامل، الحمولة..."
                  : "Search URL, type, param, payload..."}
                className="flex-1 min-w-[250px] px-4 py-2 rounded-lg text-sm"
                style={{
                  background: "var(--bg-secondary)",
                  border: "1px solid var(--border-color)",
                  color: "var(--text-primary)",
                }}
              />
              <select value={limit} onChange={e => setLimit(parseInt(e.target.value))}
                className="px-3 py-2 rounded-lg text-sm"
                style={{
                  background: "var(--bg-secondary)",
                  border: "1px solid var(--border-color)",
                  color: "var(--text-primary)",
                }}>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="200">200</option>
                <option value="500">500</option>
              </select>
            </div>

            {/* Error */}
            {error && (
              <div className="rounded p-3 text-sm"
                style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", color: "var(--accent-red)" }}>
                ⚠ {error}
              </div>
            )}

            {/* Loading */}
            {loading && (
              <div className="text-center py-10" style={{ color: "var(--text-muted)" }}>
                {isRtl ? "جارٍ التحميل..." : "Loading..."}
              </div>
            )}

            {/* Empty */}
            {!loading && visible.length === 0 && (
              <div className="rounded-2xl p-10 text-center"
                style={{ background: "var(--bg-secondary)", border: "2px dashed var(--border-color)" }}>
                <div className="text-4xl mb-3">🎯</div>
                <div className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  {findings.length === 0
                    ? (isRtl ? "لا توجد ثغرات بعد — شغّل فحصاً جديداً" : "No findings yet — run a scan")
                    : (isRtl ? "لا نتائج مطابقة" : "No matching results")}
                </div>
              </div>
            )}

            {/* Table */}
            {!loading && visible.length > 0 && (
              <div className="rounded-2xl overflow-hidden"
                style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ background: "var(--bg-tertiary)", borderBottom: "1px solid var(--border-color)" }}>
                      <th className="text-start p-3 font-mono text-xs w-12" style={{ color: "var(--accent-yellow)" }}>#</th>
                      <th className="text-start p-3 font-mono text-xs w-24" style={{ color: "var(--accent-yellow)" }}>
                        {isRtl ? "الخطورة" : "Severity"}
                      </th>
                      <th className="text-start p-3 font-mono text-xs w-32" style={{ color: "var(--accent-yellow)" }}>
                        {isRtl ? "التصنيف" : "Class"}
                      </th>
                      <th className="text-start p-3 font-mono text-xs" style={{ color: "var(--accent-yellow)" }}>
                        {isRtl ? "النوع / الوصف" : "Type / Description"}
                      </th>
                      <th className="text-start p-3 font-mono text-xs" style={{ color: "var(--accent-yellow)" }}>
                        {isRtl ? "الرابط" : "URL"}
                      </th>
                      <th className="text-end p-3 font-mono text-xs w-20" style={{ color: "var(--accent-yellow)" }}>
                        {isRtl ? "إجراء" : "Action"}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((f) => {
                      const sev = (f.severity || "info").toLowerCase()
                      const sevColor = SEV_COLORS[sev] || SEV_COLORS.info
                      return (
                        <tr
                          key={f.id}
                          onClick={() => setSelectedFinding(f)}
                          className="transition-colors"
                          style={{
                            borderBottom: "1px solid var(--border-color)",
                            cursor: "pointer",
                          }}
                          onMouseEnter={e => e.currentTarget.style.background = "var(--bg-tertiary)"}
                          onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                        >
                          <td className="p-3 font-mono text-xs" style={{ color: "var(--text-muted)" }}>
                            {f.id}
                          </td>
                          <td className="p-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold"
                              style={{
                                background: sevColor + "22",
                                color: sevColor,
                                border: `1px solid ${sevColor}`,
                              }}>
                              {sev.toUpperCase()}
                            </span>
                          </td>
                          <td className="p-3 text-xs font-mono" style={{ color: "var(--accent-yellow)" }}>
                            {f.vuln_class || "-"}
                          </td>
                          <td className="p-3 text-xs" style={{ color: "var(--text-primary)" }}>
                            {f.subtype || f.title || f.description || "-"}
                          </td>
                          <td className="p-3 text-xs truncate max-w-md"
                            style={{ color: "var(--text-secondary)", fontFamily: "ui-monospace, monospace" }}
                            title={f.url}>
                            {f.url || "-"}
                          </td>
                          <td className="p-3 text-end">
                            <button
                              onClick={(e) => { e.stopPropagation(); setSelectedFinding(f) }}
                              className="px-2 py-1 rounded text-[10px] font-bold"
                              style={{
                                background: "var(--accent-cyan)",
                                color: "#000",
                                cursor: "pointer",
                              }}>
                              📖 {isRtl ? "اشرح" : "Explain"}
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>

                {/* Footer */}
                <div className="px-3 py-2 text-xs"
                  style={{
                    background: "var(--bg-tertiary)",
                    color: "var(--text-muted)",
                    borderTop: "1px solid var(--border-color)",
                    fontFamily: "ui-monospace, monospace",
                  }}>
                  {isRtl
                    ? `يعرض ${visible.length} من ${findings.length} ثغرة`
                    : `Showing ${visible.length} of ${findings.length} findings`}
                </div>
              </div>
            )}

          </div>
        </main>
      </div>

      {/* Drawer: Arabic explanation */}
      {selectedFinding && (
        <VulnDetailDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  )
}