/**
 * DashboardV2 - Tactical Cinematic Hybrid
 */
import { useState, useEffect } from "react"
import { useTranslation } from "react-i18next"
import {
  AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts"

import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import KPICard from "../components/KPICard"
import FindingsDrawer from "../components/FindingsDrawer"
import client from "../../api/client"

const SEV_COLORS = {
  critical: "#EF4444",
  high:     "#F97316",
  medium:   "#FACC15",
  low:      "#10B981",
  info:     "#06B6D4",
}

export default function DashboardV2() {
  const { t } = useTranslation()

  const [stats, setStats] = useState({ total: 0, critical: 0, medium: 0, resolved: 0 })
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)
  const [threatData, setThreatData] = useState([])
  const [distData, setDistData] = useState([])

  useEffect(() => {
    async function fetchData() {
      try {
        // 1) Scans list — correct endpoint: /api/scans/list
        let scanList = []
        try {
          const scansRes = await client.get("/api/scans/list", { params: { limit: 50 } })
          const data = scansRes.data
          scanList = Array.isArray(data) ? data : (data.scans || [])
        } catch (e) {
          console.warn("Could not fetch scans list:", e?.response?.status)
        }

        // 2) Findings — /api/findings
        let findList = []
        try {
          const findRes = await client.get("/api/findings", { params: { limit: 200 } })
          const data = findRes.data
          findList = Array.isArray(data) ? data : (data.findings || [])
        } catch (e) {
          console.warn("Could not fetch findings:", e?.response?.status)
        }

        setFindings(findList)

        // 3) Compute stats
        const crit = findList.filter(f => (f.severity || "").toLowerCase() === "critical").length
        const med = findList.filter(f => (f.severity || "").toLowerCase() === "medium").length
        setStats({
          total: scanList.length,
          critical: crit,
          medium: med,
          resolved: 0,
        })

        // 4) Threat frequency chart — last 10 scans
        const recent = scanList.slice(-10).map((s, i) => ({
          name: `#${s.id || i + 1}`,
          findings: s.findings_count || (Array.isArray(s.findings) ? s.findings.length : 0),
          requests: s.requests_used || s.requests || 0,
        }))
        setThreatData(recent.length > 0 ? recent : [
          { name: "#1", findings: 0, requests: 0 },
        ])

        // 5) Distribution donut
        const dist = [
          { name: "Critical", value: crit, color: SEV_COLORS.critical },
          { name: "High", value: findList.filter(f => (f.severity || "").toLowerCase() === "high").length, color: SEV_COLORS.high },
          { name: "Medium", value: med, color: SEV_COLORS.medium },
          { name: "Low", value: findList.filter(f => (f.severity || "").toLowerCase() === "low").length, color: SEV_COLORS.low },
        ].filter(d => d.value > 0)
        setDistData(dist)
      } catch (e) {
        console.error("Dashboard fetch error:", e)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  return (
    <div
      className="flex min-h-screen transition-colors"
      style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}
    >
      <TacticalSidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />

        <main className="flex-1 p-6 space-y-6 overflow-x-hidden">
          <section>
            <h2
              className="text-2xl font-bold mb-4 font-mono"
              style={{ color: "var(--accent-red)" }}
            >
              {t("dashboardV2.title")}
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <KPICard icon="🎯" label={t("kpi.totalScans")} value={stats.total} subtext={t("kpi.scanUnits")} color="slate" />
              <KPICard icon="🔴" label={t("kpi.critical")} value={stats.critical} subtext={t("kpi.needsAction")} color="critical" />
              <KPICard icon="🟡" label={t("kpi.medium")} value={stats.medium} subtext={t("kpi.monitor")} color="medium" />
              <KPICard icon="🟢" label={t("kpi.resolved")} value={stats.resolved} subtext={t("kpi.allClear")} color="low" />
            </div>
          </section>

          <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div
              className="lg:col-span-2 rounded-lg p-4"
              style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}
            >
              <h3 className="text-sm font-mono uppercase mb-3" style={{ color: "var(--accent-red)" }}>
                {t("charts.threatFrequency")}
              </h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={threatData}>
                    <defs>
                      <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.6}/>
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="var(--border-color)" strokeDasharray="3 3" />
                    <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={11} />
                    <YAxis stroke="var(--text-muted)" fontSize={11} />
                    <Tooltip
                      contentStyle={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--border-color)",
                        color: "var(--text-primary)",
                        fontSize: 12,
                      }}
                    />
                    <Area type="monotone" dataKey="findings" stroke="#EF4444" strokeWidth={2} fill="url(#threatGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div
              className="rounded-lg p-4"
              style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}
            >
              <h3 className="text-sm font-mono uppercase mb-3" style={{ color: "var(--accent-red)" }}>
                {t("charts.vulnDistribution")}
              </h3>
              <div className="h-64">
                {distData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={distData} innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                        {distData.map((entry, i) => (<Cell key={i} fill={entry.color} />))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--border-color)",
                          color: "var(--text-primary)",
                          fontSize: 12,
                        }}
                      />
                      <Legend wrapperStyle={{ fontSize: 11, color: "var(--text-secondary)" }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div
                    className="h-full flex items-center justify-center text-sm"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {t("charts.noData")}
                  </div>
                )}
              </div>
            </div>
          </section>

          <section
            className="rounded-lg overflow-hidden"
            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}
          >
            <div className="px-4 py-3 border-b" style={{ borderColor: "var(--border-color)" }}>
              <h3 className="text-sm font-mono uppercase" style={{ color: "var(--accent-red)" }}>
                {t("table.recentFindings")}
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead
                  className="text-xs uppercase"
                  style={{ background: "var(--bg-tertiary)", color: "var(--text-muted)" }}
                >
                  <tr>
                    <th className="px-3 py-2 text-start">{t("table.severity")}</th>
                    <th className="px-3 py-2 text-start">{t("table.name")}</th>
                    <th className="px-3 py-2 text-start">{t("table.target")}</th>
                    <th className="px-3 py-2 text-start">{t("table.date")}</th>
                    <th className="px-3 py-2 text-end">{t("table.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.slice(0, 10).map((f, i) => {
                    const sev = (f.severity || "info").toLowerCase()
                    const sevColor = SEV_COLORS[sev] || SEV_COLORS.info
                    return (
                      <tr
                        key={i}
                        className="transition-colors"
                        style={{ borderTop: "1px solid var(--border-color)" }}
                        onMouseEnter={e => e.currentTarget.style.background = "var(--bg-tertiary)"}
                        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                      >
                        <td className="px-3 py-2">
                          <span
                            className="inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                            style={{
                              color: sevColor,
                              border: `1px solid ${sevColor}`,
                              background: `${sevColor}20`,
                            }}
                          >
                            {sev}
                          </span>
                        </td>
                        <td className="px-3 py-2" style={{ color: "var(--text-primary)" }}>
                          {f.vuln_class || f.title || f.category || "—"}
                        </td>
                        <td
                          className="px-3 py-2 font-mono text-xs max-w-[300px] truncate"
                          style={{ color: "var(--accent-cyan)" }}
                        >
                          {f.url || "—"}
                        </td>
                        <td className="px-3 py-2 text-xs" style={{ color: "var(--text-muted)" }}>
                          {f.timestamp ? new Date(f.timestamp).toLocaleDateString() : "—"}
                        </td>
                        <td className="px-3 py-2 text-end">
                          <button
                            onClick={() => setSelected(f)}
                            className="px-3 py-1 rounded text-xs font-semibold"
                            style={{
                              background: "rgba(127, 29, 29, 0.4)",
                              color: "var(--accent-red)",
                            }}
                          >
                            {t("table.viewDetails")}
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                  {findings.length === 0 && !loading && (
                    <tr>
                      <td
                        colSpan="5"
                        className="px-3 py-8 text-center"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {t("table.noFindings")}
                      </td>
                    </tr>
                  )}
                  {loading && (
                    <tr>
                      <td
                        colSpan="5"
                        className="px-3 py-8 text-center"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {t("common.loading")}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      </div>

      {selected && <FindingsDrawer finding={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
