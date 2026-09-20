/**
 * ReportStats - Visual stats for reports (with recharts)
 */
import { useMemo } from "react"
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, Tooltip } from "recharts"
import { Icon } from "./Icons"

const SEV_COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
  info: "#2563eb",
}

function detectSeverityFromName(name) {
  const n = (name || "").toLowerCase()
  if (n.includes("critical") || n.includes("rce") || n.includes("sqli") || n.includes("ssti")) return "critical"
  if (n.includes("high") || n.includes("xss") || n.includes("ssrf")) return "high"
  if (n.includes("medium") || n.includes("idor")) return "medium"
  if (n.includes("low") || n.includes("info")) return "low"
  return "info"
}

export default function ReportStats({ reports, contentCache = {} }) {
  const stats = useMemo(() => {
    const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    const byDay = {}
    let totalSize = 0
    let richCount = 0

    for (const r of reports) {
      const sev = detectSeverityFromName(r.name)
      bySev[sev]++
      totalSize += r.size || 0
      if ((r.size || 0) > 5000) richCount++

      // Group by day
      const d = new Date((r.modified || 0) * 1000)
      const key = d.toISOString().slice(0, 10)
      byDay[key] = (byDay[key] || 0) + 1
    }

    // Build 7-day timeline
    const days = []
    for (let i = 6; i >= 0; i--) {
      const d = new Date()
      d.setDate(d.getDate() - i)
      const key = d.toISOString().slice(0, 10)
      days.push({
        day: key.slice(5), // MM-DD
        count: byDay[key] || 0,
      })
    }

    const pieData = Object.entries(bySev)
      .filter(([_, v]) => v > 0)
      .map(([k, v]) => ({ name: k, value: v, color: SEV_COLORS[k] }))

    return { bySev, days, pieData, totalSize, richCount }
  }, [reports])

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* Total */}
      <div className="rounded-xl p-4" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
        <div className="flex items-center justify-between mb-2">
          <div className="text-xs font-bold" style={{ color: "var(--text-muted)" }}>TOTAL REPORTS</div>
          <Icon name="reports" size={18} style={{ color: "var(--accent-red)" }} />
        </div>
        <div className="text-3xl font-bold font-mono" style={{ color: "var(--accent-red)" }}>
          {reports.length}
        </div>
        <div className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
          {(stats.totalSize / 1024).toFixed(0)} KB total
        </div>
      </div>

      {/* Rich reports */}
      <div className="rounded-xl p-4" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
        <div className="flex items-center justify-between mb-2">
          <div className="text-xs font-bold" style={{ color: "var(--text-muted)" }}>AI-ENHANCED</div>
          <Icon name="sparkles" size={18} style={{ color: "var(--accent-purple)" }} />
        </div>
        <div className="text-3xl font-bold font-mono" style={{ color: "var(--accent-purple)" }}>
          {stats.richCount}
        </div>
        <div className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
          with full analysis
        </div>
      </div>

      {/* Severity pie */}
      <div className="rounded-xl p-4" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
        <div className="text-xs font-bold mb-2" style={{ color: "var(--text-muted)" }}>BY SEVERITY</div>
        {stats.pieData.length > 0 ? (
          <div className="flex items-center gap-3">
            <ResponsiveContainer width={70} height={70}>
              <PieChart>
                <Pie data={stats.pieData} innerRadius={20} outerRadius={32} dataKey="value">
                  {stats.pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="text-[10px] space-y-0.5 flex-1">
              {stats.pieData.map((d) => (
                <div key={d.name} className="flex justify-between">
                  <span style={{ color: d.color }}>{d.name}</span>
                  <span className="font-mono">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="text-2xl text-center" style={{ color: "var(--text-muted)" }}>—</div>
        )}
      </div>

      {/* Timeline */}
      <div className="rounded-xl p-4" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
        <div className="text-xs font-bold mb-2" style={{ color: "var(--text-muted)" }}>LAST 7 DAYS</div>
        <ResponsiveContainer width="100%" height={60}>
          <BarChart data={stats.days}>
            <XAxis dataKey="day" tick={{ fontSize: 9, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-color)", fontSize: 11 }} />
            <Bar dataKey="count" fill="var(--accent-cyan)" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
