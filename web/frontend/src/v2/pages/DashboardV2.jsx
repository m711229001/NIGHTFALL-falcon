/**
 * DashboardV2 - Enhanced with KPI + Charts + AI Summary
 */
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import { PieChart, Pie, Cell, ResponsiveContainer, LineChart, Line,
         XAxis, YAxis, Tooltip, BarChart, Bar } from "recharts"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import { frameworkScanApi } from "../../api/clientV2"
import { Icon } from "../components/Icons"

const SEV_COLORS = {
    critical: "#dc2626",
    high:     "#ea580c",
    medium:   "#ca8a04",
    low:      "#16a34a",
    info:     "#2563eb",
}

function KPICard({ icon, label, value, sub, color, onClick }) {
    return (
        <button onClick={onClick}
            className="rounded-xl p-4 text-start transition-all hover-lift"
            style={{
                background: "var(--bg-secondary)",
                border: "1px solid var(--border-color)",
                cursor: onClick ? "pointer" : "default",
            }}>
            <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-bold uppercase tracking-wider"
                    style={{ color: "var(--text-muted)" }}>
                    {label}
                </div>
                <Icon name={icon} size={18} style={{ color }} />
            </div>
            <div className="text-3xl font-bold font-mono" style={{ color }}>
                {value}
            </div>
            {sub && (
                <div className="text-[11px] mt-1" style={{ color: "var(--text-muted)" }}>
                    {sub}
                </div>
            )}
        </button>
    )
}

function Timeline({ data }) {
    const sorted = Object.entries(data || {})
        .sort()
        .slice(-14)
        .map(([date, count]) => ({
            day: date.slice(5),
            count,
        }))

    if (sorted.length === 0) {
        return <div className="text-xs text-center py-8" style={{ color: "var(--text-muted)" }}>No data</div>
    }

    return (
        <ResponsiveContainer width="100%" height={180}>
            <LineChart data={sorted}>
                <XAxis dataKey="day" tick={{ fontSize: 10, fill: "var(--text-muted)" }} />
                <YAxis tick={{ fontSize: 10, fill: "var(--text-muted)" }} allowDecimals={false} />
                <Tooltip contentStyle={{
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--border-color)",
                    fontSize: 12,
                }} />
                <Line type="monotone" dataKey="count" stroke="var(--accent-cyan)"
                    strokeWidth={2} dot={{ r: 3 }} />
            </LineChart>
        </ResponsiveContainer>
    )
}

function SeverityPie({ data }) {
    const pieData = Object.entries(data || {})
        .filter(([_, v]) => v > 0)
        .map(([k, v]) => ({ name: k, value: v, color: SEV_COLORS[k] }))

    if (pieData.length === 0) {
        return <div className="text-xs text-center py-8" style={{ color: "var(--text-muted)" }}>No findings yet</div>
    }

    return (
        <div className="flex items-center gap-4">
            <ResponsiveContainer width={120} height={120}>
                <PieChart>
                    <Pie data={pieData} innerRadius={30} outerRadius={55} dataKey="value">
                        {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                    </Pie>
                </PieChart>
            </ResponsiveContainer>
            <div className="text-xs space-y-1 flex-1">
                {pieData.map((d) => (
                    <div key={d.name} className="flex justify-between items-center">
                        <span style={{ color: d.color }} className="font-bold uppercase">{d.name}</span>
                        <span className="font-mono">{d.value}</span>
                    </div>
                ))}
            </div>
        </div>
    )
}

function TopTargets({ data }) {
    if (!data || data.length === 0) {
        return <div className="text-xs text-center py-8" style={{ color: "var(--text-muted)" }}>No targets</div>
    }

    return (
        <ResponsiveContainer width="100%" height={180}>
            <BarChart data={data} layout="vertical" margin={{ left: 20 }}>
                <XAxis type="number" tick={{ fontSize: 10, fill: "var(--text-muted)" }} allowDecimals={false} />
                <YAxis type="category" dataKey="target" width={150}
                    tick={{ fontSize: 9, fill: "var(--text-muted)" }}
                    tickFormatter={(v) => v.length > 25 ? v.slice(0, 25) + "…" : v} />
                <Tooltip contentStyle={{
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--border-color)",
                    fontSize: 11,
                }} />
                <Bar dataKey="count" fill="var(--accent-purple)" radius={[0, 4, 4, 0]} />
            </BarChart>
        </ResponsiveContainer>
    )
}

export default function DashboardV2() {
    const { t, i18n } = useTranslation()
    const isRtl = i18n.language === "ar"
    const navigate = useNavigate()
    const [stats, setStats] = useState(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        let active = true
        const load = async () => {
            try {
                const r = await frameworkScanApi.dashboardStats()
                if (active) setStats(r.data)
            } catch (e) {
                if (active) console.error(e)
            } finally {
                if (active) setLoading(false)
            }
        }
        load()
        const id = setInterval(load, 30000)
        return () => { active = false; clearInterval(id) }
    }, [])

    const s = stats || {}
    const totalFindings = Object.values(s.by_severity || {}).reduce((a, b) => a + b, 0)

    return (
        <div className="flex min-h-screen" style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
            <TacticalSidebar />
            <div className="flex-1 flex flex-col min-w-0">
                <TopHeader />
                <main className="flex-1 p-6 overflow-x-hidden space-y-6">

                    {/* Header */}
                    <div className="flex items-center gap-3">
                        <h1 className="text-3xl font-bold flex items-center gap-3"
                            style={{ color: "var(--accent-red)" }}>
                            <Icon name="dashboard" size={28} />
                            {isRtl ? "لوحة التحكم" : "Dashboard"}
                        </h1>
                        {s.scans_today > 0 && (
                            <span className="px-3 py-1 rounded-lg text-xs font-bold"
                                style={{ background: "var(--accent-green-soft)", color: "var(--accent-green)", border: "1px solid var(--accent-green)" }}>
                                +{s.scans_today} {isRtl ? "اليوم" : "today"}
                            </span>
                        )}
                    </div>

                    {loading ? (
                        <div className="p-12 text-center">
                            <Icon name="refresh" size={32} className="anim-spin mx-auto mb-2" />
                            <div className="text-sm" style={{ color: "var(--text-muted)" }}>Loading stats...</div>
                        </div>
                    ) : (
                        <>
                            {/* KPI Cards */}
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                                <KPICard
                                    icon="scan"
                                    label={isRtl ? "إجمالي الفحوصات" : "Total Scans"}
                                    value={s.total_scans || 0}
                                    sub={`${s.scans_7d || 0} ${isRtl ? "آخر 7 أيام" : "in last 7d"}`}
                                    color="var(--accent-red)"
                                    onClick={() => navigate("/v2/framework-scan")} />
                                <KPICard
                                    icon="findings"
                                    label={isRtl ? "إجمالي الثغرات" : "Total Findings"}
                                    value={totalFindings}
                                    sub={`${s.by_severity?.critical || 0} critical · ${s.by_severity?.high || 0} high`}
                                    color="var(--accent-orange)"
                                    onClick={() => navigate("/v2/findings")} />
                                <KPICard
                                    icon="sparkles"
                                    label={isRtl ? "حلّلها AI" : "AI Analyzed"}
                                    value={s.ai_analyzed_total || 0}
                                    sub={isRtl ? "findings مع تحليل" : "findings with analysis"}
                                    color="var(--accent-purple)"
                                    onClick={() => navigate("/v2/ai-settings")} />
                                <KPICard
                                    icon="star"
                                    label={isRtl ? "قابل للنشر" : "Bug Bounty Worthy"}
                                    value={s.bugbounty_worthy_total || 0}
                                    sub={isRtl ? "من التصنيف الذكي" : "from AI triage"}
                                    color="var(--accent-green)"
                                    onClick={() => navigate("/v2/triage")} />
                            </div>

                            {/* Charts Row 1 */}
                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                                <div className="lg:col-span-2 rounded-xl p-4"
                                    style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                                    <div className="text-xs font-bold mb-3 uppercase tracking-wider flex items-center gap-2"
                                        style={{ color: "var(--text-muted)" }}>
                                        <Icon name="trendUp" size={14} />
                                        {isRtl ? "النشاط (آخر 14 يوم)" : "Scan Activity (14d)"}
                                    </div>
                                    <Timeline data={s.timeline} />
                                </div>
                                <div className="rounded-xl p-4"
                                    style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                                    <div className="text-xs font-bold mb-3 uppercase tracking-wider flex items-center gap-2"
                                        style={{ color: "var(--text-muted)" }}>
                                        <Icon name="pieChart" size={14} />
                                        {isRtl ? "حسب الخطورة" : "By Severity"}
                                    </div>
                                    <SeverityPie data={s.by_severity} />
                                </div>
                            </div>

                            {/* Charts Row 2 */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                <div className="rounded-xl p-4"
                                    style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                                    <div className="text-xs font-bold mb-3 uppercase tracking-wider flex items-center gap-2"
                                        style={{ color: "var(--text-muted)" }}>
                                        <Icon name="target" size={14} />
                                        {isRtl ? "أعلى الأهداف" : "Top Targets"}
                                    </div>
                                    <TopTargets data={s.top_targets} />
                                </div>

                                <div className="rounded-xl p-4"
                                    style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                                    <div className="text-xs font-bold mb-3 uppercase tracking-wider flex items-center gap-2"
                                        style={{ color: "var(--text-muted)" }}>
                                        <Icon name="clock" size={14} />
                                        {isRtl ? "آخر الفحوصات" : "Recent Scans"}
                                    </div>
                                    <div className="space-y-2 max-h-[200px] overflow-y-auto">
                                        {(s.recent_scans || []).map((scan, i) => (
                                            <div key={i} className="flex items-center justify-between gap-2 py-2 px-3 rounded"
                                                style={{ background: "var(--bg-tertiary)" }}>
                                                <div className="min-w-0 flex-1">
                                                    <div className="text-xs font-mono truncate" style={{ color: "var(--text-primary)" }}>
                                                        {scan.target}
                                                    </div>
                                                    <div className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                                                        {scan.date}
                                                    </div>
                                                </div>
                                                <div className="text-xs font-bold px-2 py-0.5 rounded"
                                                    style={{
                                                        background: scan.findings > 0 ? "var(--accent-red-soft)" : "var(--bg-elevated)",
                                                        color: scan.findings > 0 ? "var(--accent-red)" : "var(--text-muted)",
                                                    }}>
                                                    {scan.findings}
                                                </div>
                                            </div>
                                        ))}
                                        {(!s.recent_scans || s.recent_scans.length === 0) && (
                                            <div className="text-xs text-center py-8" style={{ color: "var(--text-muted)" }}>
                                                {isRtl ? "لا فحوصات بعد" : "No scans yet"}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Quick Actions */}
                            <div className="rounded-xl p-4"
                                style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                                <div className="text-xs font-bold mb-3 uppercase tracking-wider"
                                    style={{ color: "var(--text-muted)" }}>
                                    ⚡ {isRtl ? "إجراءات سريعة" : "Quick Actions"}
                                </div>
                                <div className="flex flex-wrap gap-3">
                                    <button onClick={() => navigate("/v2/framework-scan")}
                                        className="px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover-lift"
                                        style={{ background: "var(--accent-red)", color: "white", cursor: "pointer" }}>
                                        <Icon name="scan" size={16} />
                                        {isRtl ? "فحص جديد" : "New Scan"}
                                    </button>
                                    <button onClick={() => navigate("/v2/findings")}
                                        className="px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover-lift"
                                        style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                                        <Icon name="findings" size={16} />
                                        {isRtl ? "عرض الثغرات" : "View Findings"}
                                    </button>
                                    <button onClick={() => navigate("/v2/triage")}
                                        className="px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover-lift"
                                        style={{ background: "var(--accent-purple-soft)", color: "var(--accent-purple)", border: "1px solid var(--accent-purple)", cursor: "pointer" }}>
                                        <Icon name="brain" size={16} />
                                        {isRtl ? "التحليل الذكي" : "AI Triage"}
                                    </button>
                                    <button onClick={() => navigate("/v2/reports")}
                                        className="px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover-lift"
                                        style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                                        <Icon name="reports" size={16} />
                                        {isRtl ? "التقارير" : "Reports"}
                                    </button>
                                    <button onClick={() => navigate("/v2/links")}
                                        className="px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover-lift"
                                        style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                                        <Icon name="link" size={16} />
                                        {isRtl ? "الروابط" : "Links"}
                                    </button>
                                </div>
                            </div>
                        </>
                    )}
                </main>
            </div>
        </div>
    )
}
