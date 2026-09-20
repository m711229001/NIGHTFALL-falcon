/**
 * TriageV2 - AI-powered finding prioritization
 */
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import { frameworkScanApi } from "../../api/clientV2"
import { Icon } from "../components/Icons"

const CAT_COLORS = {
    confirmed_vuln:  "#dc2626",
    theoretical:     "#eab308",
    config:          "#3b82f6",
    info:            "#64748b",
    false_positive:  "#6a6a7a",
    unknown:         "#a855f7",
}

const CAT_LABELS_AR = {
    confirmed_vuln:  "ثغرة مؤكدة",
    theoretical:     "نظرية",
    config:          "إعداد",
    info:            "معلومة",
    false_positive:  "نتيجة خاطئة",
    unknown:         "غير معروف",
}

function ScoreBadge({ score }) {
    const color = score >= 70 ? "#dc2626" : score >= 40 ? "#eab308" : "#16a34a"
    return (
        <div className="flex flex-col items-center">
            <div className="text-2xl font-bold font-mono" style={{ color }}>
                {score}
            </div>
            <div className="text-[9px] uppercase" style={{ color: "var(--text-muted)" }}>Exploit</div>
        </div>
    )
}

function TriageCard({ item, rank }) {
    const t = item._triage || {}
    const cat = t.category || "unknown"
    const color = CAT_COLORS[cat] || "#6a6a7a"
    const isWorthy = t.bugbounty_worthy

    return (
        <div className="rounded-lg p-4"
            style={{
                background: "var(--bg-secondary)",
                border: "1px solid " + (isWorthy ? color : "var(--border-color)"),
                borderLeft: "4px solid " + color,
            }}>
            <div className="flex items-start gap-4">
                {/* Rank */}
                <div className="text-xs font-bold font-mono shrink-0"
                    style={{ color: "var(--text-muted)", width: "32px" }}>
                    #{rank}
                </div>

                {/* Score */}
                <ScoreBadge score={t.exploitability_score || 0} />

                {/* Main content */}
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="text-xs font-bold uppercase px-2 py-0.5 rounded"
                            style={{ background: color + "22", color: color, border: "1px solid " + color + "55" }}>
                            {cat}
                        </span>
                        {isWorthy && (
                            <span className="text-xs font-bold px-2 py-0.5 rounded"
                                style={{ background: "rgba(220,38,38,0.15)", color: "#fca5a5", border: "1px solid #dc2626" }}>
                                ★ Bug Bounty
                            </span>
                        )}
                        <span className="text-xs px-2 py-0.5 rounded"
                            style={{ background: "var(--bg-tertiary)", color: "var(--text-muted)" }}>
                            CVSS {t.real_cvss?.toFixed(1) || "0.0"}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded"
                            style={{ background: "var(--bg-tertiary)", color: "var(--text-muted)" }}>
                            Priority {t.publish_priority || "—"}
                        </span>
                    </div>

                    <div className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
                        {item.title}
                    </div>

                    <div className="text-xs mt-1 font-mono break-all" style={{ color: "var(--text-secondary)" }}>
                        {item.url}
                    </div>

                    {t.reason && (
                        <div className="text-xs mt-2 italic" style={{ color: "var(--text-muted)" }}>
                            💡 {t.reason}
                        </div>
                    )}
                </div>

                {/* Actions */}
                <div className="flex gap-1 shrink-0">
                    <a href={item.url} target="_blank" rel="noopener noreferrer"
                        className="p-1.5 rounded"
                        style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)" }}
                        title="Open URL">
                        <Icon name="externalLink" size={14} />
                    </a>
                </div>
            </div>
        </div>
    )
}

export default function TriageV2() {
    const { t, i18n } = useTranslation()
    const isRtl = i18n.language === "ar"

    const [items, setItems] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState("")
    const [filter, setFilter] = useState("all")
    const [onlyWorthy, setOnlyWorthy] = useState(false)

    useEffect(() => {
        let active = true
        const load = async () => {
            try {
                const r = await frameworkScanApi.triageLatest()
                if (active) {
                    setItems(r.data?.items || [])
                    if (!r.data?.items?.length) {
                        setError(isRtl
                            ? "لا توجد نتائج triage — شغّل: python cli.py triage latest"
                            : "No triage data — run: python cli.py triage latest")
                    }
                }
            } catch (e) {
                if (active) setError(e?.response?.data?.detail || e.message)
            } finally {
                if (active) setLoading(false)
            }
        }
        load()
        return () => { active = false }
    }, [isRtl])

    // Stats
    const stats = items.reduce((acc, x) => {
        const cat = x._triage?.category || "unknown"
        acc[cat] = (acc[cat] || 0) + 1
        return acc
    }, {})
    const worthyCount = items.filter(x => x._triage?.bugbounty_worthy).length

    // Filter
    const filtered = items.filter(x => {
        if (onlyWorthy && !x._triage?.bugbounty_worthy) return false
        if (filter !== "all" && (x._triage?.category || "unknown") !== filter) return false
        return true
    })

    return (
        <div className="flex min-h-screen" style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
            <TacticalSidebar />
            <div className="flex-1 flex flex-col min-w-0">
                <TopHeader />
                <main className="flex-1 p-6 overflow-x-hidden">

                    {/* Header */}
                    <div className="flex justify-between items-center flex-wrap gap-3 mb-6">
                        <div>
                            <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: "var(--accent-purple)" }}>
                                <Icon name="brain" size={28} />
                                {isRtl ? "التحليل الذكي" : "AI Triage"}
                            </h1>
                            <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
                                {filtered.length} / {items.length} {isRtl ? "نتيجة" : "findings"}
                                {worthyCount > 0 && (
                                    <span className="ms-3 px-2 py-0.5 rounded text-xs font-bold"
                                        style={{ background: "rgba(220,38,38,0.15)", color: "#fca5a5" }}>
                                        ★ {worthyCount} {isRtl ? "قابل للنشر" : "bug bounty worthy"}
                                    </span>
                                )}
                            </p>
                        </div>
                    </div>

                    {/* Stats */}
                    {Object.keys(stats).length > 0 && (
                        <div className="flex flex-wrap gap-2 mb-4">
                            <button onClick={() => setFilter("all")}
                                className="px-3 py-1.5 rounded text-xs font-bold"
                                style={{
                                    background: filter === "all" ? "var(--accent-purple-soft)" : "var(--bg-secondary)",
                                    color: filter === "all" ? "var(--accent-purple)" : "var(--text-secondary)",
                                    border: "1px solid " + (filter === "all" ? "var(--accent-purple)" : "var(--border-color)"),
                                    cursor: "pointer",
                                }}>
                                All ({items.length})
                            </button>
                            {Object.entries(stats).map(([cat, n]) => {
                                const color = CAT_COLORS[cat] || "#6a6a7a"
                                return (
                                    <button key={cat} onClick={() => setFilter(cat)}
                                        className="px-3 py-1.5 rounded text-xs font-bold"
                                        style={{
                                            background: filter === cat ? color + "33" : "var(--bg-secondary)",
                                            color: filter === cat ? color : "var(--text-secondary)",
                                            border: "1px solid " + (filter === cat ? color : "var(--border-color)"),
                                            cursor: "pointer",
                                        }}>
                                        {cat} ({n})
                                    </button>
                                )
                            })}
                            <button onClick={() => setOnlyWorthy(!onlyWorthy)}
                                className="px-3 py-1.5 rounded text-xs font-bold"
                                style={{
                                    background: onlyWorthy ? "rgba(220,38,38,0.2)" : "var(--bg-secondary)",
                                    color: onlyWorthy ? "#fca5a5" : "var(--text-secondary)",
                                    border: "1px solid " + (onlyWorthy ? "#dc2626" : "var(--border-color)"),
                                    cursor: "pointer",
                                }}>
                                ★ {isRtl ? "قابل للنشر فقط" : "Worthy only"}
                            </button>
                        </div>
                    )}

                    {/* Error */}
                    {error && !loading && items.length === 0 && (
                        <div className="mb-4 p-4 rounded-lg text-sm"
                            style={{ background: "var(--accent-yellow-soft)", border: "1px solid var(--accent-yellow)", color: "var(--accent-yellow)" }}>
                            <Icon name="info" size={16} className="inline me-2" />
                            {error}
                        </div>
                    )}

                    {/* Content */}
                    {loading ? (
                        <div className="p-12 text-center">
                            <Icon name="refresh" size={32} className="anim-spin mx-auto mb-2" style={{ color: "var(--accent-purple)" }} />
                            <div className="text-sm" style={{ color: "var(--text-muted)" }}>
                                {isRtl ? "جاري التحميل..." : "Loading..."}
                            </div>
                        </div>
                    ) : filtered.length === 0 ? (
                        <div className="p-12 text-center rounded-lg"
                            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                            <Icon name="brain" size={48} className="mx-auto mb-3" style={{ color: "var(--text-muted)" }} />
                            <div className="text-lg font-bold mb-1">
                                {isRtl ? "لا توجد نتائج" : "No results"}
                            </div>
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {filtered.map((item, i) => (
                                <TriageCard key={i} item={item} rank={i + 1} />
                            ))}
                        </div>
                    )}
                </main>
            </div>
        </div>
    )
}
