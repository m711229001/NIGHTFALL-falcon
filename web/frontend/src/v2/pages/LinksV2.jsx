/**
 * LinksV2 - Discovered Endpoints Catalog
 * Shows all URLs/endpoints found by the scanner.
 */
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import { frameworkScanApi } from "../../api/clientV2"
import { Icon } from "../components/Icons"

const TYPE_COLORS = {
    api:       "#a855f7",
    graphql:   "#ec4899",
    auth:      "#eab308",
    admin:     "#dc2626",
    form:      "#06b6d4",
    xhr:       "#10b981",
    path:      "#3b82f6",
    upload:    "#f97316",
    download:  "#14b8a6",
    websocket: "#8b5cf6",
    page:      "#64748b",
    unknown:   "#6a6a7a",
}

const TYPE_ICONS = {
    api: "network",
    graphql: "network",
    auth: "lock",
    admin: "shield",
    form: "file",
    xhr: "network",
    path: "link",
    upload: "upload",
    download: "download",
    websocket: "network",
    page: "file",
    unknown: "link",
}

function TypeBadge({ type }) {
    const color = TYPE_COLORS[type] || "#6a6a7a"
    const iconName = TYPE_ICONS[type] || "link"
    return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase"
            style={{ background: color + "22", color: color, border: "1px solid " + color + "55" }}>
            <Icon name={iconName} size={10} />
            {type}
        </span>
    )
}

function EndpointCard({ ep, onCopy, onOpen, onSendScan }) {
    return (
        <div className="rounded-lg p-3 hover-lift"
            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
            <div className="flex items-start gap-3 flex-wrap">
                <TypeBadge type={ep.type} />
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded"
                    style={{
                        background: ep.method === "POST" ? "rgba(16,185,129,0.15)" : "rgba(6,182,212,0.15)",
                        color: ep.method === "POST" ? "#10b981" : "#06b6d4",
                    }}>
                    {ep.method || "GET"}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded"
                    style={{ background: "var(--bg-tertiary)", color: "var(--text-muted)" }}>
                    {ep.data_type || "HTML"}
                </span>
                {ep.status && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded"
                        style={{ background: "rgba(59,130,246,0.15)", color: "#60a5fa" }}>
                        {ep.status}
                    </span>
                )}
                {ep.confidence && (
                    <span className="text-[10px] px-2 py-0.5 rounded"
                        style={{
                            background: ep.confidence === "high" ? "rgba(16,185,129,0.15)" : "rgba(234,179,8,0.15)",
                            color: ep.confidence === "high" ? "#10b981" : "#eab308",
                        }}>
                        {ep.confidence}
                    </span>
                )}
                <div className="flex-1" />
                <div className="flex gap-1">
                    <button onClick={() => onCopy(ep.url)}
                        className="p-1 rounded hover:opacity-80"
                        style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", cursor: "pointer" }}
                        title="Copy URL">
                        <Icon name="copy" size={12} />
                    </button>
                    <a href={ep.url} target="_blank" rel="noopener noreferrer"
                        className="p-1 rounded hover:opacity-80 inline-flex items-center justify-center"
                        style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", cursor: "pointer" }}
                        title="Open in browser">
                        <Icon name="externalLink" size={12} />
                    </a>
                    <button onClick={() => onSendScan(ep.url)}
                        className="p-1 rounded hover:opacity-80"
                        style={{ background: "var(--accent-red-soft)", color: "var(--accent-red)", cursor: "pointer" }}
                        title="Scan this URL">
                        <Icon name="target" size={12} />
                    </button>
                </div>
            </div>

            <div className="mt-2 text-xs font-mono break-all" style={{ color: "var(--text-primary)" }}>
                {ep.url}
            </div>

            <div className="mt-1 text-[11px]" style={{ color: "var(--text-secondary)" }}>
                {ep.description}
            </div>

            {ep.params && ep.params.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                    {ep.params.slice(0, 10).map((p, i) => (
                        <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                            style={{ background: "var(--accent-cyan-soft)", color: "var(--accent-cyan)" }}>
                            {p}
                        </span>
                    ))}
                    {ep.params.length > 10 && (
                        <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                            +{ep.params.length - 10}
                        </span>
                    )}
                </div>
            )}
        </div>
    )
}

export default function LinksV2() {
    const { t, i18n } = useTranslation()
    const isRtl = i18n.language === "ar"

    const [scanId, setScanId] = useState(null)
    const [catalog, setCatalog] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState("")
    const [search, setSearch] = useState("")
    const [filterType, setFilterType] = useState("all")
    const [copied, setCopied] = useState("")

    // Load latest scan's links (with fallback to links-latest)
    useEffect(() => {
        let active = true
        const load = async () => {
            try {
                // 1. Try from API registry (for scans run via UI)
                let sid = null
                try {
                    const r = await frameworkScanApi.list()
                    const scans = (r.data?.scans || []).sort((a, b) =>
                        (b.started_at || "").localeCompare(a.started_at || ""))
                    if (scans.length > 0) sid = scans[0].scan_id
                } catch (_) {}

                if (sid) {
                    if (active) setScanId(sid)
                    const r2 = await frameworkScanApi.links(sid)
                    if (active) {
                        const eps = r2.data?.endpoints || []
                        setCatalog(eps)
                        if (eps.length === 0) {
                            // Fall through to latest
                            throw new Error("empty")
                        }
                        setLoading(false)
                        return
                    }
                }

                // 2. Fallback: links-latest (reads from latest output JSON)
                const r3 = await frameworkScanApi.linksLatest()
                if (active) {
                    setCatalog(r3.data?.endpoints || [])
                    if (r3.data?.scan_id) setScanId(r3.data.scan_id)
                    if (r3.data?.target) setError("")  // clear error
                }
            } catch (e) {
                if (active) {
                    // Try latest as last resort
                    try {
                        const r = await frameworkScanApi.linksLatest()
                        if (active) {
                            setCatalog(r.data?.endpoints || [])
                            if (r.data?.scan_id) setScanId(r.data.scan_id)
                        }
                    } catch (_) {
                        if (active) setError(isRtl ? "لا توجد فحوصات" : "No scans yet")
                    }
                }
            } finally {
                if (active) setLoading(false)
            }
        }
        load()
        return () => { active = false }
    }, [isRtl])

    const refresh = async () => {
        setLoading(true)
        try {
            if (scanId) {
                try {
                    const r = await frameworkScanApi.links(scanId)
                    setCatalog(r.data?.endpoints || [])
                    setLoading(false)
                    return
                } catch (_) {}
            }
            const r = await frameworkScanApi.linksLatest()
            setCatalog(r.data?.endpoints || [])
            if (r.data?.scan_id) setScanId(r.data.scan_id)
        } catch (e) {
            setError(e?.message || "refresh failed")
        } finally {
            setLoading(false)
        }
    }

    const handleCopy = async (url) => {
        try {
            await navigator.clipboard.writeText(url)
            setCopied(url)
            setTimeout(() => setCopied(""), 1500)
        } catch (_) {}
    }

    const handleSendScan = (url) => {
        window.location.href = "/v2/framework-scan?target=" + encodeURIComponent(url)
    }

    // Stats
    const stats = catalog.reduce((acc, e) => {
        acc[e.type] = (acc[e.type] || 0) + 1
        return acc
    }, {})

    // Filter
    const filtered = catalog.filter((e) => {
        if (filterType !== "all" && e.type !== filterType) return false
        if (search.trim() && !(e.url || "").toLowerCase().includes(search.toLowerCase())) return false
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
                            <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: "var(--accent-cyan)" }}>
                                <Icon name="link" size={28} />
                                {isRtl ? "الروابط المكتشفة" : "Discovered Links"}
                            </h1>
                            <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
                                {filtered.length} / {catalog.length} {isRtl ? "رابط" : "links"}
                                {scanId && <span className="ms-2 font-mono text-[10px]" style={{ color: "var(--text-muted)" }}>({scanId})</span>}
                            </p>
                        </div>
                        <button onClick={refresh} disabled={loading}
                            className="px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2"
                            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", cursor: loading ? "wait" : "pointer" }}>
                            <Icon name="refresh" size={14} className={loading ? "anim-spin" : ""} />
                            {isRtl ? "تحديث" : "Refresh"}
                        </button>
                    </div>

                    {/* Stats */}
                    {Object.keys(stats).length > 0 && (
                        <div className="flex flex-wrap gap-2 mb-4">
                            <button onClick={() => setFilterType("all")}
                                className="px-3 py-1.5 rounded text-xs font-bold"
                                style={{
                                    background: filterType === "all" ? "var(--accent-cyan-soft)" : "var(--bg-secondary)",
                                    color: filterType === "all" ? "var(--accent-cyan)" : "var(--text-primary)",
                                    border: "1px solid " + (filterType === "all" ? "var(--accent-cyan)" : "var(--border-color)"),
                                    cursor: "pointer",
                                }}>
                                All ({catalog.length})
                            </button>
                            {Object.entries(stats).sort().map(([type, n]) => {
                                const color = TYPE_COLORS[type] || "#6a6a7a"
                                return (
                                    <button key={type} onClick={() => setFilterType(type)}
                                        className="px-3 py-1.5 rounded text-xs font-bold uppercase"
                                        style={{
                                            background: filterType === type ? color + "33" : "var(--bg-secondary)",
                                            color: filterType === type ? color : "var(--text-secondary)",
                                            border: "1px solid " + (filterType === type ? color : "var(--border-color)"),
                                            cursor: "pointer",
                                        }}>
                                        {type} ({n})
                                    </button>
                                )
                            })}
                        </div>
                    )}

                    {/* Search */}
                    <div className="relative mb-4">
                        <span className={"absolute top-1/2 -translate-y-1/2 pointer-events-none " + (isRtl ? "right-3" : "left-3")}
                            style={{ color: "var(--text-muted)" }}>
                            <Icon name="search" size={14} />
                        </span>
                        <input type="text" value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            placeholder={isRtl ? "ابحث في الروابط..." : "Search URLs..."}
                            className={"w-full py-2 rounded-lg text-sm " + (isRtl ? "pr-9 pl-3" : "pl-9 pr-3")}
                            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
                    </div>

                    {/* Error */}
                    {error && (
                        <div className="mb-4 p-3 rounded-lg text-sm flex items-center gap-2"
                            style={{ background: "var(--accent-red-soft)", border: "1px solid var(--accent-red)", color: "var(--accent-red)" }}>
                            <Icon name="warning" size={16} />
                            {error}
                        </div>
                    )}

                    {/* Content */}
                    {loading ? (
                        <div className="p-12 text-center">
                            <Icon name="refresh" size={32} className="anim-spin mx-auto mb-2" style={{ color: "var(--accent-cyan)" }} />
                            <div className="text-sm" style={{ color: "var(--text-muted)" }}>
                                {isRtl ? "جاري التحميل..." : "Loading..."}
                            </div>
                        </div>
                    ) : filtered.length === 0 ? (
                        <div className="p-12 text-center rounded-lg"
                            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                            <Icon name="link" size={48} className="mx-auto mb-3" style={{ color: "var(--text-muted)" }} />
                            <div className="text-lg font-bold mb-1">
                                {catalog.length === 0
                                    ? (isRtl ? "لا توجد روابط مكتشفة" : "No links discovered")
                                    : (isRtl ? "لا نتائج مطابقة" : "No matching results")}
                            </div>
                            <div className="text-sm" style={{ color: "var(--text-muted)" }}>
                                {isRtl ? "شغّل فحصاً جديداً لبناء القائمة" : "Run a scan to build the catalog"}
                            </div>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                            {filtered.map((ep, i) => (
                                <EndpointCard key={i} ep={ep}
                                    onCopy={handleCopy}
                                    onOpen={() => {}}
                                    onSendScan={handleSendScan} />
                            ))}
                        </div>
                    )}
                </main>
            </div>

            {/* Copy toast */}
            {copied && (
                <div className="fixed bottom-6 end-6 px-4 py-2 rounded-lg text-sm font-bold anim-slide-up z-50"
                    style={{ background: "var(--accent-green)", color: "white" }}>
                    ✓ {isRtl ? "تم النسخ" : "Copied"}
                </div>
            )}
        </div>
    )
}
