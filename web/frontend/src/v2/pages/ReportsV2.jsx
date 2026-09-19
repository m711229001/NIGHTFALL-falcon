/**
 * ReportsV2 — Professional Reports Center
 * Features: search, filter, sort, stats, preview, download, print, copy,
 *           keyboard shortcuts, auto-refresh, 3 themes.
 */
import { useState, useEffect, useMemo, useCallback, useRef } from "react"
import { useTranslation } from "react-i18next"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import client from "../../api/client"
import "./ReportsV2.css"

import MarkdownViewer from "../components/MarkdownViewer"

// ============================================================
// Helpers
// ============================================================

function detectSeverity(name) {
  const n = name.toLowerCase()
  if (n.includes("critical") || n.includes("rce") || n.includes("sqli") || n.includes("ssti")) return "critical"
  if (n.includes("high") || n.includes("xss") || n.includes("ssrf")) return "high"
  if (n.includes("medium") || n.includes("idor")) return "medium"
  if (n.includes("low") || n.includes("info")) return "low"
  return "info"
}

function detectVulnType(name) {
  const n = name.toLowerCase()
  if (n.includes("ssti")) return "ssti"
  if (n.includes("sqli")) return "sqli"
  if (n.includes("xss")) return "xss"
  if (n.includes("ssrf")) return "ssrf"
  if (n.includes("idor")) return "idor"
  if (n.includes("rce")) return "rce"
  if (n.includes("lfi") || n.includes("traversal")) return "lfi"
  if (n.includes("open_redirect") || n.includes("redirect")) return "redirect"
  if (n.includes("cve")) return "cve"
  return "other"
}

function formatBytes(b) {
  if (!b) return "0 B"
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(1)} MB`
}

function formatDate(mtime) {
  if (!mtime) return "—"
  const d = new Date(mtime * 1000)
  const now = new Date()
  const diff = (now - d) / 1000
  if (diff < 60) return "just now"
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`
  return d.toLocaleDateString()
}

// ============================================================
// Component
// ============================================================

export default function ReportsV2() {
  const { t } = useTranslation()
  const searchRef = useRef(null)

  // Data
  const [reports, setReports] = useState([])
  const [selected, setSelected] = useState(null)
  const [content, setContent] = useState("")
  const [loading, setLoading] = useState(true)
  const [loadingContent, setLoadingContent] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState("")

  // UI state
  const [search, setSearch] = useState("")
  const [filterType, setFilterType] = useState("all")
  const [sortBy, setSortBy] = useState("date-desc")
  const [view, setView] = useState("split") // split | full

  // ============================================================
  // Load reports
  // ============================================================
  const loadReports = useCallback(async (showSpinner = false) => {
    if (showSpinner) setRefreshing(true)
    else setLoading(true)
    setError("")

    try {
      const r = await client.get("/api/reports")
      const raw = r.data
      let list = []
      if (Array.isArray(raw)) list = raw
      else if (raw && Array.isArray(raw.reports)) list = raw.reports
      else if (raw && Array.isArray(raw.data)) list = raw.data

      // Enrich
      const enriched = list.map((x) => ({
        ...x,
        severity: detectSeverity(x.name || ""),
        vulnType: detectVulnType(x.name || ""),
      }))
      setReports(enriched)
    } catch (e) {
      console.error("Reports fetch failed:", e)
      setError("Failed to load reports: " + (e?.message || "unknown"))
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    loadReports()
  }, [loadReports])

  // ============================================================
  // Auto-refresh every 30s
  // ============================================================
  useEffect(() => {
    const i = setInterval(() => loadReports(true), 30000)
    return () => clearInterval(i)
  }, [loadReports])

  // ============================================================
  // Keyboard shortcuts
  // ============================================================
  useEffect(() => {
    const handler = (e) => {
      if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") {
        if (e.key === "Escape") {
          e.target.blur()
          setSearch("")
        }
        return
      }
      if (e.key === "/" || (e.ctrlKey && e.key === "k")) {
        e.preventDefault()
        searchRef.current?.focus()
      }
      if (e.key === "Escape") setSelected(null)
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [])

  // ============================================================
  // Filtered + sorted
  // ============================================================
  const filtered = useMemo(() => {
    let list = [...reports]

    // Search
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter((r) => (r.name || "").toLowerCase().includes(q))
    }

    // Filter by type
    if (filterType !== "all") {
      list = list.filter((r) => r.vulnType === filterType)
    }

    // Sort
    list.sort((a, b) => {
      switch (sortBy) {
        case "date-desc": return (b.modified || 0) - (a.modified || 0)
        case "date-asc": return (a.modified || 0) - (b.modified || 0)
        case "name-asc": return (a.name || "").localeCompare(b.name || "")
        case "name-desc": return (b.name || "").localeCompare(a.name || "")
        case "size-desc": return (b.size || 0) - (a.size || 0)
        case "size-asc": return (a.size || 0) - (b.size || 0)
        default: return 0
      }
    })

    return list
  }, [reports, search, filterType, sortBy])

  // ============================================================
  // Stats
  // ============================================================
  const stats = useMemo(() => {
    const s = {
      total: reports.length,
      md: 0,
      json: 0,
      sarif: 0,
      ssti: 0,
      sqli: 0,
      xss: 0,
      other: 0,
    }
    for (const r of reports) {
      if (r.type === "markdown") s.md++
      else if (r.type === "json") s.json++
      else if (r.type === "sarif") s.sarif++

      if (r.vulnType === "ssti") s.ssti++
      else if (r.vulnType === "sqli") s.sqli++
      else if (r.vulnType === "xss") s.xss++
      else s.other++
    }
    return s
  }, [reports])

  // ============================================================
  // Open report
  // ============================================================
  const openReport = async (name) => {
    setSelected(name)
    setContent("")
    setLoadingContent(true)
    setError("")
    try {
      const r = await client.get(`/api/reports/${encodeURIComponent(name)}`)
      const text =
        r.data?.content ||
        r.data?.text ||
        (typeof r.data === "string" ? r.data : JSON.stringify(r.data, null, 2))
      setContent(text)
    } catch (e) {
      console.error("Report fetch failed:", e)
      setError("Failed to load report: " + (e?.response?.status || e?.message || "unknown"))
      setContent("")
    } finally {
      setLoadingContent(false)
    }
  }

  // ============================================================
  // Actions
  // ============================================================
  const handleDownload = () => {
    if (!selected || !content) return
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = selected
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleCopy = async () => {
    if (!content) return
    try {
      await navigator.clipboard.writeText(content)
      // Simple feedback
      const btn = document.activeElement
      if (btn) {
        const old = btn.textContent
        btn.textContent = "✓ Copied"
        setTimeout(() => (btn.textContent = old), 1500)
      }
    } catch (e) {
      console.error("Copy failed:", e)
    }
  }

  const handlePrint = () => {
    if (!selected || !content) return
    const w = window.open("", "_blank")
    w.document.write(`<!DOCTYPE html>
<html dir="rtl">
<head>
<meta charset="utf-8">
<title>${selected}</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; padding: 40px; background: white; color: #111; line-height: 1.6; }
  h1 { color: #b91c1c; border-bottom: 2px solid #b91c1c; padding-bottom: 10px; }
  pre { background: #f5f5f5; padding: 16px; border-radius: 6px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Consolas', monospace; font-size: 12px; }
  @media print { body { padding: 20px; } }
</style>
</head>
<body>
<h1>${selected}</h1>
<pre>${content.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</pre>
</body>
</html>`)
    w.document.close()
    setTimeout(() => w.print(), 500)
  }

  // ============================================================
  // Render
  // ============================================================
  return (
    <div
      className="flex min-h-screen transition-colors"
      style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}
    >
      <TacticalSidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />

        <main className="reports-page">
          {/* Header */}
          <div className="reports-header">
            <h1 className="reports-title">
              <span className="reports-title-icon">📊</span>
              Reports Center
            </h1>
            <div className="reports-actions">
              <button
                className={`icon-btn ${refreshing ? "spinning" : ""}`}
                onClick={() => loadReports(true)}
                title="Refresh (auto every 30s)"
              >
                🔄
              </button>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="error-banner">
              <span>⚠</span>
              <span>{error}</span>
              <button onClick={() => loadReports()}>Retry</button>
            </div>
          )}

          {/* Stats */}
          <div className="stats-grid">
            <div className="stat-card" style={{ "--stat-color": "var(--accent-red)" }}>
              <div className="stat-value">{stats.total}</div>
              <div className="stat-label">Total</div>
            </div>
            <div className="stat-card" style={{ "--stat-color": "var(--accent-cyan)" }}>
              <div className="stat-value">{stats.md}</div>
              <div className="stat-label">Markdown</div>
            </div>
            <div className="stat-card" style={{ "--stat-color": "var(--accent-purple)" }}>
              <div className="stat-value">{stats.json}</div>
              <div className="stat-label">JSON</div>
            </div>
            <div className="stat-card" style={{ "--stat-color": "#ef4444" }}>
              <div className="stat-value">{stats.ssti}</div>
              <div className="stat-label">SSTI</div>
            </div>
            <div className="stat-card" style={{ "--stat-color": "#f97316" }}>
              <div className="stat-value">{stats.sqli}</div>
              <div className="stat-label">SQLi</div>
            </div>
            <div className="stat-card" style={{ "--stat-color": "#10b981" }}>
              <div className="stat-value">{stats.other}</div>
              <div className="stat-label">Other</div>
            </div>
          </div>

          {/* Toolbar */}
          <div className="toolbar">
            <div className="search-box">
              <span>🔍</span>
              <input
                ref={searchRef}
                className="search-input"
                placeholder="Search reports... (press / or Ctrl+K)"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <span className="kbd-hint">/</span>
            </div>

            <select
              className="filter-select"
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
            >
              <option value="all">All Types</option>
              <option value="ssti">SSTI</option>
              <option value="sqli">SQLi</option>
              <option value="xss">XSS</option>
              <option value="ssrf">SSRF</option>
              <option value="idor">IDOR</option>
              <option value="rce">RCE</option>
              <option value="lfi">LFI</option>
              <option value="other">Other</option>
            </select>

            <select
              className="filter-select"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
            >
              <option value="date-desc">📅 Newest first</option>
              <option value="date-asc">📅 Oldest first</option>
              <option value="name-asc">🔤 Name A→Z</option>
              <option value="name-desc">🔤 Name Z→A</option>
              <option value="size-desc">📦 Largest</option>
              <option value="size-asc">📦 Smallest</option>
            </select>

            <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-muted)" }}>
              {filtered.length} / {reports.length}
            </span>
          </div>

          {/* Layout */}
          {loading ? (
            <div className="loading-state">
              <div className="spinner" />
              <div>Loading reports...</div>
            </div>
          ) : reports.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">📄</div>
              <div className="empty-title">No reports yet</div>
              <div className="empty-desc">
                Run a scan to generate reports. They will appear here automatically.
              </div>
            </div>
          ) : (
            <div className="reports-layout">
              {/* List */}
              <div className="reports-list">
                {filtered.length === 0 ? (
                  <div className="empty-state" style={{ padding: "40px 20px" }}>
                    <div className="empty-icon" style={{ fontSize: 40 }}>🔍</div>
                    <div className="empty-desc">No reports match your filter</div>
                  </div>
                ) : (
                  filtered.map((r) => {
                    const name = r.name || r.path
                    const isActive = selected === name
                    return (
                      <div
                        key={name}
                        className={`report-item ${isActive ? "active" : ""}`}
                        onClick={() => openReport(name)}
                        style={{ "--severity-color": `var(--accent-${r.severity === "critical" ? "red" : r.severity === "high" ? "orange" : r.severity === "medium" ? "yellow" : r.severity === "low" ? "green" : "cyan"})` }}
                      >
                        <div className="report-item-header">
                          <span className={`severity-badge severity-${r.severity}`}>
                            {r.severity}
                          </span>
                          <span className="report-item-name" title={name}>
                            {name}
                          </span>
                        </div>
                        <div className="report-item-meta">
                          <span>{formatBytes(r.size)}</span>
                          <span>·</span>
                          <span>{formatDate(r.modified)}</span>
                          <span>·</span>
                          <span style={{ textTransform: "uppercase", fontWeight: 600 }}>
                            {r.vulnType}
                          </span>
                        </div>
                      </div>
                    )
                  })
                )}
              </div>

              {/* Viewer */}
              <div className="report-viewer">
                {selected ? (
                  <>
                    <div className="viewer-header">
                      <div className="viewer-title" title={selected}>
                        📄 {selected}
                      </div>
                      <div className="viewer-actions">
                        <button
                          className="action-btn"
                          onClick={handlePrint}
                          disabled={!content}
                          title="Print"
                        >
                          🖨 Print
                        </button>
                        <button
                          className="action-btn primary"
                          onClick={handleDownload}
                          disabled={!content}
                          title="Download"
                        >
                          ⬇ Download
                        </button>
                        <button
                          className="action-btn"
                          onClick={handleCopy}
                          disabled={!content}
                          title="Copy"
                        >
                          📋 Copy
                        </button>
                      </div>
                    </div>

                    <div className="viewer-content">
                      {loadingContent ? (
                        <div className="loading-state" style={{ padding: 40 }}>
                          <div className="spinner" />
                          <div>Loading content...</div>
                        </div>
                      ) : content ? (
                        <MarkdownViewer content={content} />
                      ) : (
                        <div className="empty-state" style={{ padding: 40 }}>
                          <div className="empty-desc">No content available</div>
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="empty-state" style={{ flex: 1 }}>
                    <div className="empty-icon">📖</div>
                    <div className="empty-title">Select a report</div>
                    <div className="empty-desc">
                      Click any report from the list to preview its content here
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}