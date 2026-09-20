# -*- coding: utf-8 -*-
from pathlib import Path

base = Path(r"C:\BugBounty\NIGHTFALL\web\frontend\src\v2\components")
pages = Path(r"C:\BugBounty\NIGHTFALL\web\frontend\src\v2\pages")

# ============================================================
# FILE 1: MarkdownRenderer.jsx
# ============================================================
md_renderer = '''/**
 * MarkdownRenderer - Professional Arabic/English Markdown viewer
 * Features: RTL detection, syntax highlighting, copy buttons, TOC
 */
import React, { useMemo, useState, useEffect } from "react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import rehypeHighlight from "rehype-highlight"
import { Icon } from "./Icons"

function CodeBlock({ inline, className, children, ...props }) {
  const [copied, setCopied] = useState(false)
  const code = String(children).replace(/\\n$/, "")
  if (inline) return <code className={className} {...props}>{children}</code>

  const match = /language-(\\w+)/.exec(className || "")
  const lang = match ? match[1] : "text"

  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }).catch(() => {})
  }

  return (
    <div className="relative group my-4 rounded-lg overflow-hidden"
      style={{ background: "#0d0d14", border: "1px solid var(--border-color)" }}>
      <div className="flex items-center justify-between px-3 py-1.5 text-[11px] font-mono"
        style={{ background: "var(--bg-tertiary)", borderBottom: "1px solid var(--border-color)", color: "var(--text-muted)" }}>
        <span className="flex items-center gap-2">
          <Icon name="code" size={12} />
          {lang}
        </span>
        <button onClick={copy}
          className="px-2 py-0.5 rounded text-[10px] font-bold transition-all"
          style={{
            background: copied ? "var(--accent-green)" : "var(--bg-elevated)",
            color: copied ? "white" : "var(--text-primary)",
            cursor: "pointer",
            border: "1px solid var(--border-color)",
          }}>
          {copied ? "OK Copied" : "Copy"}
        </button>
      </div>
      <pre className="p-4 overflow-x-auto text-xs leading-relaxed" dir="ltr">
        <code className={className} {...props}>{children}</code>
      </pre>
    </div>
  )
}

function extractToc(md) {
  const lines = (md || "").split("\\n")
  const toc = []
  for (const line of lines) {
    const m = /^(#{1,3})\\s+(.+)$/.exec(line)
    if (m) toc.push({ level: m[1].length, text: m[2].trim() })
  }
  return toc
}

export default function MarkdownRenderer({ content, showToc = true }) {
  const isRtl = useMemo(() => {
    const arabicChars = (content || "").match(/[\\u0600-\\u06FF]/g)
    return arabicChars && arabicChars.length > 30
  }, [content])

  const toc = useMemo(() => showToc ? extractToc(content || "") : [], [content, showToc])

  if (!content) {
    return <div className="text-sm p-8 text-center" style={{ color: "var(--text-muted)" }}>
      No content to display
    </div>
  }

  const scrollToHeading = (text) => {
    const headings = document.querySelectorAll(".md-content h1, .md-content h2, .md-content h3")
    for (const h of headings) {
      if (h.textContent.includes(text.slice(0, 30))) {
        h.scrollIntoView({ behavior: "smooth", block: "start" })
        return
      }
    }
  }

  return (
    <div className="flex gap-6">
      {showToc && toc.length > 2 && (
        <aside className="hidden xl:block w-56 shrink-0">
          <div className="sticky top-4 max-h-[80vh] overflow-y-auto text-xs p-3 rounded-lg"
            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)" }}>
            <div className="font-bold mb-2 flex items-center gap-2" style={{ color: "var(--accent-cyan)" }}>
              <Icon name="file" size={12} />
              Contents ({toc.length})
            </div>
            <ul className="space-y-1">
              {toc.map((item, i) => (
                <li key={i} style={{ paddingInlineStart: (item.level - 1) * 12 }}>
                  <button onClick={() => scrollToHeading(item.text)}
                    className="hover:underline text-start w-full truncate"
                    style={{
                      color: item.level === 1 ? "var(--text-primary)" :
                             item.level === 2 ? "var(--accent-cyan)" : "var(--text-secondary)",
                      fontWeight: item.level === 1 ? "bold" : "normal",
                      background: "none", border: "none", cursor: "pointer", padding: "2px 0",
                    }}>
                    {item.text}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </aside>
      )}

      <div className="md-content flex-1 min-w-0"
        dir={isRtl ? "rtl" : "ltr"}
        style={{
          fontFamily: isRtl ? "'Segoe UI', Tahoma, 'Noto Naskh Arabic', sans-serif" : "var(--font-sans)",
          lineHeight: 1.75,
          color: "var(--text-primary)",
          fontSize: "14px",
        }}>
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          rehypePlugins={[rehypeHighlight]}
          components={{
            code: CodeBlock,
            h1: ({ children }) => (
              <h1 className="text-2xl font-bold mt-8 mb-4 pb-2 flex items-center gap-2"
                style={{ color: "var(--accent-red)", borderBottom: "2px solid var(--accent-red)" }}>
                {children}
              </h1>
            ),
            h2: ({ children }) => (
              <h2 className="text-xl font-bold mt-6 mb-3 pb-1"
                style={{ color: "var(--accent-cyan)", borderBottom: "1px solid var(--border-color)" }}>
                {children}
              </h2>
            ),
            h3: ({ children }) => (
              <h3 className="text-lg font-bold mt-5 mb-2" style={{ color: "#fbbf24" }}>{children}</h3>
            ),
            h4: ({ children }) => (
              <h4 className="text-base font-bold mt-4 mb-2" style={{ color: "#22d3ee" }}>{children}</h4>
            ),
            p: ({ children }) => <p className="my-2.5 text-sm leading-7">{children}</p>,
            ul: ({ children }) => <ul className="list-disc list-inside my-2 space-y-1 text-sm">{children}</ul>,
            ol: ({ children }) => <ol className="list-decimal list-inside my-2 space-y-1 text-sm">{children}</ol>,
            li: ({ children }) => <li className="my-1 leading-6">{children}</li>,
            a: ({ href, children }) => (
              <a href={href} target="_blank" rel="noopener noreferrer"
                style={{ color: "#60a5fa", textDecoration: "underline" }}
                className="hover:opacity-80 break-all">
                {children}
              </a>
            ),
            blockquote: ({ children }) => (
              <blockquote className="border-l-4 my-3 pl-4 py-2 italic rounded"
                style={{ borderColor: "var(--accent-yellow)", background: "rgba(234,179,8,0.08)", color: "var(--text-secondary)" }}>
                {children}
              </blockquote>
            ),
            table: ({ children }) => (
              <div className="overflow-x-auto my-4 rounded-lg" style={{ border: "1px solid var(--border-color)" }}>
                <table className="w-full text-xs border-collapse">{children}</table>
              </div>
            ),
            thead: ({ children }) => <thead style={{ background: "var(--bg-tertiary)" }}>{children}</thead>,
            th: ({ children }) => (
              <th className="px-3 py-2 text-start font-bold"
                style={{ borderBottom: "1px solid var(--border-color)", color: "var(--accent-cyan)" }}>
                {children}
              </th>
            ),
            td: ({ children }) => (
              <td className="px-3 py-2" style={{ borderBottom: "1px solid var(--border-color)" }}>{children}</td>
            ),
            hr: () => <hr className="my-6" style={{ borderColor: "var(--border-color)" }} />,
            strong: ({ children }) => <strong style={{ color: "var(--text-primary)", fontWeight: "bold" }}>{children}</strong>,
            em: ({ children }) => <em style={{ color: "var(--accent-yellow)" }}>{children}</em>,
          }}
        >
          {content}
        </ReactMarkdown>
      </div>
    </div>
  )
}
'''

(base / "MarkdownRenderer.jsx").write_text(md_renderer, encoding="utf-8")
print("[OK] MarkdownRenderer.jsx created")

# ============================================================
# FILE 2: ReportStats.jsx
# ============================================================
report_stats = '''/**
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
'''

(base / "ReportStats.jsx").write_text(report_stats, encoding="utf-8")
print("[OK] ReportStats.jsx created")

# ============================================================
# FILE 3: ReportsV2.jsx (COMPLETE REWRITE)
# ============================================================
reports_v2 = '''/**
 * ReportsV2 - Professional Reports Center
 * Features: stats, search, filters, split-view preview, TOC, copy, print, download
 */
import { useState, useEffect, useMemo, useCallback, useRef } from "react"
import { useTranslation } from "react-i18next"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import MarkdownRenderer from "../components/MarkdownRenderer"
import ReportStats from "../components/ReportStats"
import client from "../../api/client"
import { Icon } from "../components/Icons"

function formatBytes(b) {
  if (!b) return "0 B"
  if (b < 1024) return b + " B"
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB"
  return (b / 1024 / 1024).toFixed(1) + " MB"
}

function formatDate(mtime) {
  if (!mtime) return "—"
  const d = new Date(mtime * 1000)
  const now = new Date()
  const diff = (now - d) / 1000
  if (diff < 60) return "just now"
  if (diff < 3600) return Math.floor(diff / 60) + "m ago"
  if (diff < 86400) return Math.floor(diff / 3600) + "h ago"
  if (diff < 604800) return Math.floor(diff / 86400) + "d ago"
  return d.toLocaleDateString()
}

function detectSeverity(name) {
  const n = (name || "").toLowerCase()
  if (n.includes("critical") || n.includes("rce") || n.includes("sqli") || n.includes("ssti")) return "critical"
  if (n.includes("high") || n.includes("xss") || n.includes("ssrf")) return "high"
  if (n.includes("medium") || n.includes("idor")) return "medium"
  if (n.includes("low") || n.includes("info")) return "low"
  return "info"
}

function detectTarget(content) {
  if (!content) return ""
  const m = /\\*\\*الهدف:\\*\\*\\s*`([^`]+)`/.exec(content)
  return m ? m[1] : ""
}

export default function ReportsV2() {
  const { t, i18n } = useTranslation()
  const isRtl = i18n.language === "ar"
  const searchRef = useRef(null)

  const [reports, setReports] = useState([])
  const [selected, setSelected] = useState(null)
  const [content, setContent] = useState("")
  const [loading, setLoading] = useState(true)
  const [loadingContent, setLoadingContent] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState("")
  const [search, setSearch] = useState("")
  const [filterSev, setFilterSev] = useState("all")
  const [sortBy, setSortBy] = useState("date-desc")
  const [view, setView] = useState("split") // split | full

  // Load reports
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

      const enriched = list.map((x) => ({
        ...x,
        severity: detectSeverity(x.name || ""),
      }))
      setReports(enriched)
    } catch (e) {
      setError("Failed to load reports: " + (e?.message || "unknown"))
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { loadReports() }, [loadReports])

  // Auto-refresh
  useEffect(() => {
    const i = setInterval(() => loadReports(true), 30000)
    return () => clearInterval(i)
  }, [loadReports])

  // Open report
  const openReport = useCallback(async (name) => {
    setSelected(name)
    setContent("")
    setLoadingContent(true)
    setError("")
    try {
      const r = await client.get("/api/reports/" + encodeURIComponent(name))
      const text = r.data?.content || r.data?.text || (typeof r.data === "string" ? r.data : "")
      setContent(text)
    } catch (e) {
      setError("Failed to load: " + (e?.response?.status || e?.message || "unknown"))
    } finally {
      setLoadingContent(false)
    }
  }, [])

  // Keyboard shortcuts
  useEffect(() => {
    const h = (e) => {
      if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") {
        if (e.key === "Escape") { e.target.blur(); setSearch("") }
        return
      }
      if (e.key === "/" || (e.ctrlKey && e.key === "k")) {
        e.preventDefault(); searchRef.current?.focus()
      }
      if (e.key === "Escape") setSelected(null)
    }
    window.addEventListener("keydown", h)
    return () => window.removeEventListener("keydown", h)
  }, [])

  // Filter + sort
  const filtered = useMemo(() => {
    let list = [...reports]
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter((r) => (r.name || "").toLowerCase().includes(q))
    }
    if (filterSev !== "all") list = list.filter((r) => r.severity === filterSev)
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
  }, [reports, search, filterSev, sortBy])

  // Actions
  const handleDownload = () => {
    if (!selected || !content) return
    const blob = new Blob([content], { type: "text/markdown;charset=utf-8" })
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
      setError("")
    } catch (e) { /* ignore */ }
  }

  const handlePrint = () => {
    if (!selected || !content) return
    const w = window.open("", "_blank")
    w.document.write("<!DOCTYPE html><html dir=\\"" + (isRtl ? "rtl" : "ltr") + "\\"><head><meta charset=\\"utf-8\\"><title>" + selected + "</title>" +
      "<style>body{font-family:'Segoe UI',sans-serif;padding:40px;background:#fff;color:#111;line-height:1.7;max-width:900px;margin:0 auto}" +
      "h1{color:#b91c1c;border-bottom:2px solid #b91c1c;padding-bottom:8px}" +
      "h2{color:#0891b2}h3{color:#ca8a04}" +
      "pre{background:#f5f5f5;padding:16px;border-radius:6px;overflow-x:auto;font-family:Consolas,monospace;font-size:12px}" +
      "code{font-family:Consolas,monospace}" +
      "table{border-collapse:collapse;width:100%;margin:10px 0}" +
      "th,td{border:1px solid #ddd;padding:8px;text-align:start}" +
      "th{background:#f5f5f5}" +
      "a{color:#2563eb}" +
      "@media print{body{padding:20px}}</style></head><body>" +
      "<pre style=\\"white-space:pre-wrap;background:transparent;padding:0\\">" +
      content.replace(/</g, "&lt;").replace(/>/g, "&gt;") +
      "</pre></body></html>")
    w.document.close()
    setTimeout(() => w.print(), 400)
  }

  return (
    <div className="flex min-h-screen" style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <TacticalSidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />
        <main className="flex-1 p-6 overflow-x-hidden">

          {/* Header */}
          <div className="flex justify-between items-center flex-wrap gap-3 mb-6">
            <div>
              <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: "var(--accent-red)" }}>
                <Icon name="reports" size={28} />
                {t("reportsPage.title", "Reports Center")}
              </h1>
              <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
                {filtered.length} / {reports.length} {isRtl ? "تقرير" : "reports"}
              </p>
            </div>
            <button
              onClick={() => loadReports(true)}
              disabled={refreshing}
              className="px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2"
              style={{ background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", cursor: refreshing ? "wait" : "pointer" }}>
              <Icon name="refresh" size={14} className={refreshing ? "anim-spin" : ""} />
              {t("reportsPage.refresh", "Refresh")}
            </button>
          </div>

          {/* Stats */}
          <ReportStats reports={reports} />

          {/* Error */}
          {error && (
            <div className="mb-4 p-3 rounded-lg text-sm flex items-center gap-2"
              style={{ background: "var(--accent-red-soft)", border: "1px solid var(--accent-red)", color: "var(--accent-red)" }}>
              <Icon name="warning" size={16} />
              {error}
            </div>
          )}

          {/* Toolbar */}
          <div className="flex flex-wrap gap-3 mb-4 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <span className={"absolute top-1/2 -translate-y-1/2 pointer-events-none " + (isRtl ? "right-3" : "left-3")}
                style={{ color: "var(--text-muted)" }}>
                <Icon name="search" size={14} />
              </span>
              <input ref={searchRef} type="text" value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t("reportsPage.searchPlaceholder", "Search reports... (press / or Ctrl+K)")}
                className={"w-full py-2 rounded-lg text-sm " + (isRtl ? "pr-9 pl-3" : "pl-9 pr-3")}
                style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
            </div>

            <select value={filterSev} onChange={(e) => setFilterSev(e.target.value)}
              className="px-3 py-2 rounded-lg text-sm"
              style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}>
              <option value="all">{t("reportsPage.allTypes", "All severities")}</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>

            <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}
              className="px-3 py-2 rounded-lg text-sm"
              style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}>
              <option value="date-desc">Newest first</option>
              <option value="date-asc">Oldest first</option>
              <option value="name-asc">Name A → Z</option>
              <option value="name-desc">Name Z → A</option>
              <option value="size-desc">Largest</option>
              <option value="size-asc">Smallest</option>
            </select>

            <div className="flex rounded-lg overflow-hidden" style={{ border: "1px solid var(--border-color)" }}>
              <button onClick={() => setView("split")}
                className="px-3 py-2 text-xs font-bold"
                style={{ background: view === "split" ? "var(--accent-red)" : "var(--bg-secondary)", color: view === "split" ? "white" : "var(--text-primary)", cursor: "pointer" }}>
                Split
              </button>
              <button onClick={() => setView("full")}
                className="px-3 py-2 text-xs font-bold"
                style={{ background: view === "full" ? "var(--accent-red)" : "var(--bg-secondary)", color: view === "full" ? "white" : "var(--text-primary)", cursor: "pointer" }}>
                Full
              </button>
            </div>
          </div>

          {/* Content */}
          {loading ? (
            <div className="p-12 text-center text-sm" style={{ color: "var(--text-muted)" }}>
              <Icon name="refresh" size={32} className="anim-spin mx-auto mb-2" />
              Loading reports...
            </div>
          ) : reports.length === 0 ? (
            <div className="p-12 text-center rounded-lg" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
              <Icon name="reports" size={48} style={{ color: "var(--text-muted)" }} className="mx-auto mb-3" />
              <div className="text-lg font-bold mb-1">{t("reportsPage.noReports", "No reports yet")}</div>
              <div className="text-sm" style={{ color: "var(--text-muted)" }}>
                {t("reportsPage.noReportsDesc", "Run a scan to create reports")}
              </div>
            </div>
          ) : (
            <div className={"grid gap-4 " + (view === "split" ? "grid-cols-1 lg:grid-cols-[380px_1fr]" : "grid-cols-1")}>
              {/* List */}
              {view === "split" && (
                <div className="space-y-2 max-h-[calc(100vh-300px)] overflow-y-auto pe-2">
                  {filtered.length === 0 ? (
                    <div className="p-6 text-center text-xs" style={{ color: "var(--text-muted)" }}>No matching reports</div>
                  ) : filtered.map((r) => {
                    const isSelected = selected === r.name
                    const isRich = (r.size || 0) > 5000
                    return (
                      <button key={r.name} onClick={() => openReport(r.name)}
                        className="w-full text-start p-3 rounded-lg transition-all hover-lift"
                        style={{
                          background: isSelected ? "var(--accent-red-soft)" : "var(--bg-secondary)",
                          border: "1px solid " + (isSelected ? "var(--accent-red)" : "var(--border-color)"),
                          cursor: "pointer",
                        }}>
                        <div className="flex items-center gap-2 mb-1">
                          <Icon name={isRich ? "sparkles" : "file"} size={14}
                            style={{ color: isRich ? "var(--accent-purple)" : "var(--text-muted)" }} />
                          <span className="font-bold text-xs truncate flex-1">{r.name}</span>
                        </div>
                        <div className="flex items-center gap-3 text-[10px]" style={{ color: "var(--text-muted)" }}>
                          <span>{formatBytes(r.size)}</span>
                          <span>{formatDate(r.modified)}</span>
                          {isRich && <span style={{ color: "var(--accent-purple)" }}>AI</span>}
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}

              {/* Preview */}
              {(view === "full" || selected) && (
                <div className="rounded-xl p-6 overflow-hidden" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                  {view === "full" && !selected ? (
                    <div className="text-center text-sm py-12" style={{ color: "var(--text-muted)" }}>
                      Select a report from the list above
                    </div>
                  ) : loadingContent ? (
                    <div className="text-center py-12">
                      <Icon name="refresh" size={32} className="anim-spin mx-auto mb-2" style={{ color: "var(--accent-cyan)" }} />
                      <div className="text-sm" style={{ color: "var(--text-muted)" }}>Loading report...</div>
                    </div>
                  ) : (
                    <>
                      {/* Report actions */}
                      <div className="flex items-center justify-between mb-4 pb-3 flex-wrap gap-2"
                        style={{ borderBottom: "1px solid var(--border-color)" }}>
                        <div className="flex items-center gap-2">
                          <Icon name="reports" size={16} style={{ color: "var(--accent-red)" }} />
                          <span className="font-bold text-sm font-mono">{selected}</span>
                        </div>
                        <div className="flex gap-2">
                          <button onClick={handleCopy}
                            className="px-3 py-1.5 rounded text-xs font-bold flex items-center gap-1.5"
                            style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                            <Icon name="copy" size={12} /> Copy
                          </button>
                          <button onClick={handleDownload}
                            className="px-3 py-1.5 rounded text-xs font-bold flex items-center gap-1.5"
                            style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                            <Icon name="download" size={12} /> Download
                          </button>
                          <button onClick={handlePrint}
                            className="px-3 py-1.5 rounded text-xs font-bold flex items-center gap-1.5"
                            style={{ background: "var(--accent-red)", color: "white", border: "1px solid var(--accent-red)", cursor: "pointer" }}>
                            <Icon name="file" size={12} /> Print
                          </button>
                        </div>
                      </div>

                      <div className="max-h-[calc(100vh-280px)] overflow-y-auto pe-2">
                        <MarkdownRenderer content={content} showToc={true} />
                      </div>
                    </>
                  )}
                </div>
              )}

              {view === "full" && !selected && (
                <div className="rounded-xl p-6" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                  <div className="text-center text-sm py-12" style={{ color: "var(--text-muted)" }}>
                    Click a report from the list to view
                  </div>
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
'''

(pages / "ReportsV2.jsx").write_text(reports_v2, encoding="utf-8")
print("[OK] ReportsV2.jsx rewritten")
print()
print("=== Summary ===")
print("Created 3 files")
print("  1. components/MarkdownRenderer.jsx")
print("  2. components/ReportStats.jsx")
print("  3. pages/ReportsV2.jsx (rewritten)")
