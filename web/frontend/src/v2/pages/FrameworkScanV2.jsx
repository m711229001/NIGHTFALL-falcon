/**
 * FrameworkScanV2 — Run framework/cli.py via Backend V2 API.
 * Features: module picker, profile selector, manual auth, live log, result viewer.
 *
 * FIXED 2026-09-19:
 *   - MODULE_GROUPS before QUICK_PRESETS (ReferenceError fix)
 *   - Added "Modern (2024-2025)" group
 *   - Added "modern" preset + ⚡ Modern button
 *   - Auto-prepend https:// if user omits the scheme.
 */
import { useState, useEffect, useRef } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "react-router-dom"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import { frameworkScanApi, profilesV2Api } from "../../api/clientV2"

// ============================================================
// Available modules (from framework/cli.py MODULE_REGISTRY)
// ============================================================
const MODULE_GROUPS = [
  {
    label: "Recon",
    modules: [
      "tech_fingerprint",
      "fingerprint",
      "headers_check",
      "crawler",
      "js_analyzer",
      "path_discovery",
      "catch_all_detector",
      "js_endpoints",
      "js_secrets",
      "dom_xss_scanner",
      "playwright_crawler",
    ],
  },
  {
    label: "Vulnerabilities",
    modules: [
      "xss_scanner",
      "sqli_scanner",
      "nosql_scanner",
      "csrf_checker",
      "clickjacking",
      "path_traversal",
      "ssrf_scanner",
      "idor_scanner",
      "open_redirect",
      "prototype_pollution",
    ],
  },
  {
    label: "Modern (2024-2025)",
    modules: [
      "nextjs_middleware_bypass",
      "rsc_data_leakage",
      "react2shell_rce",
      "graphql_relay_idor",
      "ssr_proto_pollution",
    ],
  },
  {
    label: "Infrastructure",
    modules: [
      "tls_checker",
      "port_scanner",
      "cors_checker",
      "http_methods",
      "cookies_checker",
      "rate_limit_test",
      "subdomain_enum",
      "cve_lookup",
    ],
  },
  {
    label: "External Tools",
    modules: [
      "external_nmap",
      "external_testssl",
      "external_subfinder",
      "external_searchsploit",
    ],
  },
]

// ============================================================
// Quick presets (module shortcuts)
// ============================================================
const QUICK_PRESETS = {
  quick:  ["tech_fingerprint", "fingerprint", "headers_check"],
  recon:  ["tech_fingerprint", "fingerprint", "headers_check", "crawler", "js_analyzer", "path_discovery"],
  vulns:  ["xss_scanner", "sqli_scanner", "csrf_checker", "open_redirect"],
  modern: ["tech_fingerprint", "nextjs_middleware_bypass", "rsc_data_leakage", "react2shell_rce", "graphql_relay_idor", "ssr_proto_pollution"],
  full:   MODULE_GROUPS.flatMap(g => g.modules),
}

// ============================================================
// URL normalization helper
// ============================================================
function normalizeUrl(raw) {
  let url = (raw || "").trim()
  if (!url) return ""
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url
  }
  return url
}

export default function FrameworkScanV2() {
  const { t, i18n } = useTranslation()
  const isRtl = i18n.language === "ar"
  const [searchParams] = useSearchParams()

  // ---- Form state ----
  const [target, setTarget] = useState(searchParams.get("target") || "")
  const [selectedModules, setSelectedModules] = useState(new Set(QUICK_PRESETS.quick))
  const [useAllModules, setUseAllModules] = useState(false)

  // ---- Auth state ----
  const [authMode, setAuthMode] = useState("none")  // none | profile | manual
  const [profile, setProfile] = useState(searchParams.get("profile") || "")
  const [manualCookie, setManualCookie] = useState("")
  const [bearerToken, setBearerToken] = useState("")

  // ---- Advanced ----
  const [parallel, setParallel] = useState(1)
  const [timeout, setTimeout] = useState(1800)
  const [insecure, setInsecure] = useState(false)

  // ---- AI ----
  const [aiEnabled, setAiEnabled] = useState(true)
  const [aiMax, setAiMax] = useState(20)

  // ---- Data ----
  const [profiles, setProfiles] = useState([])
  const [profilesError, setProfilesError] = useState("")

  // ---- Scan lifecycle ----
  const [scanId, setScanId] = useState(null)
  const [scanStatus, setScanStatus] = useState(null)
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const pollRef = useRef(null)

  // ---- Load profiles ----
  useEffect(() => {
    profilesV2Api.list()
      .then(res => setProfiles(res.data.profiles || []))
      .catch(e => setProfilesError(e?.response?.data?.detail || e.message))
  }, [])

  // ---- Poll scan status + logs while running ----
  useEffect(() => {
    if (!scanId) return
    let alive = true

    const poll = async () => {
      try {
        const [statusRes, logRes] = await Promise.all([
          frameworkScanApi.status(scanId),
          frameworkScanApi.log(scanId, 500),
        ])
        if (!alive) return
        setScanStatus(statusRes.data)
        setLogs(logRes.data.lines || [])

        const st = statusRes.data.status
        if (st === "running" || st === "pending") {
          pollRef.current = setTimeout(poll, 2000)
        }
      } catch (e) {
        if (alive) setError(e?.response?.data?.detail || e.message)
      }
    }

    poll()
    return () => {
      alive = false
      if (pollRef.current) clearTimeout(pollRef.current)
    }
  }, [scanId])

  // ---- Helpers ----
  const toggleModule = (mod) => {
    const next = new Set(selectedModules)
    if (next.has(mod)) next.delete(mod)
    else next.add(mod)
    setSelectedModules(next)
    setUseAllModules(false)
  }

  const applyPreset = (key) => {
    if (!QUICK_PRESETS[key]) return
    setSelectedModules(new Set(QUICK_PRESETS[key]))
    setUseAllModules(false)
  }

  const selectAll = () => setUseAllModules(true)

  const startScan = async () => {
    setError("")
    if (!target.trim()) {
      setError(isRtl ? "الرابط مطلوب" : "Target URL required")
      return
    }

    const normalizedTarget = normalizeUrl(target)
    if (normalizedTarget !== target) {
      setTarget(normalizedTarget)
    }

    setLoading(true)
    setScanStatus(null)
    setLogs([])

    const payload = {
      url: normalizedTarget,
      all_modules: useAllModules,
      modules: useAllModules ? null : Array.from(selectedModules).join(","),
      parallel,
      timeout,
      insecure,
      no_ai: !aiEnabled,
      ai_max: aiMax,
    }
    if (authMode === "profile" && profile) {
      payload.profile = profile
    } else if (authMode === "manual") {
      if (manualCookie) payload.cookie = manualCookie
      if (bearerToken) payload.bearer_token = bearerToken
    }

    try {
      const res = await frameworkScanApi.start(payload)
      setScanId(res.data.scan_id)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const cancelScan = async () => {
    if (!scanId) return
    try {
      await frameworkScanApi.cancel(scanId)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    }
  }

  const isRunning = scanStatus?.status === "running" || scanStatus?.status === "pending"
  const isDone = scanStatus?.status === "done"
  const isError = scanStatus?.status === "error"

  return (
    <div className="flex min-h-screen transition-colors"
      style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <TacticalSidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />

        <main className="flex-1 p-6 overflow-x-hidden">
          <div className="max-w-6xl mx-auto space-y-6">

            {/* Header */}
            <div>
              <h1 className="text-3xl font-bold mb-1" style={{ color: "var(--accent-red)" }}>
                🦅 Framework Scan
              </h1>
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                {isRtl
                  ? "تشغيل framework/cli.py — 38 وحدة فحص"
                  : "Run framework/cli.py — 38 scan modules"}
              </p>
            </div>

            {/* FORM */}
            {!scanId && (
              <div className="rounded-2xl p-6 space-y-5"
                style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>

                {/* Target */}
                <div>
                  <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
                    &lt; {isRtl ? "رابط الهدف" : "Target URL"} <span style={{ color: "var(--accent-red)" }}>*</span>
                  </label>
                  <input
                    type="text"
                    value={target}
                    onChange={e => setTarget(e.target.value)}
                    placeholder="https://example.com (or just example.com)"
                    className="w-full px-4 py-2 rounded-lg font-mono text-sm"
                    style={{
                      background: "var(--bg-tertiary)",
                      border: "1px solid var(--border-color)",
                      color: "var(--text-primary)",
                    }}
                  />
                  <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                    {isRtl
                      ? "💡 إذا لم تبدأ بـ http:// أو https://، سيضاف https:// تلقائياً"
                      : "💡 If scheme is missing, https:// is auto-prepended"}
                  </p>
                </div>

                {/* Modules */}
                <div>
                  <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
                    <label className="text-sm font-mono" style={{ color: "var(--accent-yellow)" }}>
                      &lt; {isRtl ? "الوحدات" : "Modules"} ({useAllModules ? "ALL" : selectedModules.size})
                    </label>
                    <div className="flex gap-2 flex-wrap">
                      <button onClick={() => applyPreset("quick")} className="px-3 py-1 rounded text-xs"
                        style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                        Quick
                      </button>
                      <button onClick={() => applyPreset("recon")} className="px-3 py-1 rounded text-xs"
                        style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                        Recon
                      </button>
                      <button onClick={() => applyPreset("vulns")} className="px-3 py-1 rounded text-xs"
                        style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                        Vulns
                      </button>
                      <button onClick={() => applyPreset("modern")} className="px-3 py-1 rounded text-xs font-bold"
                        style={{ background: "var(--accent-cyan)", color: "#000", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                        ⚡ Modern
                      </button>
                      <button onClick={selectAll} className="px-3 py-1 rounded text-xs font-bold"
                        style={{ background: "var(--accent-red)", color: "white", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                        All
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {MODULE_GROUPS.map(group => (
                      <div key={group.label} className="rounded-lg p-3"
                        style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)" }}>
                        <div className="text-xs font-bold mb-2" style={{ color: "var(--accent-yellow)" }}>
                          {group.label}
                        </div>
                        <div className="space-y-1">
                          {group.modules.map(m => (
                            <label key={m} className="flex items-center gap-2 text-xs cursor-pointer">
                              <input
                                type="checkbox"
                                checked={useAllModules || selectedModules.has(m)}
                                onChange={() => toggleModule(m)}
                                style={{ accentColor: "var(--accent-red)" }}
                              />
                              <span style={{ color: "var(--text-primary)" }}>{m}</span>
                            </label>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Auth */}
                <div>
                  <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
                    &lt; {isRtl ? "المصادقة" : "Authentication"}
                  </label>
                  <div className="flex gap-2 mb-3">
                    {["none", "profile", "manual"].map(mode => (
                      <button key={mode} onClick={() => setAuthMode(mode)}
                        className="px-3 py-1.5 rounded text-xs font-semibold"
                        style={{
                          background: authMode === mode ? "var(--accent-red)" : "var(--bg-tertiary)",
                          color: authMode === mode ? "white" : "var(--text-secondary)",
                          border: "1px solid var(--border-color)",
                          cursor: "pointer",
                        }}>
                        {mode}
                      </button>
                    ))}
                  </div>

                  {authMode === "profile" && (
                    <div>
                      {profilesError && <div className="text-xs text-red-500 mb-2">{profilesError}</div>}
                      <select value={profile} onChange={e => setProfile(e.target.value)}
                        className="w-full px-4 py-2 rounded-lg text-sm"
                        style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}>
                        <option value="">— {isRtl ? "اختر profile" : "Select profile"} —</option>
                        {profiles.map(p => (
                          <option key={p.name} value={p.name}>
                            {p.name} ({p.provider || "?"} · {p.cookies_count} cookies)
                          </option>
                        ))}
                      </select>
                    </div>
                  )}

                  {authMode === "manual" && (
                    <div className="space-y-2">
                      <input
                        type="text"
                        value={manualCookie}
                        onChange={e => setManualCookie(e.target.value)}
                        placeholder={isRtl ? "Cookies (name=value; name2=value2)" : "Cookies (name=value; name2=value2)"}
                        className="w-full px-4 py-2 rounded-lg text-xs font-mono"
                        style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
                      />
                      <input
                        type="text"
                        value={bearerToken}
                        onChange={e => setBearerToken(e.target.value)}
                        placeholder="Bearer token (JWT)"
                        className="w-full px-4 py-2 rounded-lg text-xs font-mono"
                        style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
                      />
                    </div>
                  )}
                </div>

                {/* AI Options */}
                <div className="rounded-lg p-3"
                  style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)" }}>
                  <div className="text-xs font-bold mb-2" style={{ color: "var(--accent-cyan)" }}>
                    AI Analysis
                  </div>
                  <label className="flex items-center gap-2 text-xs cursor-pointer">
                    <input type="checkbox" checked={aiEnabled}
                      onChange={e => setAiEnabled(e.target.checked)}
                      style={{ accentColor: "var(--accent-red)" }} />
                    <span>{isRtl ? "تفعيل تحليل AI للثغرات" : "Enable AI analysis of findings"}</span>
                  </label>
                  {aiEnabled && (
                    <div className="mt-3">
                      <label className="text-xs block mb-1">
                        {isRtl ? "أقصى عدد ثغرات للتحليل" : "Max findings to analyze"}: {aiMax}
                      </label>
                      <input type="range" min="1" max="50" value={aiMax}
                        onChange={e => setAiMax(parseInt(e.target.value))}
                        className="w-full" style={{ accentColor: "var(--accent-red)" }} />
                      <div className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
                        {isRtl ? "(أعلى = أبطأ)" : "(higher = slower)"}
                      </div>
                    </div>
                  )}
                </div>

                {/* Advanced */}
                <details className="rounded-lg p-3"
                  style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)" }}>
                  <summary className="cursor-pointer text-xs font-bold" style={{ color: "var(--accent-yellow)" }}>
                    ⚙️ {isRtl ? "متقدم" : "Advanced"}
                  </summary>
                  <div className="grid grid-cols-2 gap-3 mt-3">
                    <div>
                      <label className="text-xs block mb-1">Parallel workers: {parallel}</label>
                      <input type="range" min="1" max="10" value={parallel}
                        onChange={e => setParallel(parseInt(e.target.value))}
                        className="w-full" style={{ accentColor: "var(--accent-red)" }} />
                    </div>
                    <div>
                      <label className="text-xs block mb-1">Timeout (s): {timeout}</label>
                      <input type="range" min="60" max="7200" step="60" value={timeout}
                        onChange={e => setTimeout(parseInt(e.target.value))}
                        className="w-full" style={{ accentColor: "var(--accent-red)" }} />
                    </div>
                  </div>
                  <label className="flex items-center gap-2 text-xs mt-2 cursor-pointer">
                    <input type="checkbox" checked={insecure} onChange={e => setInsecure(e.target.checked)}
                      style={{ accentColor: "var(--accent-red)" }} />
                    <span>Insecure SSL (-k)</span>
                  </label>
                </details>

                {error && (
                  <div className="rounded p-3 text-sm"
                    style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", color: "var(--accent-red)" }}>
                    ⚠ {error}
                  </div>
                )}

                <button onClick={startScan} disabled={loading}
                  className="w-full py-4 rounded-lg text-lg font-bold"
                  style={{
                    background: loading ? "var(--bg-tertiary)" : "var(--accent-red)",
                    color: "white",
                    cursor: loading ? "wait" : "pointer",
                    border: "2px solid var(--border-color)",
                  }}>
                  {loading ? "[ Starting... ]" : `[ 🦅 ${isRtl ? "بدء الفحص" : "START FRAMEWORK SCAN"} ]`}
                </button>
              </div>
            )}

            {/* SCAN RUNNING / DONE */}
            {scanId && (
              <div className="space-y-4">
                {/* Status bar */}
                <div className="rounded-2xl p-4 flex items-center justify-between flex-wrap gap-2"
                  style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>
                  <div>
                    <div className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>
                      scan_id: <span style={{ color: "var(--text-primary)" }}>{scanId}</span>
                    </div>
                    <div className="text-xs mt-1">
                      {isRtl ? "الحالة" : "Status"}:{" "}
                      <span style={{
                        color: isRunning ? "var(--accent-yellow)" :
                               isDone ? "var(--accent-green)" :
                               isError ? "var(--accent-red)" : "var(--text-secondary)",
                        fontWeight: "bold",
                      }}>
                        {scanStatus?.status || "..."}
                      </span>
                      {scanStatus?.exit_code !== null && scanStatus?.exit_code !== undefined && (
                        <span className="ms-2" style={{ color: "var(--text-muted)" }}>
                          exit={scanStatus.exit_code}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {isRunning && (
                      <button onClick={cancelScan}
                        className="px-4 py-2 rounded text-sm font-bold"
                        style={{ background: "var(--accent-red)", color: "white", cursor: "pointer" }}>
                        ⛔ Cancel
                      </button>
                    )}
                    <button onClick={() => { setScanId(null); setScanStatus(null); setLogs([]) }}
                      className="px-4 py-2 rounded text-sm font-bold"
                      style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                      ↺ New Scan
                    </button>
                  </div>
                </div>

                {/* Result (if done) */}
                {isDone && scanStatus?.result && (
                  <div className="rounded-2xl p-4"
                    style={{ background: "var(--bg-secondary)", border: "2px solid var(--accent-green)" }}>
                    <h3 className="text-sm font-bold mb-3" style={{ color: "var(--accent-green)" }}>
                      ✓ {isRtl ? "النتائج" : "Results"}
                    </h3>
                    <pre className="text-xs overflow-auto max-h-96 p-3 rounded"
                      style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", direction: "ltr", textAlign: "left" }}>
                      {JSON.stringify(scanStatus.result, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Error (if failed) */}
                {isError && (
                  <div className="rounded-2xl p-4"
                    style={{ background: "rgba(239,68,68,0.1)", border: "2px solid var(--accent-red)" }}>
                    <h3 className="text-sm font-bold mb-2" style={{ color: "var(--accent-red)" }}>
                      ✗ {isRtl ? "خطأ" : "Error"}
                    </h3>
                    <div className="text-xs font-mono" style={{ color: "var(--text-primary)", whiteSpace: "pre-wrap" }}>
                      {scanStatus.error}
                    </div>
                  </div>
                )}

                {/* Live log */}
                <div className="rounded-2xl p-4"
                  style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>
                  <h3 className="text-sm font-bold mb-3" style={{ color: "var(--accent-yellow)" }}>
                    📡 {isRtl ? "السجل المباشر" : "Live Log"} ({logs.length})
                  </h3>
                  <pre className="text-[11px] font-mono overflow-auto max-h-96 p-3 rounded leading-tight"
                    style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", direction: "ltr", textAlign: "left" }}>
                    {logs.length === 0 ? "..." : logs.join("\n")}
                  </pre>
                </div>
              </div>
            )}

          </div>
        </main>
      </div>
    </div>
  )
}