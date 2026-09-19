/**
 * LoginV2 — Two modes:
 *   1. Playwright (auto) — Basic/OAuth/SAML/Nafath + floating VNC widget
 *   2. Manual — paste cookies / bearer / headers / basic auth directly
 *
 * UPDATED 2026-09-18: added MANUAL credentials tab.
 */
import { useState, useEffect, useRef } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import { authV2Api } from "../../api/clientV2"
import client from "../../api/client"

const AUTH_TYPE_ICONS = {
  auto:   "🔍",
  basic:  "🔑",
  oauth:  "🌐",
  saml:   "🏢",
  nafath: "🇸🇦",
}

const INTERACTIVE_TYPES = ["nafath", "oauth", "saml"]
const VNC_URL = "http://localhost:6080/vnc.html?autoconnect=true&resize=scale&view_only=0"

function normalizeUrl(raw) {
  let url = (raw || "").trim()
  if (!url) return ""
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url
  }
  return url
}

// ============================================================
// Floating VNC Widget
// ============================================================
function VncWidget({ onClose, initialExpanded = false }) {
  const [expanded, setExpanded] = useState(initialExpanded)
  const [pos, setPos] = useState({ x: window.innerWidth - 460, y: window.innerHeight - 400 })
  const [size, setSize] = useState({ w: 440, h: 320 })
  const [dragging, setDragging] = useState(false)
  const dragRef = useRef({ startX: 0, startY: 0, origX: 0, origY: 0 })

  const onMouseDown = (e) => {
    setDragging(true)
    dragRef.current = { startX: e.clientX, startY: e.clientY, origX: pos.x, origY: pos.y }
    e.preventDefault()
  }

  useEffect(() => {
    if (!dragging) return
    const onMove = (e) => {
      const dx = e.clientX - dragRef.current.startX
      const dy = e.clientY - dragRef.current.startY
      setPos({
        x: Math.max(0, Math.min(window.innerWidth - size.w, dragRef.current.origX + dx)),
        y: Math.max(0, Math.min(window.innerHeight - size.h, dragRef.current.origY + dy)),
      })
    }
    const onUp = () => setDragging(false)
    document.addEventListener("mousemove", onMove)
    document.addEventListener("mouseup", onUp)
    return () => {
      document.removeEventListener("mousemove", onMove)
      document.removeEventListener("mouseup", onUp)
    }
  }, [dragging, size])

  if (expanded) {
    return (
      <div className="fixed inset-0 z-[10000] flex flex-col" style={{ background: "rgba(0,0,0,0.9)" }}>
        <div className="flex items-center justify-between px-4 py-2"
          style={{ background: "var(--bg-secondary)", borderBottom: "2px solid var(--accent-cyan)" }}>
          <div className="text-sm font-bold" style={{ color: "var(--accent-cyan)" }}>🖥️ VNC — Docker Chromium</div>
          <div className="flex gap-2">
            <button onClick={() => setExpanded(false)} className="px-3 py-1 rounded text-xs font-bold"
              style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", cursor: "pointer" }}>🗗 Minimize</button>
            <button onClick={onClose} className="px-3 py-1 rounded text-xs font-bold"
              style={{ background: "var(--accent-red)", color: "white", cursor: "pointer" }}>✕ Close</button>
          </div>
        </div>
        <iframe src={VNC_URL} title="VNC" className="flex-1 w-full"
          style={{ border: "none", background: "#000" }} allow="clipboard-read; clipboard-write" />
      </div>
    )
  }

  return (
    <div className="fixed z-[9999] rounded-lg overflow-hidden shadow-2xl"
      style={{
        left: pos.x, top: pos.y, width: size.w, height: size.h,
        background: "var(--bg-secondary)", border: "2px solid var(--accent-cyan)",
        boxShadow: "0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(6,182,212,0.4)",
      }}>
      <div onMouseDown={onMouseDown} className="flex items-center justify-between px-3 py-1.5 select-none"
        style={{ background: "rgba(6,182,212,0.2)", borderBottom: "1px solid var(--accent-cyan)", cursor: dragging ? "grabbing" : "grab" }}>
        <div className="text-xs font-bold" style={{ color: "var(--accent-cyan)" }}>🖥️ VNC</div>
        <div className="flex gap-1">
          <button onClick={() => setExpanded(true)} className="px-2 py-0.5 rounded text-[10px] font-bold"
            style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", cursor: "pointer" }}>⛶</button>
          <button onClick={onClose} className="px-2 py-0.5 rounded text-[10px] font-bold"
            style={{ background: "var(--accent-red)", color: "white", cursor: "pointer" }}>✕</button>
        </div>
      </div>
      <iframe src={VNC_URL} title="VNC" className="w-full"
        style={{ height: "calc(100% - 30px)", border: "none", background: "#000" }} allow="clipboard-read; clipboard-write" />
      <div
        onMouseDown={(e) => {
          e.stopPropagation()
          const sx = e.clientX, sy = e.clientY, sw = size.w, sh = size.h
          const onMove = (ev) => setSize({
            w: Math.max(300, sw + (ev.clientX - sx)),
            h: Math.max(200, sh + (ev.clientY - sy)),
          })
          const onUp = () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp) }
          document.addEventListener("mousemove", onMove)
          document.addEventListener("mouseup", onUp)
        }}
        className="absolute bottom-0 right-0 w-4 h-4"
        style={{ cursor: "nwse-resize", background: "var(--accent-cyan)", opacity: 0.6 }} />
    </div>
  )
}

// ============================================================
// Main
// ============================================================
export default function LoginV2() {
  const { i18n } = useTranslation()
  const isRtl = i18n.language === "ar"
  const navigate = useNavigate()

  const [mode, setMode] = useState("playwright")  // playwright | manual

  return (
    <div className="flex min-h-screen transition-colors"
      style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <TacticalSidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />

        <main className="flex-1 p-6">
          <div className="max-w-4xl mx-auto space-y-5">

            <div>
              <h1 className="text-3xl font-bold mb-1" style={{ color: "var(--accent-red)" }}>
                🔐 Authentication
              </h1>
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                {isRtl
                  ? "اختر طريقة المصادقة: Playwright التلقائي أو الإدخال اليدوي"
                  : "Choose auth method: automatic Playwright OR manual entry"}
              </p>
            </div>

            {/* Mode tabs */}
            <div className="flex gap-2">
              <button onClick={() => setMode("playwright")}
                className="flex-1 py-3 rounded-lg text-sm font-bold"
                style={{
                  background: mode === "playwright" ? "var(--accent-red)" : "var(--bg-secondary)",
                  color: mode === "playwright" ? "white" : "var(--text-secondary)",
                  border: "2px solid var(--border-color)",
                }}>
                🤖 {isRtl ? "Playwright (تلقائي)" : "Playwright (auto)"}
              </button>
              <button onClick={() => setMode("manual")}
                className="flex-1 py-3 rounded-lg text-sm font-bold"
                style={{
                  background: mode === "manual" ? "var(--accent-red)" : "var(--bg-secondary)",
                  color: mode === "manual" ? "white" : "var(--text-secondary)",
                  border: "2px solid var(--border-color)",
                }}>
                ✍️ {isRtl ? "إدخال يدوي (Cookies/Token)" : "Manual (Cookies/Token)"}
              </button>
            </div>

            {mode === "playwright" && <PlaywrightMode navigate={navigate} isRtl={isRtl} />}
            {mode === "manual" && <ManualMode navigate={navigate} isRtl={isRtl} />}

          </div>
        </main>
      </div>
    </div>
  )
}

// ============================================================
// MANUAL MODE — paste cookies / headers / tokens directly
// ============================================================
function ManualMode({ navigate, isRtl }) {
  const [profileName, setProfileName] = useState("manual_profile")
  const [targetUrl, setTargetUrl] = useState("")
  const [cookies, setCookies] = useState("")
  const [bearer, setBearer] = useState("")
  const [basicUser, setBasicUser] = useState("")
  const [basicPass, setBasicPass] = useState("")
  const [headersJson, setHeadersJson] = useState("")
  const [userAgent, setUserAgent] = useState("")
  const [referer, setReferer] = useState("")
  const [csrfToken, setCsrfToken] = useState("")

  const [saving, setSaving] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")

  const save = async () => {
    setError(""); setSuccess("")
    if (!profileName.trim()) { setError(isRtl ? "اسم profile مطلوب" : "Profile name required"); return }
    if (!cookies.trim() && !bearer.trim() && !(basicUser && basicPass) && !headersJson.trim()) {
      setError(isRtl
        ? "أدخل على الأقل: Cookies أو Bearer أو Basic Auth أو Headers"
        : "Provide at least one: Cookies, Bearer, Basic Auth, or Headers")
      return
    }

    // Validate headers JSON if provided
    let headersObj = {}
    if (headersJson.trim()) {
      try {
        headersObj = JSON.parse(headersJson)
      } catch (e) {
        setError((isRtl ? "JSON غير صالح: " : "Invalid JSON: ") + e.message)
        return
      }
    }

    setSaving(true)
    try {
      // Save via clientV2-compatible endpoint.
      // We reuse /api/v2/auth/login with a special "auth_type=manual"
      // OR just call a dedicated endpoint. For now, we POST to a simple
      // endpoint that writes the profile JSON directly.
      const payload = {
        profile: profileName.trim(),
        target_url: targetUrl.trim(),
        cookies: cookies.trim(),
        bearer_token: bearer.trim(),
        basic_auth: (basicUser && basicPass) ? { username: basicUser, password: basicPass } : null,
        headers: headersObj,
        user_agent: userAgent.trim(),
        referer: referer.trim(),
        csrf_token: csrfToken.trim(),
      }

      const res = await client.post("/api/v2/auth/manual", payload)
      setSuccess((isRtl ? "تم الحفظ: " : "Saved: ") + (res.data.path || profileName))
      setTimeout(() => navigate("/v2/profiles"), 1200)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setSaving(false)
    }
  }

  const fillExample = () => {
    setProfileName("github_manual")
    setTargetUrl("https://github.com")
    setCookies("user_session=abc123; logged_in=yes; _gh_sess=xyz789")
    setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
    setHeadersJson('{\n  "X-Requested-With": "XMLHttpRequest",\n  "Accept-Language": "ar,en"\n}')
  }

  return (
    <div className="space-y-4">
      <div className="rounded-2xl p-4 text-xs"
        style={{ background: "rgba(6,182,212,0.1)", border: "1px solid var(--accent-cyan)", color: "var(--text-secondary)" }}>
        💡 {isRtl
          ? "سجّل دخولك من متصفحك، انسخ الـ Cookies من DevTools (F12 → Application → Cookies)، الصقها هنا، واحفظ. سيُستخدم profile في Framework Scan."
          : "Log in from your browser, copy Cookies from DevTools (F12 → Application → Cookies), paste here, save. The profile will be used in Framework Scan."}
      </div>

      <div className="rounded-2xl p-6 space-y-4"
        style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>

        {/* Profile name */}
        <div>
          <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
            &lt; {isRtl ? "اسم Profile" : "Profile name"} <span style={{ color: "var(--accent-red)" }}>*</span>
          </label>
          <input type="text" value={profileName} onChange={e => setProfileName(e.target.value)}
            className="w-full px-4 py-2 rounded-lg font-mono text-sm"
            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
        </div>

        {/* Target URL (optional) */}
        <div>
          <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
            &lt; {isRtl ? "رابط الموقع (اختياري)" : "Target URL (optional)"}
          </label>
          <input type="text" value={targetUrl} onChange={e => setTargetUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-4 py-2 rounded-lg font-mono text-sm"
            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
        </div>

        {/* Cookies */}
        <div>
          <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
            🍪 Cookies <span style={{ color: "var(--text-muted)" }}>(name=value; name2=value2)</span>
          </label>
          <textarea value={cookies} onChange={e => setCookies(e.target.value)}
            placeholder={"sessionid=abc123; csrftoken=xyz789; logged_in=yes"}
            rows={4}
            className="w-full px-4 py-2 rounded-lg font-mono text-xs"
            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
          <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
            {isRtl ? "انسخ من DevTools → Application → Cookies → header value" : "Copy from DevTools → Application → Cookies → header value"}
          </p>
        </div>

        {/* Bearer Token */}
        <div>
          <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
            🔑 Bearer Token <span style={{ color: "var(--text-muted)" }}>(JWT / OAuth access token)</span>
          </label>
          <textarea value={bearer} onChange={e => setBearer(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            rows={3}
            className="w-full px-4 py-2 rounded-lg font-mono text-xs"
            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
        </div>

        {/* HTTP Basic Auth */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
              👤 {isRtl ? "Basic Auth: Username" : "Basic Auth: Username"}
            </label>
            <input type="text" value={basicUser} onChange={e => setBasicUser(e.target.value)}
              className="w-full px-4 py-2 rounded-lg font-mono text-sm"
              style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
          </div>
          <div>
            <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
              🔒 {isRtl ? "Basic Auth: Password" : "Basic Auth: Password"}
            </label>
            <input type="password" value={basicPass} onChange={e => setBasicPass(e.target.value)}
              className="w-full px-4 py-2 rounded-lg font-mono text-sm"
              style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
          </div>
        </div>

        {/* Custom Headers (JSON) */}
        <div>
          <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
            📋 Custom Headers <span style={{ color: "var(--text-muted)" }}>(JSON)</span>
          </label>
          <textarea value={headersJson} onChange={e => setHeadersJson(e.target.value)}
            placeholder={'{\n  "X-API-Key": "abc123",\n  "X-CSRF-Token": "xyz"\n}'}
            rows={5}
            className="w-full px-4 py-2 rounded-lg font-mono text-xs"
            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
        </div>

        {/* Additional useful fields */}
        <details className="rounded-lg p-3"
          style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)" }}>
          <summary className="cursor-pointer text-xs font-bold" style={{ color: "var(--accent-yellow)" }}>
            ⚙️ {isRtl ? "حقول إضافية (User-Agent, Referer, CSRF)" : "Additional (User-Agent, Referer, CSRF)"}
          </summary>
          <div className="space-y-3 mt-3">
            <div>
              <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>User-Agent</label>
              <input type="text" value={userAgent} onChange={e => setUserAgent(e.target.value)}
                placeholder="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
                className="w-full px-3 py-2 rounded text-xs font-mono"
                style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>Referer</label>
              <input type="text" value={referer} onChange={e => setReferer(e.target.value)}
                placeholder="https://example.com/dashboard"
                className="w-full px-3 py-2 rounded text-xs font-mono"
                style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>X-CSRF-Token</label>
              <input type="text" value={csrfToken} onChange={e => setCsrfToken(e.target.value)}
                placeholder="abc123..."
                className="w-full px-3 py-2 rounded text-xs font-mono"
                style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
            </div>
          </div>
        </details>

        {error && (
          <div className="rounded p-3 text-sm"
            style={{
              background: "rgba(239,68,68,0.1)",
              border: "1px solid rgba(239,68,68,0.3)",
              color: "var(--accent-red)",
              whiteSpace: "pre-wrap",
              fontFamily: "ui-monospace, monospace",
              fontSize: "12px",
            }}>
            {error}
          </div>
        )}

        {success && (
          <div className="rounded p-3 text-sm"
            style={{ background: "rgba(16,185,129,0.1)", border: "1px solid var(--accent-green)", color: "var(--accent-green)", whiteSpace: "pre-wrap" }}>
            ✓ {success}
          </div>
        )}

        <div className="flex gap-2">
          <button onClick={fillExample}
            className="px-4 py-2 rounded text-xs font-bold"
            style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-color)" }}>
            📋 {isRtl ? "مثال" : "Example"}
          </button>
          <button onClick={save} disabled={saving}
            className="flex-1 py-3 rounded-lg text-base font-bold"
            style={{
              background: saving ? "var(--bg-tertiary)" : "var(--accent-red)",
              color: "white",
              cursor: saving ? "wait" : "pointer",
              border: "2px solid var(--border-color)",
            }}>
            {saving ? "[ Saving... ]" : `[ 💾 ${isRtl ? "حفظ Profile" : "Save Profile"} ]`}
          </button>
        </div>
      </div>
    </div>
  )
}

// ============================================================
// PLAYWRIGHT MODE (existing) — kept as-is
// ============================================================
function PlaywrightMode({ navigate, isRtl }) {
  const [types, setTypes] = useState([])
  const [url, setUrl] = useState("")
  const [authType, setAuthType] = useState("auto")
  const [profile, setProfile] = useState("default")
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [totpSecret, setTotpSecret] = useState("")
  const [buttonSelector, setButtonSelector] = useState("")
  const [wait, setWait] = useState(240)

  const [loginId, setLoginId] = useState(null)
  const [status, setStatus] = useState(null)
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [showVnc, setShowVnc] = useState(false)

  const pollRef = useRef(null)

  useEffect(() => {
    authV2Api.types()
      .then(res => setTypes(res.data.auth_types || []))
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!loginId) return
    let alive = true
    const poll = async () => {
      try {
        const [st, lg] = await Promise.all([
          authV2Api.loginStatus(loginId),
          authV2Api.loginLog(loginId, 300),
        ])
        if (!alive) return
        setStatus(st.data)
        setLogs(lg.data.lines || [])
        if (st.data.status === "running" || st.data.status === "pending") {
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
  }, [loginId])

  const start = async () => {
    setError("")
    if (!url.trim()) { setError(isRtl ? "الرابط مطلوب" : "URL required"); return }
    const normalizedUrl = normalizeUrl(url)
    if (normalizedUrl !== url) setUrl(normalizedUrl)
    setLoading(true)
    setStatus(null); setLogs([])

    const payload = {
      url: normalizedUrl, auth_type: authType, profile, wait, headless: false,
    }
    if (username) payload.username = username
    if (password) payload.password = password
    if (totpSecret) payload.totp_secret = totpSecret
    if (buttonSelector) payload.button_selector = buttonSelector

    try {
      const res = await authV2Api.login(payload)
      setLoginId(res.data.login_id)
      setShowVnc(true)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const isRunning = status?.status === "running" || status?.status === "pending"
  const isDone = status?.status === "done"

  return (
    <div className="space-y-4">
      {!loginId && (
        <div className="rounded-2xl p-6 space-y-4"
          style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>
          <div>
            <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
              &lt; Login URL <span style={{ color: "var(--accent-red)" }}>*</span>
            </label>
            <input type="text" value={url} onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com/login"
              className="w-full px-4 py-2 rounded-lg font-mono text-sm"
              style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
          </div>

          <div>
            <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
              &lt; Auth Type
            </label>
            <div className="grid grid-cols-5 gap-2">
              {(types.length ? types : [
                {name:"auto"},{name:"basic"},{name:"oauth"},{name:"saml"},{name:"nafath"}
              ]).map(tp => (
                <button key={tp.name} onClick={() => { setAuthType(tp.name); setError("") }}
                  className="p-2 rounded text-xs font-bold flex flex-col items-center gap-1"
                  style={{
                    background: authType === tp.name ? "var(--accent-red)" : "var(--bg-tertiary)",
                    color: authType === tp.name ? "white" : "var(--text-secondary)",
                    border: "1px solid var(--border-color)",
                  }}>
                  <span className="text-lg">{AUTH_TYPE_ICONS[tp.name] || "🔐"}</span>
                  <span>{tp.name}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>Profile name</label>
              <input type="text" value={profile} onChange={e => setProfile(e.target.value)}
                className="w-full px-3 py-2 rounded text-sm font-mono"
                style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>Wait (seconds)</label>
              <input type="number" value={wait} onChange={e => setWait(parseInt(e.target.value) || 0)}
                className="w-full px-3 py-2 rounded text-sm font-mono"
                style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
            </div>
          </div>

          {(authType === "basic" || authType === "auto") && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>Username</label>
                <input type="text" value={username} onChange={e => setUsername(e.target.value)}
                  className="w-full px-3 py-2 rounded text-sm"
                  style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>Password</label>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                  className="w-full px-3 py-2 rounded text-sm"
                  style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
              </div>
              <div className="col-span-2">
                <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>TOTP Secret (base32)</label>
                <input type="text" value={totpSecret} onChange={e => setTotpSecret(e.target.value)}
                  placeholder="JBSWY3DPEHPK3PXP"
                  className="w-full px-3 py-2 rounded text-sm font-mono"
                  style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
              </div>
            </div>
          )}

          {INTERACTIVE_TYPES.includes(authType) && (
            <div>
              <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>
                {authType === "nafath" ? "Nafath button selector" : "SSO button selector"} (optional)
              </label>
              <input type="text" value={buttonSelector} onChange={e => setButtonSelector(e.target.value)}
                placeholder="button:has-text('Nafath')"
                className="w-full px-3 py-2 rounded text-sm font-mono"
                style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }} />
            </div>
          )}

          {error && (
            <div className="rounded p-3 text-sm"
              style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", color: "var(--accent-red)", whiteSpace: "pre-wrap", fontFamily: "ui-monospace, monospace", fontSize: "12px" }}>
              {error}
            </div>
          )}

          <button onClick={start} disabled={loading}
            className="w-full py-4 rounded-lg text-lg font-bold"
            style={{ background: loading ? "var(--bg-tertiary)" : "var(--accent-red)", color: "white", cursor: loading ? "wait" : "pointer", border: "2px solid var(--border-color)" }}>
            {loading ? "[ Starting... ]" : `[ 🔐 ${isRtl ? "تسجيل الدخول" : "LOGIN"} ]`}
          </button>
        </div>
      )}

      {loginId && (
        <div className="space-y-4">
          <div className="rounded-2xl p-4"
            style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>
            <div className="text-xs font-mono mb-2" style={{ color: "var(--text-muted)" }}>
              login_id: <span style={{ color: "var(--text-primary)" }}>{loginId}</span>
            </div>
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="text-sm">
                Status: <span style={{
                  color: isRunning ? "var(--accent-yellow)" : isDone ? "var(--accent-green)" : "var(--accent-red)",
                  fontWeight: "bold",
                }}>{status?.status || "..."}</span>
              </div>
              <div className="flex gap-2">
                <button onClick={() => setShowVnc(true)}
                  className="px-3 py-1.5 rounded text-xs font-bold"
                  style={{ background: "var(--accent-cyan)", color: "#000" }}>
                  🖥️ VNC
                </button>
                {isDone && (
                  <button onClick={() => navigate("/v2/profiles")}
                    className="px-3 py-1.5 rounded text-xs font-bold"
                    style={{ background: "var(--accent-green)", color: "white" }}>
                    ✓ Profiles
                  </button>
                )}
                <button onClick={() => { setLoginId(null); setStatus(null); setLogs([]) }}
                  className="px-3 py-1.5 rounded text-xs font-bold"
                  style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)" }}>
                  ↺ Retry
                </button>
              </div>
            </div>
          </div>

          <div className="rounded-2xl p-4"
            style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>
            <h3 className="text-sm font-bold mb-3" style={{ color: "var(--accent-yellow)" }}>
              📡 Live Log ({logs.length})
            </h3>
            <pre className="text-[11px] font-mono overflow-auto max-h-96 p-3 rounded leading-tight"
              style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)" }}>
              {logs.length === 0 ? "..." : logs.join("\n")}
            </pre>
          </div>
        </div>
      )}

      {showVnc && <VncWidget onClose={() => setShowVnc(false)} initialExpanded={false} />}

      <button
        onClick={() => setShowVnc(v => !v)}
        className="fixed bottom-6 right-6 z-[9998] rounded-full shadow-2xl flex items-center justify-center"
        style={{
          width: "60px", height: "60px",
          background: showVnc ? "var(--accent-red)" : "var(--accent-cyan)",
          color: showVnc ? "white" : "#000",
          border: "3px solid rgba(0,0,0,0.3)",
          cursor: "pointer", fontSize: "24px",
        }}>
        {showVnc ? "✕" : "🖥️"}
      </button>
    </div>
  )
}