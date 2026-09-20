/**
 * TopHeader v2 — Theme-aware, with user menu + logout.
 */
import { useState, useEffect } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import { useTheme, THEMES } from "../context/ThemeContext"
import { Icon } from "./Icons"

export default function TopHeader() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const { theme, setTheme } = useTheme()
  const [search, setSearch] = useState("")
  const [notifCount, setNotifCount] = useState(0)
  const [themeOpen, setThemeOpen] = useState(false)
  const [userOpen, setUserOpen] = useState(false)
  const [username, setUsername] = useState("")
  const [aiStatus, setAiStatus] = useState(null)
  const [quickOpen, setQuickOpen] = useState(false)
  const [totpOpen, setTotpOpen] = useState(false)
  const [totpSecret, setTotpSecret] = useState("")
  const [totpCode, setTotpCode] = useState("")

  const isRtl = i18n.language === "ar"

  // Load username from localStorage
  useEffect(() => {
    try {
      const u = JSON.parse(localStorage.getItem("user") || "{}")
      setUsername(u.username || u.email || "User")
    } catch {
      setUsername("User")
    }
  }, [])

  // Debounced search
  useEffect(() => {
    if (!search.trim()) return
    const timer = setTimeout(() => {
      console.log("search:", search)
    }, 300)
    return () => clearTimeout(timer)
  }, [search])

  // Notifications polling
  useEffect(() => {
    let active = true
    const fetch_ = async () => {
      try {
        const r = await fetch("http://localhost:8888/api/health")
        if (active && r.ok) setNotifCount(0)
      } catch { /* silent */ }
    }
    fetch_()
    const id = setInterval(fetch_, 30000)
    return () => { active = false; clearInterval(id) }
  }, [])

  // AI Status polling
  useEffect(() => {
    let active = true
    const fetchAI = async () => {
      try {
        const token = localStorage.getItem("token") || ""
        const r = await fetch("http://localhost:8888/api/ai/config", {
          headers: token ? { Authorization: "Bearer " + token } : {},
        })
        if (active && r.ok) {
          const data = await r.json()
          setAiStatus(data)
        }
      } catch { /* silent */ }
    }
    fetchAI()
    const id = setInterval(fetchAI, 60000)
    return () => { active = false; clearInterval(id) }
  }, [])

  // Keyboard shortcuts (Ctrl+K, Escape)
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault()
        const searchInput = document.querySelector("input[data-search-input]")
        if (searchInput) searchInput.focus()
      }
      if (e.key === "Escape") {
        setQuickOpen(false)
        setTotpOpen(false)
        setThemeOpen(false)
        setUserOpen(false)
      }
    }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [])

  // TOTP: generate code from secret
  const generateTotp = async () => {
    if (!totpSecret.trim()) { setTotpCode(""); return }
    // Fake TOTP for UI demo - real impl would call backend
    try {
      const token = localStorage.getItem("token") || ""
      const r = await fetch("http://localhost:8888/api/v2/auth/totp", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: "Bearer " + token } : {}),
        },
        body: JSON.stringify({ secret: totpSecret }),
      })
      if (r.ok) {
        const data = await r.json()
        setTotpCode(data.code || "")
      } else {
        setTotpCode("")
      }
    } catch {
      setTotpCode("")
    }
  }

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handler = () => { setThemeOpen(false); setUserOpen(false); setQuickOpen(false); setTotpOpen(false) }
    if (themeOpen || userOpen) {
      document.addEventListener("click", handler)
      return () => document.removeEventListener("click", handler)
    }
  }, [themeOpen, userOpen])

  const toggleLang = () => {
    const next = isRtl ? "en" : "ar"
    i18n.changeLanguage(next)
    localStorage.setItem("lang", next)
    document.documentElement.dir = next === "ar" ? "rtl" : "ltr"
  }

  const handleLogout = () => {
    localStorage.removeItem("token")
    localStorage.removeItem("user")
    navigate("/v1/login")
    window.location.reload()
  }

  return (
    <header
      className="sticky top-0 z-30 h-14 px-4 flex items-center gap-3 border-b transition-colors"
      style={{
        background: "var(--bg-primary)",
        borderColor: "var(--border-color)",
      }}
    >
      {/* === AI Status Badge === */}
      <button
        onClick={() => navigate("/v2/ai-settings")}
        className="hidden md:flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-bold transition-all hover-lift"
        style={{
          background: aiStatus?.active_provider
            ? "var(--accent-purple-soft)"
            : "var(--accent-red-soft)",
          border: "1px solid " + (aiStatus?.active_provider
            ? "var(--accent-purple)"
            : "var(--accent-red)"),
          color: aiStatus?.active_provider
            ? "var(--accent-purple)"
            : "var(--accent-red)",
        }}
        title={
          aiStatus?.active_provider
            ? "AI: " + (aiStatus.active_provider.name || "active")
            : "AI not configured — click to setup"
        }
      >
        <span
          className={"w-1.5 h-1.5 rounded-full " + (aiStatus?.active_provider ? "" : "anim-pulse")}
          style={{
            background: aiStatus?.active_provider
              ? "var(--accent-green)"
              : "var(--accent-red)",
          }}
        />
        <Icon name="sparkles" size={14} />
        <span className="hidden lg:inline">
          {aiStatus?.active_provider
            ? (aiStatus.active_provider.name || "AI").toUpperCase()
            : "AI OFF"}
        </span>
      </button>

      {/* === AI Chat === */}
      <button
        onClick={() => navigate("/v2/chat")}
        className="p-2 rounded-md transition-all hover-lift"
        style={{ color: "var(--accent-purple)", cursor: "pointer" }}
        title="AI Assistant"
      >
        <Icon name="sparkles" size={18} />
      </button>

      {/* === Search === */}
      <div className="flex-1 max-w-xl">
        <div className="relative">
          <span
            className={`absolute top-1/2 -translate-y-1/2 ${isRtl ? "right-3" : "left-3"}`}
            style={{ color: "var(--text-muted)" }}
          >
            🔍
          </span>
          <input
            type="text"
            data-search-input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={t("header.searchPlaceholder")}
            className={`w-full rounded-md py-2 text-sm focus:outline-none transition-colors ${isRtl ? "pr-10 pl-4" : "pl-10 pr-4"}`}
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-color)",
              color: "var(--text-primary)",
            }}
          />
        </div>
      </div>

      {/* === Notifications === */}
      <button
        className="relative p-2 rounded-md transition-colors"
        style={{ color: "var(--text-secondary)" }}
        title={t("header.notifications")}
      >
        🔔
        {notifCount > 0 && (
          <span className="absolute top-1 end-1 w-4 h-4 bg-red-600 text-white text-[10px] rounded-full flex items-center justify-center font-bold">
            {notifCount}
          </span>
        )}
      </button>

      {/* === TOTP Widget === */}
      <div className="relative" onClick={e => e.stopPropagation()}>
        <button
          onClick={() => { setTotpOpen(!totpOpen); setQuickOpen(false); setThemeOpen(false); setUserOpen(false) }}
          className="p-2 rounded-md transition-colors"
          style={{ color: "var(--text-secondary)" }}
          title="TOTP Generator"
        >
          <Icon name="key" size={18} />
        </button>

        {totpOpen && (
          <div
            className={`absolute top-full mt-2 z-50 rounded-md shadow-lg p-4 min-w-[280px] anim-scale-in ${isRtl ? "left-0" : "right-0"}`}
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-color)",
            }}
          >
            <div className="text-xs font-bold mb-3" style={{ color: "var(--accent-cyan)" }}>
              TOTP Generator
            </div>
            <input
              type="text"
              value={totpSecret}
              onChange={e => setTotpSecret(e.target.value)}
              placeholder="Enter base32 secret"
              className="w-full px-3 py-2 rounded text-xs font-mono mb-2"
              style={{
                background: "var(--bg-tertiary)",
                border: "1px solid var(--border-color)",
                color: "var(--text-primary)",
              }}
            />
            <button
              onClick={generateTotp}
              className="w-full py-2 rounded text-xs font-bold mb-3"
              style={{
                background: "var(--accent-red)",
                color: "white",
                cursor: "pointer",
              }}
            >
              Generate
            </button>
            {totpCode && (
              <div
                className="text-center text-2xl font-mono font-bold py-3 rounded"
                style={{
                  background: "var(--accent-green-soft)",
                  color: "var(--accent-green)",
                  border: "1px solid var(--accent-green)",
                }}
              >
                {totpCode}
              </div>
            )}
          </div>
        )}
      </div>

      {/* === Theme Switcher === */}
      <div className="relative" onClick={e => e.stopPropagation()}>
        <button
          onClick={() => { setThemeOpen(!themeOpen); setUserOpen(false) }}
          className="px-3 py-1.5 rounded-md text-xs font-bold transition-colors"
          style={{
            background: "var(--bg-secondary)",
            color: "var(--text-primary)",
            border: "1px solid var(--border-color)",
          }}
          title={t("theme.switch")}
        >
          {THEMES.find(x => x.id === theme)?.icon} {isRtl ? "المظهر" : "Theme"}
        </button>

        {themeOpen && (
          <div
            className={`absolute top-full mt-2 z-50 rounded-md shadow-lg py-1 min-w-[140px] ${isRtl ? "left-0" : "right-0"}`}
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-color)",
            }}
          >
            {THEMES.map(tm => (
              <button
                key={tm.id}
                onClick={() => { setTheme(tm.id); setThemeOpen(false) }}
                className="w-full text-start px-3 py-2 text-sm transition-colors"
                style={{
                  color: theme === tm.id ? "var(--accent-red)" : "var(--text-secondary)",
                  fontWeight: theme === tm.id ? "bold" : "normal",
                }}
              >
                {tm.icon} {isRtl ? tm.label : tm.labelEn}
                {theme === tm.id && " ✓"}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* === Language Toggle === */}
      <button
        onClick={toggleLang}
        className="px-3 py-1.5 rounded-md bg-purple-600 hover:bg-purple-700 text-white text-xs font-bold transition-colors"
      >
        {isRtl ? "EN" : "AR"}
      </button>

      {/* === Quick Actions === */}
      <div className="relative" onClick={e => e.stopPropagation()}>
        <button
          onClick={() => { setQuickOpen(!quickOpen); setTotpOpen(false); setThemeOpen(false); setUserOpen(false) }}
          className="p-2 rounded-md transition-colors"
          style={{ color: "var(--text-secondary)" }}
          title="Quick actions"
        >
          <Icon name="sparkles" size={18} />
        </button>

        {quickOpen && (
          <div
            className={`absolute top-full mt-2 z-50 rounded-md shadow-lg py-1 min-w-[200px] anim-scale-in ${isRtl ? "left-0" : "right-0"}`}
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-color)",
            }}
          >
            <button
              onClick={() => { navigate("/v2/framework-scan"); setQuickOpen(false) }}
              className="w-full text-start px-3 py-2 text-xs flex items-center gap-2"
              style={{ color: "var(--text-primary)" }}
            >
              <Icon name="target" size={14} />
              Framework Scan
            </button>
            <button
              onClick={() => { navigate("/v2/findings"); setQuickOpen(false) }}
              className="w-full text-start px-3 py-2 text-xs flex items-center gap-2"
              style={{ color: "var(--text-primary)" }}
            >
              <Icon name="findings" size={14} />
              Findings
            </button>
            <button
              onClick={() => { navigate("/v2/reports"); setQuickOpen(false) }}
              className="w-full text-start px-3 py-2 text-xs flex items-center gap-2"
              style={{ color: "var(--text-primary)" }}
            >
              <Icon name="reports" size={14} />
              Reports
            </button>
            <button
              onClick={() => { navigate("/v2/profiles"); setQuickOpen(false) }}
              className="w-full text-start px-3 py-2 text-xs flex items-center gap-2"
              style={{ color: "var(--text-primary)" }}
            >
              <Icon name="profiles" size={14} />
              Profiles
            </button>
          </div>
        )}
      </div>

      {/* === New Scan === */}
      <button
        onClick={() => navigate("/v2/new-scan")}
        className="px-4 py-2 rounded-md bg-red-600 hover:bg-red-700 text-white text-sm font-semibold transition-all"
      >
        + {t("header.newScan")}
      </button>

      {/* === User Menu + Logout === */}
      <div className="relative" onClick={e => e.stopPropagation()}>
        <button
          onClick={() => { setUserOpen(!userOpen); setThemeOpen(false) }}
          className="flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors"
          style={{
            background: "var(--bg-secondary)",
            color: "var(--text-primary)",
            border: "1px solid var(--border-color)",
          }}
          title={username}
        >
          <span className="w-6 h-6 rounded-full bg-purple-600 flex items-center justify-center text-white text-xs font-bold">
            {username.charAt(0).toUpperCase()}
          </span>
          <span className="text-xs font-semibold hidden md:inline max-w-[100px] truncate">
            {username}
          </span>
        </button>

        {userOpen && (
          <div
            className={`absolute top-full mt-2 z-50 rounded-md shadow-lg py-1 min-w-[180px] ${isRtl ? "left-0" : "right-0"}`}
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-color)",
            }}
          >
            <div
              className="px-3 py-2 text-xs"
              style={{
                color: "var(--text-muted)",
                borderBottom: "1px solid var(--border-color)",
              }}
            >
              {isRtl ? "مسجل الدخول كـ" : "Signed in as"}
              <div style={{ color: "var(--text-primary)", fontWeight: "bold", marginTop: 2 }}>
                {username}
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="w-full text-start px-3 py-2 text-sm transition-colors"
              style={{ color: "var(--accent-red)" }}
              onMouseEnter={e => e.currentTarget.style.background = "rgba(239, 68, 68, 0.1)"}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}
            >
              🚪 {isRtl ? "تسجيل خروج" : "Logout"}
            </button>
          </div>
        )}
      </div>
    </header>
  )
}
