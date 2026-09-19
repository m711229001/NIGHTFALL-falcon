/**
 * TopHeader v2 — Theme-aware, with user menu + logout.
 */
import { useState, useEffect } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import { useTheme, THEMES } from "../context/ThemeContext"

export default function TopHeader() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const { theme, setTheme } = useTheme()
  const [search, setSearch] = useState("")
  const [notifCount, setNotifCount] = useState(0)
  const [themeOpen, setThemeOpen] = useState(false)
  const [userOpen, setUserOpen] = useState(false)
  const [username, setUsername] = useState("")

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

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handler = () => { setThemeOpen(false); setUserOpen(false) }
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
