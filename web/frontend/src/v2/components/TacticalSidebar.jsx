/**
 * TacticalSidebar v2 â€” Theme-aware, with user section.
 */
import { NavLink, useNavigate } from "react-router-dom"
import { useTranslation } from "react-i18next"
import { useEffect, useState } from "react"
import WolfEyes from "./WolfEyes"

const NAV_ITEMS = [
  { to: "/v2/dashboard", icon: "ðŸ“Š", key: "nav.dashboard" },
  { to: "/v2/new-scan",  icon: "ðŸš€", key: "nav.newScan" },
  // ADDED 2026-09-18: Framework CLI
  { to: "/v2/framework-scan", icon: "ðŸ¦…", key: "nav.frameworkScan" },
  { to: "/v2/profiles",       icon: "ðŸ‘¤", key: "nav.profiles" },
  { to: "/v2/login",          icon: "ðŸ”", key: "nav.login" },
  { to: "/v2/ai-settings",    icon: "ðŸ¤–", key: "nav.aiSettings" },
  { to: "/v2/findings",  icon: "ðŸŽ¯", key: "nav.findings" },
  { to: "/v2/reports",   icon: "ðŸ“„", key: "nav.reports" },
   { to: "/v2/live-session", icon: "ðŸ‘ï¸", key: "nav.liveSession" },
  { to: "/v2/monitor",   icon: "ðŸ“¡", key: "nav.liveMonitor" },
]

export default function TacticalSidebar() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const isRtl = i18n.language === "ar"
  const [username, setUsername] = useState("User")

  useEffect(() => {
    try {
      const u = JSON.parse(localStorage.getItem("user") || "{}")
      setUsername(u.username || u.email || "User")
    } catch {
      setUsername("User")
    }
  }, [])

  const handleLogout = () => {
    localStorage.removeItem("token")
    localStorage.removeItem("user")
    navigate("/v1/login")
    window.location.reload()
  }

  return (
    <aside
      className="w-56 shrink-0 flex flex-col h-screen sticky top-0 z-20 border-e transition-colors"
      style={{
        background: "var(--bg-primary)",
        borderColor: "var(--border-color)",
      }}
    >
      {/* Brand */}
      <div
        className="px-4 py-4 flex items-center gap-3 border-b transition-colors"
        style={{ borderColor: "var(--border-color)" }}
      >
        <WolfEyes size={36} />
        <div className="min-w-0">
          <div
            className="text-sm font-bold tracking-wider"
            style={{ color: "var(--accent-red)" }}
          >
            FALCON MAG
          </div>
          <div
            className="text-[10px] tracking-widest"
            style={{ color: "var(--text-muted)" }}
          >
            AUTONOMOUS AI VAPT
          </div>
        </div>
      </div>

      {/* User */}
      <div
        className="px-4 py-3 border-b transition-colors flex items-center gap-2"
        style={{ borderColor: "var(--border-color)" }}
      >
        <span className="w-7 h-7 rounded-full bg-purple-600 flex items-center justify-center text-white text-xs font-bold shrink-0">
          {username.charAt(0).toUpperCase()}
        </span>
        <div className="min-w-0 flex-1">
          <div
            className="text-xs font-semibold truncate"
            style={{ color: "var(--text-primary)" }}
          >
            {username}
          </div>
          <div
            className="text-[10px]"
            style={{ color: "var(--accent-green)" }}
          >
            â— {isRtl ? "Ù…ØªØµÙ„" : "Online"}
          </div>
        </div>
      </div>

      {/* System Health */}
      <div
        className="px-4 py-2 border-b transition-colors"
        style={{ borderColor: "var(--border-color)" }}
      >
        <div className="flex items-center gap-2 text-xs">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span
            className="font-mono"
            style={{ color: "var(--accent-green)" }}
          >
            {t("sidebar.systemSecure")}
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-3 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map(item => (
          <NavLink
            key={item.to}
            to={item.to}
            className="flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all"
            style={({ isActive }) => ({
              background: isActive ? "rgba(127, 29, 29, 0.4)" : "transparent",
              color: isActive ? "var(--accent-red)" : "var(--text-secondary)",
              borderInlineStart: isActive
                ? "2px solid var(--accent-red)"
                : "2px solid transparent",
            })}
          >
            <span className="text-base">{item.icon}</span>
            <span className="font-medium">{t(item.key)}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer: Logout */}
      <div
        className="px-2 py-3 border-t transition-colors space-y-1"
        style={{ borderColor: "var(--border-color)" }}
      >
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors"
          style={{ color: "var(--accent-red)" }}
          onMouseEnter={e => e.currentTarget.style.background = "rgba(239, 68, 68, 0.1)"}
          onMouseLeave={e => e.currentTarget.style.background = "transparent"}
        >
          <span className="text-base">ðŸšª</span>
          <span className="font-medium">{isRtl ? "ØªØ³Ø¬ÙŠÙ„ Ø®Ø±ÙˆØ¬" : "Logout"}</span>
        </button>
        <div
          className="text-[10px] font-mono px-3"
          style={{ color: "var(--text-muted)" }}
        >
          v2.0.0 Â· {new Date().getFullYear()}
        </div>
      </div>
    </aside>
  )
}
