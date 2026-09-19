/**
 * ProfilesV2 — Manage saved login profiles (framework/profiles/*.json).
 */
import { useState, useEffect } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import { profilesV2Api } from "../../api/clientV2"

export default function ProfilesV2() {
  const { i18n } = useTranslation()
  const isRtl = i18n.language === "ar"
  const navigate = useNavigate()

  const [profiles, setProfiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  const load = () => {
    setLoading(true)
    profilesV2Api.list()
      .then(res => { setProfiles(res.data.profiles || []); setError("") })
      .catch(e => setError(e?.response?.data?.detail || e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const useInScan = (name) => {
    navigate(`/v2/framework-scan?profile=${encodeURIComponent(name)}`)
  }

  return (
    <div className="flex min-h-screen transition-colors"
      style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <TacticalSidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />

        <main className="flex-1 p-6">
          <div className="max-w-5xl mx-auto">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h1 className="text-3xl font-bold mb-1" style={{ color: "var(--accent-red)" }}>
                  👤 Login Profiles
                </h1>
                <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  {isRtl
                    ? "جلسات Playwright المحفوظة (framework/profiles/)"
                    : "Saved Playwright sessions (framework/profiles/)"}
                </p>
              </div>
              <div className="flex gap-2">
                <button onClick={load}
                  className="px-3 py-1.5 rounded text-xs"
                  style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-color)" }}>
                  ↻ Refresh
                </button>
                <button onClick={() => navigate("/v2/login")}
                  className="px-3 py-1.5 rounded text-xs font-bold"
                  style={{ background: "var(--accent-red)", color: "white" }}>
                  + New Login
                </button>
              </div>
            </div>

            {loading && <div className="text-center py-10" style={{ color: "var(--text-muted)" }}>Loading...</div>}
            {error && (
              <div className="rounded p-3 text-sm mb-4"
                style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", color: "var(--accent-red)" }}>
                ⚠ {error}
              </div>
            )}

            {!loading && profiles.length === 0 && (
              <div className="rounded-2xl p-10 text-center"
                style={{ background: "var(--bg-secondary)", border: "2px dashed var(--border-color)" }}>
                <div className="text-4xl mb-3">🔐</div>
                <div className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  {isRtl ? "لا توجد profiles بعد" : "No profiles yet"}
                </div>
                <button onClick={() => navigate("/v2/login")}
                  className="mt-4 px-4 py-2 rounded font-bold"
                  style={{ background: "var(--accent-red)", color: "white" }}>
                  {isRtl ? "إنشاء profile" : "Create Profile"}
                </button>
              </div>
            )}

            {!loading && profiles.length > 0 && (
              <div className="rounded-2xl overflow-hidden"
                style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ borderBottom: "1px solid var(--border-color)", background: "var(--bg-tertiary)" }}>
                      <th className="text-start p-3 font-mono text-xs" style={{ color: "var(--accent-yellow)" }}>Name</th>
                      <th className="text-start p-3 font-mono text-xs" style={{ color: "var(--accent-yellow)" }}>Provider</th>
                      <th className="text-start p-3 font-mono text-xs" style={{ color: "var(--accent-yellow)" }}>URL</th>
                      <th className="text-end p-3 font-mono text-xs" style={{ color: "var(--accent-yellow)" }}>Cookies</th>
                      <th className="text-start p-3 font-mono text-xs" style={{ color: "var(--accent-yellow)" }}>Saved</th>
                      <th className="text-end p-3 font-mono text-xs" style={{ color: "var(--accent-yellow)" }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {profiles.map(p => (
                      <tr key={p.name} style={{ borderBottom: "1px solid var(--border-color)" }}>
                        <td className="p-3 font-bold" style={{ color: "var(--text-primary)" }}>{p.name}</td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded text-xs"
                            style={{ background: "var(--bg-tertiary)", color: "var(--accent-yellow)" }}>
                            {p.provider || "—"}
                          </span>
                        </td>
                        <td className="p-3 text-xs truncate max-w-xs" style={{ color: "var(--text-secondary)" }}>
                          {p.login_url || "—"}
                        </td>
                        <td className="p-3 text-end font-mono" style={{ color: "var(--text-primary)" }}>
                          {p.cookies_count}
                        </td>
                        <td className="p-3 text-xs" style={{ color: "var(--text-muted)" }}>
                          {p.saved_at || "—"}
                        </td>
                        <td className="p-3 text-end">
                          <button onClick={() => useInScan(p.name)}
                            className="px-3 py-1 rounded text-xs font-bold"
                            style={{ background: "var(--accent-red)", color: "white" }}>
                            🦅 Use
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}