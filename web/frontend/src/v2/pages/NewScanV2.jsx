/**
 * NewScanV2 — Advanced Edition (V1 engine)
 *
 * ADDED 2026-09-18: Banner recommending Framework Scan (V2) with 32 modules.
 * This page still uses `/api/scans/start` (nightfall_core.py).
 * For framework/cli.py integration, use /v2/framework-scan.
 */
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import client from "../../api/client"

const TABS = [
  { id: "basic",    icon: "🎯", labelAr: "الأساسي",  labelEn: "Basic" },
  { id: "auth",     icon: "🔐", labelAr: "المصادقة", labelEn: "Auth" },
  { id: "advanced", icon: "⚙️", labelAr: "متقدم",    labelEn: "Advanced" },
]

const AUTH_TABS = [
  { id: "cookie",  icon: "🍪", labelAr: "Cookies",       labelEn: "Cookies" },
  { id: "bearer",  icon: "🔑", labelAr: "Bearer Token",  labelEn: "Bearer" },
  { id: "login",   icon: "🔐", labelAr: "Login Form",    labelEn: "Login" },
]

export default function NewScanV2() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const isRtl = i18n.language === "ar"

  // Main tabs
  const [activeTab, setActiveTab] = useState("basic")
  const [authSubTab, setAuthSubTab] = useState("cookie")

  // Basic
  const [target, setTarget] = useState("")
  const [budget, setBudget] = useState(100)
  const [exploit, setExploit] = useState(false)

  // Auth — Cookies
  const [cookies, setCookies] = useState("")

  // Auth — Bearer
  const [bearerToken, setBearerToken] = useState("")

  // Auth — Login
  const [loginUrl, setLoginUrl] = useState("")
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [smsCode, setSmsCode] = useState("")

  // Advanced
  const [customHeaders, setCustomHeaders] = useState("")
  const [method, setMethod] = useState("GET")
  const [postData, setPostData] = useState("")
  const [postJson, setPostJson] = useState("")
  const [userAgent, setUserAgent] = useState("")
  const [proxy, setProxy] = useState("")
  const [proxyEnabled, setProxyEnabled] = useState(false)

  // UI
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")

  const startScan = async () => {
    if (!target.trim()) {
      setError(isRtl ? "الهدف مطلوب" : "Target URL is required")
      return
    }
    setError("")
    setSuccess("")
    setLoading(true)

    // Parse custom headers
    const headersDict = {}
    if (customHeaders.trim()) {
      customHeaders.split("\n").forEach(line => {
        const idx = line.indexOf(":")
        if (idx > 0) {
          const k = line.slice(0, idx).trim()
          const v = line.slice(idx + 1).trim()
          if (k) headersDict[k] = v
        }
      })
    }

    // Only send auth field matching the selected sub-tab
    const authPayload = {}
    if (authSubTab === "cookie") {
      authPayload.cookies = cookies
    } else if (authSubTab === "bearer") {
      authPayload.bearer_token = bearerToken
    } else if (authSubTab === "login") {
      authPayload.login_url = loginUrl
      authPayload.username = username
      authPayload.password = password
      authPayload.sms_code = smsCode
    }

    try {
      const payload = {
        url: target,
        budget,
        exploit: exploit ? "on" : "off",
        headers: headersDict,
        method: method,
        post_data: postData,
        post_json: postJson,
        user_agent: userAgent,
        proxy: proxyEnabled ? proxy : "",
        ...authPayload,
      }

      const res = await client.post("/api/scans/start", payload)
      console.log("Scan started:", res.data)
      setSuccess(isRtl ? "تم بدء الفحص!" : "Scan started!")
      setTimeout(() => navigate("/v2/monitor"), 1000)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || "Error starting scan")
    } finally {
      setLoading(false)
    }
  }

  const fillExample = () => {
    setTarget("https://es.hrsd.gov.sa/SecureSSL/Login.aspx")
    setCookies("ASP.NET_SessionId=abc123; .AUTH=xyz789")
    setBearerToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    setCustomHeaders("X-API-Key: test123 X-Custom-Header: value")
    setLoginUrl("https://es.hrsd.gov.sa/SecureSSL/Login.aspx")
    setUsername("admin")
    setPassword("admin123")
    setSmsCode("123456")
    setUserAgent("Mozilla/5.0 (Custom) FalconMAG/2.0")
    setProxy("http://127.0.0.1:8080")
  }

  return (
    <div className="flex min-h-screen transition-colors"
      style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <TacticalSidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />

        {/* ADDED 2026-09-18: Banner recommending Framework Scan (V2) */}
        <div className="px-6 pt-6">
          <div className="max-w-5xl mx-auto rounded-lg p-3 flex items-center justify-between flex-wrap gap-2"
            style={{ background: "rgba(234,179,8,0.1)", border: "1px solid var(--accent-yellow)" }}>
            <div className="text-xs" style={{ color: "var(--accent-yellow)" }}>
              {isRtl
                ? "⚠ هذه الصفحة تستخدم محرك V1 (nightfall_core). للحصول على 32 وحدة فحص + Live logs، استخدم Framework Scan."
                : "⚠ This page uses the V1 engine (nightfall_core). For 32 modules + Live logs, use Framework Scan."}
            </div>
            <button
              onClick={() => navigate("/v2/framework-scan")}
              className="px-3 py-1.5 rounded text-xs font-bold whitespace-nowrap"
              style={{ background: "var(--accent-red)", color: "white", cursor: "pointer" }}
            >
              🦅 Framework Scan
            </button>
          </div>
        </div>

        <main className="flex-1 p-6 overflow-x-hidden">
          <div className="max-w-5xl mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
              <div>
                <h1 className="text-3xl font-bold mb-1" style={{ color: "var(--accent-red)" }}>
                  {t("new_scan")}
                </h1>
                <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  {isRtl ? "فحص أمني شامل مع دعم المصادقة (V1 Engine)" : "Comprehensive scan with auth support (V1 Engine)"}
                </p>
              </div>
              <button
                onClick={fillExample}
                className="px-3 py-1.5 rounded text-xs"
                style={{
                  background: "var(--bg-secondary)",
                  color: "var(--text-secondary)",
                  border: "1px solid var(--border-color)",
                }}
              >
                📋 {isRtl ? "مثال" : "Example"}
              </button>
            </div>

            {/* Main Tabs */}
            <div className="flex gap-2 mb-4 flex-wrap">
              {TABS.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className="px-4 py-2 rounded-lg text-sm font-semibold transition-all"
                  style={{
                    background: activeTab === tab.id ? "var(--accent-red)" : "var(--bg-secondary)",
                    color: activeTab === tab.id ? "white" : "var(--text-secondary)",
                    border: "1px solid var(--border-color)",
                  }}
                >
                  {tab.icon} {isRtl ? tab.labelAr : tab.labelEn}
                </button>
              ))}
            </div>

            {/* Form Container */}
            <div className="rounded-2xl p-6 space-y-5"
              style={{ background: "var(--bg-secondary)", border: "2px solid var(--border-color)" }}>

              {/* ===================== TAB: BASIC ===================== */}
              {activeTab === "basic" && (
                <>
                  <Field label={isRtl ? "رابط الهدف" : "Target URL"} required>
                    <input
                      type="text"
                      value={target}
                      onChange={e => setTarget(e.target.value)}
                      placeholder="https://example.com"
                      className="form-input"
                    />
                  </Field>

                  <Field label={`${isRtl ? "الميزانية" : "Budget"}: ${budget}`}>
                    <input
                      type="range" min="10" max="1000" value={budget}
                      onChange={e => setBudget(parseInt(e.target.value))}
                      className="w-full"
                      style={{ accentColor: "var(--accent-red)" }}
                    />
                    <div className="flex justify-between text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                      <span>10</span><span>500</span><span>1000</span>
                    </div>
                  </Field>

                  <Field label={isRtl ? "وضع الاستغلال" : "Exploit Mode"}>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setExploit(false)}
                        className="flex-1 py-2 rounded text-sm font-bold"
                        style={{
                          background: !exploit ? "var(--accent-red)" : "var(--bg-tertiary)",
                          color: !exploit ? "white" : "var(--text-primary)",
                          border: "1px solid var(--border-color)",
                        }}
                      >
                        {t("detect_only")}
                      </button>
                      <button
                        onClick={() => setExploit(true)}
                        className="flex-1 py-2 rounded text-sm font-bold"
                        style={{
                          background: exploit ? "var(--accent-red)" : "var(--bg-tertiary)",
                          color: exploit ? "white" : "var(--text-primary)",
                          border: "1px solid var(--border-color)",
                        }}
                      >
                        {t("detect_confirm")}
                      </button>
                    </div>
                  </Field>
                </>
              )}

              {/* ===================== TAB: AUTH ===================== */}
              {activeTab === "auth" && (
                <>
                  <InfoBox text={isRtl
                    ? "اختر طريقة المصادقة (واحدة فقط):"
                    : "Choose authentication method (only one):"} />

                  {/* Auth Sub-Tabs */}
                  <div className="flex gap-2 flex-wrap">
                    {AUTH_TABS.map(sub => (
                      <button
                        key={sub.id}
                        onClick={() => setAuthSubTab(sub.id)}
                        className="px-4 py-2 rounded-lg text-sm font-semibold transition-all"
                        style={{
                          background: authSubTab === sub.id ? "var(--accent-red)" : "var(--bg-tertiary)",
                          color: authSubTab === sub.id ? "white" : "var(--text-secondary)",
                          border: "1px solid var(--border-color)",
                        }}
                      >
                        {sub.icon} {isRtl ? sub.labelAr : sub.labelEn}
                      </button>
                    ))}
                  </div>

                  <div className="border-t pt-5" style={{ borderColor: "var(--border-color)" }}>

                    {/* --- Cookie Sub-Tab --- */}
                    {authSubTab === "cookie" && (
                      <Field label="🍪 Cookies (يدوي / Manual)">
                        <textarea
                          value={cookies}
                          onChange={e => setCookies(e.target.value)}
                          placeholder="ASP.NET_SessionId=abc123; .AUTH=xyz789"
                          rows={4}
                          className="form-input font-mono text-xs"
                        />
                        <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                          {isRtl
                            ? "الصق الـ cookies من المتصفح مباشرة (F12 → Application → Cookies)"
                            : "Paste cookies from your browser (F12 → Application → Cookies)"}
                        </p>
                      </Field>
                    )}

                    {/* --- Bearer Sub-Tab --- */}
                    {authSubTab === "bearer" && (
                      <Field label="🔑 Bearer Token (JWT)">
                        <textarea
                          value={bearerToken}
                          onChange={e => setBearerToken(e.target.value)}
                          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                          rows={4}
                          className="form-input font-mono text-xs"
                        />
                        <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                          {isRtl
                            ? "يُرسَل في header: Authorization: Bearer <token>"
                            : "Sent in header: Authorization: Bearer <token>"}
                        </p>
                      </Field>
                    )}

                    {/* --- Login Sub-Tab --- */}
                    {authSubTab === "login" && (
                      <div className="space-y-4">
                        <h3 className="text-sm font-bold" style={{ color: "var(--accent-yellow)" }}>
                          🔐 {isRtl ? "تسجيل دخول تلقائي (Login Form)" : "Auto Login (Form)"}
                        </h3>

                        <Field label={isRtl ? "رابط تسجيل الدخول" : "Login URL"} required>
                          <input
                            type="text"
                            value={loginUrl}
                            onChange={e => setLoginUrl(e.target.value)}
                            placeholder="https://example.com/login"
                            className="form-input"
                          />
                        </Field>

                        <div className="grid grid-cols-2 gap-3">
                          <Field label={isRtl ? "اسم المستخدم" : "Username"} required>
                            <input
                              type="text"
                              value={username}
                              onChange={e => setUsername(e.target.value)}
                              placeholder="admin"
                              className="form-input"
                            />
                          </Field>
                          <Field label={isRtl ? "كلمة المرور" : "Password"} required>
                            <input
                              type="password"
                              value={password}
                              onChange={e => setPassword(e.target.value)}
                              placeholder="••••••••"
                              className="form-input"
                            />
                          </Field>
                        </div>

                        <Field label={isRtl ? "📱 كود SMS / OTP (اختياري)" : "📱 SMS / OTP Code (optional)"}>
                          <input
                            type="text"
                            value={smsCode}
                            onChange={e => setSmsCode(e.target.value)}
                            placeholder="123456"
                            className="form-input font-mono"
                            maxLength={10}
                          />
                          <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                            {isRtl
                              ? "اتركه فارغاً إذا لم يكن الموقع يطلب OTP. يُرسَل في خطوة منفصلة تلقائياً."
                              : "Leave empty if site doesn't require OTP. Sent automatically in a separate step."}
                          </p>
                        </Field>
                      </div>
                    )}

                  </div>
                </>
              )}

              {/* ===================== TAB: ADVANCED ===================== */}
              {activeTab === "advanced" && (
                <>
                  <Field label={isRtl ? "ترويسات مخصصة" : "Custom Headers"}>
                    <textarea
                      value={customHeaders}
                      onChange={e => setCustomHeaders(e.target.value)}
                      placeholder={"X-API-Key: test123\nX-Custom-Header: value"}
                      rows={3}
                      className="form-input font-mono text-xs"
                    />
                    <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                      {isRtl ? "سطر لكل ترويسة: `Name: value`" : "One per line: `Name: value`"}
                    </p>
                  </Field>

                  <div className="grid grid-cols-2 gap-3">
                    <Field label="HTTP Method">
                      <select
                        value={method}
                        onChange={e => setMethod(e.target.value)}
                        className="form-input"
                      >
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="PATCH">PATCH</option>
                        <option value="DELETE">DELETE</option>
                      </select>
                    </Field>

                    <Field label="User-Agent">
                      <input
                        type="text"
                        value={userAgent}
                        onChange={e => setUserAgent(e.target.value)}
                        placeholder="Mozilla/5.0..."
                        className="form-input"
                      />
                    </Field>
                  </div>

                  {method !== "GET" && (
                    <>
                      <Field label={isRtl ? "POST Data (form)" : "POST Data (form)"}>
                        <textarea
                          value={postData}
                          onChange={e => setPostData(e.target.value)}
                          placeholder="user=admin&pass=test"
                          rows={2}
                          className="form-input font-mono text-xs"
                        />
                      </Field>

                      <Field label={isRtl ? "أو POST JSON" : "Or POST JSON"}>
                        <textarea
                          value={postJson}
                          onChange={e => setPostJson(e.target.value)}
                          placeholder='{"user":"admin","pass":"test"}'
                          rows={3}
                          className="form-input font-mono text-xs"
                        />
                      </Field>
                    </>
                  )}

                  <div className="border-t pt-4" style={{ borderColor: "var(--border-color)" }}>
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-sm font-semibold">
                        🌐 {isRtl ? "تفعيل البروكسي (Burp/ZAP)" : "Enable Proxy (Burp/ZAP)"}
                      </label>
                      <button
                        onClick={() => setProxyEnabled(!proxyEnabled)}
                        className="relative inline-flex items-center h-5 w-10 rounded-full transition-colors"
                        style={{ background: proxyEnabled ? "var(--accent-green)" : "var(--bg-tertiary)" }}
                      >
                        <span
                          className="inline-block w-4 h-4 bg-white rounded-full transition-transform"
                          style={{ transform: proxyEnabled ? "translateX(22px)" : "translateX(2px)" }}
                        />
                      </button>
                    </div>

                    {proxyEnabled && (
                      <input
                        type="text"
                        value={proxy}
                        onChange={e => setProxy(e.target.value)}
                        placeholder="http://127.0.0.1:8080"
                        className="form-input font-mono text-xs"
                      />
                    )}
                  </div>
                </>
              )}

              {/* Error / Success */}
              {error && (
                <div className="rounded p-3 text-sm"
                  style={{
                    background: "var(--kpi-red-bg)",
                    border: "1px solid var(--kpi-red-border)",
                    color: "var(--accent-red)",
                    whiteSpace: "pre-wrap",
                  }}>
                  ⚠ {error}
                </div>
              )}
              {success && (
                <div className="rounded p-3 text-sm"
                  style={{ background: "var(--kpi-green-bg)", border: "1px solid var(--kpi-green-border)", color: "var(--accent-green)" }}>
                  ✓ {success}
                </div>
              )}

              {/* Submit */}
              <button
                onClick={startScan}
                disabled={loading}
                className="w-full py-4 rounded-lg text-lg font-bold"
                style={{
                  background: loading ? "var(--bg-tertiary)" : "var(--accent-red)",
                  color: "white",
                  cursor: loading ? "wait" : "pointer",
                  border: "2px solid var(--border-color)",
                }}
              >
                {loading
                  ? `[ ${isRtl ? "جاري البدء..." : "Starting..."} ]`
                  : `[ ${t("start_scan_button")} ]`}
              </button>
            </div>
          </div>
        </main>
      </div>

      <style jsx>{`
        .form-input {
          width: 100%;
          padding: 10px 14px;
          border-radius: 8px;
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          color: var(--text-primary);
          font-size: 13px;
          outline: none;
          transition: border-color 0.2s;
        }
        .form-input:focus {
          border-color: var(--accent-red);
        }
      `}</style>
    </div>
  )
}

function Field({ label, children, required }) {
  return (
    <div>
      <label className="block text-sm font-mono mb-2" style={{ color: "var(--accent-yellow)" }}>
        &lt; {label} {required && <span style={{ color: "var(--accent-red)" }}>*</span>}
      </label>
      {children}
    </div>
  )
}

function InfoBox({ text }) {
  return (
    <div className="rounded p-3 text-xs"
      style={{
        background: "rgba(6, 182, 212, 0.1)",
        border: "1px solid rgba(6, 182, 212, 0.3)",
        color: "var(--text-secondary)",
      }}>
      ℹ️ {text}
    </div>
  )
}