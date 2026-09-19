/**
 * Falcon MAG v2 — AI Settings Page
 * Configure AI providers (DeepSeek, OpenAI, Anthropic, etc.)
 *
 * ADDED 2026-09-19
 */
import { useEffect, useState, useCallback } from "react"
import { useTranslation } from "react-i18next"
import { aiConfigApi } from "../../api/clientV2"

// ============================================================
// Provider metadata (labels + colors)
// ============================================================
const PROVIDER_META = {
  deepseek:   { color: "#4D6BFE", emoji: "🐋" },
  openai:     { color: "#10A37F", emoji: "🤖" },
  anthropic:  { color: "#D97757", emoji: "🎭" },
  gemini:     { color: "#4285F4", emoji: "💎" },
  groq:       { color: "#F55036", emoji: "⚡" },
  mistral:    { color: "#FF7000", emoji: "🌪️" },
  openrouter: { color: "#6467F2", emoji: "🔀" },
  together:   { color: "#0F6FFF", emoji: "🤝" },
  ollama:     { color: "#000000", emoji: "🦙" },
}

export default function AISettingsV2() {
  const { t } = useTranslation()

  // State
  const [providers, setProviders] = useState({})         // known templates
  const [configured, setConfigured] = useState({})       // already-saved
  const [activeProvider, setActiveProvider] = useState(null)

  // Form state
  const [selectedProvider, setSelectedProvider] = useState("deepseek")
  const [apiKey, setApiKey] = useState("")
  const [model, setModel] = useState("")
  const [baseUrl, setBaseUrl] = useState("")
  const [showKey, setShowKey] = useState(false)

  // UI state
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)     // {ok, message, error}
  const [error, setError] = useState(null)
  const [successMsg, setSuccessMsg] = useState(null)

  // ============================================================
  // Load initial config
  // ============================================================
  const loadConfig = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await aiConfigApi.providers()
      setProviders(res.data.known || {})
      setConfigured(res.data.configured || {})
      setActiveProvider(res.data.active_provider || null)
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadConfig()
  }, [loadConfig])

  // ============================================================
  // Auto-fill form when provider changes
  // ============================================================
  useEffect(() => {
    const tpl = providers[selectedProvider]
    if (!tpl) return
    const saved = configured[selectedProvider]

    // Prefer saved values, fallback to template
    setModel(saved?.model || tpl.models?.[0] || "")
    setBaseUrl(saved?.base_url || tpl.base_url || "")
    setApiKey("")
    setTestResult(null)
  }, [selectedProvider, providers, configured])

  // ============================================================
  // Handlers
  // ============================================================
  const handleSave = async () => {
    setSaving(true)
    setError(null)
    setSuccessMsg(null)
    setTestResult(null)
    try {
      const res = await aiConfigApi.save({
        provider: selectedProvider,
        api_key: apiKey,
        model,
        base_url: baseUrl,
      })
      setConfigured(res.data.config.providers || {})
      setActiveProvider(res.data.config.active_provider)
      setSuccessMsg(t("aiSettings.savedOk", "تم الحفظ بنجاح ✓"))
      setApiKey("")
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    setError(null)
    try {
      const res = await aiConfigApi.test({
        provider: selectedProvider,
        api_key: apiKey || undefined,
        model,
        base_url: baseUrl,
      })
      setTestResult(res.data)
    } catch (e) {
      setTestResult({
        ok: false,
        error: e.response?.data?.detail || e.message,
      })
    } finally {
      setTesting(false)
    }
  }

  const handleActivate = async (provider) => {
    try {
      const res = await aiConfigApi.activate(provider)
      setActiveProvider(res.data.config.active_provider)
      setSuccessMsg(t("aiSettings.activatedOk", "تم التفعيل ✓"))
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    }
  }

  const handleDelete = async (provider) => {
    if (!window.confirm(t("aiSettings.confirmDelete", `حذف ${provider}؟`))) return
    try {
      const res = await aiConfigApi.remove(provider)
      setConfigured(res.data.config.providers || {})
      setActiveProvider(res.data.config.active_provider)
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    }
  }

  // ============================================================
  // Render
  // ============================================================
  const tpl = providers[selectedProvider] || {}
  const meta = PROVIDER_META[selectedProvider] || { color: "#666", emoji: "🤖" }
  const configuredList = Object.keys(configured)

  return (
    <div className="p-6 max-w-5xl mx-auto" dir="auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--accent-red)" }}>
          🤖 {t("aiSettings.title", "إعدادات الذكاء الاصطناعي")}
        </h1>
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          {t("aiSettings.subtitle", "اختر مزوّد AI، أدخل المفتاح، وفعّله — التشفير تلقائي")}
        </p>
      </div>

      {/* Error / Success banners */}
      {error && (
        <div className="mb-4 p-3 rounded border-l-4 border-red-500 bg-red-950/40 text-red-200 text-sm">
          ❌ {error}
        </div>
      )}
      {successMsg && (
        <div className="mb-4 p-3 rounded border-l-4 border-green-500 bg-green-950/40 text-green-200 text-sm">
          ✅ {successMsg}
        </div>
      )}

      {/* ============================================ */}
      {/* Status Card */}
      {/* ============================================ */}
      <div
        className="mb-6 p-4 rounded-lg border"
        style={{
          background: "var(--bg-secondary)",
          borderColor: "var(--border-color)",
        }}
      >
        <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text-muted)" }}>
          {t("aiSettings.currentStatus", "الحالة الحالية")}
        </div>
        {activeProvider ? (
          <div className="flex items-center gap-3">
            <span className="text-2xl">{PROVIDER_META[activeProvider]?.emoji || "🤖"}</span>
            <div>
              <div className="font-bold text-lg" style={{ color: "var(--text-primary)" }}>
                {providers[activeProvider]?.label || activeProvider}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                {configured[activeProvider]?.model || "—"} • {configured[activeProvider]?.base_url || "—"}
              </div>
            </div>
            <span className="ms-auto px-3 py-1 rounded text-xs font-bold bg-green-600 text-white">
              {t("aiSettings.active", "نشط")}
            </span>
          </div>
        ) : (
          <div className="text-sm" style={{ color: "var(--text-muted)" }}>
            ⚪ {t("aiSettings.noActive", "لا يوجد مزود مفعّل — اختر مزوداً من الأسفل")}
          </div>
        )}
      </div>

      {/* ============================================ */}
      {/* Provider Selector Grid */}
      {/* ============================================ */}
      <div className="mb-6">
        <div className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
          {t("aiSettings.chooseProvider", "اختر المزوّد")}
        </div>
        <div className="grid grid-cols-3 md:grid-cols-5 gap-2">
          {Object.keys(providers).map((name) => {
            const m = PROVIDER_META[name] || { color: "#666", emoji: "🤖" }
            const isSelected = name === selectedProvider
            const isConfigured = !!configured[name]
            return (
              <button
                key={name}
                onClick={() => setSelectedProvider(name)}
                className="p-3 rounded-lg border text-left transition-all hover:scale-105 relative"
                style={{
                  background: isSelected ? m.color + "22" : "var(--bg-secondary)",
                  borderColor: isSelected ? m.color : "var(--border-color)",
                  borderWidth: isSelected ? 2 : 1,
                }}
              >
                {isConfigured && (
                  <span
                    className="absolute top-1 end-1 w-2 h-2 rounded-full bg-green-500"
                    title={t("aiSettings.configured", "مُعدّ")}
                  />
                )}
                <div className="text-xl mb-1">{m.emoji}</div>
                <div className="text-xs font-bold truncate" style={{ color: "var(--text-primary)" }}>
                  {providers[name]?.label || name}
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* ============================================ */}
      {/* Configuration Form */}
      {/* ============================================ */}
      <div
        className="mb-6 p-4 rounded-lg border"
        style={{
          background: "var(--bg-secondary)",
          borderColor: "var(--border-color)",
        }}
      >
        <div className="flex items-center gap-2 mb-4">
          <span className="text-2xl">{meta.emoji}</span>
          <div className="font-bold" style={{ color: "var(--text-primary)" }}>
            {tpl.label || selectedProvider}
          </div>
          {tpl.docs_url && (
            <a
              href={tpl.docs_url}
              target="_blank"
              rel="noopener noreferrer"
              className="ms-auto text-xs underline"
              style={{ color: "var(--accent-red)" }}
            >
              {t("aiSettings.getApiKey", "احصل على API Key ↗")}
            </a>
          )}
        </div>

        <div className="space-y-3">
          {/* API Key */}
          <div>
            <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>
              {t("aiSettings.apiKey", "API Key")}
              {tpl.no_key_required && (
                <span className="ms-2 text-[10px] text-green-400">
                  ({t("aiSettings.noKeyNeeded", "غير مطلوب لهذا المزود")})
                </span>
              )}
            </label>
            <div className="flex gap-2">
              <input
                type={showKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={configured[selectedProvider]?.configured
                  ? t("aiSettings.keepExisting", "اتركه فارغاً للاحتفاظ بالمفتاح الحالي")
                  : "sk-..."}
                className="flex-1 px-3 py-2 rounded border bg-transparent text-sm font-mono"
                style={{
                  borderColor: "var(--border-color)",
                  color: "var(--text-primary)",
                }}
              />
              <button
                type="button"
                onClick={() => setShowKey(!showKey)}
                className="px-3 py-2 rounded border text-xs"
                style={{
                  borderColor: "var(--border-color)",
                  color: "var(--text-muted)",
                }}
              >
                {showKey ? "🙈" : "👁"}
              </button>
            </div>
          </div>

          {/* Model */}
          <div>
            <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>
              {t("aiSettings.model", "الموديل")}
            </label>
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="w-full px-3 py-2 rounded border bg-transparent text-sm"
              style={{
                borderColor: "var(--border-color)",
                color: "var(--text-primary)",
              }}
            >
              {(tpl.models || []).map((m) => (
                <option key={m} value={m} style={{ background: "#1a1a1a" }}>
                  {m}
                </option>
              ))}
              {model && !(tpl.models || []).includes(model) && (
                <option value={model}>{model}</option>
              )}
            </select>
            {/* Manual model input */}
            <input
              type="text"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder={t("aiSettings.customModel", "أو اكتب موديلاً مخصصاً")}
              className="w-full mt-2 px-3 py-1.5 rounded border bg-transparent text-xs"
              style={{
                borderColor: "var(--border-color)",
                color: "var(--text-muted)",
              }}
            />
          </div>

          {/* Base URL */}
          <div>
            <label className="block text-xs mb-1" style={{ color: "var(--text-muted)" }}>
              {t("aiSettings.baseUrl", "Base URL")}
            </label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.example.com/v1"
              className="w-full px-3 py-2 rounded border bg-transparent text-sm font-mono"
              style={{
                borderColor: "var(--border-color)",
                color: "var(--text-primary)",
              }}
            />
          </div>

          {/* Actions */}
          <div className="flex gap-2 pt-2">
            <button
              onClick={handleTest}
              disabled={testing || loading}
              className="px-4 py-2 rounded border text-sm font-medium disabled:opacity-50"
              style={{
                borderColor: "var(--border-color)",
                color: "var(--text-primary)",
              }}
            >
              {testing ? "⏳" : "🧪"} {t("aiSettings.testConnection", "اختبار الاتصال")}
            </button>
            <button
              onClick={handleSave}
              disabled={saving || loading}
              className="px-4 py-2 rounded text-sm font-bold text-white disabled:opacity-50"
              style={{ background: "var(--accent-red)" }}
            >
              {saving ? "⏳" : "💾"} {t("aiSettings.save", "حفظ")}
            </button>
          </div>

          {/* Test Result */}
          {testResult && (
            <div
              className="mt-3 p-3 rounded border-l-4 text-xs"
              style={{
                borderColor: testResult.ok ? "#22c55e" : "#ef4444",
                background: testResult.ok ? "rgba(34,197,94,0.1)" : "rgba(239,68,68,0.1)",
                color: testResult.ok ? "#86efac" : "#fca5a5",
              }}
            >
              {testResult.ok
                ? `✅ ${testResult.message || "Connection successful"}`
                : `❌ ${testResult.error || "Unknown error"}`}
            </div>
          )}
        </div>
      </div>

      {/* ============================================ */}
      {/* Configured Providers */}
      {/* ============================================ */}
      {configuredList.length > 0 && (
        <div className="mb-6">
          <div className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
            {t("aiSettings.configuredProviders", "المزودون المُعدّون")}
          </div>
          <div className="space-y-2">
            {configuredList.map((name) => {
              const meta = PROVIDER_META[name] || { color: "#666", emoji: "🤖" }
              const isActive = name === activeProvider
              return (
                <div
                  key={name}
                  className="p-3 rounded border flex items-center gap-3"
                  style={{
                    background: isActive ? "var(--accent-red)10" : "var(--bg-secondary)",
                    borderColor: isActive ? "var(--accent-red)" : "var(--border-color)",
                  }}
                >
                  <span className="text-xl">{meta.emoji}</span>
                  <div className="flex-1 min-w-0">
                    <div className="font-bold text-sm truncate" style={{ color: "var(--text-primary)" }}>
                      {providers[name]?.label || name}
                    </div>
                    <div className="text-xs truncate" style={{ color: "var(--text-muted)" }}>
                      {configured[name]?.model || "—"}
                    </div>
                  </div>
                  {isActive ? (
                    <span className="px-2 py-1 rounded text-[10px] font-bold bg-green-600 text-white">
                      {t("aiSettings.active", "نشط")}
                    </span>
                  ) : (
                    <button
                      onClick={() => handleActivate(name)}
                      className="px-3 py-1 rounded text-xs border"
                      style={{
                        borderColor: "var(--accent-red)",
                        color: "var(--accent-red)",
                      }}
                    >
                      {t("aiSettings.activate", "تفعيل")}
                    </button>
                  )}
                  <button
                    onClick={() => handleDelete(name)}
                    className="px-2 py-1 rounded text-xs text-red-400 hover:bg-red-950/40"
                    title={t("aiSettings.delete", "حذف")}
                  >
                    🗑
                  </button>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="text-center py-8 text-sm" style={{ color: "var(--text-muted)" }}>
          ⏳ {t("common.loading", "جارٍ التحميل...")}
        </div>
      )}

      {/* Hint */}
      <div className="mt-6 text-xs" style={{ color: "var(--text-muted)" }}>
        🔒 {t("aiSettings.securityNote", "المفاتيح تُشفَّر بـ Fernet وتُخزَّن في framework/config/ai_config.json")}
      </div>
    </div>
  )
}