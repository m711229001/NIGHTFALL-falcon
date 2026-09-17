import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import Layout from "../components/Layout";
import { scanApi } from "../api/client";

const DEFAULT_BURP_PROXY = "http://127.0.0.1:8080";

export default function NewScan() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [budget, setBudget] = useState(100);
  const [exploit, setExploit] = useState("off");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(null);

  const [proxyEnabled, setProxyEnabled] = useState(false);
  const [proxyUrl, setProxyUrl] = useState(DEFAULT_BURP_PROXY);

  useEffect(() => {
    try {
      const savedEnabled = localStorage.getItem("proxy_enabled") === "true";
      const savedUrl = localStorage.getItem("proxy_url") || DEFAULT_BURP_PROXY;
      setProxyEnabled(savedEnabled);
      setProxyUrl(savedUrl);
    } catch (e) {}
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem("proxy_enabled", proxyEnabled ? "true" : "false");
      localStorage.setItem("proxy_url", proxyUrl);
    } catch (e) {}
  }, [proxyEnabled, proxyUrl]);

  const handleStart = async () => {
    setError("");
    setSuccess(null);
    setLoading(true);
    try {
      const payload = { url, budget, exploit };
      if (proxyEnabled && proxyUrl.trim()) {
        payload.proxy = proxyUrl.trim();
      }
      const res = await scanApi.start(payload);
      setSuccess(res.data);
      setTimeout(() => navigate("/monitor"), 2000);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout>
      <div className="max-w-3xl mx-auto">
        <h1 className="text-3xl font-bold text-red-600 mb-2">{t("new_scan")}</h1>
        <p className="text-gray-400 text-sm mb-8">{t("launch_scan_desc")}</p>

        <div className="bg-black/60 backdrop-blur-xl rounded-2xl p-8 border-2 border-red-900/50">
          <div className="space-y-6">
            <div>
              <label className="block text-sm mb-2 text-amber-500/90 font-mono">&gt; {t("target_url")}</label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="http://example.com"
                className="w-full px-4 py-3 rounded-lg bg-black/70 border border-red-900/50 focus:border-red-600 outline-none text-white font-mono"
              />
            </div>

            <div>
              <label className="block text-sm mb-2 text-amber-500/90 font-mono">&gt; {t("budget_requests")}: {budget}</label>
              <input
                type="range"
                min="10"
                max="1000"
                step="10"
                value={budget}
                onChange={(e) => setBudget(parseInt(e.target.value))}
                className="w-full accent-red-600"
              />
              <div className="flex justify-between text-xs text-gray-500 mt-1 font-mono">
                <span>10</span><span>500</span><span>1000</span>
              </div>
            </div>

            <div>
              <label className="block text-sm mb-2 text-amber-500/90 font-mono">&gt; {t("exploit_mode")}</label>
              <div className="flex gap-3">
                {["off", "confirm"].map((mode) => (
                  <button
                    key={mode}
                    onClick={() => setExploit(mode)}
                    className={`px-6 py-2 rounded-lg font-mono text-sm transition ${
                      exploit === mode
                        ? "bg-red-700 text-white border-2 border-red-500"
                        : "bg-black/50 text-gray-400 border-2 border-red-900/30 hover:border-red-700"
                    }`}
                  >
                    {mode === "off" ? t("detect_only") : t("detect_confirm")}
                  </button>
                ))}
              </div>
            </div>

            <div className="border-t border-purple-900/30 pt-6">
              <div className="flex items-center justify-between mb-4">
                <label className="text-sm text-purple-400 font-mono">
                  &gt; {t("proxy_label")}
                </label>
                <button
                  type="button"
                  onClick={() => setProxyEnabled(!proxyEnabled)}
                  className={`flex items-center gap-3 px-4 py-2 rounded-lg font-mono text-xs transition border-2 ${
                    proxyEnabled
                      ? "bg-purple-900/50 border-purple-500 text-purple-200"
                      : "bg-black/50 border-purple-900/30 text-gray-500"
                  }`}
                >
                  <span
                    className={`relative inline-block w-10 h-5 rounded-full transition ${
                      proxyEnabled ? "bg-purple-500" : "bg-gray-700"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                        proxyEnabled ? "translate-x-5" : "translate-x-0"
                      }`}
                    />
                  </span>
                  <span>
                    {proxyEnabled ? `✅ ${t("proxy_enabled")}` : `⛔ ${t("proxy_disabled")}`}
                  </span>
                </button>
              </div>

              {proxyEnabled && (
                <div className="space-y-2">
                  <label className="block text-xs text-purple-400/70 font-mono">
                    {t("proxy_burp_url")}
                  </label>
                  <input
                    type="text"
                    value={proxyUrl}
                    onChange={(e) => setProxyUrl(e.target.value)}
                    placeholder={DEFAULT_BURP_PROXY}
                    className="w-full px-4 py-3 rounded-lg bg-black/70 border border-purple-900/50 focus:border-purple-600 outline-none text-white font-mono text-sm"
                  />
                  <div className="flex gap-2 mt-2">
                    <button
                      type="button"
                      onClick={() => setProxyUrl(DEFAULT_BURP_PROXY)}
                      className="text-xs text-purple-400/70 hover:text-purple-300 font-mono"
                    >
                      ↺ Burp: {DEFAULT_BURP_PROXY}
                    </button>
                  </div>
                </div>
              )}
            </div>

            {error && (
              <div className="text-red-500 text-sm font-mono p-3 bg-red-950/30 rounded border border-red-900">
                [!] {error}
              </div>
            )}

            {success && (
              <div className="text-green-400 text-sm font-mono p-3 bg-green-950/30 rounded border border-green-900">
                [+] {t("scan_started_pid")}: {success.pid}
                <br />
                {t("redirecting_monitor")}
              </div>
            )}

            <button
              onClick={handleStart}
              disabled={loading || !url}
              className="w-full py-4 rounded-lg bg-gradient-to-r from-red-950 via-red-700 to-red-950 text-white font-bold tracking-[0.2em] hover:from-red-900 hover:via-red-600 hover:to-red-900 transition shadow-[0_0_30px_rgba(220,38,38,0.6)] disabled:opacity-50 border border-red-800 font-mono"
            >
              {loading ? `[ ${t("starting")}... ]` : `[ ${t("start_scan_button")} ]`}
            </button>
          </div>
        </div>
      </div>
    </Layout>
  );
}