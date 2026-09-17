import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import Layout from "../components/Layout";
import client from "../api/client";

const API_BASE = "http://localhost:8888";

export default function ScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    client.get(`/api/scans/${id}`).then((r) => {
      setData(r.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [id]);

  const translateStatus = (s) => {
    if (!s) return "";
    const key = `status_${s.toLowerCase()}`;
    const translated = t(key);
    return translated === key ? s.toUpperCase() : translated;
  };

  const downloadFile = async (format) => {
    const token = localStorage.getItem("token");
    const url = `${API_BASE}/api/scans/${id}/export/${format}${format === "sarif" ? "?download=true" : ""}`;
    const ext = format === "sarif" ? "sarif" : "pdf";
    const prefix = format === "sarif" ? "nightfall_scan" : "falcon_scan";

    try {
      const res = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) {
        const errText = await res.text();
        alert(`Export failed (${res.status}): ${errText.slice(0, 200)}`);
        return;
      }
      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      a.download = `${prefix}_${id}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);
    } catch (err) {
      alert(`Download error: ${err.message}`);
    }
  };

  if (loading) {
    return <Layout><div className="text-center py-20 text-gray-500">{t("loading")}</div></Layout>;
  }

  if (!data || !data.scan) {
    return (
      <Layout>
        <div className="text-center py-20">
          <p className="text-red-500">{t("scan_not_found")}</p>
          <button onClick={() => navigate("/dashboard")} className="mt-4 px-4 py-2 rounded bg-red-900 text-white">
            {t("back_to_dashboard")}
          </button>
        </div>
      </Layout>
    );
  }

  const { scan, findings } = data;

  return (
    <Layout>
      <div className="max-w-5xl mx-auto">
        <div className="flex justify-between items-center mb-4 flex-wrap gap-2">
          <button onClick={() => navigate("/dashboard")} className="text-amber-500 hover:text-amber-400 text-sm">
            ← {t("back_to_dashboard")}
          </button>
          <div className="flex gap-2">
            <button
              onClick={() => downloadFile("pdf")}
              className="px-4 py-2 rounded-lg bg-red-900/50 hover:bg-red-800 text-red-300 text-sm font-mono border border-red-700 transition cursor-pointer"
            >
              📄 {t("export_pdf")}
            </button>
            <button
              onClick={() => downloadFile("sarif")}
              className="px-4 py-2 rounded-lg bg-purple-900/50 hover:bg-purple-800 text-purple-300 text-sm font-mono border border-purple-700 transition cursor-pointer"
            >
              📊 {t("export_sarif")}
            </button>
          </div>
        </div>

        <h1 className="text-3xl font-bold text-red-600 mb-2">{t("scan_number")} #{scan.id}</h1>
        <p className="text-gray-400 text-sm mb-8 font-mono truncate">{scan.target}</p>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <div className="bg-black/60 rounded-xl p-4 border border-red-900/30">
            <div className="text-xs text-amber-500/70 font-mono">{t("status")}</div>
            <div className="text-xl font-bold text-green-400">{translateStatus(scan.status)}</div>
          </div>
          <div className="bg-black/60 rounded-xl p-4 border border-red-900/30">
            <div className="text-xs text-amber-500/70 font-mono">{t("findings")}</div>
            <div className="text-xl font-bold text-red-400">{scan.findings_count}</div>
          </div>
          <div className="bg-black/60 rounded-xl p-4 border border-red-900/30">
            <div className="text-xs text-amber-500/70 font-mono">{t("requests")}</div>
            <div className="text-xl font-bold text-amber-400">{scan.requests_used}</div>
          </div>
          <div className="bg-black/60 rounded-xl p-4 border border-red-900/30">
            <div className="text-xs text-amber-500/70 font-mono">{t("duration_seconds")}</div>
            <div className="text-xl font-bold text-purple-400">{scan.elapsed_seconds}s</div>
          </div>
        </div>

        <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-red-900/50 p-6 mb-6">
          <h2 className="text-lg font-bold text-amber-500 mb-4 font-mono">{t("scan_info")}</h2>
          <dl className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <dt className="text-gray-500">{t("budget")}</dt>
              <dd className="text-white">{scan.budget}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t("exploit_mode_label")}</dt>
              <dd className="text-white">{scan.exploit}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t("ai_tokens_label")}</dt>
              <dd className="text-white">{scan.ai_tokens?.toLocaleString() || 0}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t("started_at")}</dt>
              <dd className="text-white font-mono text-xs">
                {scan.started_at ? new Date(scan.started_at * 1000).toLocaleString() : "—"}
              </dd>
            </div>
          </dl>
        </div>

        {scan.ai_plan && (
          <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-amber-900/50 p-6 mb-6">
            <h2 className="text-lg font-bold text-amber-500 mb-4 font-mono">🧠 {t("ai_plan")}</h2>
            <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap max-h-[600px] overflow-y-auto bg-black/40 p-4 rounded">
              {typeof scan.ai_plan === "string" ? (() => {
                try { return JSON.stringify(JSON.parse(scan.ai_plan), null, 2); }
                catch { return scan.ai_plan; }
              })() : JSON.stringify(scan.ai_plan, null, 2)}
            </pre>
          </div>
        )}

        {scan.waf && (
          <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-orange-900/50 p-6 mb-6">
            <h2 className="text-lg font-bold text-orange-500 mb-4 font-mono">{t("waf_detected")}</h2>
            <div className="flex items-center gap-4 mb-4">
              <span className="text-3xl font-bold text-orange-400">{scan.waf}</span>
              <span className="px-3 py-1 rounded bg-orange-900/50 text-orange-200 text-xs font-mono">{t("active")}</span>
            </div>
            {scan.waf_info && (
              <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
                <div className="bg-black/40 rounded p-3">
                  <div className="text-xs text-orange-400/70 font-mono mb-1">{t("probes_triggered")}</div>
                  <div className="text-xl font-bold text-white">
                    {scan.waf_info.triggered_probes} / {scan.waf_info.probes_sent}
                  </div>
                </div>
                <div className="bg-black/40 rounded p-3">
                  <div className="text-xs text-orange-400/70 font-mono mb-1">{t("signals_detected")}</div>
                  <div className="text-xl font-bold text-white">
                    {scan.waf_info.signals?.length || 0}
                  </div>
                </div>
              </div>
            )}
            {scan.waf_info?.signals?.length > 0 && (
              <div className="mb-4">
                <div className="text-xs text-orange-400/70 font-mono mb-2">{t("signals")}:</div>
                <div className="space-y-1 max-h-40 overflow-y-auto">
                  {scan.waf_info.signals.slice(0, 8).map((sig, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs bg-black/40 rounded px-2 py-1">
                      <span className="px-2 py-0.5 rounded bg-orange-900/50 text-orange-200 font-mono">{sig.source}</span>
                      <span className="text-gray-400 font-mono truncate">{sig.pattern}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <p className="text-gray-400 text-sm">
              {t("waf_protection_msg").replace("{waf}", scan.waf)}
            </p>
          </div>
        )}

        {scan.hidden_paths && scan.hidden_paths.length > 0 && (
          <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-purple-900/50 p-6 mb-6">
            <h2 className="text-lg font-bold text-purple-400 mb-4 font-mono">
              🗺️ {t("hidden_paths")} ({scan.hidden_paths.length})
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-purple-900/30">
                  <tr className="text-xs text-purple-400/80">
                    <th className="text-left py-2 pr-4">{t("status")}</th>
                    <th className="text-left py-2 pr-4">{t("path_col")}</th>
                    <th className="text-left py-2 pr-4">{t("type_col")}</th>
                    <th className="text-left py-2">{t("size_col")}</th>
                  </tr>
                </thead>
                <tbody>
                  {scan.hidden_paths.map((hp, i) => (
                    <tr key={i} className="border-b border-purple-900/20 hover:bg-purple-900/10">
                      <td className="py-2 pr-4">
                        <span className={`font-mono text-xs px-2 py-1 rounded ${
                          hp.status === 200 ? "bg-green-900/50 text-green-300" :
                          hp.status === 403 ? "bg-red-900/50 text-red-300" :
                          hp.status === 401 ? "bg-amber-900/50 text-amber-300" :
                          "bg-gray-800 text-gray-400"
                        }`}>
                          {hp.status}
                        </span>
                      </td>
                      <td className="py-2 pr-4 text-amber-300 font-mono text-xs">{hp.path}</td>
                      <td className="py-2 pr-4">
                        <span className={`text-xs px-2 py-1 rounded ${
                          hp.type === "critical_exposure" ? "bg-red-900/50 text-red-200 border border-red-700" :
                          hp.type === "sensitive_file" ? "bg-orange-900/50 text-orange-200" :
                          hp.type === "admin_panel" ? "bg-amber-900/50 text-amber-200" :
                          hp.type === "reconnaissance" ? "bg-blue-900/50 text-blue-200" :
                          "bg-gray-800 text-gray-400"
                        }`}>
                          {hp.type}
                        </span>
                      </td>
                      <td className="py-2 text-gray-500 font-mono text-xs">{hp.size}b</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-red-900/50 p-6">
          <h2 className="text-lg font-bold text-amber-500 mb-4 font-mono">
            {t("findings")} ({findings.length})
          </h2>
          {findings.length === 0 ? (
            <p className="text-gray-500 text-center py-8">{t("no_vulns_in_scan")}</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b border-red-900/30">
                <tr className="text-xs text-amber-500/80">
                  <th className="text-left py-2">{t("severity_col")}</th>
                  <th className="text-left py-2">{t("class_col")}</th>
                  <th className="text-left py-2">{t("url_col")}</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} className="border-b border-red-900/20">
                    <td className="py-2 text-red-400">{f.severity}</td>
                    <td className="py-2 text-amber-300">{f.vuln_class}</td>
                    <td className="py-2 text-gray-400 font-mono text-xs truncate">{f.url}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </Layout>
  );
}