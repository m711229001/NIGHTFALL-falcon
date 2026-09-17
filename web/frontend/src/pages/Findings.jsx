import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import Layout from "../components/Layout";
import { findingsApi } from "../api/client";

export default function Findings() {
  const { t } = useTranslation();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);

  const severityColor = {
    critical: "bg-red-900 text-red-200 border-red-600",
    high: "bg-red-800 text-red-200 border-red-500",
    medium: "bg-orange-800 text-orange-200 border-orange-500",
    low: "bg-amber-800 text-amber-200 border-amber-500",
    info: "bg-gray-800 text-gray-300 border-gray-600",
  };

  useEffect(() => {
    findingsApi.list({ limit: 200 }).then((r) => {
      setFindings(r.data || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  return (
    <Layout>
      <div className="max-w-6xl mx-auto">
        <h1 className="text-3xl font-bold text-red-600 mb-2">{t("findings")}</h1>
        <p className="text-gray-400 text-sm mb-8">{findings.length} {t("vulnerabilities_detected")}</p>

        {loading ? (
          <div className="text-center text-gray-500 py-12">{t("loading")}</div>
        ) : findings.length === 0 ? (
          <div className="text-center py-16 bg-black/40 rounded-2xl border-2 border-red-900/30">
            <div className="text-6xl mb-4">🛡️</div>
            <p className="text-gray-400">{t("no_findings_yet")}</p>
            <p className="text-gray-600 text-sm mt-2">{t("no_findings_yet_desc")}</p>
          </div>
        ) : (
          <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-red-900/50 overflow-hidden">
            <table className="w-full">
              <thead className="bg-black/60 border-b border-red-900/30">
                <tr className="text-left text-xs text-amber-500/80 font-mono">
                  <th className="px-4 py-3">{t("severity_col")}</th>
                  <th className="px-4 py-3">{t("class_col")}</th>
                  <th className="px-4 py-3">{t("url_col")}</th>
                  <th className="px-4 py-3">{t("param_col")}</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} className="border-b border-red-900/20 hover:bg-red-900/10 transition">
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 rounded text-xs font-mono border ${severityColor[f.severity] || severityColor.info}`}>
                        {f.severity?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-amber-300 font-mono">{f.vuln_class}</td>
                    <td className="px-4 py-3 text-xs text-gray-400 font-mono truncate max-w-xs">{f.url}</td>
                    <td className="px-4 py-3 text-xs text-red-400 font-mono">{f.param}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}