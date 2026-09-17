import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import Layout from "../components/Layout";
import client from "../api/client";

export default function Reports() {
  const { t } = useTranslation();
  const [reports, setReports] = useState([]);
  const [selected, setSelected] = useState(null);
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    client.get("/api/reports").then((r) => {
      setReports(r.data || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  const openReport = async (name) => {
    setSelected(name);
    try {
      const r = await client.get(`/api/reports/${name}`);
      setContent(r.data.content || "");
    } catch (e) {
      setContent(t("error_loading_report"));
    }
  };

  return (
    <Layout>
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold text-red-600 mb-2">{t("reports")}</h1>
        <p className="text-gray-400 text-sm mb-8">{reports.length} {t("reports_available")}</p>

        {loading ? (
          <div className="text-center text-gray-500 py-12">{t("loading")}</div>
        ) : reports.length === 0 ? (
          <div className="text-center py-16 bg-black/40 rounded-2xl border-2 border-red-900/30">
            <div className="text-6xl mb-4">📄</div>
            <p className="text-gray-400">{t("no_reports_yet")}</p>
            <p className="text-gray-600 text-sm mt-2">{t("no_reports_yet_desc")}</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="md:col-span-1 space-y-2">
              {reports.map((r) => (
                <button
                  key={r.path}
                  onClick={() => openReport(r.name)}
                  className={`w-full text-left p-4 rounded-lg transition border ${
                    selected === r.name
                      ? "bg-red-900/40 border-red-600 text-red-200"
                      : "bg-black/40 border-red-900/30 text-gray-300 hover:border-red-700"
                  }`}
                >
                  <div className="font-mono text-sm truncate">{r.name}</div>
                  <div className="text-xs text-gray-500 mt-1">
                    {(r.size / 1024).toFixed(1)} KB • {r.type}
                  </div>
                </button>
              ))}
            </div>
            <div className="md:col-span-2 bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-red-900/50 p-6">
              {selected ? (
                <>
                  <h2 className="text-lg font-bold text-amber-500 mb-4 font-mono">{selected}</h2>
                  <pre className="whitespace-pre-wrap text-xs text-gray-300 font-mono max-h-[600px] overflow-y-auto">
                    {content}
                  </pre>
                </>
              ) : (
                <div className="text-center text-gray-500 py-20">
                  {t("select_report")}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}