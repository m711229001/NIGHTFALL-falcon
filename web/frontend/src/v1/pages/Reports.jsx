import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import Layout from "../components/Layout";
import client from "../../api/client";

export default function Reports() {
  const { t } = useTranslation();
  const [reports, setReports] = useState([]);
  const [selected, setSelected] = useState(null);
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    setError("");
    client
      .get("/api/reports")
      .then((r) => {
        // Handle multiple backend shapes: array, {reports: [...]}, {data: [...]}
        const raw = r.data;
        let list = [];
        if (Array.isArray(raw)) {
          list = raw;
        } else if (raw && Array.isArray(raw.reports)) {
          list = raw.reports;
        } else if (raw && Array.isArray(raw.data)) {
          list = raw.data;
        } else if (raw && Array.isArray(raw.files)) {
          list = raw.files;
        }
        setReports(list);
      })
      .catch((e) => {
        console.error("Reports fetch failed:", e);
        setError("Failed to load reports: " + (e?.message || "unknown"));
      })
      .finally(() => setLoading(false));
  }, []);

  const openReport = async (name) => {
    setSelected(name);
    setContent("");
    setError("");
    try {
      const r = await client.get(`/api/reports/${encodeURIComponent(name)}`);
      const text =
        r.data?.content ||
        r.data?.text ||
        (typeof r.data === "string" ? r.data : JSON.stringify(r.data, null, 2));
      setContent(text);
    } catch (e) {
      console.error("Report fetch failed:", e);
      setError(
        "Failed to load report: " +
          (e?.response?.status || e?.message || "unknown")
      );
      setContent("");
    }
  };

  const handleDownload = () => {
    if (!selected || !content) return;
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = selected;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <Layout>
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold text-red-600 mb-2">{t("reports")}</h1>
        <p className="text-gray-400 text-sm mb-8">
          {reports.length} {t("reports_available")}
        </p>

        {error && (
          <div className="mb-4 p-3 rounded bg-red-900/40 border border-red-700 text-red-200 text-sm">
            ⚠ {error}
          </div>
        )}

        {loading ? (
          <div className="text-center text-gray-500 py-12">{t("loading")}</div>
        ) : reports.length === 0 ? (
          <div className="text-center py-16 bg-black/40 rounded-2xl border-2 border-red-900/30">
            <div className="text-6xl mb-4">📄</div>
            <p className="text-gray-400">{t("no_reports_yet")}</p>
            <p className="text-gray-600 text-sm mt-2">
              {t("no_reports_yet_desc")}
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="md:col-span-1 space-y-2">
              {reports.map((r) => {
                const name = r.name || r.path || r;
                const size = r.size
                  ? `${(r.size / 1024).toFixed(1)} KB`
                  : "";
                const type = r.type || "text";
                return (
                  <button
                    key={name}
                    onClick={() => openReport(name)}
                    className={`w-full text-left p-4 rounded-lg transition border ${
                      selected === name
                        ? "bg-red-900/40 border-red-600 text-red-200"
                        : "bg-black/40 border-red-900/30 text-gray-300 hover:border-red-700"
                    }`}
                  >
                    <div className="font-mono text-sm truncate">{name}</div>
                    <div className="text-xs text-gray-500 mt-1">
                      {size}
                      {size && type ? " • " : ""}
                      {type}
                    </div>
                  </button>
                );
              })}
            </div>
            <div className="md:col-span-2 bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-red-900/50 p-6">
              {selected ? (
                <>
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-bold text-amber-500 font-mono truncate">
                      {selected}
                    </h2>
                    <button
                      onClick={handleDownload}
                      disabled={!content}
                      className="px-3 py-1.5 rounded text-xs font-semibold bg-emerald-900/40 text-emerald-300 hover:bg-emerald-900/60 disabled:opacity-50"
                    >
                      ⬇ Download
                    </button>
                  </div>
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