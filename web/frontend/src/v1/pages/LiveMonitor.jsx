import { useEffect, useState, useRef } from "react";
import { useTranslation } from "react-i18next";
import Layout from "../components/Layout";
import { scanApi } from "../../api/client";

export default function LiveMonitor() {
  const { t } = useTranslation();
  const [status, setStatus] = useState(null);
  const [lines, setLines] = useState([]);
  const logRef = useRef(null);

  useEffect(() => {
    const poll = async () => {
      try {
        const [s, l] = await Promise.all([scanApi.status(), scanApi.log(200)]);
        setStatus(s.data);
        setLines(l.data.lines || []);
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
      } catch (e) { /* ignore */ }
    };
    poll();
    const interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, []);

  const statusColor = {
    running: "text-amber-500 animate-pulse",
    completed: "text-green-500",
    stopped: "text-gray-500",
    idle: "text-gray-600",
  }[status?.status] || "text-gray-500";

  const translateStatus = (s) => {
    if (!s) return t("status_idle");
    const key = `status_${s.toLowerCase()}`;
    const translated = t(key);
    return translated === key ? s.toUpperCase() : translated;
  };

  return (
    <Layout>
      <div className="max-w-6xl mx-auto">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-3xl font-bold text-red-600">{t("live_monitor")}</h1>
            <p className="text-gray-400 text-sm">{status?.url || t("no_active_scan")}</p>
          </div>
          <div className="text-right">
            <div className={`text-lg font-bold font-mono ${statusColor}`}>
              {translateStatus(status?.status)}
            </div>
            {status?.budget && <div className="text-xs text-gray-500 font-mono">{t("budget_label")}: {status.budget}</div>}
          </div>
        </div>

        <div className="bg-black/80 backdrop-blur-xl rounded-2xl border-2 border-red-900/50 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 bg-black/60 border-b border-red-900/30">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <div className="w-3 h-3 rounded-full bg-amber-500"></div>
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
            <span className="text-xs text-gray-500 font-mono ml-2">nightfall@falcon:~$</span>
          </div>
          <div ref={logRef} className="h-[600px] overflow-y-auto p-4 font-mono text-xs text-green-400/90 whitespace-pre-wrap">
            {lines.length === 0 ? (
              <div className="text-gray-600">{t("waiting_scan")}</div>
            ) : (
              lines.map((line, i) => (
                <div key={i} className="hover:bg-red-900/10 px-2 -mx-2">{line}</div>
              ))
            )}
          </div>
        </div>

        {status?.status === "running" && (
          <button
            onClick={() => scanApi.stop()}
            className="mt-4 px-6 py-2 rounded-lg bg-red-900/50 hover:bg-red-800 text-red-300 font-mono text-sm border border-red-700"
          >
            [ {t("stop_scan_button")} ]
          </button>
        )}
      </div>
    </Layout>
  );
}