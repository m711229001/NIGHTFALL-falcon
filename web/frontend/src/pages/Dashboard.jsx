import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import Layout from "../components/Layout";
import client, { scanApi } from "../api/client";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
} from "recharts";

const SEVERITY_COLORS = {
  critical: "#dc2626",
  high: "#ef4444",
  medium: "#f97316",
  low: "#f59e0b",
  info: "#6b7280",
};

export default function Dashboard() {
  const { t } = useTranslation();
  const [stats, setStats] = useState(null);
  const [status, setStatus] = useState(null);
  const [scans, setScans] = useState([]);

  useEffect(() => {
    scanApi.stats().then((r) => setStats(r.data)).catch(() => {});
    scanApi.status().then((r) => setStatus(r.data)).catch(() => {});
    client.get("/api/scans/list?limit=10").then((r) => setScans(r.data || [])).catch(() => {});
  }, []);

  const cards = [
    { label: t("findings"), value: stats?.findings || 0, icon: "🎯" },
    { label: t("objectives"), value: stats?.objectives || 0, icon: "📋" },
    { label: t("callbacks"), value: stats?.callbacks || 0, icon: "📡" },
    { label: t("evidence"), value: stats?.evidence || 0, icon: "📁" },
  ];

  const severityData = Object.entries(stats?.by_severity || {}).map(([name, value]) => ({
    name: t(`severity_${name.toLowerCase()}`),
    value,
    color: SEVERITY_COLORS[name.toLowerCase()] || "#6b7280",
  }));

  const classData = Object.entries(stats?.by_class || {}).map(([name, value]) => ({
    name: name.toUpperCase(),
    count: value,
  }));

  const scansTimeline = [...scans].reverse().map((s) => ({
    name: `#${s.id}`,
    duration: s.elapsed_seconds,
    tokens: s.ai_tokens,
    requests: s.requests_used,
  }));

  const translateStatus = (s) => {
    const key = `status_${s?.toLowerCase()}`;
    const translated = t(key);
    return translated === key ? (s?.toUpperCase() || "") : translated;
  };

  return (
    <Layout>
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-red-600 mb-2">{t("dashboard")}</h1>
          <p className="text-gray-400 text-sm">
            {t("status")}: <span className={status?.status === "running" ? "text-amber-500" : "text-gray-500"}>
              {translateStatus(status?.status) || t("status_idle")}
            </span>
          </p>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          {cards.map((c) => (
            <div key={c.label} className="bg-black/60 backdrop-blur-xl rounded-xl p-6 border-2 border-red-900/30 hover:border-red-700/50 transition">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-xs text-amber-500/70 font-mono tracking-wider">{c.label}</p>
                  <p className="text-4xl font-bold text-white mt-2">{c.value}</p>
                </div>
                <span className="text-3xl">{c.icon}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          {/* Severity Doughnut */}
          <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-red-900/50 p-6">
            <h2 className="text-lg font-bold text-amber-500 mb-4 font-mono">{t("vulnerabilities_by_severity")}</h2>
            {severityData.length === 0 ? (
              <div className="text-center text-gray-500 py-12">{t("no_findings_yet")}</div>
            ) : (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {severityData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0a0014", border: "1px solid #dc2626", color: "#fff" }} />
                  <Legend wrapperStyle={{ color: "#fff", fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Class Bar chart */}
          <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-amber-900/50 p-6">
            <h2 className="text-lg font-bold text-amber-500 mb-4 font-mono">{t("vulnerabilities_by_class")}</h2>
            {classData.length === 0 ? (
              <div className="text-center text-gray-500 py-12">{t("no_findings_yet")}</div>
            ) : (
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={classData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="name" stroke="#f59e0b" fontSize={11} />
                  <YAxis stroke="#f59e0b" fontSize={11} />
                  <Tooltip contentStyle={{ background: "#0a0014", border: "1px solid #f59e0b", color: "#fff" }} />
                  <Bar dataKey="count" fill="#dc2626" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Scans Timeline */}
        {scansTimeline.length > 0 && (
          <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-purple-900/50 p-6 mb-8">
            <h2 className="text-lg font-bold text-amber-500 mb-4 font-mono">{t("scan_timeline")}</h2>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={scansTimeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis dataKey="name" stroke="#a855f7" fontSize={11} />
                <YAxis stroke="#a855f7" fontSize={11} />
                <Tooltip contentStyle={{ background: "#0a0014", border: "1px solid #a855f7", color: "#fff" }} />
                <Legend wrapperStyle={{ color: "#fff", fontSize: 12 }} />
                <Bar dataKey="duration" fill="#dc2626" name={t("duration_seconds")} />
                <Bar dataKey="requests" fill="#f59e0b" name={t("requests")} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Action cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <Link to="/new-scan" className="bg-gradient-to-br from-red-950/60 to-black/60 backdrop-blur-xl rounded-xl p-8 border-2 border-red-900/50 hover:border-red-600 transition group">
            <div className="text-4xl mb-3">🚀</div>
            <h2 className="text-xl font-bold text-red-500 mb-1">{t("new_scan")}</h2>
            <p className="text-gray-400 text-sm">{t("launch_new_scan_desc")}</p>
          </Link>
          <Link to="/findings" className="bg-gradient-to-br from-amber-950/60 to-black/60 backdrop-blur-xl rounded-xl p-8 border-2 border-amber-900/50 hover:border-amber-600 transition group">
            <div className="text-4xl mb-3">🎯</div>
            <h2 className="text-xl font-bold text-amber-500 mb-1">{t("findings")}</h2>
            <p className="text-gray-400 text-sm">{t("review_findings_desc")}</p>
          </Link>
        </div>

        {/* Recent scans */}
        {scans.length > 0 && (
          <div className="bg-black/60 backdrop-blur-xl rounded-2xl border-2 border-red-900/50 p-6">
            <h2 className="text-lg font-bold text-amber-500 mb-4 font-mono">{t("recent_scans")}</h2>
            <div className="space-y-2">
              {scans.slice(0, 5).map((s) => (
                <Link
                  key={s.id}
                  to={`/scans/${s.id}`}
                  className="flex items-center justify-between p-3 rounded-lg bg-black/40 border border-red-900/20 hover:border-red-700 hover:bg-red-900/10 transition"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-mono text-gray-500">#{s.id}</span>
                      <span className="text-sm text-white font-mono truncate">{s.target}</span>
                    </div>
                    <div className="flex gap-4 mt-1 text-xs text-gray-500">
                      <span>{t("budget")}: {s.budget}</span>
                      <span>{t("requests")}: {s.requests_used}</span>
                      <span>{t("time")}: {s.elapsed_seconds}s</span>
                      <span>{t("ai_tokens")}: {s.ai_tokens?.toLocaleString() || 0}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 ml-4">
                    <span className={`text-xs px-2 py-1 rounded ${
                      s.status === "completed" ? "bg-green-900/50 text-green-300" :
                      s.status === "running" ? "bg-amber-900/50 text-amber-300" :
                      "bg-gray-800 text-gray-400"
                    }`}>
                      {translateStatus(s.status)}
                    </span>
                    {s.findings_count > 0 && (
                      <span className="text-xs px-2 py-1 rounded bg-red-900/50 text-red-300">
                        {s.findings_count} {t("findings_count_short")}
                      </span>
                    )}
                    <span className="text-amber-500">→</span>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}