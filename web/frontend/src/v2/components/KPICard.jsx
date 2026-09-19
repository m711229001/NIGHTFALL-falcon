/**
 * KPICard v2 — Theme-aware
 */
export default function KPICard({ icon, label, value, subtext, color = "slate" }) {
  const colorMap = {
    critical: {
      text: "var(--accent-red)",
      bg: "var(--kpi-red-bg, rgba(127, 29, 29, 0.4))",
      border: "var(--kpi-red-border, rgba(239, 68, 68, 0.5))",
    },
    high: {
      text: "var(--accent-orange)",
      bg: "var(--kpi-orange-bg, rgba(124, 45, 18, 0.4))",
      border: "var(--kpi-orange-border, rgba(249, 115, 22, 0.5))",
    },
    medium: {
      text: "var(--accent-yellow)",
      bg: "var(--kpi-yellow-bg, rgba(113, 63, 18, 0.4))",
      border: "var(--kpi-yellow-border, rgba(250, 204, 21, 0.4))",
    },
    low: {
      text: "var(--accent-green)",
      bg: "var(--kpi-green-bg, rgba(6, 78, 59, 0.4))",
      border: "var(--kpi-green-border, rgba(16, 185, 129, 0.4))",
    },
    info: {
      text: "var(--accent-cyan)",
      bg: "var(--kpi-cyan-bg, rgba(22, 78, 99, 0.4))",
      border: "var(--kpi-cyan-border, rgba(6, 182, 212, 0.4))",
    },
    slate: {
      text: "var(--text-primary)",
      bg: "var(--bg-tertiary)",
      border: "var(--border-color)",
    },
  }
  const c = colorMap[color] || colorMap.slate

  return (
    <div
      className="rounded-lg p-4 flex items-start justify-between min-h-[110px] transition-colors"
      style={{
        background: c.bg,
        border: `1px solid ${c.border}`,
      }}
    >
      <div className="flex flex-col gap-1">
        <span
          className="text-xs uppercase tracking-wider font-mono"
          style={{ color: "var(--text-secondary)" }}
        >
          {label}
        </span>
        <span
          className="text-4xl font-bold leading-none mt-1"
          style={{ color: c.text }}
        >
          {value}
        </span>
        {subtext && (
          <span
            className="text-[11px] mt-1"
            style={{ color: "var(--text-muted)" }}
          >
            {subtext}
          </span>
        )}
      </div>
      <span className="text-3xl opacity-80">{icon}</span>
    </div>
  )
}