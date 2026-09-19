/**
 * FindingsDrawer v2 — Tactical
 */
import { useTranslation } from "react-i18next"

const SEV_COLOR = {
  critical: "#EF4444",
  high:     "#F97316",
  medium:   "#FACC15",
  low:      "#10B981",
  info:     "#06B6D4",
}

export default function FindingsDrawer({ finding, onClose }) {
  const { t, i18n } = useTranslation()
  const isRtl = i18n.language === "ar"

  if (!finding) return null

  const sev = (finding.severity || "info").toLowerCase()
  const sevColor = SEV_COLOR[sev] || SEV_COLOR.info

  const title = finding.title || finding.vuln_class || finding.category || finding.name || "Finding"

  const handleCopy = () => {
    if (finding.url) {
      navigator.clipboard.writeText(finding.url)
      alert(t("drawer.copied"))
    }
  }

  return (
    <>
      <div onClick={onClose} className="fixed inset-0 z-40" style={{ background: "rgba(0,0,0,0.85)", backdropFilter: "blur(4px)" }} />

      <aside
        className={`fixed top-0 h-full w-[480px] max-w-[90vw] z-50 flex flex-col ${isRtl ? "left-0" : "right-0"}`}
        style={{ background: "var(--bg-primary, #0a0e1a)", backgroundColor: "#0a0e1a", borderInline: "1px solid var(--border-color)" }}
      >
        <div className="p-4 flex items-center justify-between" style={{ borderBottom: "1px solid var(--border-color)" }}>
          <h3 className="text-lg font-bold" style={{ color: "var(--accent-red)" }}>
            {t("drawer.title")}
          </h3>
          <button onClick={onClose} className="text-2xl leading-none" style={{ color: "var(--text-secondary)" }}>
            ×
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div
            className="inline-block px-3 py-1 rounded text-xs font-bold uppercase"
            style={{ color: sevColor, border: `1px solid ${sevColor}`, background: `${sevColor}20` }}
          >
            {sev}
          </div>

          <h2 className="text-xl font-bold" style={{ color: "var(--text-primary)" }}>
            {title}
          </h2>

          {(finding.category || finding.vuln_class) && (
            <div>
              <div className="text-xs uppercase font-mono" style={{ color: "var(--text-muted)" }}>
                {t("table.category")}
              </div>
              <div className="text-sm mt-1" style={{ color: "var(--accent-yellow)" }}>
                {finding.category || finding.vuln_class}
              </div>
            </div>
          )}

          {finding.url && (
            <div>
              <div className="text-xs uppercase font-mono" style={{ color: "var(--text-muted)" }}>
                {t("drawer.url")}
              </div>
              <div className="text-sm font-mono break-all mt-1" style={{ color: "var(--accent-cyan)" }}>
                {finding.url}
              </div>
            </div>
          )}

          {finding.param && (
            <div>
              <div className="text-xs uppercase font-mono" style={{ color: "var(--text-muted)" }}>
                {t("table.parameter")}
              </div>
              <div className="text-sm font-mono mt-1" style={{ color: "var(--accent-orange)" }}>
                {finding.param}
              </div>
            </div>
          )}

          {finding.payload && (
            <div>
              <div className="text-xs uppercase font-mono" style={{ color: "var(--text-muted)" }}>
                {t("drawer.payload")}
              </div>
              <div className="text-sm font-mono p-3 rounded mt-1 break-all"
                style={{ background: "var(--bg-tertiary)", color: "var(--accent-red)" }}>
                {finding.payload}
              </div>
            </div>
          )}

          {finding.evidence && (
            <div>
              <div className="text-xs uppercase font-mono" style={{ color: "var(--text-muted)" }}>
                {t("drawer.evidence")}
              </div>
              <pre className="text-xs p-3 rounded mt-1 whitespace-pre-wrap break-all"
                style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)" }}>
                {finding.evidence}
              </pre>
            </div>
          )}

          {finding.description && (
            <div>
              <div className="text-xs uppercase font-mono" style={{ color: "var(--text-muted)" }}>
                {t("drawer.description")}
              </div>
              <div className="text-sm mt-1 leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                {finding.description}
              </div>
            </div>
          )}
        </div>

        <div className="p-4 flex gap-2" style={{ borderTop: "1px solid var(--border-color)" }}>
          <button
            onClick={handleCopy}
            className="flex-1 py-2 rounded text-sm font-semibold"
            style={{ background: "var(--kpi-cyan-bg, rgba(22, 78, 99, 0.4))", color: "var(--accent-cyan)" }}
          >
            {t("drawer.copyUrl")}
          </button>
          <button
            onClick={onClose}
            className="flex-1 py-2 rounded text-sm"
            style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)" }}
          >
            {t("drawer.close")}
          </button>
        </div>
      </aside>
    </>
  )
}
