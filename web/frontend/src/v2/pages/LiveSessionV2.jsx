/**
 * LiveSessionV2 — Full-page VNC viewer for Docker Playwright.
 * FIXED 2026-09-19: for observing Chromium during interactive auth.
 */
import { useState, useEffect } from "react"
import { useTranslation } from "react-i18next"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"

// VNC URLs
const VNC_PROXY = "/vnc/vnc.html?autoconnect=true&resize=scale&view_only=false"
const VNC_DIRECT = "http://" + window.location.hostname + ":6080/vnc.html?autoconnect=true&resize=scale"

export default function LiveSessionV2() {
  const { i18n } = useTranslation()
  const isRtl = i18n.language === "ar"

  const [viewOnly, setViewOnly] = useState(false)
  const [useDirect, setUseDirect] = useState(false)
  const [connected, setConnected] = useState(false)
  const [iframeKey, setIframeKey] = useState(0)

  const vncUrl = useDirect
    ? VNC_DIRECT
    : VNC_PROXY.replace("view_only=false", "view_only=" + viewOnly)

  useEffect(() => {
    setConnected(false)
  }, [vncUrl, iframeKey])

  const reload = () => setIframeKey(k => k + 1)

  const openNewTab = () => window.open(vncUrl, "_blank")

  return (
    <div className="flex min-h-screen transition-colors"
      style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <TacticalSidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader />

        <main className="flex-1 p-4 overflow-hidden">
          <div className="h-full max-w-7xl mx-auto flex flex-col gap-3">

            {/* Header bar */}
            <div className="rounded-lg p-3 flex items-center justify-between flex-wrap gap-2"
              style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
              <div className="flex items-center gap-3">
                <span className="text-xl">👁️</span>
                <div>
                  <div className="text-sm font-bold" style={{ color: "var(--accent-cyan)" }}>
                    {isRtl ? "المتصفح المباشر (VNC)" : "Live Browser (VNC)"}
                  </div>
                  <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                    {isRtl
                      ? "شاهد Chromium داخل Docker أثناء الفحص"
                      : "Watch Docker Chromium during scans"}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                {/* Status */}
                <div className="flex items-center gap-2 px-3 py-1 rounded"
                  style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)" }}>
                  <span className="w-2 h-2 rounded-full"
                    style={{
                      background: connected ? "var(--accent-green)" : "var(--accent-yellow)",
                      animation: connected ? "pulse 2s infinite" : "none",
                    }} />
                  <span className="text-xs font-mono" style={{ color: "var(--text-secondary)" }}>
                    {connected
                      ? (isRtl ? "متصل" : "LIVE")
                      : (isRtl ? "بانتظار" : "WAITING")}
                  </span>
                </div>

                {/* View-only toggle */}
                <button onClick={() => setViewOnly(v => !v)}
                  className="px-3 py-1.5 rounded text-xs font-bold"
                  style={{
                    background: viewOnly ? "var(--accent-yellow)" : "var(--bg-tertiary)",
                    color: viewOnly ? "#000" : "var(--text-primary)",
                    border: "1px solid var(--border-color)",
                    cursor: "pointer",
                  }}>
                  {viewOnly
                    ? (isRtl ? "🔒 عرض فقط" : "🔒 View Only")
                    : (isRtl ? "🔓 تفاعلي" : "🔓 Interactive")}
                </button>

                {/* Direct vs proxy */}
                <button onClick={() => setUseDirect(d => !d)}
                  className="px-3 py-1.5 rounded text-xs font-bold"
                  style={{
                    background: useDirect ? "var(--accent-red)" : "var(--bg-tertiary)",
                    color: useDirect ? "white" : "var(--text-primary)",
                    border: "1px solid var(--border-color)",
                    cursor: "pointer",
                  }}>
                  {useDirect ? ":6080 مباشر" : "proxy (/vnc/)"}
                </button>

                {/* Reload */}
                <button onClick={reload}
                  className="px-3 py-1.5 rounded text-xs font-bold"
                  style={{ background: "var(--accent-cyan)", color: "#000", cursor: "pointer" }}>
                  ↻ {isRtl ? "إعادة" : "Reload"}
                </button>

                {/* Open new tab */}
                <button onClick={openNewTab}
                  className="px-3 py-1.5 rounded text-xs font-bold"
                  style={{
                    background: "var(--bg-tertiary)",
                    color: "var(--text-primary)",
                    border: "1px solid var(--border-color)",
                    cursor: "pointer",
                  }}>
                  ↗ {isRtl ? "نافذة جديدة" : "New tab"}
                </button>
              </div>
            </div>

            {/* VNC iframe */}
            <div className="flex-1 rounded-lg overflow-hidden relative"
              style={{
                background: "#000",
                border: "2px solid var(--accent-cyan)",
                minHeight: "70vh",
              }}>
              <iframe
                key={iframeKey}
                src={vncUrl}
                title="Falcon MAG Live Browser"
                className="w-full h-full border-none"
                allow="clipboard-read; clipboard-write"
                onLoad={() => setConnected(true)}
              />

              {/* Info bar */}
              <div
                className="absolute bottom-0 left-0 right-0 px-3 py-2 flex justify-between text-[10px] font-mono"
                style={{
                  background: "rgba(0,0,0,0.75)",
                  backdropFilter: "blur(8px)",
                  color: "var(--text-muted)",
                  borderTop: "1px solid var(--border-color)",
                }}>
                <div>DISPLAY :99 • 1920×1080 • Xvfb</div>
                <div style={{ color: "var(--accent-green)" }}>
                  ● {useDirect ? "DIRECT :6080" : "PROXY /vnc/"}
                </div>
              </div>
            </div>

            {/* Hint */}
            <div className="rounded-lg p-2 text-xs"
              style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)" }}>
              💡 {isRtl
                ? "افتح صفحة Framework Scan أو Login ثم اضغط START — سترى Chromium يعمل هنا مباشرة."
                : "Open Framework Scan or Login, click START — Chromium will appear here live."}
            </div>

          </div>
        </main>
      </div>
    </div>
  )
}