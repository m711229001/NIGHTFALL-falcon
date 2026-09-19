/**
 * Falcon MAG — Root Router
 * Routes to v1 (Cinematic) or v2 (Tactical).
 *
 *   /v1/*  → Cinematic Edition
 *   /v2/*  → Tactical Edition
 *   /*     → redirect to /v2
 */
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"

import AppV1 from "./v1/App"
import AppV2 from "./v2/App"

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* v1 — Cinematic Edition */}
        <Route path="/v1/*" element={<AppV1 />} />

        {/* v2 — Tactical Edition */}
        <Route path="/v2/*" element={<AppV2 />} />

        {/* Default: redirect to v2 */}
        <Route path="/" element={<Navigate to="/v2/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/v2/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  )
}