/**
 * Falcon MAG v2 — Tactical Edition
 */
import { Routes, Route, Navigate } from "react-router-dom"
import "./index.css"
import { ThemeProvider } from "./context/ThemeContext"
import DashboardV2 from "./pages/DashboardV2"
import NewScanV2 from "./pages/NewScanV2"
import FindingsV2 from "./pages/FindingsV2"
import ReportsV2 from "./pages/ReportsV2"
import LiveMonitorV2 from "./pages/LiveMonitorV2"
import ScanDetailsV2 from "./pages/ScanDetailsV2"
import LiveSessionV2 from "./pages/LiveSessionV2"

// ADDED 2026-09-18: Framework CLI pages
import FrameworkScanV2 from "./pages/FrameworkScanV2"
import ProfilesV2 from "./pages/ProfilesV2"
import LoginV2 from "./pages/LoginV2"

export default function AppV2() {
  return (
    <ThemeProvider>
      <Routes>
        <Route path="framework-scan" element={<FrameworkScanV2 />} />
        <Route path="profiles" element={<ProfilesV2 />} />
        <Route path="login" element={<LoginV2 />} />
        <Route path="dashboard" element={<DashboardV2 />} />
        <Route path="new-scan" element={<NewScanV2 />} />
        <Route path="findings" element={<FindingsV2 />} />
        <Route path="reports" element={<ReportsV2 />} />
        <Route path="monitor" element={<LiveMonitorV2 />} />
        <Route path="scans/:id" element={<ScanDetailsV2 />} />
        <Route path="*" element={<Navigate to="dashboard" replace />} />
      </Routes>
    </ThemeProvider>
  )
}