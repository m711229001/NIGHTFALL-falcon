import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import LiveMonitor from "./pages/LiveMonitor";
import Findings from "./pages/Findings";
import Reports from "./pages/Reports";
import ScanDetails from "./pages/ScanDetails";
import SmokeBackground from "./components/SmokeBackground";
import Particles from "./components/Particles";
import WolfEyes from "./components/WolfEyes";

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="min-h-screen flex items-center justify-center text-[#FFD700]">Loading...</div>;
  return user ? children : <Navigate to="/login" />;
}

function PublicRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="min-h-screen flex items-center justify-center text-[#FFD700]">Loading...</div>;
  return user ? <Navigate to="/dashboard" /> : children;
}

export default function App() {
  return (
    <AuthProvider>
      <SmokeBackground />
      <Particles />
      <WolfEyes />
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
          <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />
          <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/new-scan" element={<ProtectedRoute><NewScan /></ProtectedRoute>} />
          <Route path="/monitor" element={<ProtectedRoute><LiveMonitor /></ProtectedRoute>} />
          <Route path="/findings" element={<ProtectedRoute><Findings /></ProtectedRoute>} />
          <Route path="/reports" element={<ProtectedRoute><Reports /></ProtectedRoute>} />
          <Route path="/scans/:id" element={<ProtectedRoute><ScanDetails /></ProtectedRoute>} />
          <Route path="/" element={<Navigate to="/dashboard" />} />
          <Route path="*" element={<Navigate to="/dashboard" />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
