import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../context/AuthContext";
import Logo from "../components/Logo";
import GlitchText from "../components/GlitchText";

export default function Login() {
  const { t } = useTranslation();
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await login(username, password);
      navigate("/dashboard");
    } catch (err) {
      setError(t("login_failed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative">
      <div className="bg-black/80 backdrop-blur-2xl rounded-2xl p-10 w-full max-w-md border-2 border-red-900/60 shadow-[0_0_80px_rgba(220,38,38,0.4),inset_0_0_40px_rgba(0,0,0,0.8)] relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-red-950/30 via-transparent to-black/50 pointer-events-none" />
        <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-red-600 to-transparent animate-pulse" />
        <div className="absolute bottom-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-amber-500 to-transparent animate-pulse" />
        <div className="relative">
          <div className="flex flex-col items-center mb-8">
            <div className="animate-flicker"><Logo size={120} /></div>
            <div className="mt-4">
              <GlitchText text="Falcon MAG" className="text-4xl font-bold text-red-600 tracking-widest" />
            </div>
            <p className="text-amber-500/80 text-xs tracking-[0.4em] mt-2">AUTONOMOUS AI VAPT</p>
            <div className="w-full h-px bg-gradient-to-r from-transparent via-amber-700/50 to-transparent mt-4" />
          </div>
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-xs mb-2 text-amber-500/90 tracking-wider font-mono">&gt; {t("username")}</label>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required className="w-full px-4 py-3 rounded-lg bg-black/70 border border-red-900/50 focus:border-red-600 focus:shadow-[0_0_20px_rgba(220,38,38,0.6)] outline-none text-amber-100 transition font-mono" />
            </div>
            <div>
              <label className="block text-xs mb-2 text-amber-500/90 tracking-wider font-mono">&gt; {t("password")}</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required className="w-full px-4 py-3 rounded-lg bg-black/70 border border-red-900/50 focus:border-red-600 focus:shadow-[0_0_20px_rgba(220,38,38,0.6)] outline-none text-amber-100 transition font-mono" />
            </div>
            {error && <div className="text-red-500 text-sm text-center animate-pulse font-mono">[!] {error}</div>}
            <button type="submit" disabled={loading} className="w-full py-3 rounded-lg bg-gradient-to-r from-red-950 via-red-700 to-red-950 text-amber-100 font-bold tracking-[0.2em] hover:from-red-900 hover:via-red-600 hover:to-red-900 transition shadow-[0_0_30px_rgba(220,38,38,0.6)] disabled:opacity-50 border border-red-800 font-mono relative overflow-hidden group">
              <span className="relative z-10">{loading ? "[...]" : `[ ${t("login").toUpperCase()} ]`}</span>
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-amber-500/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" />
            </button>
          </form>
          <p className="text-center mt-6 text-sm text-gray-500 font-mono">
            <Link to="/register" className="text-red-500 hover:text-amber-400 hover:underline transition">&gt;&gt; {t("register")}</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
