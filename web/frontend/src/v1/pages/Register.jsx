import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../context/AuthContext";
import Logo from "../components/Logo";

export default function Register() {
  const { t } = useTranslation();
  const { register } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await register(username, email, password);
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.detail || t("register_failed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="bg-black/70 backdrop-blur-xl rounded-2xl p-8 w-full max-w-md border-2 border-red-900/50 shadow-[0_0_60px_rgba(220,38,38,0.3)] relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-red-950/20 to-transparent pointer-events-none" />
        <div className="relative">
          <div className="flex flex-col items-center mb-6">
            <div className="animate-flicker"><Logo size={90} /></div>
            <h1 className="text-4xl font-bold text-red-600 mt-4 tracking-wider" style={{ textShadow: "0 0 20px #dc2626, 0 0 40px #7f1d1d" }}>Falcon MAG</h1>
            <p className="text-red-400/70 text-xs tracking-[0.3em] mt-1">{t("register").toUpperCase()}</p>
          </div>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs mb-1 text-red-400/80 tracking-wider">{t("username")}</label>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required className="w-full px-4 py-2 rounded-lg bg-black/60 border border-red-900/50 focus:border-red-600 focus:shadow-[0_0_15px_rgba(220,38,38,0.5)] outline-none text-white transition" />
            </div>
            <div>
              <label className="block text-xs mb-1 text-red-400/80 tracking-wider">{t("email")}</label>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required className="w-full px-4 py-2 rounded-lg bg-black/60 border border-red-900/50 focus:border-red-600 focus:shadow-[0_0_15px_rgba(220,38,38,0.5)] outline-none text-white transition" />
            </div>
            <div>
              <label className="block text-xs mb-1 text-red-400/80 tracking-wider">{t("password")}</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} className="w-full px-4 py-2 rounded-lg bg-black/60 border border-red-900/50 focus:border-red-600 focus:shadow-[0_0_15px_rgba(220,38,38,0.5)] outline-none text-white transition" />
            </div>
            {error && <div className="text-red-500 text-sm text-center">{error}</div>}
            <button type="submit" disabled={loading} className="w-full py-3 rounded-lg bg-gradient-to-r from-red-900 via-red-700 to-red-900 text-white font-bold tracking-wider hover:from-red-800 hover:via-red-600 hover:to-red-800 transition shadow-[0_0_20px_rgba(220,38,38,0.4)] disabled:opacity-50">
              {loading ? "..." : t("register").toUpperCase()}
            </button>
          </form>
          <p className="text-center mt-6 text-sm text-gray-500">
            <Link to="/login" className="text-red-500 hover:text-red-400 hover:underline transition">{t("login")}</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
