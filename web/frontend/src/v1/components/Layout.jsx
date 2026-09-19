import { Link, useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../context/AuthContext";
import Logo from "./Logo";

export default function Layout({ children }) {
  const { t, i18n } = useTranslation();
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const toggleLang = () => {
    const newLang = i18n.language === "ar" ? "en" : "ar";
    i18n.changeLanguage(newLang);
    localStorage.setItem("lang", newLang);
    document.documentElement.dir = newLang === "ar" ? "rtl" : "ltr";
    document.documentElement.lang = newLang;
  };

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const navItems = [
    { path: "/dashboard", label: t("dashboard"), icon: "📊" },
    { path: "/new-scan", label: t("new_scan"), icon: "🚀" },
    { path: "/findings", label: t("findings"), icon: "🎯" },
    { path: "/reports", label: t("reports"), icon: "📄" },
  ];

  return (
    <div className="min-h-screen">
      <header className="fixed top-0 left-0 right-0 z-50 bg-black/80 backdrop-blur-xl border-b border-red-900/50">
        <div className="flex items-center justify-between px-6 py-3">
          <Link to="/dashboard" className="flex items-center gap-3">
            <Logo size={45} />
            <div>
              <h1 className="text-xl font-bold text-red-600 tracking-wider">Falcon MAG</h1>
              <p className="text-[10px] text-amber-500/70 tracking-widest">AUTONOMOUS AI VAPT</p>
            </div>
          </Link>
          <div className="flex items-center gap-3">
            <span className="text-sm text-amber-500/80 hidden md:inline">{user?.username}</span>
            <button onClick={toggleLang} className="px-3 py-1.5 rounded-lg bg-purple-700 hover:bg-purple-600 text-white text-xs font-mono">
              {i18n.language === "ar" ? "EN" : "AR"}
            </button>
            <button onClick={handleLogout} className="px-3 py-1.5 rounded-lg bg-red-900/50 hover:bg-red-800 text-red-300 text-xs">
              {t("logout")}
            </button>
          </div>
        </div>
      </header>
      <div className="flex pt-16">
        <aside className="fixed left-0 top-16 bottom-0 w-56 bg-black/60 backdrop-blur-xl border-r border-red-900/30 p-4">
          <nav className="space-y-1">
            {navItems.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                  location.pathname === item.path
                    ? "bg-red-900/40 text-red-300 border border-red-700/50"
                    : "text-gray-400 hover:bg-red-900/20 hover:text-red-300"
                }`}
              >
                <span className="text-lg">{item.icon}</span>
                <span className="text-sm">{item.label}</span>
              </Link>
            ))}
          </nav>
        </aside>
        <main className="flex-1 p-6 ml-56">
          {children}
        </main>
      </div>
    </div>
  );
}
