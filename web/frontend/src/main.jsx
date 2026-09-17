import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import "./i18n";
import App from "./App.jsx";

const lang = localStorage.getItem("lang") || "ar";
document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
document.documentElement.lang = lang;

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>
);
