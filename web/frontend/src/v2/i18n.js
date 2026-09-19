/**
 * Falcon MAG v2 — i18n (Tactical Edition)
 * Uses shared translations from ../locales/
 */
import i18n from "i18next"
import { initReactI18next } from "react-i18next"
import ar from "../locales/ar.json"
import en from "../locales/en.json"

// Only initialize once
if (!i18n.isInitialized) {
  const savedLang = localStorage.getItem("lang") || "ar"
  i18n
    .use(initReactI18next)
    .init({
      resources: {
        ar: { translation: ar },
        en: { translation: en },
      },
      lng: savedLang,
      fallbackLng: "en",
      interpolation: { escapeValue: false },
    })

  document.documentElement.dir = savedLang === "ar" ? "rtl" : "ltr"
  document.documentElement.lang = savedLang
}

export default i18n