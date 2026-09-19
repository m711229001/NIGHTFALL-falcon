/**
 * ThemeContext - Multiple themes (dark/mid/light)
 * Persists choice in localStorage, applies `data-theme` on <html>.
 */
import { createContext, useContext, useEffect, useState } from "react"

const ThemeContext = createContext({
  theme: "dark",
  setTheme: () => {},
  toggleTheme: () => {},
})

export const THEMES = [
  { id: "dark",  label: "داكن",  labelEn: "Dark",  icon: "🌙" },
  { id: "mid",   label: "متوسط", labelEn: "Mid",   icon: "🌗" },
  { id: "light", label: "فاتح",  labelEn: "Light", icon: "☀️" },
]

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    return localStorage.getItem("theme") || "dark"
  })

  const setTheme = (id) => {
    setThemeState(id)
    localStorage.setItem("theme", id)
    document.documentElement.setAttribute("data-theme", id)
  }

  const toggleTheme = () => {
    const order = THEMES.map(t => t.id)
    const idx = order.indexOf(theme)
    setTheme(order[(idx + 1) % order.length])
  }

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme)
  }, [theme])

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)