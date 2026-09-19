import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

// Shared Tailwind + base styles
import "./index.css"

// Initialize i18n ONCE
import "./i18n.js"

import App from "./App.jsx"

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>
)