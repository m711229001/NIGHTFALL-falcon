/**
 * MarkdownRenderer - Professional Arabic/English Markdown viewer
 * Features: RTL detection, syntax highlighting, copy buttons, TOC
 */
import React, { useMemo, useState, useEffect } from "react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import rehypeHighlight from "rehype-highlight"
import { Icon } from "./Icons"

function CodeBlock({ inline, className, children, ...props }) {
  const [copied, setCopied] = useState(false)
  const code = String(children).replace(/\n$/, "")
  if (inline) return <code className={className} {...props}>{children}</code>

  const match = /language-(\w+)/.exec(className || "")
  const lang = match ? match[1] : "text"

  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }).catch(() => {})
  }

  return (
    <div className="relative group my-4 rounded-lg overflow-hidden"
      style={{ background: "#0d0d14", border: "1px solid var(--border-color)" }}>
      <div className="flex items-center justify-between px-3 py-1.5 text-[11px] font-mono"
        style={{ background: "var(--bg-tertiary)", borderBottom: "1px solid var(--border-color)", color: "var(--text-muted)" }}>
        <span className="flex items-center gap-2">
          <Icon name="code" size={12} />
          {lang}
        </span>
        <button onClick={copy}
          className="px-2 py-0.5 rounded text-[10px] font-bold transition-all"
          style={{
            background: copied ? "var(--accent-green)" : "var(--bg-elevated)",
            color: copied ? "white" : "var(--text-primary)",
            cursor: "pointer",
            border: "1px solid var(--border-color)",
          }}>
          {copied ? "OK Copied" : "Copy"}
        </button>
      </div>
      <pre className="p-4 overflow-x-auto text-xs leading-relaxed" dir="ltr">
        <code className={className} {...props}>{children}</code>
      </pre>
    </div>
  )
}

function extractToc(md) {
  const lines = (md || "").split("\n")
  const toc = []
  for (const line of lines) {
    const m = /^(#{1,3})\s+(.+)$/.exec(line)
    if (m) toc.push({ level: m[1].length, text: m[2].trim() })
  }
  return toc
}

export default function MarkdownRenderer({ content, showToc = true }) {
  const isRtl = useMemo(() => {
    const arabicChars = (content || "").match(/[\u0600-\u06FF]/g)
    return arabicChars && arabicChars.length > 30
  }, [content])

  const toc = useMemo(() => showToc ? extractToc(content || "") : [], [content, showToc])

  if (!content) {
    return <div className="text-sm p-8 text-center" style={{ color: "var(--text-muted)" }}>
      No content to display
    </div>
  }

  const scrollToHeading = (text) => {
    const headings = document.querySelectorAll(".md-content h1, .md-content h2, .md-content h3")
    for (const h of headings) {
      if (h.textContent.includes(text.slice(0, 30))) {
        h.scrollIntoView({ behavior: "smooth", block: "start" })
        return
      }
    }
  }

  return (
    <div className="flex gap-6">
      {showToc && toc.length > 2 && (
        <aside className="hidden xl:block w-56 shrink-0">
          <div className="sticky top-4 max-h-[80vh] overflow-y-auto text-xs p-3 rounded-lg"
            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)" }}>
            <div className="font-bold mb-2 flex items-center gap-2" style={{ color: "var(--accent-cyan)" }}>
              <Icon name="file" size={12} />
              Contents ({toc.length})
            </div>
            <ul className="space-y-1">
              {toc.map((item, i) => (
                <li key={i} style={{ paddingInlineStart: (item.level - 1) * 12 }}>
                  <button onClick={() => scrollToHeading(item.text)}
                    className="hover:underline text-start w-full truncate"
                    style={{
                      color: item.level === 1 ? "var(--text-primary)" :
                             item.level === 2 ? "var(--accent-cyan)" : "var(--text-secondary)",
                      fontWeight: item.level === 1 ? "bold" : "normal",
                      background: "none", border: "none", cursor: "pointer", padding: "2px 0",
                    }}>
                    {item.text}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </aside>
      )}

      <div className="md-content flex-1 min-w-0"
        dir={isRtl ? "rtl" : "ltr"}
        style={{
          fontFamily: isRtl ? "'Segoe UI', Tahoma, 'Noto Naskh Arabic', sans-serif" : "var(--font-sans)",
          lineHeight: 1.75,
          color: "var(--text-primary)",
          fontSize: "14px",
        }}>
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          rehypePlugins={[rehypeHighlight]}
          components={{
            code: CodeBlock,
            h1: ({ children }) => (
              <h1 className="text-2xl font-bold mt-8 mb-4 pb-2 flex items-center gap-2"
                style={{ color: "var(--accent-red)", borderBottom: "2px solid var(--accent-red)" }}>
                {children}
              </h1>
            ),
            h2: ({ children }) => (
              <h2 className="text-xl font-bold mt-6 mb-3 pb-1"
                style={{ color: "var(--accent-cyan)", borderBottom: "1px solid var(--border-color)" }}>
                {children}
              </h2>
            ),
            h3: ({ children }) => (
              <h3 className="text-lg font-bold mt-5 mb-2" style={{ color: "#fbbf24" }}>{children}</h3>
            ),
            h4: ({ children }) => (
              <h4 className="text-base font-bold mt-4 mb-2" style={{ color: "#22d3ee" }}>{children}</h4>
            ),
            p: ({ children }) => <p className="my-2.5 text-sm leading-7">{children}</p>,
            ul: ({ children }) => <ul className="list-disc list-inside my-2 space-y-1 text-sm">{children}</ul>,
            ol: ({ children }) => <ol className="list-decimal list-inside my-2 space-y-1 text-sm">{children}</ol>,
            li: ({ children }) => <li className="my-1 leading-6">{children}</li>,
            a: ({ href, children }) => (
              <a href={href} target="_blank" rel="noopener noreferrer"
                style={{ color: "#60a5fa", textDecoration: "underline" }}
                className="hover:opacity-80 break-all">
                {children}
              </a>
            ),
            blockquote: ({ children }) => (
              <blockquote className="border-l-4 my-3 pl-4 py-2 italic rounded"
                style={{ borderColor: "var(--accent-yellow)", background: "rgba(234,179,8,0.08)", color: "var(--text-secondary)" }}>
                {children}
              </blockquote>
            ),
            table: ({ children }) => (
              <div className="overflow-x-auto my-4 rounded-lg" style={{ border: "1px solid var(--border-color)" }}>
                <table className="w-full text-xs border-collapse">{children}</table>
              </div>
            ),
            thead: ({ children }) => <thead style={{ background: "var(--bg-tertiary)" }}>{children}</thead>,
            th: ({ children }) => (
              <th className="px-3 py-2 text-start font-bold"
                style={{ borderBottom: "1px solid var(--border-color)", color: "var(--accent-cyan)" }}>
                {children}
              </th>
            ),
            td: ({ children }) => (
              <td className="px-3 py-2" style={{ borderBottom: "1px solid var(--border-color)" }}>{children}</td>
            ),
            hr: () => <hr className="my-6" style={{ borderColor: "var(--border-color)" }} />,
            strong: ({ children }) => <strong style={{ color: "var(--text-primary)", fontWeight: "bold" }}>{children}</strong>,
            em: ({ children }) => <em style={{ color: "var(--accent-yellow)" }}>{children}</em>,
          }}
        >
          {content}
        </ReactMarkdown>
      </div>
    </div>
  )
}
