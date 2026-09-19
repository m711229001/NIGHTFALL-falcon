/**
 * MarkdownViewer — Professional Markdown renderer
 * GFM + syntax highlighting + custom styling (3 themes)
 */
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import rehypeHighlight from "rehype-highlight"
import "highlight.js/styles/github-dark.css"
import "./MarkdownViewer.css"

export default function MarkdownViewer({ content }) {
  if (!content) {
    return (
      <div className="mdv-empty">
        <div style={{ fontSize: 48, opacity: 0.3 }}>📄</div>
        <div>No content</div>
      </div>
    )
  }

  return (
    <div className="markdown-viewer">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeHighlight]}
        components={{
          h1: ({ children }) => <h1 className="mdv-h1">{children}</h1>,
          h2: ({ children }) => <h2 className="mdv-h2">{children}</h2>,
          h3: ({ children }) => <h3 className="mdv-h3">{children}</h3>,
          h4: ({ children }) => <h4 className="mdv-h4">{children}</h4>,
          p: ({ children }) => <p className="mdv-p">{children}</p>,
          a: ({ href, children }) => (
            <a href={href} target="_blank" rel="noopener noreferrer" className="mdv-link">
              {children}
            </a>
          ),
          ul: ({ children }) => <ul className="mdv-ul">{children}</ul>,
          ol: ({ children }) => <ol className="mdv-ol">{children}</ol>,
          li: ({ children }) => <li className="mdv-li">{children}</li>,
          code: ({ inline, className, children, ...props }) => {
            if (inline) {
              return <code className="mdv-inline-code">{children}</code>
            }
            return (
              <code className={`mdv-code-block ${className || ""}`} {...props}>
                {children}
              </code>
            )
          },
          pre: ({ children }) => <pre className="mdv-pre">{children}</pre>,
          blockquote: ({ children }) => (
            <blockquote className="mdv-blockquote">{children}</blockquote>
          ),
          table: ({ children }) => (
            <div className="mdv-table-wrapper">
              <table className="mdv-table">{children}</table>
            </div>
          ),
          thead: ({ children }) => <thead className="mdv-thead">{children}</thead>,
          tbody: ({ children }) => <tbody>{children}</tbody>,
          tr: ({ children }) => <tr className="mdv-tr">{children}</tr>,
          th: ({ children }) => <th className="mdv-th">{children}</th>,
          td: ({ children }) => <td className="mdv-td">{children}</td>,
          hr: () => <hr className="mdv-hr" />,
          strong: ({ children }) => <strong className="mdv-strong">{children}</strong>,
          em: ({ children }) => <em className="mdv-em">{children}</em>,
          img: ({ src, alt }) => (
            <img src={src} alt={alt} className="mdv-img" loading="lazy" />
          ),
          input: ({ checked, type }) => {
            if (type === "checkbox") {
              return <input type="checkbox" checked={checked} readOnly className="mdv-checkbox" />
            }
            return null
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  )
}