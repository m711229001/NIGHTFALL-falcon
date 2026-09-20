/**
 * ChatV2 - Chat with AI + Maintenance
 */
import { useState, useRef, useEffect } from "react"
import { useTranslation } from "react-i18next"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import TacticalSidebar from "../components/TacticalSidebar"
import TopHeader from "../components/TopHeader"
import client from "../../api/client"
import { Icon } from "../components/Icons"

const API = "/api/v2/chat"

function Message({ role, content, onApplyChanges }) {
    let text = content
    let changes = null
    const jsonMatch = content.match(/```json\s*(\{[\s\S]*?"changes"[\s\S]*?\})\s*```/)
    if (jsonMatch) {
        try {
            const parsed = JSON.parse(jsonMatch[1])
            if (parsed.changes && Array.isArray(parsed.changes)) {
                changes = parsed.changes
                text = content.replace(jsonMatch[0], "\n**📋 التغييرات المقترحة:**\n")
            }
        } catch (_) {}
    }
    const isUser = role === "user"
    return (
        <div className={`flex gap-3 mb-4 ${isUser ? "flex-row-reverse" : ""}`}>
            <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0"
                style={{ background: isUser ? "var(--accent-cyan)" : "var(--accent-purple)", color: "white" }}>
                <Icon name={isUser ? "user" : "sparkles"} size={14} />
            </div>
            <div className={`flex-1 min-w-0 ${isUser ? "text-end" : ""}`}>
                <div className="inline-block max-w-[90%] px-4 py-3 rounded-lg text-start"
                    style={{ background: isUser ? "var(--bg-tertiary)" : "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                    <ReactMarkdown remarkPlugins={[remarkGfm]}
                        components={{
                            code: ({ inline, children, ...props }) => inline
                                ? <code style={{ background: "var(--bg-tertiary)", padding: "2px 6px", borderRadius: 4 }}>{children}</code>
                                : <pre className="my-2 p-3 rounded overflow-x-auto text-xs" style={{ background: "var(--bg-primary)", border: "1px solid var(--border-color)" }} dir="ltr"><code {...props}>{children}</code></pre>,
                            p: ({ children }) => <p className="my-1 leading-7">{children}</p>,
                            ul: ({ children }) => <ul className="list-disc list-inside my-1 space-y-0.5">{children}</ul>,
                            ol: ({ children }) => <ol className="list-decimal list-inside my-1 space-y-0.5">{children}</ol>,
                            a: ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent-cyan)" }}>{children}</a>,
                        }}>{text}</ReactMarkdown>
                </div>
                {changes && (
                    <div className="mt-2 rounded-lg p-3 max-w-[90%]"
                        style={{ background: "var(--accent-yellow-soft)", border: "1px solid var(--accent-yellow)" }}>
                        <div className="text-xs font-bold mb-2" style={{ color: "var(--accent-yellow)" }}>
                            ⚠ {changes.length} ملف سيتغير
                        </div>
                        {changes.map((c, i) => (
                            <div key={i} className="text-[11px] font-mono mb-1" style={{ color: "var(--text-secondary)" }}>
                                📝 {c.path}
                            </div>
                        ))}
                        <button onClick={() => onApplyChanges(changes)}
                            className="mt-3 w-full py-2 rounded text-xs font-bold"
                            style={{ background: "var(--accent-yellow)", color: "white", cursor: "pointer" }}>
                            ✓ تطبيق التغييرات (git commit)
                        </button>
                    </div>
                )}
            </div>
        </div>
    )
}

export default function ChatV2() {
    const { i18n } = useTranslation()
    const isRtl = i18n.language === "ar"
    const [messages, setMessages] = useState([])
    const [input, setInput] = useState("")
    const [loading, setLoading] = useState(false)
    const [contextFile, setContextFile] = useState("")
    const [contextContent, setContextContent] = useState("")
    const [showFiles, setShowFiles] = useState(false)
    const [files, setFiles] = useState([])
    const [gitLog, setGitLog] = useState([])
    const [showGit, setShowGit] = useState(false)
    const [toast, setToast] = useState("")
    const scrollRef = useRef(null)

    useEffect(() => {
        if (messages.length === 0) {
            setMessages([{ role: "assistant", content: isRtl
                ? "👋 مرحباً! أنا مساعد Falcon MAG الذكي.\n\nيمكنني:\n- **شرح الكود** والمعمارية\n- **اقتراح تحسينات**\n- **إصلاح الأخطاء**\n- **إضافة ميزات**\n\nاسألني أي شيء!"
                : "👋 Hi! I'm the Falcon MAG AI assistant. Ask me anything!" }])
        }
    }, [isRtl])

    useEffect(() => {
        if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }, [messages, loading])

    const loadFiles = async () => {
        try { const r = await client.get(`${API}/files`); setFiles(r.data.files || []); setShowFiles(true) }
        catch (e) { setToast("Failed") }
    }
    const loadFile = async (path) => {
        try {
            const r = await client.get(`${API}/file/${path}`)
            setContextFile(path); setContextContent(r.data.content || ""); setShowFiles(false)
            setToast(`Loaded: ${path}`); setTimeout(() => setToast(""), 2000)
        } catch (e) { setToast("Failed") }
    }
    const loadGitLog = async () => {
        try { const r = await client.get(`${API}/git-log?limit=20`); setGitLog(r.data.commits || []); setShowGit(true) }
        catch (e) { setToast("Failed") }
    }
    const sendMessage = async () => {
        if (!input.trim() || loading) return
        setMessages(prev => [...prev, { role: "user", content: input }])
        setInput(""); setLoading(true)
        try {
            const r = await client.post(`${API}/message`, { message: input, context: contextContent, mode: "chat" })
            setMessages(prev => [...prev, { role: "assistant", content: r.data.error ? "❌ " + r.data.error : r.data.response }])
        } catch (e) {
            setMessages(prev => [...prev, { role: "assistant", content: "❌ " + (e?.message || "Error") }])
        } finally { setLoading(false) }
    }
    const applyChanges = async (changes) => {
        if (!confirm(`تطبيق ${changes.length} تغيير؟`)) return
        let success = 0, failed = 0
        for (const c of changes) {
            try { await client.post(`${API}/file/${c.path}`, { path: c.path, content: c.content, commit_message: `chat-edit: ${c.path}` }); success++ }
            catch (e) { failed++ }
        }
        setMessages(prev => [...prev, { role: "assistant", content: `✅ نجح: ${success} | فشل: ${failed}` }])
    }
    const handleKeyDown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage() } }

    return (
        <div className="flex min-h-screen" style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
            <TacticalSidebar />
            <div className="flex-1 flex flex-col min-w-0">
                <TopHeader />
                <main className="flex-1 p-6 flex flex-col overflow-hidden" style={{ maxHeight: "100vh" }}>
                    <div className="flex justify-between items-center flex-wrap gap-3 mb-4">
                        <div>
                            <h1 className="text-2xl font-bold flex items-center gap-3" style={{ color: "var(--accent-purple)" }}>
                                <Icon name="sparkles" size={24} />
                                {isRtl ? "المساعد الذكي" : "AI Assistant"}
                            </h1>
                        </div>
                        <div className="flex gap-2">
                            <button onClick={loadFiles} className="px-3 py-1.5 rounded text-xs font-bold"
                                style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                                📂 الملفات
                            </button>
                            <button onClick={loadGitLog} className="px-3 py-1.5 rounded text-xs font-bold"
                                style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
                                🔄 Git
                            </button>
                        </div>
                    </div>
                    {contextFile && (
                        <div className="mb-3 p-2 rounded flex items-center gap-3"
                            style={{ background: "var(--accent-cyan-soft)", border: "1px solid var(--accent-cyan)" }}>
                            <span className="text-xs font-mono flex-1" style={{ color: "var(--accent-cyan)" }}>{contextFile}</span>
                            <button onClick={() => { setContextFile(""); setContextContent("") }} style={{ cursor: "pointer", color: "var(--accent-cyan)" }}>✕</button>
                        </div>
                    )}
                    <div ref={scrollRef} className="flex-1 overflow-y-auto rounded-lg p-4 mb-4"
                        style={{ background: "var(--bg-primary)", border: "1px solid var(--border-color)" }}>
                        {messages.map((m, i) => <Message key={i} role={m.role} content={m.content} onApplyChanges={applyChanges} />)}
                        {loading && <div className="text-xs" style={{ color: "var(--text-muted)" }}>جاري التفكير...</div>}
                    </div>
                    <div className="rounded-lg p-3" style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }}>
                        <textarea value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={handleKeyDown}
                            placeholder="اسأل عن الكود، اطلب تحسينات... (Enter للإرسال)"
                            rows={3} className="w-full px-3 py-2 rounded text-sm font-mono"
                            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", resize: "none" }} />
                        <div className="flex justify-between items-center mt-2">
                            <div className="text-[10px]" style={{ color: "var(--text-muted)" }}>Shift+Enter للسطر الجديد</div>
                            <button onClick={sendMessage} disabled={loading || !input.trim()}
                                className="px-4 py-1.5 rounded text-sm font-bold"
                                style={{ background: loading || !input.trim() ? "var(--bg-tertiary)" : "var(--accent-purple)", color: "white", cursor: "pointer" }}>
                                إرسال →
                            </button>
                        </div>
                    </div>
                    {showFiles && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: "rgba(0,0,0,0.8)" }} onClick={() => setShowFiles(false)}>
                            <div className="rounded-lg p-4 max-w-3xl w-full max-h-[80vh] overflow-y-auto"
                                style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }} onClick={(e) => e.stopPropagation()}>
                                <div className="text-lg font-bold mb-3">📂 اختر ملفاً</div>
                                {files.slice(0, 200).map((f, i) => (
                                    <button key={i} onClick={() => loadFile(f.path)}
                                        className="w-full text-start px-3 py-1.5 rounded text-xs font-mono mb-1"
                                        style={{ background: "var(--bg-tertiary)", cursor: "pointer" }}>
                                        {f.path}
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}
                    {showGit && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: "rgba(0,0,0,0.8)" }} onClick={() => setShowGit(false)}>
                            <div className="rounded-lg p-4 max-w-2xl w-full max-h-[80vh] overflow-y-auto"
                                style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)" }} onClick={(e) => e.stopPropagation()}>
                                <div className="text-lg font-bold mb-3">🔄 Git Log</div>
                                {gitLog.map((c, i) => (
                                    <div key={i} className="px-3 py-2 rounded text-xs mb-1" style={{ background: "var(--bg-tertiary)" }}>
                                        <span className="font-mono" style={{ color: "var(--accent-cyan)" }}>{c.hash}</span>
                                        <span className="ms-2">{c.message}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {toast && (
                        <div className="fixed bottom-6 end-6 px-4 py-2 rounded-lg text-sm font-bold z-50"
                            style={{ background: "var(--accent-green)", color: "white" }}>{toast}</div>
                    )}
                </main>
            </div>
        </div>
    )
}