"""Falcon MAG - Chat + Maintenance API"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from pathlib import Path
from core.security import get_current_user
import subprocess
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

router = APIRouter(prefix="/api/v2/chat", tags=["chat"])

PROJECT_ROOT = Path("/app")

ALLOWED_PREFIXES = (
    "framework/",
    "web/backend/",
    "web/frontend/src/",
    "SESSION_STATE.md",
    "README.md",
)

EXCLUDED_PATTERNS = (
    "__pycache__", ".git/", "node_modules/", "venv/", ".venv/",
    "output/", "logs/", ".pyc", ".db", "ai_config.json", ".ai_master_key",
    ".env",
)

MAX_FILE_SIZE = 100 * 1024


class ChatMessage(BaseModel):
    message: str
    context: str = ""
    mode: str = "chat"


class FileWriteRequest(BaseModel):
    path: str
    content: str
    commit_message: str = ""


def _is_safe_path(rel_path):
    if not rel_path:
        return False
    rel = rel_path.replace("\\", "/").lstrip("/")
    if ".." in rel.split("/"):
        return False
    if not any(rel.startswith(p) or rel == p for p in ALLOWED_PREFIXES):
        return False
    for pat in EXCLUDED_PATTERNS:
        if pat in rel:
            return False
    return True


def _git(cmd):
    try:
        r = subprocess.run(
            ["git"] + cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        return r.stdout + r.stderr, r.returncode
    except Exception as e:
        return str(e), 1


@router.get("/files")
async def list_files(prefix: str = "", user: dict = Depends(get_current_user)):
    files = []
    for root, dirs, filenames in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if not any(
            p in os.path.join(root, d) for p in EXCLUDED_PATTERNS
        )]
        for fn in filenames:
            full = Path(root) / fn
            rel = str(full.relative_to(PROJECT_ROOT)).replace("\\", "/")
            if _is_safe_path(rel):
                if prefix and not rel.startswith(prefix):
                    continue
                try:
                    st = full.stat()
                    files.append({
                        "path": rel,
                        "size": st.st_size,
                        "modified": st.st_mtime,
                        "ext": full.suffix,
                    })
                except Exception:
                    continue
    files.sort(key=lambda x: x["path"])
    return {"files": files, "total": len(files)}


@router.get("/file/{path:path}")
async def read_file(path: str, user: dict = Depends(get_current_user)):
    if not _is_safe_path(path):
        raise HTTPException(403, "Path not allowed")
    full = PROJECT_ROOT / path
    if not full.exists():
        raise HTTPException(404, f"File not found: {path}")
    if full.stat().st_size > MAX_FILE_SIZE:
        raise HTTPException(400, "File too large")
    try:
        content = full.read_text(encoding="utf-8")
        return {"path": path, "content": content, "size": len(content)}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/file/{path:path}")
async def write_file(path: str, req: FileWriteRequest, user: dict = Depends(get_current_user)):
    if not _is_safe_path(path):
        raise HTTPException(403, "Path not allowed")
    if len(req.content) > MAX_FILE_SIZE:
        raise HTTPException(400, "Content too large")
    full = PROJECT_ROOT / path
    full.parent.mkdir(parents=True, exist_ok=True)
    original = None
    if full.exists():
        try:
            original = full.read_text(encoding="utf-8")
        except Exception:
            pass
    _git(["add", "-A"])
    try:
        full.write_text(req.content, encoding="utf-8")
    except Exception as e:
        raise HTTPException(500, f"Write failed: {e}")
    _git(["add", path])
    msg = req.commit_message or f"chat-edit: {path}"
    _, code = _git(["commit", "-m", msg])
    if code != 0:
        if original is not None:
            full.write_text(original, encoding="utf-8")
        raise HTTPException(500, "Git commit failed — file restored")
    out, _ = _git(["rev-parse", "HEAD"])
    commit_hash = out.strip().split("\n")[0]
    return {
        "status": "committed",
        "path": path,
        "commit": commit_hash[:8],
        "message": msg,
    }


@router.get("/git-log")
async def git_log(limit: int = 20, user: dict = Depends(get_current_user)):
    out, code = _git(["log", f"-{limit}", "--oneline", "--decorate"])
    if code != 0:
        return {"commits": [], "error": out}
    commits = []
    for line in out.strip().split("\n"):
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) >= 2:
            commits.append({"hash": parts[0], "message": parts[1]})
    return {"commits": commits}


@router.get("/git-status")
async def git_status(user: dict = Depends(get_current_user)):
    out, _ = _git(["status", "--short"])
    branch_out, _ = _git(["rev-parse", "--abbrev-ref", "HEAD"])
    return {
        "branch": branch_out.strip(),
        "changes": out.strip().split("\n") if out.strip() else [],
    }


@router.post("/message")
async def chat_message(req: ChatMessage, user: dict = Depends(get_current_user)):
    """Send message to AI with dynamic provider info."""
    import subprocess
    import json as _json

    context_block = ""
    if req.context:
        context_block = "\n\n**Current file context:**\n```\n" + req.context[:5000] + "\n```\n"

    # === Get active provider info (honest) ===
    provider_info = {"name": "unknown", "model": "unknown"}

    # Method 1: ai_config_store
    try:
        from core.ai_config_store import get_ai_config
        cfg = get_ai_config()
        raw = cfg.get_raw()
        active_name = raw.get("active")
        if active_name:
            provider_info["name"] = active_name
            providers = raw.get("providers", {})
            if active_name in providers:
                provider_info["model"] = providers[active_name].get("model", "unknown")
    except Exception as e:
        pass

    # Method 2: fallback to ai_analyzer
    if provider_info["name"] == "unknown":
        try:
            from core.ai_analyzer import _get_active_provider
            p = _get_active_provider()
            if p:
                provider_info["name"] = p.get("name", "unknown")
                provider_info["model"] = p.get("model", "unknown")
        except Exception:
            pass

    pname = provider_info["name"]
    pmodel = provider_info["model"]

    # === System prompt - HONEST about provider ===
    system_prompt = (
        "You are Falcon MAG AI Assistant, an expert Python/React developer.\n"
        f"Currently running on: {pname} / {pmodel}\n\n"
        "## Your voice\n"
        "- Talk like a helpful senior engineer, warm but concise\n"
        "- Use Arabic naturally (not stiff/formal), mix English tech terms freely\n"
        "- Short paragraphs, concrete examples, no fluff\n"
        "- Offer to help proactively; ask clarifying questions when needed\n"
        "- Vary your phrasing — don't repeat the same intro every time\n\n"
        "## Rules\n"
        f"- If asked who you are: 'I run on {pname} / {pmodel}' (never claim Claude/GPT unless it's true)\n"
        "- Never refuse legitimate dev/security requests\n"
        "- NEVER modify project files without explicit user request\n"
        "- When suggesting code, ALWAYS show what will change FIRST, ask for approval\n"
        "- Never run destructive commands (rm -rf, git reset --hard, DROP TABLE) without explicit confirm\n\n"
        "## Project structure\n"
        "- framework/  -> Python CLI + security modules\n"
        "- web/backend/ -> FastAPI\n"
        "- web/frontend/src/ -> React + Vite\n\n"
        "## When user wants code changes\n"
        "1. Explain WHAT and WHY in Arabic (short)\n"
        "2. Show the change as JSON — user will click 'Apply' to commit:\n"
        '```json\n'
        '{"changes":[{"path":"path/to/file.py","content":"<full new content>"}]}\n'
        '```\n'
        "3. If unsure, ASK before suggesting changes\n"
    )

    user_prompt = req.message + context_block

    snippet = (
        "import sys\n"
        "sys.path.insert(0, '/app/framework')\n"
        "from core.ai_analyzer import _is_available, _call_deepseek\n"
        "import json\n"
        "if not _is_available():\n"
        "    print(json.dumps({'error': 'AI not configured - go to /v2/ai-settings'}))\n"
        "else:\n"
        "    resp = _call_deepseek("
        + _json.dumps(system_prompt) + ", "
        + _json.dumps(user_prompt) + ", "
        + "timeout=180, max_tokens=8000)\n"
        "    print(json.dumps({'response': resp or ''}))\n"
    )

    try:
        result = subprocess.run(
            ["python", "-c", snippet],
            capture_output=True,
            text=True,
            timeout=200,
        )
        out = (result.stdout or "").strip()
        if not out:
            err = (result.stderr or "")[:300]
            return {"error": "Empty AI output. stderr: " + err}

        lines = [l.strip() for l in out.split("\n") if l.strip()]
        json_line = None
        for line in reversed(lines):
            if line.startswith("{") and line.endswith("}"):
                json_line = line
                break

        if not json_line:
            return {"error": "No JSON in output: " + out[:200]}

        try:
            return _json.loads(json_line)
        except Exception as e:
            return {"error": "JSON parse: " + str(e)[:150]}
    except subprocess.TimeoutExpired:
        return {"error": "AI timeout (200s)"}
    except Exception as e:
        return {"error": "Chat failed: " + str(e)[:200]}


