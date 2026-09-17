"""Falcon MAG - PDF Export API (Arabic RTL support v3)"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime
import sys
import os
import json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.security import get_current_user
from core import nightfall_db

BACKEND_DIR = Path(__file__).resolve().parent.parent
EXPORT_DIR = BACKEND_DIR / "exports"
EXPORT_DIR.mkdir(exist_ok=True)

router = APIRouter(prefix="/api/scans", tags=["export"])


# ============================================================
# Arabic / RTL support
# ============================================================
ARABIC_FONT_PATH = r"C:\Windows\Fonts\segoeui.ttf"
ARABIC_FONT_NAME = "SegoeUI"
_ARABIC_FONT_REGISTERED = False

# Unicode directional marks
RLM = "\u200F"   # Right-to-Left Mark
LRM = "\u200E"   # Left-to-Right Mark


def _register_arabic_font():
    """Register Segoe UI font for Arabic support (idempotent)."""
    global _ARABIC_FONT_REGISTERED
    if _ARABIC_FONT_REGISTERED:
        return True
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        if os.path.exists(ARABIC_FONT_PATH):
            pdfmetrics.registerFont(TTFont(ARABIC_FONT_NAME, ARABIC_FONT_PATH))
            _ARABIC_FONT_REGISTERED = True
            return True
    except Exception:
        pass
    return False


def _has_arabic(text):
    """Detect Arabic characters in text."""
    if not text:
        return False
    return any(
        '\u0600' <= c <= '\u06FF'
        or '\u0750' <= c <= '\u077F'
        or '\uFB50' <= c <= '\uFDFF'
        or '\uFE70' <= c <= '\uFEFF'
        for c in str(text)
    )


def _reshape(text):
    """Reshape + bidi for Arabic text only."""
    if not text:
        return ""
    text = str(text)
    if not _has_arabic(text):
        return text
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        return get_display(arabic_reshaper.reshape(text))
    except Exception:
        return text


def _reshape_arabic_only(text):
    """
    Reshape Arabic-only text (no bidi reordering).
    Used when we want to keep the logical order but with connected letters.
    """
    if not text:
        return ""
    text = str(text)
    if not _has_arabic(text):
        return text
    try:
        import arabic_reshaper
        return arabic_reshaper.reshape(text)
    except Exception:
        return text


def _escape_html(text):
    """Escape HTML entities for reportlab Paragraph."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _para_simple(text, style):
    """
    Simple paragraph.
    - If Arabic: reshape + bidi
    - Otherwise: keep as-is
    """
    from reportlab.platypus import Paragraph
    text = str(text) if text is not None else ""
    if not text:
        return Paragraph("", style)
    if _has_arabic(text):
        reshaped = _reshape(text)
        return Paragraph(_escape_html(reshaped), style)
    return Paragraph(_escape_html(text), style)


def _para_label(label, value, style):
    """
    Create paragraph with bold Arabic label + value.
    KEY INSIGHT: Colon MUST be outside the reshaped label,
    otherwise bidi moves it to the wrong visual position.
    """
    from reportlab.platypus import Paragraph
    label = str(label) if label is not None else ""
    value = str(value) if value is not None else ""

    # 1. Reshape label ONLY (Arabic shaping, no colon)
    if _has_arabic(label):
        reshaped_label = _reshape(label)
        label_html = f"<b>{_escape_html(reshaped_label)}</b>"
    else:
        label_html = f"<b>{_escape_html(label)}</b>"

    # 2. Value: reshape if Arabic, otherwise keep as-is
    if _has_arabic(value):
        value_html = _escape_html(_reshape(value))
    else:
        # Wrap Latin value with LRM to keep it LTR inside RTL paragraph
        value_html = f"{LRM}{_escape_html(value)}{LRM}"

    # 3. Combine: colon is OUTSIDE the bold label (critical!)
    combined = f"{label_html}: {value_html}"
    return Paragraph(combined, style)


def _para_arabic_only(text, style):
    """For section headers and standalone Arabic text."""
    from reportlab.platypus import Paragraph
    text = str(text) if text is not None else ""
    if not text:
        return Paragraph("", style)
    reshaped = _reshape(text)
    return Paragraph(_escape_html(reshaped), style)


def _safe_text(value):
    """Sanitize text for PDF."""
    if value is None:
        return ""
    return str(value)[:5000]


# ============================================================
# Arabic translations
# ============================================================
L = {
    "title": "فالكون ماج",
    "subtitle": "منصة VAPT ذاتية بالذكاء الاصطناعي",
    "scan_report": "تقرير الفحص",
    "target": "الهدف",
    "status": "الحالة",
    "budget": "الميزانية",
    "exploit_mode": "وضع الاستغلال",
    "requests_used": "عدد الطلبات المستخدمة",
    "duration": "المدة",
    "ai_tokens": "رموز الذكاء الاصطناعي",
    "generated": "تاريخ الإنشاء",
    "waf_detected": "تم اكتشاف جدار الحماية (WAF)",
    "firewall": "الجدار",
    "probes_triggered": "الفحوصات المُفعَّلة",
    "source": "المصدر",
    "pattern": "النمط",
    "hidden_paths": "المسارات المخفية المكتشفة",
    "status_col": "الحالة",
    "path_col": "المسار",
    "type_col": "النوع",
    "size_col": "الحجم",
    "findings": "الثغرات المكتشفة",
    "no_vulns": "لم يتم اكتشاف أي ثغرات.",
    "severity": "الخطورة",
    "class_col": "التصنيف",
    "subtype_col": "النوع الفرعي",
    "url_col": "الرابط",
    "ai_plan": "خطة الذكاء الاصطناعي",
    "num_col": "#",
}


# Status translations
STATUS_MAP = {
    "completed": "مكتمل",
    "running": "قيد التشغيل",
    "stopped": "متوقف",
    "idle": "خامل",
    "failed": "فشل",
}


# ============================================================
# PDF generation
# ============================================================
def generate_pdf(scan: dict, findings: list, output_path: str) -> str:
    """Generate Arabic PDF report for a scan."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )
    from reportlab.lib.enums import TA_RIGHT, TA_CENTER

    _register_arabic_font()
    font_name = ARABIC_FONT_NAME if _ARABIC_FONT_REGISTERED else "Helvetica"

    # Colors
    DARK = HexColor("#0a0014")
    RED = HexColor("#dc2626")
    AMBER = HexColor("#f59e0b")
    GRAY = HexColor("#6b7280")

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ArTitle",
        parent=styles["Title"],
        fontName=font_name,
        fontSize=26,
        textColor=RED,
        spaceAfter=6,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "ArSubtitle",
        parent=styles["BodyText"],
        fontName=font_name,
        fontSize=12,
        textColor=GRAY,
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    h2_style = ParagraphStyle(
        "ArH2",
        parent=styles["Heading2"],
        fontName=font_name,
        fontSize=16,
        textColor=AMBER,
        spaceBefore=16,
        spaceAfter=8,
        alignment=TA_RIGHT,
    )
    body_style = ParagraphStyle(
        "ArBody",
        parent=styles["BodyText"],
        fontName=font_name,
        fontSize=11,
        leading=18,
        alignment=TA_RIGHT,
    )
    cell_style = ParagraphStyle(
        "ArCell",
        parent=styles["BodyText"],
        fontName=font_name,
        fontSize=9,
        leading=13,
        alignment=TA_RIGHT,
    )
    code_style = ParagraphStyle(
        "ArCode",
        parent=styles["Code"],
        fontName=font_name,
        fontSize=8,
        leading=11,
        textColor=GRAY,
        alignment=TA_RIGHT,
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    story = []

    # ------------------------------------------------------------
    # Title
    # ------------------------------------------------------------
    story.append(_para_arabic_only(L["title"], title_style))
    story.append(_para_arabic_only(L["subtitle"], subtitle_style))
    story.append(Spacer(1, 16))

    # ------------------------------------------------------------
    # Scan info
    # ------------------------------------------------------------
    scan_id = scan.get("id", "N/A")
    story.append(_para_label(L["scan_report"], f"#{scan_id}", h2_style))

    story.append(_para_label(L["target"], _safe_text(scan.get("target")), body_style))
    story.append(_para_label(
        L["status"],
        STATUS_MAP.get(scan.get("status", ""), scan.get("status", "")),
        body_style,
    ))
    story.append(_para_label(L["budget"], scan.get("budget", 0), body_style))
    story.append(_para_label(L["exploit_mode"], _safe_text(scan.get("exploit")), body_style))
    story.append(_para_label(L["requests_used"], scan.get("requests_used", 0), body_style))
    story.append(_para_label(L["duration"], f"{scan.get('elapsed_seconds', 0)}s", body_style))
    story.append(_para_label(L["ai_tokens"], scan.get("ai_tokens", 0), body_style))
    story.append(_para_label(
        L["generated"],
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + " UTC",
        body_style,
    ))
    story.append(Spacer(1, 16))

    # ------------------------------------------------------------
    # WAF Detection
    # ------------------------------------------------------------
    if scan.get("waf"):
        story.append(_para_arabic_only(L["waf_detected"], h2_style))
        story.append(_para_label(L["firewall"], _safe_text(scan.get("waf")), body_style))
        waf_info = scan.get("waf_info") or {}
        if isinstance(waf_info, dict):
            triggered = waf_info.get("triggered_probes", 0)
            sent = waf_info.get("probes_sent", 0)
            story.append(_para_label(L["probes_triggered"], f"{triggered} / {sent}", body_style))
            signals = waf_info.get("signals", [])
            if signals:
                sig_data = [[
                    _para_arabic_only(L["source"], cell_style),
                    _para_arabic_only(L["pattern"], cell_style),
                ]]
                for sig in signals[:10]:
                    sig_data.append([
                        _para_simple(_safe_text(sig.get("source", "")), cell_style),
                        _para_simple(_safe_text(sig.get("pattern", ""))[:60], cell_style),
                    ])
                sig_table = Table(sig_data, colWidths=[1.5 * inch, 5.0 * inch])
                sig_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), DARK),
                    ("TEXTCOLOR", (0, 0), (-1, 0), AMBER),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
                    ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]))
                story.append(sig_table)
        story.append(Spacer(1, 12))

    # ------------------------------------------------------------
    # Hidden Paths
    # ------------------------------------------------------------
    hidden = scan.get("hidden_paths") or []
    if hidden:
        story.append(_para_arabic_only(f"{L['hidden_paths']} ({len(hidden)})", h2_style))
        hp_data = [[
            _para_arabic_only(L["status_col"], cell_style),
            _para_arabic_only(L["path_col"], cell_style),
            _para_arabic_only(L["type_col"], cell_style),
            _para_arabic_only(L["size_col"], cell_style),
        ]]
        for hp in hidden[:50]:
            hp_data.append([
                _para_simple(str(hp.get("status", "")), cell_style),
                _para_simple(_safe_text(hp.get("path", ""))[:50], cell_style),
                _para_simple(_safe_text(hp.get("type", ""))[:25], cell_style),
                _para_simple(f"{hp.get('size', 0)}b", cell_style),
            ])
        hp_table = Table(hp_data, colWidths=[0.7 * inch, 3 * inch, 1.8 * inch, 1 * inch])
        hp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), AMBER),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
        ]))
        story.append(hp_table)
        story.append(Spacer(1, 12))

    # ------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------
    story.append(_para_arabic_only(f"{L['findings']} ({len(findings)})", h2_style))
    if not findings:
        story.append(_para_arabic_only(L["no_vulns"], body_style))
    else:
        data = [[
            _para_arabic_only(L["num_col"], cell_style),
            _para_arabic_only(L["severity"], cell_style),
            _para_arabic_only(L["class_col"], cell_style),
            _para_arabic_only(L["subtype_col"], cell_style),
            _para_arabic_only(L["url_col"], cell_style),
        ]]
        for i, f in enumerate(findings[:50], 1):
            data.append([
                _para_simple(str(i), cell_style),
                _para_simple(_safe_text(f.get("severity", "info")), cell_style),
                _para_simple(_safe_text(f.get("vuln_class", "")), cell_style),
                _para_simple(_safe_text(f.get("subtype", "")), cell_style),
                _para_simple(_safe_text(f.get("url", ""))[:60], cell_style),
            ])
        table = Table(data, colWidths=[0.4 * inch, 1 * inch, 1.2 * inch, 1 * inch, 3.3 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), AMBER),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
        ]))
        story.append(table)

    # ------------------------------------------------------------
    # AI Plan
    # ------------------------------------------------------------
    if scan.get("ai_plan"):
        story.append(PageBreak())
        story.append(_para_arabic_only(L["ai_plan"], h2_style))
        try:
            plan = json.loads(scan["ai_plan"]) if isinstance(scan["ai_plan"], str) else scan["ai_plan"]
            plan_text = json.dumps(plan, indent=2, ensure_ascii=False)
            for line in plan_text.split("\n")[:200]:
                story.append(_para_simple(line, code_style))
        except Exception:
            story.append(_para_simple(_safe_text(scan["ai_plan"]), code_style))

    doc.build(story)
    return output_path


@router.get("/{scan_id}/export/pdf")
async def export_scan_pdf(scan_id: int, user: dict = Depends(get_current_user)):
    scan = nightfall_db.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = nightfall_db.get_findings(scan_id=scan_id)
    filename = f"falcon_scan_{scan_id}_{int(datetime.utcnow().timestamp())}.pdf"
    output_path = str(EXPORT_DIR / filename)
    try:
        generate_pdf(scan, findings, output_path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")
    return FileResponse(output_path, media_type="application/pdf", filename=filename)