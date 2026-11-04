"""Render a private Chinese CloudTrail report without HTML or external services.

The portable attachment renders only whitelisted account metadata and aggregate
counts. Individual events, actors, API names and request contents are never read
or serialized by this module.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import os
from pathlib import Path
import tempfile
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


CATEGORIES = ("新增", "修改", "删除", "Secrets Manager 查看", "登录信息", "其他操作")
NAVY = colors.HexColor("#18304D")
BLUE = colors.HexColor("#2563A6")
MUTED = colors.HexColor("#526477")
PALE = colors.HexColor("#EDF3F9")
LINE = colors.HexColor("#D6E0EB")
WIDTH = 176 * mm


def _font(font_path=None):
    if not font_path:
        candidates = (
            Path("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"),
            Path("/usr/share/fonts/truetype/arphic/uming.ttc"),
            Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts/simsun.ttc",
        )
        font_path = next((str(path) for path in candidates if path.is_file()), None)
    if font_path:
        path = Path(font_path).expanduser().resolve()
        if not path.is_file():
            raise ValueError("PDF_FONT_PATH 指定的字体文件不存在。")
        name = "AuditCjk-" + sha256(str(path).encode()).hexdigest()[:12]
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(path), subfontIndex=0))
        return name
    name = "STSong-Light"
    if name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(UnicodeCIDFont(name))
    return name


def _text(value):
    value = str(value if value is not None else "")
    # XML control characters are shown explicitly, never interpreted as markup.
    value = "".join(char if ord(char) >= 32 or char in "\n\t" else "\\u%04x" % ord(char)
                    for char in value)
    return escape(value).replace("\t", "    ").replace("\n", "<br/>")


def _beijing(value):
    if not value:
        return "未提供"
    stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("PDF 时间必须包含时区。")
    return stamp.astimezone(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")


def _count(value):
    if type(value) is not int or value < 0:
        raise ValueError("PDF 汇总计数必须为非负整数。")
    return value


def _summary(report):
    """Copy only the display whitelist; never traverse the events collection."""
    if not isinstance(report, dict) or not isinstance(report.get("metadata"), dict):
        raise ValueError("PDF 需要有效的 metadata 汇总信息。")
    meta = report["metadata"]
    raw = meta.get("counts")
    if not isinstance(raw, dict) or type(meta.get("complete")) is not bool:
        raise ValueError("PDF 需要有效的分类汇总与完整性状态。")
    counts = {category: _count(raw.get(category, 0)) for category in CATEGORIES}
    total = _count(meta.get("total", sum(counts.values())))
    failed = _count(meta.get("failed_or_partial", 0))
    if total != sum(counts.values()) or failed > total:
        raise ValueError("PDF 总事件数、分类计数或失败次数不一致。")
    summary = {key: meta.get(key) for key in (
        "account_id", "account_name", "audit_date", "generated_at",
        "window_start_local", "window_end_local_exclusive")}
    summary.update(counts=counts, total=total, failed=failed, complete=meta["complete"],
                   offline=meta.get("offline") is True,
                   demo=meta.get("demo") is True or report.get("demo") is True)
    return summary


def _label(value, maximum=120):
    """Bound account display labels so a configured name cannot expand the report."""
    value = str(value if value is not None else "").strip()
    return value if len(value) <= maximum else value[:maximum - 1] + "…"


def render_report_pdf(report: dict, path: Path, font_path: str | None = None) -> Path:
    """Write one account's summary-only PDF atomically, with mode 0600.

    Only the metadata whitelist and aggregate counts are rendered. The events
    collection can be arbitrarily large and is never inspected by this function.
    """
    summary = _summary(report)
    font = _font(font_path)
    styles = {
        "title": ParagraphStyle("AuditTitle", fontName=font, fontSize=20, leading=27,
                                textColor=NAVY, spaceAfter=10, wordWrap="CJK"),
        "sub": ParagraphStyle("AuditSub", fontName=font, fontSize=9, leading=15,
                              textColor=MUTED, wordWrap="CJK", spaceAfter=4),
        "body": ParagraphStyle("AuditBody", fontName=font, fontSize=11, leading=18,
                               textColor=NAVY, wordWrap="CJK", spaceAfter=5),
        "section": ParagraphStyle("AuditSection", fontName=font, fontSize=13, leading=19,
                                  textColor=BLUE, spaceBefore=10, spaceAfter=8),
        "number": ParagraphStyle("AuditNumber", fontName=font, fontSize=24, leading=31,
                                 textColor=BLUE, alignment=TA_CENTER),
        "center": ParagraphStyle("AuditCenter", fontName=font, fontSize=10, leading=16,
                                 textColor=NAVY, alignment=TA_CENTER, wordWrap="CJK"),
    }
    p = lambda value, style="body": Paragraph(_text(value), styles[style])
    account = _label(summary["account_id"] or "unknown", 80)
    name = _label(summary["account_name"])
    account_line = "账号：" + account
    if name and name != account:
        account_line += "（" + name + "）"
    title = "AWS 账号操作审计日报"
    story = [p(f"{title} · {_label(summary['audit_date'], 32)}", "title"),
             p(account_line),
             p("生成时间（北京时间）：" + _beijing(summary["generated_at"]), "sub")]
    if summary["demo"]:
        story.insert(0, p("离线演示 - 所有账号与统计均为虚构", "sub"))
    if summary["offline"]:
        story.append(p("离线输入报告 - 数据完整性未经 AWS 验证", "sub"))
    if summary["window_start_local"] and summary["window_end_local_exclusive"]:
        story.append(p("查询窗口（北京时间）：" + _beijing(summary["window_start_local"])
                       + " 至 " + _beijing(summary["window_end_local_exclusive"])
                       + "（结束时刻不含）", "sub"))
    story.extend([Spacer(1, 5 * mm), p("账号操作统计", "section")])
    rows = []
    for offset in (0, 3):
        selected = CATEGORIES[offset:offset + 3]
        rows.append([p(category, "center") for category in selected])
        rows.append([p(f"{summary['counts'][category]:,}", "number") for category in selected])
    cards = Table(rows, colWidths=[WIDTH / 3] * 3)
    cards.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.extend([cards, Spacer(1, 6 * mm),
                  p(f"报告事件 {summary['total']:,} 条；其中失败或含失败响应 {summary['failed']:,} 条。"),
                  p("查询状态：所列查询完成。" if summary["complete"]
                    else "查询或事件解析不完整，请检查任务日志后补跑。", "sub")])
    if summary["total"] == 0:
        story.append(p("未取得符合报告规则的事件，请结合查询状态判断。", "sub"))

    def footer(canvas, document):
        page_width, _ = A4
        canvas.saveState()
        canvas.setStrokeColor(LINE)
        canvas.line(17 * mm, 14 * mm, page_width - 17 * mm, 14 * mm)
        canvas.setFont(font, 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(17 * mm, 9.5 * mm, "AWS 账号审计 | " + account[:36])
        canvas.drawRightString(page_width - 17 * mm, 9.5 * mm, f"第 {document.page} 页")
        canvas.restoreState()

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".audit-pdf-", suffix=".pdf", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        document = SimpleDocTemplate(str(temporary), pagesize=A4,
                                     leftMargin=17 * mm, rightMargin=17 * mm,
                                     topMargin=18 * mm, bottomMargin=21 * mm,
                                     title=f"{title} {account}", author="AWS Account Audit")
        document.build(story, onFirstPage=footer, onLaterPages=footer)
        if os.name == "posix":
            temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path
