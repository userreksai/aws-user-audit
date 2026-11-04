"""Render a private Chinese CloudTrail report without HTML or external services.

The PDF uses the same normalized, redacted events as the web report. Submitted
parameters and identity details remain readable across page boundaries instead
of being placed inside a single, potentially unprintable table row.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


CATEGORIES = ("新增", "修改", "删除", "Secrets Manager 查看", "登录信息", "其他操作")
NAVY = colors.HexColor("#18304D")
BLUE = colors.HexColor("#2563A6")
MUTED = colors.HexColor("#526477")
PALE = colors.HexColor("#EDF3F9")
LINE = colors.HexColor("#D6E0EB")
WIDTH = 263 * mm


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


def _json_blocks(value, paragraph):
    """Bound flowable size without dropping any character from a long JSON value."""
    text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    lines = []
    for line in text.split("\n"):
        lines.extend(line[offset:offset + 160] for offset in range(0, max(1, len(line)), 160))
    return [paragraph("\n".join(lines[index:index + 12]), "code")
            for index in range(0, len(lines), 12)]


def render_report_pdf(report: dict, path: Path, font_path: str | None = None) -> Path:
    """Write one account's complete operation details atomically, with mode 0600.

    ``report`` has the ``metadata``/``events`` schema produced by build_report.
    No AWS, SMTP, browser or network calls are made by this function.
    """
    from aws_daily_audit import redact

    if (not isinstance(report, dict) or not isinstance(report.get("metadata"), dict)
            or not isinstance(report.get("events"), list)
            or any(not isinstance(row, dict) or row.get("category") not in CATEGORIES
                   for row in report["events"])):
        raise ValueError("PDF 需要有效的 metadata 和 events 审计报告。")
    report = redact(report)
    meta, events = report["metadata"], report["events"]
    font = _font(font_path)
    styles = {
        "title": ParagraphStyle("AuditTitle", fontName=font, fontSize=21, leading=28,
                                textColor=NAVY, spaceAfter=5, wordWrap="CJK"),
        "sub": ParagraphStyle("AuditSub", fontName=font, fontSize=9, leading=14,
                              textColor=MUTED, wordWrap="CJK", spaceAfter=2),
        "body": ParagraphStyle("AuditBody", fontName=font, fontSize=9, leading=14,
                               textColor=NAVY, wordWrap="CJK", spaceAfter=3, splitLongWords=True),
        "section": ParagraphStyle("AuditSection", fontName=font, fontSize=13, leading=19,
                                  textColor=BLUE, spaceBefore=12, spaceAfter=7, keepWithNext=True),
        "event": ParagraphStyle("AuditEvent", fontName=font, fontSize=10, leading=16,
                                textColor=NAVY, spaceBefore=8, spaceAfter=4, keepWithNext=True,
                                wordWrap="CJK", splitLongWords=True),
        "label": ParagraphStyle("AuditLabel", fontName=font, fontSize=9, leading=14,
                                textColor=BLUE, spaceBefore=4, keepWithNext=True),
        "code": ParagraphStyle("AuditCode", fontName=font, fontSize=8, leading=11.5,
                               textColor=NAVY, wordWrap="CJK", splitLongWords=True,
                               leftIndent=8, rightIndent=8, spaceAfter=2),
        "head": ParagraphStyle("AuditHead", fontName=font, fontSize=8.5, leading=13,
                               textColor=colors.white, wordWrap="CJK"),
        "number": ParagraphStyle("AuditNumber", fontName=font, fontSize=16, leading=22,
                                 textColor=BLUE, alignment=TA_CENTER),
        "center": ParagraphStyle("AuditCenter", fontName=font, fontSize=9, leading=14,
                                 textColor=NAVY, alignment=TA_CENTER, wordWrap="CJK"),
    }
    p = lambda value, style="body": Paragraph(_text(value), styles[style])
    account = str(meta.get("account_id", "unknown"))
    generated = _beijing(meta.get("generated_at"))
    title = "AWS 账号操作审计日报"
    story = [p(f"{title} · {meta.get('audit_date', '')}", "title"),
             p(f"账号：{account}  {meta.get('account_name', '')}    生成时间（北京时间）：{generated}", "sub")]
    if meta.get("offline"):
        story.insert(0, p("离线输入报告 - 数据完整性未经 AWS 验证", "sub"))
    if meta.get("demo") or report.get("demo"):
        story.insert(0, p("离线演示 - 所有账号、用户与操作均为虚构", "sub"))
    if meta.get("complete") is not True:
        story.append(p("查询或事件解析不完整，请检查任务日志后补跑。", "sub"))
    # Keep the actual window explicit in the portable attachment.
    if meta.get("window_start_local") and meta.get("window_end_local_exclusive"):
        story.append(p("查询窗口（北京时间）：" + _beijing(meta["window_start_local"])
                       + " 至 " + _beijing(meta["window_end_local_exclusive"]) + "（结束时刻不含）", "sub"))
    story.append(Spacer(1, 4 * mm))
    counts = Counter(row["category"] for row in events)
    categories = [category for category in CATEGORIES if category != "其他操作" or counts[category]]
    cards = Table([[p(category, "center") for category in categories],
                   [p(f"{counts[category]:,}", "number") for category in categories]],
                  colWidths=[WIDTH / len(categories)] * len(categories))
    cards.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PALE),
                               ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                               ("INNERGRID", (0, 0), (-1, -1), 0.3, LINE),
                               ("TOPPADDING", (0, 0), (-1, -1), 6),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.extend([cards, p(f"报告事件 {len(events):,} 条；失败或含失败响应 "
                           f"{sum(bool(row.get('failed')) for row in events):,} 条。", "sub")])

    actors = defaultdict(Counter)
    for row in events:
        actors[str(row.get("actor", "未知身份"))][row["category"]] += 1
    story.append(p("按操作者汇总", "section"))
    if actors:
        table_rows = [[p("操作者", "head")] + [p(category, "head") for category in categories]]
        for actor, values in sorted(actors.items()):
            table_rows.append([p(actor)] + [p(str(values[category]), "center") for category in categories])
        table = LongTable(table_rows, colWidths=[80 * mm] + [183 * mm / len(categories)] * len(categories),
                          repeatRows=1, splitInRow=1, hAlign="LEFT")
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY),
                                  ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                                  ("GRID", (0, 1), (-1, -1), 0.3, LINE),
                                  ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                  ("TOPPADDING", (0, 0), (-1, -1), 5),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(table)
    else:
        story.append(p("本次查询未取得符合报告规则的事件。", "sub"))

    for category in categories:
        if not counts[category]:
            continue
        story.append(p(f"{category} · {counts[category]:,}", "section"))
        for index, row in enumerate((item for item in events if item["category"] == category), 1):
            stamp = _beijing(row.get("time_utc") or row.get("time_local"))
            story.append(p(f"{index}. {stamp}    {row.get('actor', '未知身份')}", "event"))
            story.append(p("操作信息：" + str(row.get("description", ""))
                           + " | " + str(row.get("event_name", ""))))
            story.append(p("资源：" + "; ".join(str(item) for item in (row.get("resources") or []))))
            story.append(p("区域：" + str(row.get("region", "")) + "    来源 IP："
                           + str(row.get("source_ip", "")) + "    请求结果：" + str(row.get("result", ""))))
            story.append(p("提交参数", "label"))
            story.extend(_json_blocks(row.get("parameters"), p))
            story.append(p("身份信息", "label"))
            story.extend(_json_blocks(row.get("identity"), p))
            if row.get("login_details"):
                story.append(p("登录信息", "label"))
                story.extend(_json_blocks(row["login_details"], p))
            if row.get("error_code"):
                # AWS error text can contain arbitrary request content; only the code is displayed.
                story.append(p("错误码：" + str(row["error_code"])))
            story.append(p("事件 ID：" + str(row.get("event_id", "")), "sub"))
    story.append(Spacer(1, 3 * mm))
    story.append(p("提交参数是日志记录的请求值，未必包含修改前旧值。请求无报错不证明异步变更最终完成。", "sub"))

    def footer(canvas, document):
        page_width, _ = landscape(A4)
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
        document = SimpleDocTemplate(str(temporary), pagesize=landscape(A4),
                                     leftMargin=17 * mm, rightMargin=17 * mm,
                                     topMargin=14 * mm, bottomMargin=21 * mm,
                                     title=f"{title} {account}", author="AWS Account Audit")
        document.build(story, onFirstPage=footer, onLaterPages=footer)
        if os.name == "posix":
            temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path
