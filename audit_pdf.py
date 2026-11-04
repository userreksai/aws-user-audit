"""Render a private Chinese CloudTrail report without HTML or external services.

The portable attachment renders whitelisted AWS account metadata, identity
counts, and precomputed identity/event counts. Individual event records and
request contents are never read or serialized by this module.
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
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle


CATEGORIES = ("新增", "修改", "删除", "Secrets Manager 查看", "登录信息", "其他操作")
NAVY = colors.HexColor("#18304D")
BLUE = colors.HexColor("#2563A6")
MUTED = colors.HexColor("#526477")
PALE = colors.HexColor("#EDF3F9")
LINE = colors.HexColor("#D6E0EB")
WIDTH = 176 * mm
IDENTITY_TYPES = {"IAMUser": "IAM 用户", "Role": "角色", "Root": "Root",
                  "AWSService": "AWS 服务", "IdentityCenterUser": "身份中心用户",
                  "FederatedUser": "联合身份用户", "Unknown": "未知身份"}
TRANSLATION_STATUSES = {"reviewed", "official_zh", "untranslated"}


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


def _valid_label(value, maximum):
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= maximum
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def _identity_totals(rows):
    """Compare displayed identities without relying on private identity keys."""
    result = {}
    for row in rows:
        key = (row["identity_type"], row["actor"])
        values = result.setdefault(key, {"total": 0, "failed": 0,
                                         "counts": {category: 0 for category in CATEGORIES}})
        values["total"] += row["total"]
        values["failed"] += row["failed"]
        if "category" in row:
            values["counts"][row["category"]] += row["total"]
        else:
            for category in CATEGORIES:
                values["counts"][category] += row["counts"][category]
    return result


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
    raw_actors = report.get("actors")
    if raw_actors is None and total == 0:
        raw_actors = []
    if not isinstance(raw_actors, list) or (total > 0 and not raw_actors):
        raise ValueError("报告缺少 IAM 用户/角色汇总，请使用新版程序重新生成报告。")
    actors, actor_counts, actor_total, actor_failed = [], {category: 0 for category in CATEGORIES}, 0, 0
    for raw_actor in raw_actors:
        if not isinstance(raw_actor, dict):
            raise ValueError("PDF 身份汇总必须为对象数组。")
        actor, identity_type = raw_actor.get("actor"), raw_actor.get("identity_type")
        if (not _valid_label(actor, 1024)
                or not isinstance(identity_type, str) or identity_type not in IDENTITY_TYPES
                or not isinstance(raw_actor.get("counts"), dict)):
            raise ValueError("PDF 身份名称、类型或分类汇总无效。")
        values = {category: _count(raw_actor["counts"].get(category, 0)) for category in CATEGORIES}
        row_total = _count(raw_actor.get("total"))
        row_failed = _count(raw_actor.get("failed"))
        if row_total != sum(values.values()) or row_failed > row_total:
            raise ValueError("PDF 身份汇总的分类计数、总数或失败数不一致。")
        actors.append({"actor": actor, "identity_type": identity_type,
                       "counts": values, "failed": row_failed, "total": row_total})
        for category in CATEGORIES:
            actor_counts[category] += values[category]
        actor_total += row_total
        actor_failed += row_failed
    if actor_counts != counts or actor_total != total or actor_failed != failed:
        raise ValueError("PDF 各身份汇总与 AWS 账号总计不一致，请重新生成报告。")
    raw_actor_events = report.get("actor_events")
    if raw_actor_events is None and total == 0:
        raw_actor_events = []
    if not isinstance(raw_actor_events, list) or (total > 0 and not raw_actor_events):
        raise ValueError("报告缺少用户操作与事件汇总，请使用新版程序重新生成报告。")
    actor_events = []
    for raw_event in raw_actor_events:
        if not isinstance(raw_event, dict):
            raise ValueError("PDF 用户事件汇总必须为对象数组。")
        actor, identity_type = raw_event.get("actor"), raw_event.get("identity_type")
        source, event_name = raw_event.get("source"), raw_event.get("event_name")
        event_label, status = raw_event.get("event_label"), raw_event.get("translation_status")
        category = raw_event.get("category")
        if (not _valid_label(actor, 1024)
                or not isinstance(identity_type, str) or identity_type not in IDENTITY_TYPES
                or not _valid_label(source, 256) or not _valid_label(event_name, 256)
                or not _valid_label(event_label, 8192)
                or not isinstance(status, str) or status not in TRANSLATION_STATUSES
                or not isinstance(category, str) or category not in CATEGORIES):
            raise ValueError("PDF 用户事件汇总的身份、事件、翻译状态或分类无效。")
        row_total, row_failed = _count(raw_event.get("total")), _count(raw_event.get("failed"))
        if row_failed > row_total:
            raise ValueError("PDF 用户事件汇总的失败次数超过调用次数。")
        actor_events.append({"actor": actor, "identity_type": identity_type, "source": source,
                             "event_name": event_name, "event_label": event_label,
                             "translation_status": status, "category": category,
                             "total": row_total, "failed": row_failed})
    if _identity_totals(actor_events) != _identity_totals(actors):
        raise ValueError("PDF 用户事件汇总与各身份分类、调用或失败总计不一致，请重新生成报告。")
    summary = {key: meta.get(key) for key in (
        "account_id", "account_name", "audit_date", "generated_at",
        "window_start_local", "window_end_local_exclusive")}
    summary.update(counts=counts, total=total, failed=failed, actors=actors,
                   actor_events=actor_events, complete=meta["complete"],
                   offline=meta.get("offline") is True,
                   demo=meta.get("demo") is True or report.get("demo") is True)
    return summary


def _label(value, maximum=120):
    """Bound account display labels so a configured name cannot expand the report."""
    value = str(value if value is not None else "").strip()
    return value if len(value) <= maximum else value[:maximum - 1] + "…"


def render_report_pdf(report: dict, path: Path, font_path: str | None = None) -> Path:
    """Write one account's summary-only PDF atomically, with mode 0600.

    Only metadata and precomputed identity/event-count whitelists are rendered.
    The events collection is never inspected by this function.
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
        "cell": ParagraphStyle("AuditCell", fontName=font, fontSize=8.5, leading=12.5,
                               textColor=NAVY, wordWrap="CJK", splitLongWords=True),
        "head": ParagraphStyle("AuditHead", fontName=font, fontSize=8, leading=12,
                               textColor=colors.white, wordWrap="CJK", alignment=TA_CENTER),
        "center": ParagraphStyle("AuditCenter", fontName=font, fontSize=8.5, leading=12.5,
                                 textColor=NAVY, alignment=TA_CENTER, wordWrap="CJK"),
    }
    p = lambda value, style="body": Paragraph(_text(value), styles[style])
    account = _label(summary["account_id"] or "unknown", 80)
    name = _label(summary["account_name"])
    account_line = "AWS账号：" + account
    if name and name != account:
        account_line += "（" + name + "）"
    title = "AWS 账号操作审计日报"
    story = [p(f"{title} · {_label(summary['audit_date'], 32)}", "title"),
             p(account_line),
             p("生成时间（北京时间）：" + _beijing(summary["generated_at"]), "sub")]
    if summary["demo"]:
        story.insert(0, p("离线演示 - 统计次数为虚构，不代表真实账号活动", "sub"))
    if summary["offline"]:
        story.append(p("离线输入报告 - 数据完整性未经 AWS 验证", "sub"))
    if summary["window_start_local"] and summary["window_end_local_exclusive"]:
        story.append(p("查询窗口（北京时间）：" + _beijing(summary["window_start_local"])
                       + " 至 " + _beijing(summary["window_end_local_exclusive"])
                       + "（结束时刻不含）", "sub"))
    story.extend([Spacer(1, 4 * mm), p("按 IAM 用户 / 角色统计", "section")])
    labels = ["账号 / 角色", "身份类型", "新增", "修改", "删除", "Secret\n查看", "登录", "其他", "失败", "合计"]
    rows = [[p(label, "head") for label in labels]]
    for actor in summary["actors"]:
        values = [actor["counts"][category] for category in CATEGORIES] + [actor["failed"], actor["total"]]
        rows.append([p(actor["actor"], "cell"), p(IDENTITY_TYPES[actor["identity_type"]], "cell")]
                    + [p(f"{value:,}", "center") for value in values])
    total_values = [summary["counts"][category] for category in CATEGORIES] + [summary["failed"], summary["total"]]
    rows.append([p("账号合计", "cell"), p("", "cell")]
                + [p(f"{value:,}", "center") for value in total_values])
    table = LongTable(rows, colWidths=[36 * mm, 20 * mm] + [15 * mm] * 8,
                      repeatRows=1, splitInRow=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, PALE]),
        ("BACKGROUND", (0, -1), (-1, -1), PALE),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    story.append(p("用户操作与事件汇总", "section"))
    event_labels = ["账号 / 角色", "身份类型", "中文事件", "调用次数", "失败次数"]
    event_rows = [[p(label, "head") for label in event_labels]]
    for event in summary["actor_events"]:
        label = event["event_label"]
        if event["translation_status"] == "untranslated":
            label = "待补中文：" + event["event_name"] + "\n服务：" + event["source"]
        event_rows.append([p(event["actor"], "cell"),
                           p(IDENTITY_TYPES[event["identity_type"]], "cell"), p(label, "cell"),
                           p(f"{event['total']:,}", "center"), p(f"{event['failed']:,}", "center")])
    if summary["actor_events"]:
        event_table = LongTable(event_rows, colWidths=[36 * mm, 20 * mm, 90 * mm, 15 * mm, 15 * mm],
                                repeatRows=1, splitInRow=1, hAlign="LEFT")
        event_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(event_table)
    else:
        story.append(p("本报告没有可汇总的用户事件。", "sub"))
    story.extend([Spacer(1, 4 * mm),
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
