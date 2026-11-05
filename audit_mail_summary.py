"""Render per-account resource summaries for the email body only.

Only account metadata and the normalized resource-summary helper are consumed.
The PDF renderer, raw events and SMTP delivery are deliberately independent.
"""
from __future__ import annotations

from html import escape

from audit_resource_summary import RESOURCE_COLUMNS, summarize_resource_operations


_IDENTITY_LABELS = {
    "Role": "角色（Role）",
    "AssumedRole": "角色（AssumedRole）",
    "Root": "Root",
    "AWSService": "AWS 服务（AWSService）",
    "IdentityCenterUser": "身份中心用户（IdentityCenterUser）",
    "FederatedUser": "联合身份用户（FederatedUser）",
    "Unknown": "未知身份（Unknown）",
}
_CELL_STYLE = "border:1px solid #cbd5e1;padding:8px;text-align:right;vertical-align:top;"
_NAME_STYLE = "border:1px solid #cbd5e1;padding:8px;text-align:left;vertical-align:top;word-break:break-word;"
_HEAD_STYLE = "border:1px solid #cbd5e1;padding:8px;background-color:#f1f5f9;text-align:left;vertical-align:top;"


def _line(value):
    """Keep labels on one line without truncating any identity or account tag."""
    if not isinstance(value, str):
        return ""
    return "".join(character if ord(character) >= 32 and ord(character) != 127 else " "
                   for character in value).strip()


def _sections(reports):
    reports = [reports] if isinstance(reports, dict) else reports
    if not isinstance(reports, list) or not reports:
        raise ValueError("邮件资源汇总需要至少一份账号报告。")
    for report in reports:
        if not isinstance(report, dict) or not isinstance(report.get("metadata"), dict):
            raise ValueError("邮件资源汇总需要有效的账号 metadata。")
        meta = report["metadata"]
        account = _line(meta.get("account_id")) or "未知账号"
        tag = _line(meta.get("account_tag"))
        heading = account + "-" + tag if tag else account
        status = ("查询状态：所列查询完成。" if meta.get("complete") is True else
                  "查询状态：不完整；部分查询或解析失败，请检查任务日志。")
        yield heading, status, summarize_resource_operations(report)


def _identity(row):
    actor = _line(row.get("actor")) or "未知身份"
    kind = _line(row.get("identity_type")) or "Unknown"
    if kind == "IAMUser":
        return actor
    label = _IDENTITY_LABELS.get(kind, "身份（" + kind + "）")
    return label + "：" + actor


def _counts(row):
    """Read only the seven fixed aggregate counts from the helper result."""
    values = row["counts"]
    return [str(values[column]) for column in RESOURCE_COLUMNS]


def _text_cell(value):
    # Escaped pipes keep a label from masquerading as additional table columns.
    return value.replace("\\", "\\\\").replace("|", "\\|")


def render_resource_tables_text(reports):
    """Return all accounts and identities as readable pipe-separated tables."""
    sections = []
    for heading, status, summary in _sections(reports):
        lines = [heading, status]
        if not summary["available"]:
            lines.append("资源操作统计不可用；请使用新版程序重新生成报告。")
        elif not summary["rows"]:
            lines.append("本账号无报告事件。")
        else:
            lines.append(" | ".join(["具体用户", *RESOURCE_COLUMNS]))
            lines.append(" | ".join(["---"] * (len(RESOURCE_COLUMNS) + 1)))
            for row in summary["rows"]:
                lines.append(" | ".join([_text_cell(_identity(row)), *_counts(row)]))
        sections.append("\n".join(lines))
    return "\n\n".join(sections)


def render_resource_tables_html(reports):
    """Return escaped email HTML fragments with inline-styled real tables."""
    sections = []
    for heading, status, summary in _sections(reports):
        parts = ['<div style="margin:24px 0;">',
                 '<h3 style="margin:0 0 8px;font-size:16px;">' + escape(heading) + '</h3>',
                 '<p style="margin:0 0 12px;">' + escape(status) + '</p>']
        if not summary["available"]:
            parts.append('<p style="margin:0;">资源操作统计不可用；请使用新版程序重新生成报告。</p>')
        elif not summary["rows"]:
            parts.append('<p style="margin:0;">本账号无报告事件。</p>')
        else:
            parts.append('<table style="border-collapse:collapse;width:100%;font-size:13px;">')
            parts.append('<thead><tr>')
            for column in ["具体用户", *RESOURCE_COLUMNS]:
                parts.append('<th scope="col" style="' + _HEAD_STYLE + '">' + escape(column) + '</th>')
            parts.append('</tr></thead><tbody>')
            for row in summary["rows"]:
                parts.append('<tr><td style="' + _NAME_STYLE + '">' + escape(_identity(row)) + '</td>')
                for value in _counts(row):
                    parts.append('<td style="' + _CELL_STYLE + '">' + escape(value) + '</td>')
                parts.append('</tr>')
            parts.append('</tbody></table>')
        parts.append('</div>')
        sections.append("".join(parts))
    return "\n".join(sections)
