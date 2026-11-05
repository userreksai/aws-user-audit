"""Private JSON/JSONC settings and TLS-protected PDF email delivery.

Importing this module and validating settings never contacts SMTP. Error messages
name fields or delivery stages, never credentials or provider response text.
"""
from __future__ import annotations

from copy import deepcopy
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr
import json
import math
from pathlib import Path
import re
import smtplib
import ssl


DEFAULTS = {
    "SMTP_HOST": "",
    "SMTP_PORT": 465,
    "SMTP_USERNAME": "",
    "SMTP_AUTH_CODE": "",
    "SMTP_SECURITY": "ssl",
    "SMTP_TIMEOUT": 30,
    "MAIL_RECIPIENTS": [],
    "MAIL_CC": [],
    "MAIL_SUBJECT": "AWS账号操作审计日报",
    "MAIL_SENDER_NAME": "",
    "PDF_FONT_PATH": "",
    "AUTO_MAIL_MAX_PER_DAY": 1,
    "LARK_ALERTS_ENABLED": False,
}


class MailDeliveryError(RuntimeError):
    """Sanitized failure; uncertain submission must not be blindly retried."""

    def __init__(self, message, *, delivery_uncertain=False, refused=None):
        super().__init__(message)
        self.delivery_uncertain = delivery_uncertain
        self.refused = list(refused or [])


def _header(value, name, *, allow_empty=False):
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} 必须为无控制字符的单行字符串")
    value = value.strip()
    if not value and not allow_empty:
        raise ValueError(f"请填写 {name}")
    return value


def _address(value, name):
    value = _header(value, name)
    display_name, parsed = parseaddr(value)
    if display_name or parsed != value or not re.fullmatch(r"[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+", value):
        raise ValueError(f"{name} 必须为邮箱地址，不含显示名称")
    return value


def _addresses(values, name, *, required=False):
    if not isinstance(values, list) or (required and not values):
        raise ValueError(f"{name} 必须为{'非空' if required else ''}邮箱地址数组")
    result, seen = [], set()
    for value in values:
        address = _address(value, name)
        if address.casefold() not in seen:
            seen.add(address.casefold())
            result.append(address)
    return result


def validate_mail_config(config, require_complete=True):
    """Return isolated validated settings, optionally allowing a blank template."""
    if not isinstance(config, dict):
        raise ValueError("邮件配置必须为对象")
    result = {key: deepcopy(config.get(key, value)) for key, value in DEFAULTS.items()}
    for key in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_AUTH_CODE", "MAIL_SUBJECT", "MAIL_SENDER_NAME", "PDF_FONT_PATH"):
        result[key] = _header(result[key], key, allow_empty=key != "MAIL_SUBJECT")
    host = result["SMTP_HOST"]
    if host and (any(char.isspace() for char in host) or any(char in host for char in "/@\\?#")):
        raise ValueError("SMTP_HOST 必须为邮件服务器主机名或地址，不含协议和路径")
    if result["SMTP_USERNAME"]:
        result["SMTP_USERNAME"] = _address(result["SMTP_USERNAME"], "SMTP_USERNAME")
    port = result["SMTP_PORT"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("SMTP_PORT 必须为 1-65535 的整数")
    timeout = result["SMTP_TIMEOUT"]
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 600 or not math.isfinite(timeout)):
        raise ValueError("SMTP_TIMEOUT 必须大于 0 且不超过 600 秒")
    if result["SMTP_SECURITY"] not in ("ssl", "starttls"):
        raise ValueError("SMTP_SECURITY 仅支持 ssl 或 starttls")
    result["MAIL_RECIPIENTS"] = _addresses(result["MAIL_RECIPIENTS"], "MAIL_RECIPIENTS")
    recipients = {value.casefold() for value in result["MAIL_RECIPIENTS"]}
    result["MAIL_CC"] = [value for value in _addresses(result["MAIL_CC"], "MAIL_CC")
                         if value.casefold() not in recipients]
    limit = result["AUTO_MAIL_MAX_PER_DAY"]
    if type(limit) is not int or limit not in (0, 1):
        raise ValueError("AUTO_MAIL_MAX_PER_DAY 仅支持 0 或 1")
    if type(result["LARK_ALERTS_ENABLED"]) is not bool:
        raise ValueError("LARK_ALERTS_ENABLED 必须为布尔值")
    if require_complete:
        for key in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_AUTH_CODE"):
            if not result[key]:
                raise ValueError(f"请填写 {key}")
        if not result["MAIL_RECIPIENTS"]:
            raise ValueError("MAIL_RECIPIENTS 至少配置一个收件人")
    return result


def strip_json_comments(text):
    """Strip JSONC comments without changing quoted strings or token positions."""
    if not isinstance(text, str):
        raise ValueError("配置内容必须为字符串")
    result = []
    position, length = 0, len(text)
    in_string = escaped = False
    while position < length:
        char = text[position]
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            position += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            position += 1
            continue
        if text[position:position + 2] == "//":
            result.extend((" ", " "))
            position += 2
            while position < length and text[position] not in "\r\n":
                result.append(" ")
                position += 1
            continue
        if text[position:position + 2] == "/*":
            result.extend((" ", " "))
            position += 2
            while position < length:
                if text[position:position + 2] == "*/":
                    result.extend((" ", " "))
                    position += 2
                    break
                result.append(text[position] if text[position] in "\r\n" else " ")
                position += 1
            else:
                raise ValueError("配置块注释未闭合")
            continue
        result.append(char)
        position += 1
    if in_string:
        raise ValueError("配置字符串未闭合")
    return "".join(result)


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("配置存在重复字段")
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise ValueError("配置不能包含非 JSON 数值常量")


def load_mail_config(path, require_complete=True):
    """Read JSON/JSONC locally; resolve an optional font beside this file."""
    try:
        source = Path(path).expanduser().resolve()
        content = strip_json_comments(source.read_text(encoding="utf-8-sig"))
        raw = json.loads(content, object_pairs_hook=_unique_json_pairs, parse_constant=_reject_json_constant)
    except (OSError, RuntimeError):
        raise ValueError("无法读取邮件配置文件，请检查路径和权限") from None
    except (ValueError, UnicodeError, TypeError):
        raise ValueError("邮件配置不是有效且无重复字段的 UTF-8 JSON/JSONC，请检查语法和注释闭合") from None
    result = validate_mail_config(raw, require_complete=require_complete)
    if result["PDF_FONT_PATH"]:
        try:
            font = Path(result["PDF_FONT_PATH"]).expanduser()
            result["PDF_FONT_PATH"] = str((source.parent / font).resolve() if not font.is_absolute() else font.resolve())
        except (OSError, RuntimeError):
            raise ValueError("PDF_FONT_PATH 无法解析，请检查字体路径") from None
    return result


def send_reports(config, attachments, body, subject=None, *, html_body=None):
    """Submit PDF attachments once; SMTP acceptance is not inbox delivery."""
    config = validate_mail_config(config)
    host, port = config["SMTP_HOST"], config["SMTP_PORT"]
    sender, password = config["SMTP_USERNAME"], config["SMTP_AUTH_CODE"]
    mail_subject = _header(subject if subject is not None else config["MAIL_SUBJECT"], "MAIL_SUBJECT")
    envelope = config["MAIL_RECIPIENTS"] + config["MAIL_CC"]
    if not isinstance(body, str):
        raise ValueError("邮件正文必须为字符串")
    if html_body is not None and not isinstance(html_body, str):
        raise ValueError("HTML 邮件正文必须为字符串")
    if not isinstance(attachments, (list, tuple)) or not attachments:
        raise ValueError("邮件至少需要一个 PDF 附件")
    message = EmailMessage()
    message["From"] = formataddr((config["MAIL_SENDER_NAME"], sender))
    message["To"] = ", ".join(config["MAIL_RECIPIENTS"])
    if config["MAIL_CC"]:
        message["Cc"] = ", ".join(config["MAIL_CC"])
    message["Subject"] = mail_subject
    message["Date"] = formatdate(localtime=False, usegmt=True)
    message["Message-ID"] = make_msgid()
    message.set_content(body)
    if html_body is not None:
        message.add_alternative(html_body, subtype="html")
    names = set()
    for item in attachments:
        path = Path(item)
        name = _header(path.name, "PDF 文件名")
        if name.casefold() in names:
            raise ValueError("PDF 附件文件名不能重复")
        names.add(name.casefold())
        try:
            content = path.read_bytes()
        except OSError:
            raise ValueError("无法读取 PDF 附件，请检查路径和权限") from None
        if path.suffix.lower() != ".pdf" or not content.startswith(b"%PDF-"):
            raise ValueError("附件必须为 PDF 文件")
        message.add_attachment(content, maintype="application", subtype="pdf", filename=name)
    smtp, submitted = None, False
    stage = "连接邮件服务器"
    try:
        context = ssl.create_default_context()
        if config["SMTP_SECURITY"] == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=config["SMTP_TIMEOUT"], context=context)
        else:
            smtp = smtplib.SMTP(host, port, timeout=config["SMTP_TIMEOUT"])
        code, _ = smtp.ehlo()
        if code != 250:
            raise MailDeliveryError("邮件服务器 EHLO 未成功")
        if config["SMTP_SECURITY"] == "starttls":
            stage = "建立 STARTTLS"
            smtp.starttls(context=context)
            code, _ = smtp.ehlo()
            if code != 250:
                raise MailDeliveryError("邮件服务器 TLS 后 EHLO 未成功")
        stage = "SMTP 认证"
        smtp.login(sender, password)
        stage = "提交邮件"
        submitted = True
        refused = smtp.send_message(message, from_addr=sender, to_addrs=envelope)
        if refused:
            raise MailDeliveryError("部分收件人被拒绝，其他收件人可能已收到；请核实后手动重发。",
                                    delivery_uncertain=True,
                                    refused=[address for address in envelope if address in refused])
        return {"smtp_accepted": True, "recipients": envelope,
                "message_id": str(message["Message-ID"]), "attachment_count": len(attachments)}
    except smtplib.SMTPRecipientsRefused:
        raise MailDeliveryError("邮件服务器拒绝所有收件人；PDF 已保留。") from None
    except (OSError, smtplib.SMTPException) as exc:
        raise MailDeliveryError(f"{stage}失败（{type(exc).__name__}）；PDF 已保留。",
                                delivery_uncertain=submitted) from None
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except (OSError, smtplib.SMTPException):
                pass
            finally:
                try:
                    smtp.close()
                except (OSError, smtplib.SMTPException):
                    pass
