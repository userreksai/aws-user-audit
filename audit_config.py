"""Private JSONC settings for multi-account CloudTrail audit delivery."""
from __future__ import annotations

import json
from pathlib import Path
import posixpath
import re
import unicodedata
from urllib.parse import urlsplit

DEFAULT_INSTALL_DIR = "/usr/local/aws-user-audit"


def _text(value, name, *, required=False):
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(name + " 必须为无控制字符的字符串")
    value = value.strip()
    if required and not value:
        raise ValueError(name + " 不能为空")
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("配置存在重复字段")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("非 JSON 数值常量")


def _overlap(first, second):
    return first == second or first in second.parents or second in first.parents


def _publish_path(value, source):
    """Keep the Nginx-readable tree separate from private inputs and system trees."""
    text = _text(value, "PUBLISH_DIRECTORY", required=True)
    # Apply the Linux deployment boundary even in Windows-side configuration tests.
    def safe_tree(logical):
        if (logical in {"/", "/usr", "/usr/local", "/var", "/var/lib", "/opt", "/srv", "/home", "/root", "/tmp"}
                or any(logical == prefix or logical.startswith(prefix + "/")
                       for prefix in ("/etc", "/proc", "/sys", "/dev", "/bin", "/sbin", "/lib", "/lib64",
                                      "/boot", "/run", "/app", "/root/.aws", "/usr/bin", "/usr/sbin",
                                      "/usr/lib", "/usr/lib64", "/usr/share", "/usr/local/bin", "/usr/local/sbin"))):
            raise ValueError("PUBLISH_DIRECTORY 必须使用独立网页目录，不能使用系统敏感目录")
    if text.startswith("/"):
        safe_tree(posixpath.normpath(text))
    item = Path(text).expanduser()
    candidate = item if item.is_absolute() else source.parent / item
    for component in (candidate, *candidate.parents):
        if component.is_symlink() or (hasattr(component, "is_junction") and component.is_junction()):
            raise ValueError("PUBLISH_DIRECTORY 及其父目录不能为符号链接或 junction")
    destination = candidate.resolve()
    safe_tree(destination.as_posix())
    if destination == Path(destination.anchor):
        raise ValueError("PUBLISH_DIRECTORY 必须使用独立网页目录")
    if destination.exists() and not destination.is_dir():
        raise ValueError("PUBLISH_DIRECTORY 必须为网页目录")
    return str(destination)


def _report_url(value):
    value = _text(value, "REPORT_URL")
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment
                or any(char.isspace() or char in "{}<>" or ord(char) in {34, 39, 92, 96}
                       or unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value)):
            raise ValueError
        parsed.port
    except (ValueError, TypeError):
        raise ValueError("REPORT_URL 必须为不含凭据、查询参数、片段或模板的 HTTP/HTTPS 网页地址") from None
    return value


def load_config(path, *, require_mail=False):
    """Read and validate without retrieving credentials or contacting services."""
    from audit_mail import strip_json_comments, validate_mail_config

    source = Path(path).expanduser().resolve()
    try:
        raw = json.loads(strip_json_comments(source.read_text(encoding="utf-8-sig")),
                         object_pairs_hook=_unique, parse_constant=_constant)
    except (OSError, ValueError, UnicodeError):
        raise ValueError("无法读取有效的 UTF-8 JSON/JSONC 配置；请检查路径、权限和语法") from None
    if not isinstance(raw, dict):
        raise ValueError("配置必须为 JSON 对象")
    result = dict(raw)
    result.update(validate_mail_config(raw, require_complete=require_mail))

    def local_path(key, default):
        text = _text(raw.get(key, default), key, required=True)
        item = Path(text).expanduser()
        return str((source.parent / item).resolve() if not item.is_absolute() else item.resolve())

    result["OUTPUT_DIRECTORY"] = local_path("OUTPUT_DIRECTORY", "reports")
    result["STATE_DIRECTORY"] = local_path("STATE_DIRECTORY", ".state")
    font = _text(raw.get("PDF_FONT_PATH", ""), "PDF_FONT_PATH")
    result["PDF_FONT_PATH"] = local_path("PDF_FONT_PATH", font) if font else ""
    result["TIMEZONE"] = _text(raw.get("TIMEZONE", "Asia/Shanghai"), "TIMEZONE")
    if result["TIMEZONE"] != "Asia/Shanghai":
        raise ValueError("TIMEZONE 固定为 Asia/Shanghai（北京时间）")
    from audit_schedule import DEFAULT_MAIL_TIME, DEFAULT_START_TIME, DEFAULT_END_TIME, parse_clock
    for key, default in (("DAILY_MAIL_TIME", DEFAULT_MAIL_TIME), ("REPORT_START_TIME", DEFAULT_START_TIME),
                         ("REPORT_END_TIME", DEFAULT_END_TIME)):
        result[key] = _text(raw.get(key, default), key, required=True)
        parse_clock(result[key], key)
    if result["DAILY_MAIL_TIME"] < result["REPORT_END_TIME"]:
        raise ValueError("DAILY_MAIL_TIME 不能早于 REPORT_END_TIME，请在统计窗口结束后启动日报")
    result["ACCOUNT_CONCURRENCY"] = raw.get("ACCOUNT_CONCURRENCY", 7)
    if type(result["ACCOUNT_CONCURRENCY"]) is not int or not 1 <= result["ACCOUNT_CONCURRENCY"] <= 32:
        raise ValueError("ACCOUNT_CONCURRENCY 必须为 1-32 的整数")
    result["AUTO_MAIL_MAX_PER_DAY"] = raw.get("AUTO_MAIL_MAX_PER_DAY", 1)
    if type(result["AUTO_MAIL_MAX_PER_DAY"]) is not int or result["AUTO_MAIL_MAX_PER_DAY"] not in (0, 1):
        raise ValueError("AUTO_MAIL_MAX_PER_DAY 仅支持 0 或 1")
    from lark_notify import DEFAULT_REPORT_URL, validate_webhook_url
    result["HTML_REPORT_ENABLED"] = raw.get("HTML_REPORT_ENABLED", True)
    result["LARK_REPORT_ENABLED"] = raw.get("LARK_REPORT_ENABLED", False)
    for key in ("HTML_REPORT_ENABLED", "LARK_REPORT_ENABLED"):
        if type(result[key]) is not bool:
            raise ValueError(key + " 必须为 true 或 false")
    result["PUBLISH_DIRECTORY"] = _publish_path(raw.get("PUBLISH_DIRECTORY", "index"), source)
    result["REPORT_URL"] = _report_url(raw.get("REPORT_URL", DEFAULT_REPORT_URL))
    result["LARK_ALERTS_ENABLED"] = raw.get("LARK_ALERTS_ENABLED", False)
    if type(result["LARK_ALERTS_ENABLED"]) is not bool:
        raise ValueError("LARK_ALERTS_ENABLED 必须为 true 或 false")
    for key in ("LARK_WEBHOOK_URL", "LARK_SIGNING_SECRET"):
        result[key] = _text(raw.get(key, ""), key)
    if result["LARK_WEBHOOK_URL"]:
        try:
            validate_webhook_url(result["LARK_WEBHOOK_URL"])
        except ValueError:
            raise ValueError("LARK_WEBHOOK_URL 必须为有效的 Lark/飞书 HTTPS 机器人地址") from None
    elif result["LARK_ALERTS_ENABLED"] or result["LARK_REPORT_ENABLED"]:
        raise ValueError("开启异常告警或日报通知须填写 LARK_WEBHOOK_URL")
    if result["LARK_REPORT_ENABLED"] and not result["HTML_REPORT_ENABLED"]:
        raise ValueError("开启 LARK_REPORT_ENABLED 须同时开启 HTML_REPORT_ENABLED")
    if result["LARK_REPORT_ENABLED"] and not result["REPORT_URL"]:
        raise ValueError("开启日报通知须填写 REPORT_URL")

    if Path(result["OUTPUT_DIRECTORY"]) == Path(result["STATE_DIRECTORY"]):
        raise ValueError("报告目录与状态目录必须分开")
    for key in ("OUTPUT_DIRECTORY", "STATE_DIRECTORY"):
        destination = Path(result[key])
        if source == destination or destination in source.parents:
            raise ValueError(key + " 不能包含或覆盖私有配置文件")
    publish = Path(result["PUBLISH_DIRECTORY"])
    if _overlap(publish, source):
        raise ValueError("PUBLISH_DIRECTORY 不能包含或覆盖私有配置文件")
    for key in ("OUTPUT_DIRECTORY", "STATE_DIRECTORY"):
        if _overlap(publish, Path(result[key])):
            raise ValueError("PUBLISH_DIRECTORY 必须与 OUTPUT_DIRECTORY、STATE_DIRECTORY 分开且不能互相嵌套")
    accounts = raw.get("ACCOUNTS")
    if not isinstance(accounts, list) or not accounts:
        raise ValueError("ACCOUNTS 必须为非空账号数组")
    normalized, names, identities = [], set(), set()
    for position, item in enumerate(accounts, 1):
        prefix = f"ACCOUNTS[{position}]"
        if not isinstance(item, dict):
            raise ValueError(prefix + " 必须为对象")
        account = {}
        for key in ("NAME", "ACCOUNT_ID", "TAG", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
            account[key] = _text(item.get(key, ""), prefix + "." + key, required=key in ("NAME", "ACCOUNT_ID"))
        if (len(account["TAG"]) > 120
                or any(unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
                       for char in item.get("TAG", ""))):
            raise ValueError(prefix + ".TAG 必须为不超过 120 字符且无控制字符的字符串")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", account["NAME"]):
            raise ValueError(prefix + ".NAME 仅允许 1-80 位字母、数字、下划线和连字符")
        if not re.fullmatch(r"[0-9]{12}", account["ACCOUNT_ID"]):
            raise ValueError(prefix + ".ACCOUNT_ID 必须为 12 位数字")
        if account["NAME"].casefold() in names or account["ACCOUNT_ID"] in identities:
            raise ValueError("ACCOUNTS 的 NAME 和 ACCOUNT_ID 必须分别唯一")
        names.add(account["NAME"].casefold())
        identities.add(account["ACCOUNT_ID"])
        account["ENABLED"] = item.get("ENABLED", True)
        if type(account["ENABLED"]) is not bool:
            raise ValueError(prefix + ".ENABLED 必须为 true 或 false")
        if bool(account["AWS_ACCESS_KEY_ID"]) != bool(account["AWS_SECRET_ACCESS_KEY"]):
            raise ValueError(prefix + " 的 Access Key ID 与 Secret 必须成对填写")
        if account["AWS_PROFILE"] and account["AWS_ACCESS_KEY_ID"]:
            raise ValueError(prefix + " 不能同时填写 AWS_PROFILE 和 Access Key")
        if account["AWS_SESSION_TOKEN"] and not account["AWS_ACCESS_KEY_ID"]:
            raise ValueError(prefix + " 临时 Token 需要配套 Access Key")
        regions = item.get("REGIONS", "all")
        if regions == "all":
            account["REGIONS"] = "all"
        else:
            regions = regions.split(",") if isinstance(regions, str) else regions
            if not isinstance(regions, list) or not regions or any(not isinstance(r, str) for r in regions):
                raise ValueError(prefix + ".REGIONS 必须为 all、区域数组或逗号分隔字符串")
            regions = sorted({r.strip() for r in regions})
            if any(not re.fullmatch(r"[a-z]{2,}(?:-[a-z0-9]+)+-\d+", r) for r in regions):
                raise ValueError(prefix + ".REGIONS 包含无效区域名称")
            account["REGIONS"] = regions
        normalized.append(account)
    if not any(a["ENABLED"] for a in normalized):
        raise ValueError("至少启用一个 AWS 账号")
    result["ACCOUNTS"] = normalized
    return result
