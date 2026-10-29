"""Lark 自定义机器人通知；显式调用才发送，可推送摘要或完整审计明细。"""
from __future__ import annotations

import base64
import argparse
import hashlib
import hmac
import json
import os
import re
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

DEFAULT_REPORT_URL = "https://zybocedata-pass.v668live.com/audit/"

class LarkNotificationError(RuntimeError):
    """可安全显示的推送错误，不包含 Webhook、签名或消息原文。"""


def validate_webhook_url(url):
    if not isinstance(url, str):
        raise ValueError("webhook_url 必须为字符串；请检查配置字段名称。")
    if not url:
        raise ValueError("Webhook 地址为空；请填写 webhook_url，并检查环境变量是否为空。")
    if url.startswith(("[", "<", "\"", "'", "`")) or "](" in url:
        raise ValueError("Webhook 包含 Markdown 链接、尖括号或额外引号；请只粘贴纯 HTTPS 地址。")
    if any(ch.isspace() or ch in "\u200b\ufeff\u2060" or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise ValueError("Webhook 地址含空格、换行或不可见字符；请重新复制纯地址。")
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError("Webhook 地址结构或端口格式无效；请从群机器人设置重新复制。") from None
    if parts.scheme != "https":
        raise ValueError("Webhook 必须以 https:// 开头。")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Webhook 地址不能包含用户名或密码。")
    if parts.hostname not in {"open.larksuite.com", "open.feishu.cn"}:
        raise ValueError("Webhook 域名须为 open.larksuite.com 或 open.feishu.cn，请使用机器人提供的地址。")
    if port not in (None, 443):
        raise ValueError("Webhook 端口必须为默认 HTTPS 端口 443。")
    if parts.query or parts.fragment:
        raise ValueError("Webhook 地址带有 ? 查询参数或 # 片段；请复制原始地址，不要附加参数。")
    if not re.fullmatch(r"/open-apis/bot/v2/hook/[A-Za-z0-9_-]+", parts.path):
        raise ValueError("Webhook 路径须为 /open-apis/bot/v2/hook/ 后接机器人标识；请复制完整地址。")
    if parts.path.rsplit("/", 1)[-1].upper() in {"REPLACE_WITH_YOUR_TOKEN", "YOUR_TOKEN", "REPLACE_ME"}:
        raise ValueError("Webhook 仍为模板占位地址；请将 REPLACE/YOUR_TOKEN 替换为群机器人的真实地址。")
    return url


def load_lark_config(path):
    config = {}
    target = Path(path)
    if target.exists():
        try:
            config = json.loads(target.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            raise ValueError("Lark 配置文件无法读取或不是有效 JSON。") from None
        if not isinstance(config, dict):
            raise ValueError("Lark 配置文件必须为 JSON 对象。")
    elif not os.environ.get("LARK_WEBHOOK_URL"):
        raise ValueError("未找到 Lark 配置；请创建 lark-config.json 或设置 LARK_WEBHOOK_URL。")
    if "LARK_WEBHOOK_URL" in os.environ:
        config["webhook_url"] = os.environ["LARK_WEBHOOK_URL"]
    if "LARK_SIGNING_SECRET" in os.environ:
        config["signing_secret"] = os.environ["LARK_SIGNING_SECRET"]
    source = "LARK_WEBHOOK_URL 环境变量（覆盖配置文件）" if "LARK_WEBHOOK_URL" in os.environ else "配置文件的 webhook_url"
    try:
        validate_webhook_url(config.get("webhook_url", ""))
    except ValueError as exc:
        raise ValueError(f"生效来源：{source}。{exc}") from None
    for key in ("signing_secret", "report_url_template", "title_prefix", "message_mode"):
        if key in config and not isinstance(config[key], str):
            raise ValueError(f"Lark 配置的 {key} 必须为字符串。")
    if config.get("message_mode", "overview") not in {"overview", "summary", "full"}:
        raise ValueError("Lark message_mode 必须为 overview、summary 或 full。")
    return config


def _validate_report_url(url):
    try:
        parts = urllib.parse.urlsplit(url)
        if (not isinstance(url, str) or parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.username is not None or parts.password is not None or any(ch.isspace() for ch in url)):
            raise ValueError
        parts.port
    except (ValueError, TypeError, AttributeError):
        raise ValueError("报告链接必须是有效的 HTTP/HTTPS 地址。") from None
    return url


def format_report_url(template, report):
    if not template:
        return ""
    meta = report["metadata"]
    values = {"date": str(meta["audit_date"]), "account_id": str(meta["account_id"]),
              "filename": f"{meta['audit_date']}-aws操作审计.html"}
    try:
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is not None and (name not in values or spec or conversion):
                raise ValueError
        result = template.format(**{key: urllib.parse.quote(value, safe="") for key, value in values.items()})
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("报告链接模板仅支持 {date}、{account_id}、{filename}。") from None
    return _validate_report_url(result)


def _fragment(value, limit=180):
    # 防止事件中的名字或资源名被解释为 @群成员指令。
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).replace("<", "＜").replace(">", "＞")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _beijing(value):
    if isinstance(value, datetime):
        stamp = value
    else:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("报告时间缺少时区。")
    return stamp.astimezone(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")


def build_lark_payload(report, *, report_url="", title_prefix="AWS操作审计日报"):
    if report_url:
        _validate_report_url(report_url)
    meta = report["metadata"]
    lines = [f"{_fragment(title_prefix, 100)} | {_fragment(meta['audit_date'], 20)}"]
    if meta.get("offline"):
        lines.append("【离线示例数据，非真实 AWS 账号审计】")
    if not meta.get("complete", False):
        lines.append(f"【采集不完整】存在 {len(meta.get('errors', []))} 项查询或解析失败，请补跑。")
    lines.append("账号：" + _fragment(meta["account_id"], 64))
    if meta.get("window_end_utc_exclusive"):
        lines.append("统计截至：" + _beijing(meta["window_end_utc_exclusive"]) + "（北京时间）")
    if meta.get("in_progress"):
        lines.append("统计今天零点至本次查询开始时刻。")
    counts = meta.get("counts", {})
    lines.append("；".join(f"{_fragment(key, 30)} {int(value)}" for key, value in counts.items() if key != "其他操作" or value))
    lines.append(f"共 {int(meta.get('total', 0))} 条；失败或含失败响应 {int(meta.get('failed_or_partial', 0))} 条。")
    events = report.get("events", [])
    if events:
        lines.append("最近操作：")
    for row in events[-8:]:
        occurred = _beijing(row.get("time_utc") or row["time_local"])
        resources = row.get("resources") or []
        line = f"{occurred} | {row.get('actor', '')} | {row.get('description') or row.get('event_name', '')}"
        if resources:
            line += " | " + str(resources[0])
        line += " | " + str(row.get("result", ""))
        lines.append(_fragment(line, 180))
    if len(events) > 8:
        lines.append("仅列最近 8 条，完整明细见日报。")
    if report_url:
        lines.append("查看完整报告：" + report_url)
    else:
        lines.append(f"完整报告：{meta['audit_date']}-aws操作审计.html（保存在服务器，本消息未附文件）")
    return {"msg_type": "text", "content": {"text": "\n".join(lines)}}


def make_lark_signature(secret, timestamp):
    key = f"{int(timestamp)}\n{secret}".encode("utf-8")
    return base64.b64encode(hmac.new(key, b"", hashlib.sha256).digest()).decode("ascii")


def _payload_bytes(payload):
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _full_report_body(report, report_url):
    # 与 HTML 共用规范化数据和脱敏函数，避免从 HTML 反解文本造成字段丢失。
    from aws_daily_audit import redact

    meta = report["metadata"]
    counts = meta.get("counts", {})
    blocks = ["分类统计：" + "；".join(f"{_fragment(key, 30)} {int(value)}" for key, value in counts.items() if key != "其他操作" or value),
              f"共 {int(meta.get('total', 0))} 条；失败或含失败响应 {int(meta.get('failed_or_partial', 0))} 条。"]
    if meta.get("generated_at"):
        blocks.append("生成时间：" + _beijing(meta["generated_at"]) + "（北京时间）")
    if meta.get("window_end_utc_exclusive"):
        blocks.append("统计截至：" + _beijing(meta["window_end_utc_exclusive"]) + "（北京时间）")
    actor_counts = {}
    for row in report.get("events", []):
        actor = str(row.get("actor", ""))
        category = str(row.get("category", ""))
        categories = actor_counts.setdefault(actor, {})
        categories[category] = categories.get(category, 0) + 1
    if actor_counts:
        from aws_daily_audit import redact
        blocks.append("按操作者汇总：\n" + json.dumps(redact(actor_counts), ensure_ascii=False, indent=2).replace("<", "＜").replace(">", "＞"))
    for index, row in enumerate(report.get("events", []), 1):
        details = {"操作时间（北京时间）": _beijing(row.get("time_utc") or row["time_local"]),
                   "操作者": row.get("actor", ""), "分类": row.get("category", ""),
                   "操作信息": row.get("description", ""), "API": row.get("event_name", ""),
                   "服务": row.get("source", ""), "资源": row.get("resources", []),
                   "区域": row.get("region", ""), "来源IP": row.get("source_ip", ""),
                   "请求结果": row.get("result", ""), "EventID": row.get("event_id", ""),
                   "身份": row.get("identity"), "请求参数": row.get("parameters"),
                   "响应字段": row.get("response"), "错误码": row.get("error_code", ""),
                   "错误信息": row.get("error_message", ""), "UserAgent": row.get("user_agent", "")}
        if row.get("login_details"):
            details["登录信息"] = row["login_details"]
        text = json.dumps(redact(details), ensure_ascii=False, indent=2, default=str)
        # Lark 纯文本也识别 <at> 标签，按 HTML 中的普通文字含义显示。
        text = text.replace("<", "＜").replace(">", "＞")
        blocks.append(f"操作记录 {index}\n{text}")
    if not report.get("events"):
        blocks.append("无操作记录。")
    if report_url:
        blocks.append("查看完整报告：" + report_url)
    return "\n\n".join(blocks)


def build_lark_payloads(report, config, *, access_password=None):
    mode = config.get("message_mode", "overview")
    if mode not in {"overview", "summary", "full"}:
        raise ValueError("Lark message_mode 必须为 overview、summary 或 full。")
    if access_password is not None:
        if mode != "overview" or not isinstance(access_password, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24}", access_password):
            raise ValueError("单密码访问通知须使用 overview 模式及有效的随机密码。")
    report_url = format_report_url(config.get("report_url_template", ""), report)
    title = config.get("title_prefix", "AWS操作审计日报")
    if mode == "overview":
        meta = report["metadata"]
        counts = meta.get("counts", {})
        lines = [f"{_fragment(title, 100)} | {_fragment(meta['audit_date'], 20)}",
                 f"新增：{int(counts.get('新增', 0))}　删除：{int(counts.get('删除', 0))}　修改：{int(counts.get('修改', 0))}",
                 f"Secrets Manager 查看：{int(counts.get('Secrets Manager 查看', 0))}　登录信息：{int(counts.get('登录信息', 0))}",
                 f"总计：{int(meta.get('total', 0))} 条；其中失败或含失败响应：{int(meta.get('failed_or_partial', 0))} 条。",
                 "账号：" + _fragment(meta["account_id"], 64)]
        if meta.get("window_start_utc") and meta.get("window_end_utc_exclusive"):
            lines.append("北京时间：" + _beijing(meta["window_start_utc"]) + " 至 " + _beijing(meta["window_end_utc_exclusive"]))
        if meta.get("offline"):
            lines.append("【离线示例数据，非真实 AWS 账号审计】")
        if not meta.get("complete", False):
            lines.append("【采集不完整，请检查 JSON 并补跑】")
        lines.append("详细报告：" + (report_url or DEFAULT_REPORT_URL))
        if access_password is not None:
            if urllib.parse.urlsplit(report_url or DEFAULT_REPORT_URL).scheme != "https":
                raise ValueError("带访问密码的报告链接必须使用 HTTPS。")
            lines.append("访问密码：" + access_password)
            lines.append("打开链接后仅输入密码；下次日报更新时更换，同日报表重跑沿用。")
        return [{"msg_type": "text", "content": {"text": "\n".join(lines)}}]
    if mode == "summary":
        return [build_lark_payload(report, report_url=report_url, title_prefix=title)]
    meta = report["metadata"]
    header = (f"{_fragment(title, 100)} | {_fragment(meta['audit_date'], 20)}\n"
              f"账号：{_fragment(meta['account_id'], 64)}\n")
    if meta.get("offline"):
        header += "【离线示例数据，非真实 AWS 账号审计】\n"
    if not meta.get("complete", False):
        header += "【采集不完整，请检查 JSON 并补跑】\n"
    text = _full_report_body(report, report_url)
    # 标题、中文、JSON 换行转义均计入 UTF-8 字节数。预留签名字段空间。
    limit = 19 * 1024
    reserved_header = header + "第 999999999999/999999999999 条\n\n"
    chunks = []
    offset = 0
    while offset < len(text):
        low, high = 0, min(len(text) - offset, limit)
        while low < high:
            middle = (low + high + 1) // 2
            candidate = {"msg_type": "text", "content": {"text": reserved_header + text[offset:offset + middle]}}
            if len(_payload_bytes(candidate)) <= limit:
                low = middle
            else:
                high = middle - 1
        if low == 0:
            raise LarkNotificationError("Lark 消息标题或报告字段过长，无法分条。")
        chunks.append(text[offset:offset + low])
        offset += low
    total = len(chunks)
    return [{"msg_type": "text", "content": {"text": header + f"第 {index}/{total} 条\n\n" + chunk}}
            for index, chunk in enumerate(chunks, 1)]


def _signed_payload(payload, secret, now):
    payload = dict(payload)
    if secret:
        if isinstance(now, datetime):
            if now.tzinfo is None:
                raise ValueError("签名时间必须包含时区。")
            timestamp = int(now.timestamp())
        else:
            timestamp = int(time.time() if now is None else now)
        payload["timestamp"] = str(timestamp)
        payload["sign"] = make_lark_signature(secret, timestamp)
    return payload


def _send_payload(payload, webhook, opener):
    data = _payload_bytes(payload)
    if len(data) > 20 * 1024:
        raise LarkNotificationError("Lark 消息超过 20 KB，请缩短标题或报告链接。")
    request = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
    try:
        # 单次投递：网络超时可能是群已收到消息，不自动重试以免重复。
        with (opener or urllib.request.urlopen)(request, timeout=20) as response:
            status = getattr(response, "status", None) or response.getcode()
            if not 200 <= status < 300:
                raise LarkNotificationError(f"Lark HTTP 请求失败（状态码 {int(status)}）。")
            body = response.read(65537)
            if len(body) > 65536:
                raise LarkNotificationError("Lark 响应过大，未确认投递结果。")
    except urllib.error.HTTPError as exc:
        raise LarkNotificationError(f"Lark HTTP 请求失败（状态码 {exc.code}）。") from None
    except LarkNotificationError:
        raise
    except Exception as exc:
        raise LarkNotificationError(f"Lark 网络请求失败（{type(exc).__name__}）；投递结果未确认。") from None
    try:
        result = json.loads(body)
    except (ValueError, UnicodeError):
        raise LarkNotificationError("Lark 响应不是有效 JSON，未确认投递结果。") from None
    if not isinstance(result, dict) or not ({"code", "StatusCode"} & result.keys()):
        raise LarkNotificationError("Lark 响应缺少状态码，未确认投递结果。")
    code = result.get("code", result.get("StatusCode"))
    if isinstance(code, bool) or code not in (0, "0"):
        safe_code = str(code) if re.fullmatch(r"[0-9]{1,10}", str(code)) else "未知"
        hints = {"19001": "请求参数或 Webhook 未被接受，不能仅凭错误码确定原因；请核对目标群机器人地址、LARK_WEBHOOK_URL 环境变量覆盖及消息格式", "19021": "请检查签名密钥及服务器时间", "19022": "请检查机器人 IP 白名单", "19024": "请检查机器人关键词与 title_prefix", "11232": "触发限流，请稍后手动重试"}
        message = str(result.get("msg", result.get("StatusMessage", ""))).lower()
        if safe_code == "19001" and "incoming webhook access token invalid" in message:
            hints["19001"] = "Webhook 访问标识无效；请从目标群机器人重新复制地址，检查机器人是否仍存在及 LARK_WEBHOOK_URL 是否覆盖配置文件"
        raise LarkNotificationError(f"Lark 返回错误码 {safe_code}；{hints.get(safe_code, '请检查机器人配置')}。")
    return result


def send_lark_notification(report, config, *, opener=None, now=None, sleep=None, access_password=None):
    webhook = validate_webhook_url(config.get("webhook_url", ""))
    payloads = build_lark_payloads(report, config, access_password=access_password)
    secret = config.get("signing_secret", "")
    # 所有消息先校验大小，防止格式问题导致前半份报告已发、后半份才失败。
    for payload in payloads:
        if len(_payload_bytes(_signed_payload(payload, secret, now))) > 20 * 1024:
            raise LarkNotificationError("Lark 消息超过 20 KB，请缩短标题或报告链接。")
    sent = 0
    result = None
    for payload in payloads:
        if sent:
            (sleep or time.sleep)(0.7)
        try:
            result = _send_payload(_signed_payload(payload, secret, now), webhook, opener)
        except LarkNotificationError as exc:
            raise LarkNotificationError(f"{exc} 已成功发送 {sent}/{len(payloads)} 条，已停止后续发送。") from None
        sent += 1
    if config.get("message_mode", "summary") == "full":
        return {"code": 0, "messages_sent": sent}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="本地检查 Lark 配置；不发送任何消息。")
    parser.add_argument("--config", default="lark-config.json")
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args(argv)
    if not args.check_config:
        parser.error("请使用 --check-config；此入口只做本地配置检查。")
    print("配置文件路径：" + str(Path(args.config).resolve()))
    if "LARK_WEBHOOK_URL" in os.environ:
        print("Webhook 来源：LARK_WEBHOOK_URL 环境变量（覆盖文件" + ("，当前为空" if not os.environ["LARK_WEBHOOK_URL"] else "") + "）")
    else:
        print("Webhook 来源：配置文件")
    try:
        config = load_lark_config(args.config)
        print("Webhook 域名：" + urllib.parse.urlsplit(config["webhook_url"]).hostname)
        print("地址格式检查通过；未向 Lark 验证地址有效性，未发送消息。")
        print("发送模式：" + config.get("message_mode", "overview"))
        print("签名：" + ("已配置" if config.get("signing_secret") else "未配置"))
        print("报告链接：" + ("已配置" if config.get("report_url_template") else "未配置"))
        return 0
    except (ValueError, OSError) as exc:
        print(f"配置检查失败：{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
