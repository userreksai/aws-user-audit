"""Persistent, locked PDF mail delivery receipts without SMTP secrets.

Automatic messages share one allowance per Beijing natural day. A receipt is
committed before SMTP submission, so an interrupted process cannot silently
send the same report again. Explicit manual sends may exceed the daily budget;
repeating a successful or uncertain report requires ``force_resend=True``.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from zoneinfo import ZoneInfo


class MailStateError(RuntimeError):
    """An intentionally sanitized local state or lock failure."""


_STATUSES = {"sending", "accepted", "failed", "uncertain"}
_BLOCKED = {"sending", "accepted", "uncertain"}


def _day(value):
    if not isinstance(value, str) or date.fromisoformat(value).isoformat() != value:
        raise ValueError("日期格式无效")
    return value


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("重复状态字段")
        result[key] = value
    return result


def _load(path, today):
    if not path.exists() and not path.is_symlink():
        return {"schema_version": 1, "days": {}, "reports": {}}
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError
        if os.name == "posix" and path.stat().st_mode & 0o077:
            raise ValueError
        value = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_pairs)
        if (not isinstance(value, dict) or set(value) != {"schema_version", "days", "reports"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or not isinstance(value["days"], dict) or not isinstance(value["reports"], dict)):
            raise ValueError
        for key, entry in value["days"].items():
            if (_day(key) > today or not isinstance(entry, dict) or set(entry) != {"used"}
                    or type(entry["used"]) is not int or entry["used"] not in (0, 1)):
                raise ValueError
        for key, entry in value["reports"].items():
            if (not re.fullmatch(r"[0-9a-f]{64}", key) or not isinstance(entry, dict)
                    or set(entry) != {"report_day", "sending_day", "status", "last_attempt"}
                    or entry["status"] not in _STATUSES):
                raise ValueError
            _day(entry["report_day"])
            sending_day = _day(entry["sending_day"])
            if sending_day > today or sending_day not in value["days"]:
                raise ValueError
            if entry["status"] in _BLOCKED and value["days"][sending_day]["used"] != 1:
                raise ValueError
            stamp = datetime.fromisoformat(entry["last_attempt"])
            if stamp.tzinfo is None or stamp.utcoffset() is None:
                raise ValueError
        return value
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise MailStateError("邮件投递状态无法安全读取；请核对历史投递后修复，不会自动清空额度。") from None


def _save(path, value):
    temporary = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".mail-delivery-", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=True, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
        if os.name == "posix":
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except OSError:
        raise MailStateError("邮件投递状态更新失败；PDF 已保留，请检查目录权限和磁盘空间。") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def _locked(directory):
    handle = None
    locked = False
    try:
        if directory.is_symlink():
            raise OSError
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not directory.is_dir() or (os.name == "posix" and directory.stat().st_mode & 0o077):
            raise OSError
        path = directory / "mail.lock"
        if path.is_symlink():
            raise OSError
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        handle = os.fdopen(descriptor, "r+b")
        if os.name == "posix":
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            import msvcrt
            if handle.seek(0, 2) == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        locked = True
    except OSError:
        if handle is not None:
            handle.close()
        raise MailStateError("无法取得邮件投递锁；可能已有任务发送，或私有状态目录权限异常。") from None
    try:
        yield
    finally:
        if handle is not None:
            try:
                if locked:
                    if os.name == "posix":
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    else:
                        import msvcrt
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                handle.close()


def _line(value, maximum=256):
    return "".join(character for character in str(value) if ord(character) >= 32 and ord(character) != 127)[:maximum]


def _count(value):
    if type(value) is not int or value < 0:
        raise ValueError("邮件报告计数必须为非负整数。")
    return value


def message_body(report, report_url=""):
    """Render only report metadata, never event payloads or provider replies."""
    meta = report["metadata"]
    counts = meta["counts"]
    lines = ["AWS 账号操作审计日报", f"账号：{_line(meta['account_id'])}",
             f"报表日期：{_day(meta['audit_date'])}",
             f"新增 {_count(counts.get('新增', 0))}；删除 {_count(counts.get('删除', 0))}；修改 {_count(counts.get('修改', 0))}",
             f"Secrets Manager 查看 {_count(counts.get('Secrets Manager 查看', 0))}；登录信息 {_count(counts.get('登录信息', 0))}；其他操作 {_count(counts.get('其他操作', 0))}",
             f"失败或含失败响应：{_count(meta.get('failed_or_partial', 0))}",
             "查询范围（北京时间，结束时刻不含）：",
             f"{_line(meta.get('window_start_local', '未提供'))} 至 {_line(meta.get('window_end_local_exclusive', '未提供'))}",
             "查询状态：所列查询完成。" if meta["complete"] else "查询状态：不完整；部分查询或解析失败，请检查任务日志。"]
    if meta.get("offline"):
        lines.append("离线输入报告；未向 AWS 验证数据完整性。")
    lines.append("PDF 附件仅含本账号各类操作总数；具体操作明细见网页或本地 JSON 报告。")
    if report_url:
        lines.append("网页详情：" + _line(report_url, 2048))
    lines.append("CloudTrail 日志可能延迟到达；API 请求未报错不代表异步操作最终完成。")
    return "\n".join(lines)


def deliver_reports(reports, pdf_paths, config, state_dir, *, automatic=False,
                    force_resend=False, now=None, report_url=""):
    """Submit all account PDFs once, or return the preserved delivery status.

    ``failed`` means SMTP clearly rejected or never submitted the message.
    ``uncertain`` means some recipients may already have received it. Neither
    return value promises an automatic retry; the scheduler chooses when to run.
    """
    from audit_mail import MailDeliveryError, send_reports

    if automatic and force_resend:
        raise ValueError("自动邮件不能使用强制重发。")
    limit = config.get("AUTO_MAIL_MAX_PER_DAY", 1)
    if type(limit) is not int or limit not in (0, 1):
        raise ValueError("AUTO_MAIL_MAX_PER_DAY 仅支持 0 或 1。")
    now = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("邮件任务时间必须包含时区。")
    if (not isinstance(reports, list) or not reports or not isinstance(pdf_paths, list)
            or len(reports) != len(pdf_paths)):
        raise ValueError("每个账号报告必须对应一份 PDF 附件。")
    metadata = [report["metadata"] for report in reports]
    if any(type(meta.get("complete")) is not bool for meta in metadata):
        raise ValueError("报告完整性状态无效。")
    complete = all(meta["complete"] for meta in metadata)
    report_days = {_day(meta["audit_date"]) for meta in metadata}
    if len(report_days) != 1:
        raise ValueError("同一封邮件中的账号必须使用同一报表日期。")
    report_day = report_days.pop()
    account_ids = [str(meta["account_id"]) for meta in metadata]
    if len(set(account_ids)) != len(account_ids):
        raise ValueError("同一封日报邮件不能包含重复 AWS 账号。")
    today = now.astimezone(ZoneInfo("Asia/Shanghai")).date().isoformat()
    identity = sorted([str(meta["account_id"]), report_day, str(meta.get("window_start_utc", "")),
                       str(meta.get("window_end_utc_exclusive", ""))] for meta in metadata)
    key = hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()
    body = "\n\n".join(message_body(report, report_url) for report in sorted(reports, key=lambda row: str(row["metadata"]["account_id"])))
    subject = str(config.get("MAIL_SUBJECT", "AWS账号操作审计日报")) + " " + report_day
    if not complete:
        subject += " [不完整]"
    if any(meta.get("offline") for meta in metadata):
        subject += " [离线输入]"

    def result(status, reason):
        return {"status": status, "reason": reason, "report_day": report_day,
                "sending_day": today, "complete": complete, "account_count": len(reports)}

    directory = Path(state_dir).absolute()
    with _locked(directory):
        path = directory / "mail-delivery.json"
        try:
            state = _load(path, today)
        except MailStateError:
            return result("uncertain", "invalid_state")
        if automatic and not limit:
            return result("disabled", "automatic_mail_disabled")
        existing = state["reports"].get(key)
        unresolved = any(entry["report_day"] == report_day and entry["status"] in {"sending", "uncertain"}
                         for entry in state["reports"].values())
        if unresolved and not force_resend:
            return result("uncertain", "delivery_unresolved")
        if existing and existing["status"] in _BLOCKED and not force_resend:
            if existing["status"] == "accepted":
                return result("suppressed", "report_already_accepted")
            return result("uncertain", "delivery_unresolved")
        day_entry = state["days"].setdefault(today, {"used": 0})
        if automatic and day_entry["used"]:
            return result("suppressed", "daily_limit")
        previously_used = day_entry["used"]
        entry = {"report_day": report_day, "sending_day": today, "status": "sending",
                 "last_attempt": now.astimezone(timezone.utc).isoformat()}
        state["reports"][key] = entry
        day_entry["used"] = 1
        _save(path, state)  # A crash after this point conservatively reserves delivery.
        try:
            delivery = send_reports(config, [Path(path) for path in pdf_paths], body, subject=subject)
            if not isinstance(delivery, dict) or delivery.get("smtp_accepted") is not True:
                raise RuntimeError("SMTP result is not an acceptance receipt")
        except MailDeliveryError as exc:
            status = "uncertain" if exc.delivery_uncertain else "failed"
            entry["status"] = status
            if status == "failed":
                day_entry["used"] = previously_used
                if existing and existing["status"] in _BLOCKED:
                    state["reports"][key] = existing
            _save(path, state)
            return result(status, "smtp_delivery_uncertain" if exc.delivery_uncertain else "smtp_failed")
        except (ValueError, OSError):
            # The sender validates MIME/configuration and reads files before
            # contacting SMTP; transport failures are wrapped by MailDeliveryError.
            entry["status"] = "failed"
            day_entry["used"] = previously_used
            if existing and existing["status"] in _BLOCKED:
                state["reports"][key] = existing
            _save(path, state)
            return result("failed", "mail_preparation_failed")
        except Exception:
            entry["status"] = "uncertain"
            _save(path, state)
            return result("uncertain", "unexpected_delivery_result")
        entry["status"] = "accepted"
        _save(path, state)
        return result("accepted", "smtp_accepted")


def deliver_report(report, pdf_path, config, state_dir, **options):
    """Single-account compatibility wrapper for the combined SMTP transaction."""
    return deliver_reports([report], [pdf_path], config, state_dir, **options)
