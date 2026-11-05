#!/usr/bin/env python3
"""Run the existing audit job in Docker without changing host services.

The scheduler owns only docker-schedule.json, its lock and a heartbeat. Existing
mail receipts and the business job lock remain owned by the audit implementation.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
from threading import Event
import time
import uuid
from zoneinfo import ZoneInfo

APP_DIRECTORY = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP_DIRECTORY))
from audit_config import DEFAULT_INSTALL_DIR, load_config
from audit_schedule import latest_report_date, parse_clock

DEFAULT_CONFIG = DEFAULT_INSTALL_DIR + "/aws-audit-config.json"
BEIJING = ZoneInfo("Asia/Shanghai")
UTC = timezone.utc
POLL_SECONDS = 5.0
CHILD_POLL_SECONDS = 1.0
TERMINATE_GRACE_SECONDS = 15.0
HEARTBEAT_MAX_AGE_SECONDS = 90.0
SCHEDULE_FILE = "docker-schedule.json"
HEARTBEAT_FILE = "docker-heartbeat.json"
LOCK_FILE = "docker-schedule.lock"
SCHEDULE_KEYS = ("DAILY_MAIL_TIME", "REPORT_START_TIME", "REPORT_END_TIME")
_MISSING = object()


class RuntimeStateError(RuntimeError):
    """A local validation failure whose details must never expose settings."""


class StopRequest:
    def __init__(self):
        self.signal = None
        self.event = Event()

    @property
    def stopping(self):
        return self.signal is not None

    def stop(self, signum=signal.SIGTERM, frame=None):
        if self.signal is None:
            self.signal = signum
        self.event.set()

    def wait(self, seconds):
        self.event.wait(seconds)


def utc_now():
    return datetime.now(UTC)


def _aware(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise RuntimeStateError("任务时钟必须包含时区。")
    return value


def latest_due(now, daily_mail_time):
    """Return the latest scheduled Beijing instant, independently of host TZ."""
    local = _aware(now).astimezone(BEIJING)
    due = datetime.combine(local.date(), parse_clock(daily_mail_time), BEIJING)
    return due if due <= local else due - timedelta(days=1)


def _private_directory(directory, *, create=True):
    if directory.is_symlink():
        raise RuntimeStateError("私有状态目录不能为符号链接。")
    if create:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (not directory.is_dir()
            or (os.name == "posix" and directory.stat().st_mode & 0o077)):
        raise RuntimeStateError("私有状态目录须属于任务用户且权限为 0700。")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeStateError("状态存在重复字段。")
        result[key] = value
    return result


def _invalid_constant(value):
    raise RuntimeStateError("状态数值无效。")


def _read_json(path):
    if not path.exists() and not path.is_symlink():
        return _MISSING
    if (path.is_symlink() or not path.is_file() or path.stat().st_size > 65536
            or (os.name == "posix" and path.stat().st_mode & 0o077)):
        raise RuntimeStateError("私有状态文件类型、大小或权限无效。")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs,
                          parse_constant=_invalid_constant)
    except (OSError, ValueError, UnicodeError):
        raise RuntimeStateError("私有状态文件损坏；请人工核对，不会自动重置。") from None


def _write_json(path, value):
    """Commit private state before a job starts, including the directory entry."""
    if path.is_symlink():
        raise RuntimeStateError("私有状态文件不能为符号链接。")
    temporary = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".docker-runtime-", suffix=".tmp", dir=path.parent)
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
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def scheduler_lock(directory):
    """One scheduler per persistent state directory; never use mail.lock."""
    path = directory / LOCK_FILE
    if path.is_symlink():
        raise RuntimeStateError("调度锁不能为符号链接。")
    handle = None
    locked = False
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        handle = os.fdopen(descriptor, "r+b")
        mode = os.fstat(handle.fileno()).st_mode
        if not stat.S_ISREG(mode) or (os.name == "posix" and mode & 0o077):
            raise RuntimeStateError("调度锁必须为私有普通文件。")
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
        yield
    except OSError:
        raise RuntimeStateError("无法取得 Docker 调度锁；请检查重复容器和状态目录权限。") from None
    finally:
        if handle is not None:
            if locked:
                if os.name == "posix":
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                else:
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            handle.close()


def checked_config(config_path, *, mail_mode=None):
    """Validate files only; profile lookup deliberately never gets credentials."""
    config = load_config(config_path, require_mail=False)
    if mail_mode == "manual" or (mail_mode == "automatic" and config["AUTO_MAIL_MAX_PER_DAY"]):
        config = load_config(config_path, require_mail=True)
    profiles = {account["AWS_PROFILE"] for account in config["ACCOUNTS"]
                if account["ENABLED"] and account["AWS_PROFILE"]}
    if profiles:
        try:
            import boto3
            for profile in profiles:
                if profile not in boto3.Session(profile_name=profile).available_profiles:
                    raise RuntimeStateError("启用账号的 AWS profile 未在容器本地凭据文件中找到。")
        except Exception:
            raise RuntimeStateError("无法读取启用账号的本地 AWS profile；请核对只读凭据挂载。") from None
    return config


def _schedule(config):
    return {key: config[key] for key in SCHEDULE_KEYS}


def report_fingerprint(config):
    # No credentials or SMTP values enter scheduler state, including its hash.
    accounts = [{key: account[key] for key in ("NAME", "ACCOUNT_ID", "TAG", "REGIONS")}
                for account in config["ACCOUNTS"] if account["ENABLED"]]
    public = {"start": config["REPORT_START_TIME"], "end": config["REPORT_END_TIME"],
              "accounts": sorted(accounts, key=lambda account: account["ACCOUNT_ID"])}
    return hashlib.sha256(json.dumps(public, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def _stamp(value):
    try:
        result = datetime.fromisoformat(value)
        _aware(result)
        if result.astimezone(BEIJING).isoformat() != value:
            raise ValueError
        return result
    except (TypeError, ValueError):
        raise RuntimeStateError("调度状态时间格式无效。") from None


def read_schedule_state(path, now):
    state = _read_json(path)
    if state is _MISSING:
        return None
    fields = {"schema_version", "schedule", "last_due", "last_success_report_day", "last_success_fingerprint"}
    if (not isinstance(state, dict) or set(state) != fields
            or type(state["schema_version"]) is not int or state["schema_version"] != 1
            or not isinstance(state["schedule"], dict) or set(state["schedule"]) != set(SCHEDULE_KEYS)):
        raise RuntimeStateError("调度状态格式无效；不会重置或补发。")
    for key in SCHEDULE_KEYS:
        parse_clock(state["schedule"][key], key)
    if state["schedule"]["DAILY_MAIL_TIME"] < state["schedule"]["REPORT_END_TIME"]:
        raise RuntimeStateError("调度状态时间顺序无效。")
    due = _stamp(state["last_due"])
    if (due > _aware(now) or due.second or due.microsecond
            or due.astimezone(BEIJING).time() != parse_clock(state["schedule"]["DAILY_MAIL_TIME"])):
        raise RuntimeStateError("调度游标无效或晚于当前时钟；不会重置或补发。")
    day, fingerprint = state["last_success_report_day"], state["last_success_fingerprint"]
    if day is None and fingerprint is None:
        return state
    try:
        if (not isinstance(day, str) or date.fromisoformat(day).isoformat() != day
                or day > now.astimezone(BEIJING).date().isoformat()
                or not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)):
            raise ValueError
    except (ValueError, TypeError):
        raise RuntimeStateError("调度成功记录无效；不会重置或补发。") from None
    return state


def _baseline(config, now, previous=None):
    return {"schema_version": 1, "schedule": _schedule(config),
            "last_due": latest_due(now, config["DAILY_MAIL_TIME"]).isoformat(),
            "last_success_report_day": previous["last_success_report_day"] if previous else None,
            "last_success_fingerprint": previous["last_success_fingerprint"] if previous else None}


def process_identity(pid):
    """An OS process start identity prevents stale heartbeats passing PID reuse."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise OSError("Process unavailable")
        creation, exited, system, user = (wintypes.FILETIME() for _ in range(4))
        try:
            if not kernel.GetProcessTimes(handle, creation, exited, system, user):
                raise OSError("Process unavailable")
            return "windows:" + str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
        finally:
            kernel.CloseHandle(handle)
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
    boot = str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()))
    return boot + ":" + fields[19] + ":" + os.readlink(f"/proc/{pid}/ns/pid")


def _heartbeat(directory, instance, identity, status, now, child_pid=None):
    _write_json(directory / HEARTBEAT_FILE,
                {"schema_version": 1, "instance_id": instance, "pid": os.getpid(),
                 "process_start": identity, "updated_at": _aware(now).astimezone(UTC).isoformat(),
                 "status": status, "child_pid": child_pid})


def healthy(config_path, *, now=None, identity_reader=None, max_age=HEARTBEAT_MAX_AGE_SECONDS):
    """Read-only health: fresh local heartbeat belonging to the live scheduler."""
    now = _aware(now or utc_now())
    identity_reader = identity_reader or process_identity
    config = load_config(config_path, require_mail=False)
    directory = Path(config["STATE_DIRECTORY"])
    _private_directory(directory, create=False)
    value = _read_json(directory / HEARTBEAT_FILE)
    fields = {"schema_version", "instance_id", "pid", "process_start", "updated_at", "status", "child_pid"}
    if (not isinstance(value, dict) or set(value) != fields
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["status"], str) or value["status"] not in {"idle", "running"}
            or not isinstance(value["instance_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["instance_id"])
            or type(value["pid"]) is not int or value["pid"] < 1
            or not isinstance(value["process_start"], str) or not value["process_start"]
            or (value["child_pid"] is not None and (type(value["child_pid"]) is not int or value["child_pid"] < 1))):
        return False
    try:
        stamp = _aware(datetime.fromisoformat(value["updated_at"]))
        age = (now - stamp).total_seconds()
        return -5 <= age <= max_age and identity_reader(value["pid"]) == value["process_start"]
    except (OSError, ValueError, TypeError, IndexError, RuntimeStateError):
        return False


def build_command(config_path, selected_date, *, send_mail=False, automatic_mail=False, force_resend=False):
    command = [sys.executable, str(APP_DIRECTORY / "aws_audit_multi.py"), "--config", str(config_path),
               "--date", selected_date]
    for enabled, flag in ((send_mail, "--send-mail"), (automatic_mail, "--automatic-mail"),
                          (force_resend, "--force-resend")):
        if enabled:
            command.append(flag)
    return command


def signal_child(child, signum):
    if os.name == "posix":
        try:
            os.killpg(child.pid, signum)
            return
        except ProcessLookupError:
            return
        except OSError:
            child.send_signal(signum)
    elif signum == getattr(signal, "SIGKILL", 9):
        child.kill()
    else:
        child.terminate()


def run_child(command, *, control=None, popen=None, wait=None, monotonic=None,
              heartbeat=None, signaler=None, grace=TERMINATE_GRACE_SECONDS):
    """Forward shutdown to the entire job group, then reap it within a bound."""
    control = control or StopRequest()
    popen, wait = popen or subprocess.Popen, wait or time.sleep
    monotonic, signaler = monotonic or time.monotonic, signaler or signal_child
    if control.stopping:
        return 128 + control.signal
    child = popen(command, cwd=str(APP_DIRECTORY), start_new_session=os.name == "posix")
    deadline = None
    try:
        while True:
            result = child.poll()
            if result is not None:
                child.wait()
                return result
            if control.stopping and deadline is None:
                signaler(child, control.signal)
                deadline = monotonic() + grace
            elif deadline is not None and monotonic() >= deadline:
                signaler(child, getattr(signal, "SIGKILL", 9))
                return child.wait(timeout=5)
            if heartbeat:
                heartbeat(child.pid)
            wait(CHILD_POLL_SECONDS)
    except BaseException:
        # Heartbeat/disk failures must not leave a detached audit job behind.
        try:
            signaler(child, getattr(signal, "SIGKILL", 9))
        finally:
            child.wait(timeout=5)
        raise


def init_schedule(config_path, *, now=None):
    """Create a missing baseline only; never overwrite existing cursors/receipts."""
    config = checked_config(config_path, mail_mode="automatic")
    directory = Path(config["STATE_DIRECTORY"])
    _private_directory(directory)
    current = _aware(now or utc_now())
    with scheduler_lock(directory):
        if read_schedule_state(directory / SCHEDULE_FILE, current) is None:
            _write_json(directory / SCHEDULE_FILE, _baseline(config, current))
    print("Docker 定时基线已就绪；未查询 AWS、未发送邮件或告警。", flush=True)
    return 0


def run_schedule(config_path, *, now=None, wait=None, monotonic=None, popen=None,
                 control=None, identity_reader=None, signaler=None):
    now = now or utc_now
    control = control or StopRequest()
    idle_wait = wait or control.wait
    config = checked_config(config_path, mail_mode="automatic")
    directory = Path(config["STATE_DIRECTORY"])
    _private_directory(directory)
    instance = uuid.uuid4().hex
    identity = (identity_reader or process_identity)(os.getpid())
    with scheduler_lock(directory):
        path = directory / SCHEDULE_FILE
        current = _aware(now())
        state = read_schedule_state(path, current)
        if state is None or state["schedule"] != _schedule(config):
            state = _baseline(config, current, state)
            _write_json(path, state)
            print("Docker 定时基线已初始化，等待下一次北京时间发送时刻。", flush=True)
        else:
            print("Docker 定时已恢复；错过的计划仅补最近一个已结束窗口。", flush=True)
        try:
            while not control.stopping:
                config = checked_config(config_path, mail_mode="automatic")
                if Path(config["STATE_DIRECTORY"]) != directory:
                    raise RuntimeStateError("状态目录变更须重建容器，不能在运行中迁移调度锁。")
                current = _aware(now())
                if state["schedule"] != _schedule(config):
                    state = _baseline(config, current, state)
                    _write_json(path, state)
                    print("Docker 时间计划已更新，等待下一次发送时刻。", flush=True)
                due = latest_due(current, config["DAILY_MAIL_TIME"])
                if due > _stamp(state["last_due"]):
                    state["last_due"] = due.isoformat()
                    _write_json(path, state)  # Reserve before spawning; crashes cannot repeat this due.
                    selected = latest_report_date(current, config["REPORT_END_TIME"])
                    fingerprint = report_fingerprint(config)
                    if (state["last_success_report_day"] == selected
                            and state["last_success_fingerprint"] == fingerprint):
                        print("最近已结束窗口已完成；本次仅推进定时游标。", flush=True)
                    else:
                        print("Docker 日报开始：" + selected + "（北京时间）。", flush=True)
                        command = build_command(config_path, selected, send_mail=True, automatic_mail=True)
                        code = run_child(command, control=control, popen=popen, wait=wait, monotonic=monotonic,
                                         signaler=signaler, heartbeat=lambda pid: _heartbeat(
                                             directory, instance, identity, "running", now(), pid))
                        if code == 0:
                            state["last_success_report_day"] = selected
                            state["last_success_fingerprint"] = fingerprint
                            _write_json(path, state)
                        print("Docker 日报进程已结束，退出码：" + str(code) + "。", flush=True)
                        # A long job may cross several due times. Resume at the next future
                        # daily boundary rather than running a catch-up loop on completion.
                        completed_due = latest_due(_aware(now()), config["DAILY_MAIL_TIME"])
                        if completed_due > _stamp(state["last_due"]):
                            state["last_due"] = completed_due.isoformat()
                            _write_json(path, state)
                if not control.stopping:
                    _heartbeat(directory, instance, identity, "idle", now())
                    idle_wait(POLL_SECONDS)
        finally:
            try:
                _heartbeat(directory, instance, identity, "stopped", now())
            except OSError:
                pass
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("schedule", "once", "check-config", "healthcheck", "init-schedule"):
        command = commands.add_parser(name)
        command.add_argument("--config", default=DEFAULT_CONFIG, help="只读统一 JSON/JSONC 配置")
        if name == "once":
            command.add_argument("--date", help="指定报表结束日期；默认最近已结束窗口")
            command.add_argument("--send-mail", action="store_true")
            command.add_argument("--automatic-mail", action="store_true")
            command.add_argument("--force-resend", action="store_true")
    args = parser.parse_args(argv)
    control = StopRequest()
    previous_handlers = {}
    try:
        if args.command in {"schedule", "once"}:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[signum] = signal.signal(signum, control.stop)
        if args.command == "schedule":
            return run_schedule(args.config, control=control)
        if args.command == "init-schedule":
            return init_schedule(args.config)
        if args.command == "check-config":
            checked_config(args.config, mail_mode="automatic")
            print("Docker 配置本地检查通过；未查询 AWS、未发送邮件或告警。", flush=True)
            return 0
        if args.command == "healthcheck":
            return 0 if healthy(args.config) else 1
        if (args.automatic_mail and not args.send_mail) or (args.force_resend and (not args.send_mail or args.automatic_mail)):
            raise RuntimeStateError("邮件参数组合无效。")
        mode = ("automatic" if args.automatic_mail else "manual") if args.send_mail else None
        config = checked_config(args.config, mail_mode=mode)
        selected = args.date or latest_report_date(utc_now(), config["REPORT_END_TIME"])
        if date.fromisoformat(selected).isoformat() != selected:
            raise RuntimeStateError("日期须为 YYYY-MM-DD。")
        code = run_child(build_command(args.config, selected, send_mail=args.send_mail,
                                      automatic_mail=args.automatic_mail, force_resend=args.force_resend), control=control)
        return code if code >= 0 else 128 - code
    except Exception as exc:
        # Exception messages may contain private JSON values, paths or SDK text.
        print("Docker 运行失败（" + type(exc).__name__ + "）；请检查本地配置、权限和运行环境。", file=sys.stderr, flush=True)
        return 1
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
