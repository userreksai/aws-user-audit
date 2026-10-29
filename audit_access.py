"""每日单密码状态与会话；私有密码只供 Lark 重发，不写入报告。"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from datetime import date
from pathlib import Path

ITERATIONS = 600_000
SESSION_SECONDS = 8 * 60 * 60
STATE_FIELDS = {"version", "audit_date", "rotation_id", "password_salt", "password_hash", "iterations", "session_key"}


class AccessError(RuntimeError):
    """错误信息不含密码、哈希或会话密钥。"""


def _validate_state(state):
    try:
        if not isinstance(state, dict) or set(state) != STATE_FIELDS or state["version"] != 1:
            raise ValueError
        if date.fromisoformat(state["audit_date"]).isoformat() != state["audit_date"]:
            raise ValueError
        if state["iterations"] != ITERATIONS:
            raise ValueError
        for key, size in (("rotation_id", 32), ("password_salt", 32), ("password_hash", 64), ("session_key", 64)):
            if not re.fullmatch("[0-9a-f]{" + str(size) + "}", state[key]):
                raise ValueError
    except (KeyError, ValueError, TypeError):
        raise AccessError("访问认证状态格式无效；请检查服务器认证状态文件。") from None
    return state


def _read_json(path, *, private=False):
    path = Path(path)
    try:
        if path.is_symlink() or path.stat().st_size > 32768:
            raise ValueError
        if os.name == "posix" and path.stat().st_mode & (0o077 if private else 0o027):
            raise ValueError
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise AccessError("访问认证状态无法安全读取；请检查文件是否存在、格式及权限。") from None


def load_access(path):
    return _validate_state(_read_json(path))


def verify_password(password, state):
    if not isinstance(password, str) or not 1 <= len(password) <= 128:
        return False
    try:
        _validate_state(state)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(state["password_salt"]), ITERATIONS).hex()
        return hmac.compare_digest(actual, state["password_hash"])
    except (AccessError, UnicodeError):
        return False


def make_session(state, now=None):
    _validate_state(state)
    issued = int(time.time() if now is None else now)
    message = f"{state['rotation_id']}.{issued}.{issued + SESSION_SECONDS}"
    signature = hmac.new(bytes.fromhex(state["session_key"]), message.encode("ascii"), hashlib.sha256).hexdigest()
    return message + "." + signature


def verify_session(token, state, now=None):
    try:
        _validate_state(state)
        if not isinstance(token, str) or len(token) > 160:
            return False
        rotation, issued, expires, signature = token.split(".")
        if not re.fullmatch(r"[0-9]{1,12}", issued) or not re.fullmatch(r"[0-9]{1,12}", expires):
            return False
        clock = int(time.time() if now is None else now)
        if rotation != state["rotation_id"] or int(expires) - int(issued) != SESSION_SECONDS:
            return False
        if int(issued) > clock + 30 or clock >= int(expires):
            return False
        message = f"{rotation}.{issued}.{expires}"
        expected = hmac.new(bytes.fromhex(state["session_key"]), message.encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except (AccessError, ValueError, TypeError):
        return False


def _atomic_json(path, value, mode):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".auth-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            if os.name == "posix":
                os.chown(temporary, -1, path.parent.stat().st_gid)
                os.chmod(temporary, mode)
            stream.write(json.dumps(value, ensure_ascii=True).encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError:
        raise AccessError("认证状态更新失败；请检查认证目录写入权限和磁盘空间。") from None
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


class AccessRotation:
    """锁覆盖发布和通知。同日报表复用密码，失败重跑不会使已发送密码失效。"""

    def __init__(self, state_dir, publish_dir, audit_date, archive_dir=None):
        self.directory = Path(state_dir).resolve()
        self.day = audit_date
        self.lock = None
        self.state = None
        self._password = None
        if date.fromisoformat(audit_date).isoformat() != audit_date:
            raise AccessError("认证日期必须为 YYYY-MM-DD。")
        for public in (publish_dir, archive_dir):
            if public is not None:
                public = Path(public).resolve()
                if self.directory == public or self.directory in public.parents or public in self.directory.parents:
                    raise AccessError("认证目录必须独立于网页发布目录和报告归档目录。")

    @property
    def password(self):
        return self._password

    def __enter__(self):
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name == "posix" and self.directory.stat().st_mode & 0o027:
                raise AccessError("认证目录不能允许组写入或其他用户访问；请使用 2750 或 0700。")
            lock_path = self.directory / "rotation.lock"
            if lock_path.is_symlink():
                raise AccessError("认证锁文件无效。")
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self.lock = os.fdopen(fd, "r+b")
            if os.name == "posix":
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                if self.lock.seek(0, 2) == 0:
                    self.lock.write(b"0")
                    self.lock.flush()
                self.lock.seek(0)
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            self._prepare()
            return self
        except (OSError, AccessError):
            self.__exit__(None, None, None)
            raise AccessError("无法准备访问密码；可能已有任务运行，或认证状态、目录权限异常。") from None

    def _prepare(self):
        active_path = self.directory / "access.json"
        active = load_access(active_path) if active_path.exists() else None
        if active and self.day < active["audit_date"]:
            raise AccessError("不能用较早日期的报告覆盖现有密码认证网页。")
        private_path = self.directory / "delivery.json"
        records = []
        if private_path.exists():
            private = _read_json(private_path, private=True)
            if not isinstance(private, dict) or private.get("version") != 1 or not isinstance(private.get("credentials"), list):
                raise AccessError("私有密码恢复记录无效。")
            records = private["credentials"]
            if len(records) > 2:
                raise AccessError("私有密码恢复记录无效。")
            for record in records:
                if not isinstance(record, dict) or set(record) != {"state", "password"}:
                    raise AccessError("私有密码恢复记录无效。")
                _validate_state(record["state"])
                if not verify_password(record["password"], record["state"]):
                    raise AccessError("私有密码恢复记录与认证状态不一致。")
        active_record = next((record for record in records if record["state"] == active), None)
        if active and active_record is None:
            raise AccessError("缺少有效密码的私有恢复记录；停止覆盖现有认证。")
        candidate = active_record if active and active["audit_date"] == self.day else next(
            (record for record in records if record["state"]["audit_date"] == self.day), None)
        if candidate is None:
            password = secrets.token_urlsafe(18)
            salt = secrets.token_hex(16)
            state = {"version": 1, "audit_date": self.day, "rotation_id": secrets.token_hex(16),
                     "password_salt": salt, "iterations": ITERATIONS,
                     "password_hash": hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), bytes.fromhex(salt), ITERATIONS).hex(),
                     "session_key": secrets.token_hex(32)}
            candidate = {"state": state, "password": password}
            _atomic_json(private_path, {"version": 1, "credentials": ([active_record] if active_record else []) + [candidate]}, 0o600)
        self.state, self._password = candidate["state"], candidate["password"]

    def activate(self):
        if self.lock is None or self.state is None:
            raise AccessError("访问密码尚未准备。")
        _atomic_json(self.directory / "access.json", self.state, 0o640)

    def __exit__(self, *_):
        if self.lock is not None:
            # 关闭描述符会释放系统级文件锁；文件保留供下次运行复用。
            self.lock.close()
            self.lock = None
        self._password = None
