"""仅供 Nginx 回环代理的审计报告服务：单密码登录、受保护静态文件。"""
from __future__ import annotations

import argparse
from collections import OrderedDict, deque
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import os
from pathlib import Path
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

from audit_access import AccessError, SESSION_SECONDS, load_access, make_session, verify_password, verify_session


COOKIE_NAME = "__Secure-audit_session"
CSP = ("default-src 'self'; base-uri 'none'; object-src 'none'; style-src 'self'; "
       "img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'")
FILES = {
    "/audit/": ("index.html", "text/html; charset=utf-8"),
    "/audit/index.html": ("index.html", "text/html; charset=utf-8"),
    "/audit/audit-report.css": ("audit-report.css", "text/css; charset=utf-8"),
    "/audit/audit-report.js": ("audit-report.js", "text/javascript; charset=utf-8"),
}
LOGIN_CSS = b"""html{font-family:system-ui,sans-serif;color:#182739;background:#f3f6fa}body{margin:0;padding:10vh 24px}main{max-width:380px;margin:auto;padding:32px;background:white;border:1px solid #dce4ef;border-radius:12px}h1{font-size:24px;margin:0 0 16px}p{line-height:1.7;color:#536579}label{display:block;margin:22px 0 8px}input,button{box-sizing:border-box;width:100%;padding:12px;border:1px solid #aab9cc;border-radius:6px;font:inherit}button{margin-top:16px;color:white;background:#145e9f;border:0;cursor:pointer}.error{color:#a52b20}small{color:#536579}"""


def _login_page(error=""):
    # error is a fixed server message, never a submitted password or query string.
    notice = '<p class="error">' + error + "</p>" if error else ""
    return ('''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AWS 审计报告登录</title>
<link rel="stylesheet" href="/audit/login.css"></head><body><main>
<h1>AWS 操作审计报告</h1><p>请输入 Lark 日报通知中的访问密码。</p>'''
            + notice + '''<form method="post" action="/audit/login">
<label for="password">访问密码</label><input id="password" name="password" type="password"
autocomplete="current-password" maxlength="128" required autofocus>
<button type="submit">查看报告</button></form><p><small>密码在下一次日报更新时更换。</small></p>
</main></body></html>''').encode("utf-8")


class _LoginLimiter:
    """Bound memory and expensive password checks; all clocks are monotonic."""

    def __init__(self):
        self.lock = threading.Lock()
        self.attempts = deque()
        self.failures = OrderedDict()

    def allow(self, address):
        now = time.monotonic()
        with self.lock:
            while self.attempts and self.attempts[0] <= now - 60:
                self.attempts.popleft()
            previous = self.failures.get(address, deque())
            while previous and previous[0] <= now - 300:
                previous.popleft()
            if len(self.attempts) >= 60 or len(previous) >= 5:
                return False
            self.attempts.append(now)
            return True

    def record(self, address, success):
        with self.lock:
            if success:
                self.failures.pop(address, None)
                return
            previous = self.failures.setdefault(address, deque(maxlen=5))
            previous.append(time.monotonic())
            self.failures.move_to_end(address)
            while len(self.failures) > 1024:
                self.failures.popitem(last=False)


class AuditHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, publish_dir, state_dir, port):
        self.publish_dir = Path(publish_dir).resolve()
        state_directory = Path(state_dir).resolve()
        if (state_directory == self.publish_dir or self.publish_dir in state_directory.parents
                or state_directory in self.publish_dir.parents):
            raise ValueError("认证目录必须独立于网页发布目录。")
        self.state_file = state_directory / "access.json"
        self.limiter = _LoginLimiter()
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(("127.0.0.1", port), AuditHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # No traceback containing request headers, cookie or submitted values.
        return


class AuditHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "AuditReport"
    sys_version = ""

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, format, *args):
        # Do not log URLs, cookies or request data. Nginx may log route/status.
        return

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler can otherwise reflect malformed request text.
        self._reply(code, b"Request rejected.\n", "text/plain; charset=utf-8")

    def _headers(self, status, content_type, length, *, location=None, cookie=None, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True

    def _reply(self, status, body=b"", content_type="text/html; charset=utf-8", **kwargs):
        try:
            self._headers(status, content_type, len(body), **kwargs)
            if self.command != "HEAD" and body:
                self.wfile.write(body)
        except (OSError, socket.timeout):
            self.close_connection = True

    def _path(self):
        try:
            parts = urlsplit(self.path)
            if parts.scheme or parts.netloc or parts.fragment:
                return None
            return parts.path
        except ValueError:
            return None

    def _state(self):
        try:
            return load_access(self.server.state_file)
        except (AccessError, OSError, ValueError, TypeError):
            self._reply(503, "认证尚未就绪，请稍后重试。".encode("utf-8"))
            return None

    def _session(self, state):
        try:
            header = self.headers.get("Cookie", "")
            if len(header) > 4096:
                return False
            cookies = SimpleCookie()
            cookies.load(header)
            item = cookies.get(COOKIE_NAME)
            return bool(item and verify_session(item.value, state))
        except (CookieError, ValueError, TypeError):
            return False

    def _address(self):
        # Only this loopback service is reachable. The Nginx snippet overwrites
        # X-Real-IP, rather than forwarding a caller-controlled header.
        address = self.headers.get("X-Real-IP", self.client_address[0])
        try:
            return str(ipaddress.ip_address(address))
        except ValueError:
            return self.client_address[0]

    def _same_origin(self):
        """Require a browser form from the public HTTPS host Nginx preserves."""
        hosts = self.headers.get_all("Host", [])
        origins = self.headers.get_all("Origin", [])
        referers = self.headers.get_all("Referer", [])
        if len(hosts) != 1 or len(origins) > 1 or len(referers) > 1:
            return False
        origin = origins[0] if origins else referers[0] if referers else ""
        try:
            expected = urlsplit("https://" + hosts[0])
            actual = urlsplit(origin)
            if (not expected.hostname or expected.username is not None or expected.password is not None
                    or expected.path or expected.query or expected.fragment
                    or actual.scheme != "https" or actual.username is not None or actual.password is not None
                    or not actual.hostname or any(ch.isspace() for ch in hosts[0] + origin)):
                return False
            if origins and (actual.path or actual.query or actual.fragment):
                return False
            actual_port = 443 if actual.port is None else actual.port
            expected_port = 443 if expected.port is None else expected.port
            return (actual.hostname.lower(), actual_port) == (expected.hostname.lower(), expected_port)
        except ValueError:
            return False

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self._path()
        if path == "/audit":
            self._reply(303, location="/audit/")
            return
        if path == "/audit/login.css":
            self._reply(200, LOGIN_CSS, "text/css; charset=utf-8")
            return
        if path == "/audit/logout":
            self._reply(405, extra={"Allow": "POST"})
            return
        if path not in FILES and path != "/audit/login":
            self._reply(404, b"Not found.\n", "text/plain; charset=utf-8")
            return
        state = self._state()
        if state is None:
            return
        if path == "/audit/login":
            self._reply(200, _login_page())
            return
        if not self._session(state):
            self._reply(303, location="/audit/login")
            return
        name, content_type = FILES[path]
        target = self.server.publish_dir / name
        try:
            if not target.resolve().is_relative_to(self.server.publish_dir):
                raise FileNotFoundError
            with target.open("rb") as stream:
                length = os.fstat(stream.fileno()).st_size
                if length > 128 * 1024 * 1024:
                    self._reply(503, b"Report unavailable.\n", "text/plain; charset=utf-8")
                    return
                self._headers(200, content_type, length)
                if self.command != "HEAD":
                    while chunk := stream.read(65536):
                        self.wfile.write(chunk)
        except (FileNotFoundError, IsADirectoryError, PermissionError):
            self._reply(404, b"Not found.\n", "text/plain; charset=utf-8")
        except (OSError, socket.timeout):
            self.close_connection = True

    def _read_body(self):
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding"):
            raise ValueError
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdigit() or len(lengths[0]) > 6:
            raise ValueError
        length = int(lengths[0])
        if length > 2048:
            # Drain a small rejected body before closing so the OS does not
            # discard our error response with a reset. Larger bodies are
            # rejected by Nginx's client_max_body_size before reaching here.
            if length <= 65536:
                self.rfile.read(length)
            raise ValueError
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError
        return body

    def _form(self, body):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            raise ValueError
        return parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True, max_num_fields=2)

    def do_POST(self):
        path = self._path()
        try:
            body = self._read_body()
        except (ValueError, OSError):
            self._reply(400, _login_page("请求格式无效，请重新输入密码。"))
            return
        if path not in {"/audit/login", "/audit/logout"}:
            self._reply(404, b"Not found.\n", "text/plain; charset=utf-8")
            return
        if not self._same_origin():
            self._reply(403, _login_page("请通过 HTTPS 报告页面提交密码。"))
            return
        if path == "/audit/logout":
            self._reply(303, location="/audit/login", cookie=(
                COOKIE_NAME + "=; Path=/audit/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"))
            return
        address = self._address()
        if not self.server.limiter.allow(address):
            self._reply(429, _login_page("尝试次数过多，请五分钟后再试。"), extra={"Retry-After": "300"})
            return
        state = self._state()
        if state is None:
            return
        try:
            values = self._form(body)
            if set(values) != {"password"} or len(values["password"]) != 1:
                raise ValueError
            password = values["password"][0]
            if not 1 <= len(password) <= 128:
                raise ValueError
        except (ValueError, UnicodeError, OSError):
            self._reply(400, _login_page("请求格式无效，请重新输入密码。"))
            return
        success = verify_password(password, state)
        self.server.limiter.record(address, success)
        if not success:
            self._reply(401, _login_page("密码不正确，请使用最新 Lark 通知中的密码。"))
            return
        token = make_session(state)
        self._reply(303, location="/audit/", cookie=(
            COOKIE_NAME + "=" + token + f"; Path=/audit/; Max-Age={SESSION_SECONDS}; Secure; HttpOnly; SameSite=Strict"))


def create_server(publish_dir, state_dir, port=0):
    """Return a loopback-only server. Caller owns serve_forever/shutdown."""
    return AuditHTTPServer(publish_dir, state_dir, port)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish-dir", default="/usr/local/shenji/index")
    parser.add_argument("--state-dir", default="/usr/local/shenji/auth")
    parser.add_argument("--port", type=int, default=9998)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port 必须在 1 至 65535 之间")
    try:
        server = create_server(args.publish_dir, args.state_dir, args.port)
        print(f"审计密码服务监听 127.0.0.1:{server.server_port}；仅供 Nginx 本机代理。", flush=True)
        with server:
            server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError) as exc:
        print(f"服务启动失败：{type(exc).__name__}。", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
