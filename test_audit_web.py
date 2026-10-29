"""单密码网页登录的 loopback HTTP 测试；不访问用户域名或外网。"""
import http.client
import tempfile
import threading
import unittest
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode

import audit_access as access
import audit_web as web


class PasswordWebsiteTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-web-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.publish = self.root / "site"
        self.publish.mkdir()
        self.state_dir = self.root / "private"
        self.html = "<!doctype html><html><body>PRIVATE_REPORT_TEST_ONLY</body></html>"
        (self.publish / "index.html").write_text(self.html, encoding="utf-8")
        (self.publish / "audit-report.css").write_text("body{color:#123456}", encoding="utf-8")
        (self.publish / "audit-report.js").write_text('"use strict";', encoding="utf-8")
        (self.publish / "report.json").write_text('{"secret":"NOT_PUBLIC"}', encoding="utf-8")
        with access.AccessRotation(self.state_dir, self.publish, "2026-10-28") as rotation:
            rotation.activate()
            self.password = rotation.password
        self.server = web.create_server(self.publish, self.state_dir, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        headers = dict(headers or {})
        if method == "POST" and "Origin" not in headers:
            # 模拟浏览器经过外层 Nginx HTTPS 后转发至回环 HTTP 服务。
            headers["Origin"] = "https://127.0.0.1:" + str(self.server.server_address[1])
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def login(self, password=None):
        status, headers, body = self.request("POST", "/audit/login", urlencode({"password": self.password if password is None else password}),
                                             {"Content-Type": "application/x-www-form-urlencoded"})
        return status, headers, body

    def valid_cookie(self):
        status, headers, _ = self.login()
        self.assertEqual(status, 303)
        cookie = SimpleCookie()
        cookie.load(headers["Set-Cookie"])
        return "__Secure-audit_session=" + cookie["__Secure-audit_session"].value

    def test_login_form_has_one_password_field_and_no_inline_scripts_or_styles(self):
        status, headers, data = self.request("GET", "/audit/login")
        self.assertEqual(status, 200)
        text = data.decode("utf-8")
        self.assertIn('name="password"', text)
        self.assertNotIn('name="username"', text)
        self.assertNotIn("<script", text)
        self.assertNotIn("<style", text)
        self.assertNotIn(self.password, text)
        self.assertIn("no-store", headers.get("Cache-Control", ""))
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        status, headers, css = self.request("GET", "/audit/login.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", headers.get("Content-Type", ""))
        self.assertNotIn(self.password.encode("ascii"), css)

    def test_every_report_resource_requires_login_and_missing_state_fails_closed(self):
        for path in ("/audit/", "/audit/index.html", "/audit/audit-report.css", "/audit/audit-report.js"):
            with self.subTest(path=path):
                status, headers, data = self.request("GET", path)
                self.assertEqual(status, 303)
                self.assertEqual(headers.get("Location"), "/audit/login")
                self.assertNotIn(b"PRIVATE_REPORT_TEST_ONLY", data)
        (self.state_dir / "access.json").unlink()
        status, _, data = self.request("GET", "/audit/")
        self.assertEqual(status, 503)
        self.assertNotIn(b"PRIVATE_REPORT_TEST_ONLY", data)

    def test_successful_login_sets_secure_cookie_and_protected_assets_have_correct_mime(self):
        status, headers, _ = self.login()
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("Location"), "/audit/")
        cookie = SimpleCookie()
        cookie.load(headers["Set-Cookie"])
        morsel = cookie["__Secure-audit_session"]
        self.assertEqual(morsel["path"], "/audit/")
        self.assertTrue(morsel["secure"])
        self.assertTrue(morsel["httponly"])
        self.assertEqual(morsel["samesite"].lower(), "strict")
        auth_header = {"Cookie": "__Secure-audit_session=" + morsel.value}
        status, headers, data = self.request("GET", "/audit/", headers=auth_header)
        self.assertEqual(status, 200)
        self.assertEqual(data.decode("utf-8"), self.html)
        self.assertIn("no-store", headers.get("Cache-Control", ""))
        self.assertIn("text/html", headers.get("Content-Type", ""))
        for path, mime in (("audit-report.css", "text/css"), ("audit-report.js", "javascript")):
            with self.subTest(path=path):
                status, headers, _ = self.request("GET", "/audit/" + path + "?v=TEST", headers=auth_header)
                self.assertEqual(status, 200)
                self.assertIn(mime, headers.get("Content-Type", ""))

    def test_bad_password_and_tampered_cookie_cannot_read_report(self):
        status, _, data = self.login("TEST_WRONG_PASSWORD")
        self.assertIn(status, (401, 403))
        self.assertNotIn(b"PRIVATE_REPORT_TEST_ONLY", data)
        status, headers, data = self.request("GET", "/audit/", headers={"Cookie": "__Secure-audit_session=forged"})
        self.assertEqual(status, 303)
        self.assertNotIn(b"PRIVATE_REPORT_TEST_ONLY", data)

    def test_rotation_revokes_old_cookie_and_old_password(self):
        cookie = self.valid_cookie()
        with access.AccessRotation(self.state_dir, self.publish, "2026-10-29") as rotation:
            rotation.activate()
            next_password = rotation.password
        status, _, data = self.request("GET", "/audit/", headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        self.assertNotIn(b"PRIVATE_REPORT_TEST_ONLY", data)
        self.assertIn(self.login(self.password)[0], (401, 403))
        self.assertEqual(self.login(next_password)[0], 303)

    def test_unknown_paths_archives_and_traversal_never_expose_files(self):
        cookie = self.valid_cookie()
        for path in ("/audit/report.json", "/audit/../private/access.json", "/audit/%2e%2e/private/access.json", "/audit/index.html/extra", "/audit/.index-old.tmp", "/elsewhere"):
            with self.subTest(path=path):
                status, _, data = self.request("GET", path, headers={"Cookie": cookie})
                self.assertIn(status, (303, 404))
                self.assertNotIn(b"NOT_PUBLIC", data)
                self.assertNotIn(self.password.encode("ascii"), data)
                self.assertNotIn(b"password_hash", data)

    def test_head_checks_auth_but_sends_no_body_and_logout_clears_cookie(self):
        self.assertEqual(self.request("HEAD", "/audit/")[0], 303)
        cookie = self.valid_cookie()
        status, headers, data = self.request("HEAD", "/audit/", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertEqual(data, b"")
        self.assertEqual(int(headers.get("Content-Length", "-1")), len(self.html.encode("utf-8")))
        status, headers, _ = self.request("POST", "/audit/logout", body="", headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        self.assertIn("Max-Age=0", headers.get("Set-Cookie", ""))

    def test_oversized_login_body_and_ambiguous_form_are_rejected(self):
        status, _, _ = self.request("POST", "/audit/login", "password=" + "x" * 3000,
                                    {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertIn(status, (400, 413))
        status, _, _ = self.request("POST", "/audit/login", "password=a&password=b",
                                    {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 400)

    def test_cross_origin_form_cannot_create_authenticated_session(self):
        status, headers, data = self.request("POST", "/audit/login", urlencode({"password": self.password}),
                                            {"Origin": "https://foreign.example.invalid", "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn(self.password.encode("ascii"), data)

    def test_repeated_bad_passwords_are_limited_before_more_hashing(self):
        for _ in range(5):
            self.assertEqual(self.login("TEST_WRONG_PASSWORD")[0], 401)
        status, headers, data = self.login()
        self.assertEqual(status, 429)
        self.assertIn("Retry-After", headers)
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn(self.password.encode("ascii"), data)


if __name__ == "__main__":
    unittest.main()
