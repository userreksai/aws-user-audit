"""密码通知与发布顺序；全部使用本地文件与模拟 Lark。"""
import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import audit_access as access
import aws_daily_audit as audit
import lark_notify as notify
from test_lark_notify import FAKE_WEBHOOK, sample_report


class AccessDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-access-delivery-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.web = self.root / "web"
        self.web.mkdir()
        self.source = self.root / "report.html"
        self.source.write_text("<p>FICTIONAL_REPORT_ONLY</p>", encoding="utf-8")
        self.args = argparse.Namespace(auth_state_dir=str(self.root / "private"),
                                       output_dir=str(self.root / "archive"),
                                       lark_config="unused", lark_mode="overview",
                                       report_url="https://audit.example.invalid/audit/")
        self.config = {"webhook_url": FAKE_WEBHOOK}
        self.report = sample_report(audit_date="2026-10-28")

    def run_delivery(self, sender):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(notify, "load_lark_config", return_value=dict(self.config)), \
             patch.object(notify, "send_lark_notification", side_effect=sender) as send, \
             redirect_stdout(stdout), redirect_stderr(stderr):
            result = audit.publish_with_access(self.report, self.source, self.args, self.web)
        return result, send, stdout.getvalue() + stderr.getvalue()

    def test_publishes_activates_then_sends_password_separately_from_report(self):
        def sender(report, config, *, access_password):
            self.assertEqual((self.web / "index.html").read_bytes(), self.source.read_bytes())
            state = access.load_access(self.root / "private" / "access.json")
            self.assertTrue(access.verify_password(access_password, state))
            self.assertNotIn(access_password, json.dumps(report))
            self.assertNotIn(access_password, json.dumps(config))
            return {"code": 0}
        result, send, output = self.run_delivery(sender)
        self.assertEqual(result, 0)
        password = send.call_args.kwargs["access_password"]
        self.assertNotIn(password, output)
        self.assertNotIn(password, (self.web / "index.html").read_text())

    def test_uncertain_lark_failure_keeps_valid_password_and_retry_resends_same_one(self):
        result, send, output = self.run_delivery(notify.LarkNotificationError("模拟超时"))
        password = send.call_args.kwargs["access_password"]
        self.assertEqual(result, 3)
        self.assertTrue(access.verify_password(password, access.load_access(self.root / "private" / "access.json")))
        self.assertNotIn(password, output)
        result, retry, _ = self.run_delivery(lambda *a, **kw: {"code": 0})
        self.assertEqual(result, 0)
        self.assertEqual(retry.call_args.kwargs["access_password"], password)

    def test_copy_failure_does_not_activate_or_notify(self):
        with patch.object(audit, "publish_report", side_effect=OSError("simulated")):
            result, send, _ = self.run_delivery(lambda *a, **kw: {"code": 0})
        self.assertEqual(result, 4)
        send.assert_not_called()
        self.assertFalse((self.root / "private" / "access.json").exists())

    def test_invalid_link_stops_before_publication_and_activation(self):
        self.args.report_url = "http://audit.example.invalid/audit/"
        result, send, _ = self.run_delivery(lambda *a, **kw: {"code": 0})
        self.assertEqual(result, 4)
        send.assert_not_called()
        self.assertFalse((self.web / "index.html").exists())
        self.assertFalse((self.root / "private" / "access.json").exists())

    def test_overview_counts_and_link_are_followed_by_password_without_username(self):
        password = "TEST_ONLY_PASSWORD_12345"
        payload = notify.build_lark_payloads(self.report, {**self.config, "message_mode": "overview",
                                                          "report_url_template": self.args.report_url}, access_password=password)[0]
        text = payload["content"]["text"]
        self.assertLess(text.index("新增："), text.index("详细报告："))
        self.assertIn("访问密码：" + password, text)
        self.assertNotIn("用户名", text)
        self.assertNotIn(password, self.args.report_url)

    def test_non_overview_access_notification_rejected_before_transport(self):
        with self.assertRaises(ValueError):
            notify.build_lark_payloads(self.report, {**self.config, "message_mode": "full"},
                                      access_password="TEST_ONLY_PASSWORD_12345")

    def test_cli_archive_write_is_inside_the_rotation_lock(self):
        from datetime import datetime, timezone
        start = datetime(2026, 10, 26, 23, tzinfo=timezone.utc)
        end = datetime(2026, 10, 28, 0, tzinfo=timezone.utc)
        real_write = audit.write_report

        def locked_write(report, directory):
            with self.assertRaises(access.AccessError):
                with access.AccessRotation(self.args.auth_state_dir, self.web, "2026-10-28", self.args.output_dir):
                    self.fail("归档写入须已持有发布锁")
            return real_write(report, directory)

        with patch.object(audit, "resolve_window", return_value=("2026-10-28", start, end, False)), \
             patch.object(audit, "load_input", return_value=[]), \
             patch.object(audit, "write_report", side_effect=locked_write), \
             patch.object(notify, "load_lark_config", return_value=dict(self.config)), \
             patch.object(notify, "send_lark_notification", return_value={"code": 0}) as send, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = audit.main(["--input-file", "unused.json", "--publish-dir", str(self.web),
                                 "--auth-state-dir", self.args.auth_state_dir,
                                 "--output-dir", self.args.output_dir, "--send-lark"])
        self.assertEqual(result, 0)
        send.assert_called_once()

    def test_auth_cannot_be_enabled_without_password_notification(self):
        with patch.object(audit, "load_input") as read, redirect_stderr(io.StringIO()):
            result = audit.main(["--input-file", "unused.json", "--publish-dir", str(self.web),
                                 "--auth-state-dir", self.args.auth_state_dir])
        self.assertEqual(result, 1)
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
