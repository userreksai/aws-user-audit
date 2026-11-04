"""Only actionable failures reach the Lark transport; all requests are mocked."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from audit_alerts import notify_issues


NOW = datetime(2026, 11, 4, 0, 1, tzinfo=timezone.utc)
TOKEN = "11111111-1111-4111-8111-111111111111"


class AuditAlertTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-alert-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = {"LARK_ALERTS_ENABLED": True,
                       "LARK_WEBHOOK_URL": "https://open.larksuite.com/open-apis/bot/v2/hook/" + TOKEN,
                       "LARK_SIGNING_SECRET": "TEST_SIGNING_SECRET_NOT_FOR_OUTPUT", "STATE_DIRECTORY": str(self.root / "state")}
        self.transport = patch("lark_notify._send_payload").start()
        self.addCleanup(patch.stopall)

    def notify(self, issues=None, **options):
        options.setdefault("now", NOW)
        return notify_issues(self.config, "2026-11-04", issues if issues is not None else [{"account_id": "123456789012", "stage": "collection"}], **options)

    def test_healthy_runs_and_disabled_alerts_are_silent_without_creating_state(self):
        self.assertEqual(self.notify([]), {"sent": False, "failed": False})
        self.config["LARK_ALERTS_ENABLED"] = False
        self.assertEqual(self.notify(), {"sent": False, "failed": False})
        self.transport.assert_not_called()
        self.assertFalse(Path(self.config["STATE_DIRECTORY"]).exists())

    def test_failure_payload_exposes_only_account_stage_date_and_signing_material_is_not_report_text(self):
        issues = [{"account_id": "123456789012", "stage": "collection", "error": "TEST_PROVIDER_SECRET"},
                  {"account_id": "TEST_BAD_ACCOUNT_SECRET", "stage": "TEST_UNKNOWN_STAGE_SECRET"},
                  {"stage": "mail", "smtp_password": "TEST_SMTP_SECRET"},
                  {"account_id": "123456789012", "stage": "collection"}]
        self.assertEqual(self.notify(issues), {"sent": True, "failed": False})
        self.transport.assert_called_once()
        payload, webhook, opener = self.transport.call_args.args
        text = payload["content"]["text"]
        self.assertIn("123456789012", text)
        self.assertIn("采集或解析不完整", text)
        self.assertIn("邮件投递失败或未确认", text)
        self.assertIn("2026-11-04", text)
        self.assertEqual(text.count("账号 123456789012"), 1)
        self.assertEqual(payload["timestamp"], str(int(NOW.timestamp())))
        self.assertTrue(payload["sign"])
        self.assertEqual(webhook, self.config["LARK_WEBHOOK_URL"])
        self.assertIsNone(opener)
        state = (Path(self.config["STATE_DIRECTORY"]) / "lark-failure.json").read_text()
        for secret in ("TEST_PROVIDER_SECRET", "TEST_BAD_ACCOUNT_SECRET", "TEST_UNKNOWN_STAGE_SECRET", "TEST_SMTP_SECRET",
                       self.config["LARK_SIGNING_SECRET"], TOKEN):
            self.assertNotIn(secret, text + state)

    def test_identical_errors_are_suppressed_for_one_hour_but_new_stage_is_sent(self):
        self.notify()
        result = self.notify(now=NOW + timedelta(minutes=59))
        self.assertTrue(result["suppressed"])
        self.assertEqual(self.transport.call_count, 1)
        self.notify(now=NOW + timedelta(hours=1))
        self.assertEqual(self.transport.call_count, 2)
        self.notify([{"stage": "publish"}], now=NOW + timedelta(hours=1, minutes=1))
        self.assertEqual(self.transport.call_count, 3)

    def test_transport_failure_is_safe_and_next_actual_run_attempts_again(self):
        self.transport.side_effect = RuntimeError("TEST_PRIVATE_WEBHOOK_AND_PROVIDER_RESPONSE")
        self.assertEqual(self.notify(), {"sent": False, "failed": True})
        self.assertFalse((Path(self.config["STATE_DIRECTORY"]) / "lark-failure.json").exists())
        self.transport.side_effect = None
        self.assertEqual(self.notify(), {"sent": True, "failed": False})
        self.assertEqual(self.transport.call_count, 2)

    def test_large_failure_lists_are_bounded_below_transport_limit(self):
        self.notify([{"account_id": f"{number:012d}", "stage": "collection"} for number in range(100)])
        payload = self.transport.call_args.args[0]
        text = payload["content"]["text"]
        self.assertIn("另有 50 项", text)
        self.assertLess(len(json.dumps(payload, ensure_ascii=False).encode("utf-8")), 20 * 1024)
        self.assertEqual(text.count("：采集或解析不完整"), 50)

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits")
    def test_alert_state_is_private(self):
        self.notify()
        directory = Path(self.config["STATE_DIRECTORY"])
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / "lark-failure.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
