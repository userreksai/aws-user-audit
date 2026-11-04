"""Offline SMTP delivery-budget tests; no provider is contacted."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import audit_mail_delivery as delivery
from audit_mail import MailDeliveryError


NOW = datetime(2026, 11, 4, 0, 1, tzinfo=timezone.utc)


def report(account="123456789012", day="2026-11-04", complete=True):
    return {"metadata": {"account_id": account, "audit_date": day, "complete": complete,
                         "counts": {"新增": 3, "删除": 2, "修改": 4, "Secrets Manager 查看": 5,
                                    "登录信息": 1, "其他操作": 0},
                         "window_start_local": "2026-11-03 07:00:00+08:00",
                         "window_end_local_exclusive": "2026-11-04 08:00:00+08:00",
                         "window_start_utc": "2026-11-02T23:00:00+00:00",
                         "window_end_utc_exclusive": "2026-11-04T00:00:00+00:00",
                         "generated_at": "2026-11-04T08:01:00+08:00", "offline": False,
                         "failed_or_partial": 1}, "events": []}


class AuditMailDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-mail-delivery-")
        self.root = Path(self.temporary.name)
        self.state = self.root / "private"
        self.pdf = self.root / "123456789012-2026-11-04-aws操作审计.pdf"
        self.pdf.write_bytes(b"%PDF-1.4\nfictional test PDF")
        self.config = {"AUTO_MAIL_MAX_PER_DAY": 1, "MAIL_SUBJECT": "AWS账号操作审计日报",
                       "SMTP_AUTH_CODE": "TEST_SECRET_NEVER_SAVED", "MAIL_RECIPIENTS": ["private@example.invalid"]}
        self.sender = patch("audit_mail.send_reports", return_value={"smtp_accepted": True}).start()
        self.addCleanup(patch.stopall)
        self.addCleanup(self.temporary.cleanup)

    def send(self, value=None, **options):
        options.setdefault("now", NOW)
        return delivery.deliver_report(value or report(), self.pdf, self.config, self.state, **options)

    def read_state(self):
        return json.loads((self.state / "mail-delivery.json").read_text(encoding="utf-8"))

    def test_multiple_accounts_share_one_message_with_all_pdfs(self):
        another = self.root / "210987654321-2026-11-04-aws操作审计.pdf"
        another.write_bytes(self.pdf.read_bytes())
        reports = [report(), report("210987654321", complete=False)]
        result = delivery.deliver_reports(reports, [self.pdf, another], self.config, self.state,
                                         automatic=True, now=NOW, report_url="https://example.invalid/audit/")
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["account_count"], 2)
        self.assertFalse(result["complete"])
        self.sender.assert_called_once()
        args, kwargs = self.sender.call_args
        self.assertEqual(args[1], [self.pdf, another])
        self.assertIn("123456789012", args[2])
        self.assertIn("210987654321", args[2])
        self.assertIn("新增 3；删除 2；修改 4", args[2])
        self.assertIn("Secrets Manager 查看 5", args[2])
        self.assertIn("2026-11-03 07:00:00", args[2])
        self.assertIn("https://example.invalid/audit/", args[2])
        self.assertIn("不完整", kwargs["subject"])

    def test_automatic_revisions_recipients_and_account_changes_cannot_send_second_message(self):
        self.assertEqual(self.send(automatic=True)["status"], "accepted")
        changed = report()
        changed["metadata"]["counts"]["新增"] = 999
        changed["metadata"]["complete"] = False
        self.config["MAIL_RECIPIENTS"] = ["changed@example.invalid"]
        self.assertEqual(self.send(changed, automatic=True)["status"], "suppressed")
        self.assertEqual(self.send(report("210987654321"), automatic=True)["reason"], "daily_limit")
        self.sender.assert_called_once()

    def test_manual_repeat_requires_force_and_forced_failure_preserves_previous_acceptance(self):
        self.assertEqual(self.send()["status"], "accepted")
        self.assertEqual(self.send()["reason"], "report_already_accepted")
        self.sender.side_effect = MailDeliveryError("TEST_AUTH_SECRET_NOT_LOGGED")
        self.assertEqual(self.send(force_resend=True)["status"], "failed")
        self.assertEqual(self.send()["reason"], "report_already_accepted")
        self.assertEqual(self.sender.call_count, 2)

    def test_explicit_manual_send_can_exceed_day_budget_for_a_different_report(self):
        self.send(automatic=True)
        self.assertEqual(self.send(report("210987654321"))["status"], "accepted")
        self.assertEqual(self.sender.call_count, 2)
        self.assertEqual(self.send(report("999999999999"), automatic=True)["reason"], "daily_limit")

    def test_manual_acceptance_also_prevents_an_automatic_second_message_that_day(self):
        self.send()
        self.assertEqual(self.send(report("210987654321"), automatic=True)["reason"], "daily_limit")
        self.sender.assert_called_once()

    def test_disabled_automatic_mode_does_not_submit_but_manual_still_can(self):
        self.config["AUTO_MAIL_MAX_PER_DAY"] = 0
        self.assertEqual(self.send(automatic=True)["status"], "disabled")
        self.sender.assert_not_called()
        self.assertEqual(self.send()["status"], "accepted")

    def test_sending_reservation_is_on_disk_before_smtp(self):
        def check(*args, **kwargs):
            value = self.read_state()
            self.assertEqual(value["days"]["2026-11-04"]["used"], 1)
            self.assertEqual(next(iter(value["reports"].values()))["status"], "sending")
            return {"smtp_accepted": True}
        self.sender.side_effect = check
        self.assertEqual(self.send(automatic=True)["status"], "accepted")

    def test_crash_during_submission_keeps_uncertain_receipt_and_blocks_restart(self):
        self.sender.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.send(automatic=True)
        self.sender.side_effect = None
        self.assertEqual(self.send(automatic=True)["reason"], "delivery_unresolved")
        self.sender.assert_called_once()

    def test_explicit_connection_failure_releases_budget_for_next_execution(self):
        self.sender.side_effect = MailDeliveryError("TEST_SECRET")
        self.assertEqual(self.send(automatic=True)["status"], "failed")
        self.assertEqual(self.read_state()["days"]["2026-11-04"]["used"], 0)
        self.sender.side_effect = None
        self.sender.return_value = {"smtp_accepted": True}
        self.assertEqual(self.send(automatic=True)["status"], "accepted")
        self.assertEqual(self.sender.call_count, 2)

    def test_partial_refusal_or_disconnect_does_not_retry_without_explicit_force(self):
        self.sender.side_effect = MailDeliveryError("TEST_PROVIDER_SECRET", delivery_uncertain=True)
        self.assertEqual(self.send(automatic=True)["status"], "uncertain")
        self.assertEqual(self.send(automatic=True)["reason"], "delivery_unresolved")
        self.assertEqual(self.send()["reason"], "delivery_unresolved")
        self.assertEqual(self.send(report("210987654321"))["reason"], "delivery_unresolved")
        self.sender.assert_called_once()

    def test_unknown_sender_exception_is_conservatively_uncertain(self):
        self.sender.side_effect = RuntimeError("TEST_PROVIDER_SECRET")
        self.assertEqual(self.send()["status"], "uncertain")
        self.assertEqual(self.send()["reason"], "delivery_unresolved")
        self.sender.assert_called_once()

    def test_invalid_sender_receipt_is_not_claimed_as_success(self):
        self.sender.return_value = {"smtp_accepted": False}
        self.assertEqual(self.send()["status"], "uncertain")

    def test_preparation_error_is_retryable_and_never_leaks_provider_values(self):
        self.sender.side_effect = ValueError("TEST_SECRET_NEVER_PRINTED")
        result = self.send()
        self.assertEqual(result["reason"], "mail_preparation_failed")
        serialized = json.dumps(result) + (self.state / "mail-delivery.json").read_text()
        self.assertNotIn("TEST_SECRET", serialized)
        self.assertNotIn("private@example.invalid", serialized)
        self.assertNotIn("SMTP_AUTH_CODE", serialized)

    def test_invalid_or_duplicate_state_is_preserved_without_sending(self):
        self.state.mkdir(mode=0o700)
        path = self.state / "mail-delivery.json"
        for content in ("not-json TEST_SECRET", '{"schema_version":1,"schema_version":1,"days":{},"reports":{}}',
                        '{"schema_version":true,"days":{},"reports":{}}'):
            with self.subTest(content=content):
                path.write_text(content)
                path.chmod(0o600)
                self.assertEqual(self.send()["reason"], "invalid_state")
                self.assertEqual(path.read_text(), content)
        self.sender.assert_not_called()

    def test_atomic_reservation_failure_prevents_smtp(self):
        with patch.object(delivery, "_save", side_effect=delivery.MailStateError("state failed")):
            with self.assertRaises(delivery.MailStateError):
                self.send()
        self.sender.assert_not_called()

    def test_final_receipt_write_failure_leaves_sending_reservation(self):
        original = delivery._save
        calls = []
        def save(path, value):
            calls.append(1)
            if len(calls) == 2:
                raise delivery.MailStateError("state failed")
            return original(path, value)
        with patch.object(delivery, "_save", side_effect=save):
            with self.assertRaises(delivery.MailStateError):
                self.send()
        self.assertEqual(self.send()["reason"], "delivery_unresolved")
        self.sender.assert_called_once()

    def test_local_beijing_midnight_resets_budget_for_the_new_report(self):
        before = datetime(2026, 11, 4, 15, 59, tzinfo=timezone.utc)
        after = datetime(2026, 11, 4, 16, 0, tzinfo=timezone.utc)
        self.send(automatic=True, now=before)
        result = self.send(report(day="2026-11-05"), automatic=True, now=after)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["sending_day"], "2026-11-05")

    def test_same_report_is_not_resent_on_the_next_day_without_force(self):
        self.send(automatic=True)
        next_day = datetime(2026, 11, 5, 0, 1, tzinfo=timezone.utc)
        self.assertEqual(self.send(automatic=True, now=next_day)["reason"], "report_already_accepted")
        self.sender.assert_called_once()

    def test_concurrent_sender_cannot_take_the_same_process_lock(self):
        with delivery._locked(self.state):
            with self.assertRaises(delivery.MailStateError):
                self.send()
        self.sender.assert_not_called()
        self.assertEqual(self.send()["status"], "accepted")

    def test_another_process_holding_delivery_lock_prevents_duplicate_sender(self):
        ready = self.root / "ready"
        script = (
            "import sys; from pathlib import Path; from audit_mail_delivery import _locked; "
            "\nwith _locked(Path(sys.argv[1])):\n"
            "    Path(sys.argv[2]).write_text('ready')\n"
            "    sys.stdin.readline()\n"
        )
        process = subprocess.Popen([sys.executable, "-c", script, str(self.state), str(ready)],
                                   cwd=Path(__file__).resolve().parent, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "child failed to acquire its private delivery lock")
            with self.assertRaises(delivery.MailStateError):
                self.send()
            self.sender.assert_not_called()
        finally:
            try:
                process.communicate("release\n", timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        self.assertEqual(self.send()["status"], "accepted")

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits")
    def test_private_permissions_and_symlink_state(self):
        self.send()
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        path = self.state / "mail-delivery.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        original = path.read_bytes()
        other = self.root / "other.json"
        other.write_bytes(original)
        path.unlink()
        path.symlink_to(other)
        self.assertEqual(self.send()["reason"], "invalid_state")
        self.assertEqual(other.read_bytes(), original)
        self.sender.assert_called_once()

    def test_offline_and_incomplete_flags_are_visible_without_arbitrary_error_payloads(self):
        value = report(complete=False)
        value["metadata"].update(offline=True, errors=["TEST_SECRET_PROVIDER_RESPONSE"])
        self.send(value)
        _, kwargs = self.sender.call_args
        self.assertIn("[不完整]", kwargs["subject"])
        self.assertIn("[离线输入]", kwargs["subject"])
        body = self.sender.call_args.args[2]
        self.assertIn("不完整", body)
        self.assertIn("离线输入", body)
        self.assertNotIn("TEST_SECRET", body)

    def test_configuration_invalid_reports_and_force_automatic_are_rejected(self):
        with self.assertRaises(ValueError):
            self.send(automatic=True, force_resend=True)
        for limit in (True, -1, 2, "1"):
            self.config["AUTO_MAIL_MAX_PER_DAY"] = limit
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.send()
        self.config["AUTO_MAIL_MAX_PER_DAY"] = 1
        with self.assertRaises(ValueError):
            self.send(now=datetime(2026, 11, 4))
        with self.assertRaises(ValueError):
            delivery.deliver_reports([report(), report()], [self.pdf, self.pdf], self.config, self.state, now=NOW)
        with self.assertRaises(ValueError):
            delivery.deliver_reports([report()], [], self.config, self.state, now=NOW)
        with self.assertRaises(ValueError):
            delivery.deliver_reports([report(), report("210987654321", day="2026-11-05")],
                                     [self.pdf, self.pdf], self.config, self.state, now=NOW)
        self.sender.assert_not_called()


if __name__ == "__main__":
    unittest.main()
