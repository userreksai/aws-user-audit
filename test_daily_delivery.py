"""日报25小时窗口、发布副本与总览通知；使用假数据且不访问网络。"""
import io
import tempfile
import unittest
from html.parser import HTMLParser
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import aws_daily_audit as audit
import lark_notify as notify


class DailyWindowTests(unittest.TestCase):
    now = datetime(2026, 10, 28, 0, 1, tzinfo=timezone.utc)

    def test_0801_run_covers_previous_0700_to_current_0800(self):
        day, start, end, partial = audit.resolve_window(None, "Asia/Shanghai", now=self.now, daily=True)
        self.assertEqual(day, "2026-10-28")
        self.assertEqual(start, datetime(2026, 10, 26, 23, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 10, 28, 0, tzinfo=timezone.utc))
        self.assertEqual(end - start, timedelta(hours=25))
        self.assertFalse(partial)

    def test_successive_reports_have_exactly_one_hour_overlap(self):
        _, _, first_end, _ = audit.resolve_window("2026-10-27", "Asia/Shanghai", now=self.now, daily=True)
        _, second_start, _, _ = audit.resolve_window("2026-10-28", "Asia/Shanghai", now=self.now, daily=True)
        self.assertEqual(first_end - second_start, timedelta(hours=1))

    def test_today_flag_matches_default_and_historical_date_is_end_date(self):
        expected = audit.resolve_window(None, "Asia/Shanghai", now=self.now, daily=True)
        self.assertEqual(audit.resolve_window(None, "Asia/Shanghai", today=True, now=self.now, daily=True), expected)
        self.assertEqual(audit.resolve_window("2026-10-28", "Asia/Shanghai", now=self.now, daily=True), expected)

    def test_before_eight_and_future_dates_rejected_without_shortening_window(self):
        for day, clock in ((None, self.now - timedelta(minutes=2)), ("2026-10-29", self.now)):
            with self.subTest(day=day), self.assertRaises(ValueError):
                audit.resolve_window(day, "Asia/Shanghai", now=clock, daily=True)

    def test_cross_month_calendar_boundary_and_fixed_beijing(self):
        clock = datetime(2026, 11, 1, 0, 1, tzinfo=timezone.utc)
        day, start, end, _ = audit.resolve_window(None, "Asia/Shanghai", now=clock, daily=True)
        self.assertEqual(day, "2026-11-01")
        self.assertEqual(start, datetime(2026, 10, 30, 23, tzinfo=timezone.utc))
        self.assertEqual(end - start, timedelta(hours=25))
        with self.assertRaises(ValueError):
            audit.resolve_window(None, "UTC", now=clock, daily=True)

    def test_end_is_exclusive_and_archival_metadata_records_overlap(self):
        day, start, end, _ = audit.resolve_window(None, "Asia/Shanghai", now=self.now, daily=True)
        base = {"eventName": "CreateUser", "eventSource": "iam.amazonaws.com", "readOnly": False,
                "awsRegion": "us-east-1", "userIdentity": {"type": "IAMUser", "userName": "demo"}}
        events = [dict(base, eventID=str(index), eventTime=stamp.isoformat())
                  for index, stamp in enumerate((start - timedelta(seconds=1), start, end - timedelta(seconds=1), end))]
        report = audit.build_report(events, audit_date=day, timezone_name="Asia/Shanghai", start=start, end=end,
                                   offline=True, window_mode="daily_25h", regions=["us-east-1"])
        self.assertEqual([x["event_id"] for x in report["events"]], ["1", "2"])
        self.assertEqual(report["metadata"]["overlap_hours"], 1)
        self.assertIn("25小时", report["metadata"]["period_label"])


class PublishAndOverviewTests(unittest.TestCase):
    def test_copy_preserves_archive_and_replaces_index_with_complete_bytes(self):
        with tempfile.TemporaryDirectory(prefix="audit-publish-test-") as folder:
            root = Path(folder)
            source = root / "2026-10-28-aws操作审计.html"
            source.write_text("<!doctype html><p>审计日报</p>", encoding="utf-8")
            destination = root / "web"
            destination.mkdir()
            (destination / "index.html").write_text("old report", encoding="utf-8")
            target = audit.publish_report(source, destination)
            self.assertEqual(target.name, "index.html")
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertTrue(source.exists())
            self.assertFalse(list(destination.glob(".index-*.tmp")))

    def test_failed_copy_keeps_previous_index_and_removes_only_its_temporary_file(self):
        with tempfile.TemporaryDirectory(prefix="audit-publish-test-") as folder:
            root = Path(folder)
            (root / "index.html").write_text("previous", encoding="utf-8")
            (root / "unused-source.html").write_text("<!doctype html><p>new</p>", encoding="utf-8")
            with patch.object(audit.shutil, "copyfile", side_effect=PermissionError("test denial")):
                with self.assertRaises(PermissionError):
                    audit.publish_report(root / "unused-source.html", root)
            self.assertEqual((root / "index.html").read_text(encoding="utf-8"), "previous")
            self.assertFalse(list(root.glob(".index-*.tmp")))

    def test_overview_lists_counts_before_details_link_without_operation_rows(self):
        report = {"metadata": {"audit_date": "2026-10-28", "account_id": "123456789012", "complete": True,
                  "total": 12, "failed_or_partial": 1, "window_start_utc": "2026-10-26T23:00:00Z",
                  "window_end_utc_exclusive": "2026-10-28T00:00:00Z",
                  "counts": {"新增": 2, "删除": 3, "修改": 7}},
                  "events": [{"actor": "SHOULD_NOT_BE_SENT_AS_DETAILS"}]}
        payloads = notify.build_lark_payloads(report, {})
        text = payloads[0]["content"]["text"]
        self.assertEqual(len(payloads), 1)
        for field in ("新增：2", "删除：3", "修改：7", "2026-10-27 07:00:00", "2026-10-28 08:00:00", notify.DEFAULT_REPORT_URL):
            self.assertIn(field, text)
        self.assertLess(text.index("新增：2"), text.index("详细报告："))
        self.assertNotIn("SHOULD_NOT_BE_SENT_AS_DETAILS", text)

    def test_cli_publishes_before_sending_and_forces_requested_overview_url(self):
        day, start, end, _ = audit.resolve_window(None, "Asia/Shanghai", now=DailyWindowTests.now, daily=True)
        order = []
        with patch.object(audit, "resolve_window", return_value=(day, start, end, False)) as window, \
             patch.object(audit, "load_input", return_value=[]), \
             patch.object(audit, "write_report", return_value=Path("archives")), \
             patch.object(audit, "publish_report", side_effect=lambda *a: order.append("publish") or Path("web/index.html")), \
             patch.object(notify, "load_lark_config", return_value={"webhook_url": "unused", "message_mode": "full"}), \
             patch.object(notify, "send_lark_notification", side_effect=lambda *a: order.append("notify") or {"code": 0}) as send, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            status = audit.main(["--input-file", "unused.json", "--publish-dir", "web", "--send-lark"])
        self.assertEqual(status, 0)
        self.assertEqual(order, ["publish", "notify"])
        self.assertTrue(window.call_args.kwargs["daily"])
        self.assertEqual(send.call_args.args[1]["message_mode"], "overview")
        self.assertEqual(send.call_args.args[1]["report_url_template"], notify.DEFAULT_REPORT_URL)

    def test_publish_failure_preserves_archives_and_prevents_stale_link_notification(self):
        day, start, end, _ = audit.resolve_window(None, "Asia/Shanghai", now=DailyWindowTests.now, daily=True)
        with patch.object(audit, "resolve_window", return_value=(day, start, end, False)), \
             patch.object(audit, "load_input", return_value=[]), \
             patch.object(audit, "write_report", return_value=Path("archives")) as write, \
             patch.object(audit, "publish_report", side_effect=PermissionError("test denial")), \
             patch.object(notify, "send_lark_notification") as send, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            status = audit.main(["--input-file", "unused.json", "--publish-dir", "web", "--send-lark"])
        self.assertEqual(status, 4)
        write.assert_called_once()
        send.assert_not_called()


class ReportCspCompatibilityTests(unittest.TestCase):
    def make_report(self):
        day, start, end, _ = audit.resolve_window(None, "Asia/Shanghai", now=DailyWindowTests.now, daily=True)
        return audit.build_report([], audit_date=day, timezone_name="Asia/Shanghai", start=start, end=end,
                                  offline=True, window_mode="daily_25h", regions=["us-east-1"])

    def test_html_uses_same_origin_css_and_script_with_no_inline_code(self):
        class Inspect(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links, self.scripts, self.inline = [], [], []

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "style" or "style" in attrs or any(key.startswith("on") for key in attrs):
                    self.inline.append(tag)
                if tag == "link" and attrs.get("rel") == "stylesheet":
                    self.links.append(attrs.get("href"))
                if tag == "script":
                    if not attrs.get("src"):
                        self.inline.append(tag)
                    self.scripts.append(attrs)

        parser = Inspect()
        parser.feed(audit.render_html(self.make_report()))
        self.assertFalse(parser.inline)
        self.assertEqual(parser.links, [audit.asset_url("audit-report.css")])
        self.assertEqual(len(parser.scripts), 1)
        self.assertEqual(parser.scripts[0]["src"], audit.asset_url("audit-report.js"))
        self.assertIn("defer", parser.scripts[0])
        for reference in parser.links + [parser.scripts[0]["src"]]:
            self.assertNotIn("://", reference)
            self.assertIn("?v=", reference)

    def test_generated_archive_and_published_index_have_all_matching_assets(self):
        with tempfile.TemporaryDirectory(prefix="audit-csp-test-") as folder:
            root = Path(folder)
            report = self.make_report()
            archived = audit.write_report(report, root / "reports")
            source = archived / "2026-10-28-aws操作审计.html"
            index = audit.publish_report(source, root / "web")
            self.assertEqual(index.read_bytes(), source.read_bytes())
            for name, content in audit.report_assets().items():
                self.assertEqual((archived / name).read_text(encoding="utf-8"), content)
                self.assertEqual((index.parent / name).read_bytes(), (archived / name).read_bytes())
            self.assertTrue((archived / "report.json").is_file())
            self.assertFalse((index.parent / "report.json").exists())

    def test_missing_referenced_asset_does_not_publish_broken_index(self):
        with tempfile.TemporaryDirectory(prefix="audit-csp-test-") as folder:
            root = Path(folder)
            archived = audit.write_report(self.make_report(), root / "reports")
            (archived / "audit-report.css").unlink()
            destination = root / "web"
            destination.mkdir()
            (destination / "index.html").write_text("previous report", encoding="utf-8")
            (destination / "audit-report.js").write_text("previous script", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                audit.publish_report(archived / "2026-10-28-aws操作审计.html", destination)
            self.assertEqual((destination / "index.html").read_text(encoding="utf-8"), "previous report")
            self.assertEqual((destination / "audit-report.js").read_text(encoding="utf-8"), "previous script")


if __name__ == "__main__":
    unittest.main()
