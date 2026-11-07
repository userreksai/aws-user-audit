"""Publication and notification boundaries with fictional reports and no network."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit_publication as publication
from aws_daily_audit import build_report, report_assets


NOW = datetime(2026, 11, 7, 5, tzinfo=timezone.utc)
START = datetime(2026, 11, 6, 2, tzinfo=timezone.utc)
END = datetime(2026, 11, 7, 2, tzinfo=timezone.utc)
SECRET = "THIS_IS_A_PRIVATE_EVENT_PASSWORD"
WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/fictional-token"


def report(number=1, *, description="i-current", complete=True):
    identity = f"{number:012d}"
    event = {"eventID": f"fictional-{number}-{description}", "eventTime": "2026-11-06T04:00:00Z",
             "eventSource": "ec2.amazonaws.com", "eventName": "RunInstances", "readOnly": False,
             "awsRegion": "us-east-1", "recipientAccountId": identity, "sourceIPAddress": "203.0.113.4",
             "userIdentity": {"type": "IAMUser", "userName": "test-user", "accountId": identity},
             "requestParameters": {"instanceId": description, "password": SECRET},
             "responseElements": {"success": True}}
    value = build_report([event], audit_date="2026-11-07", timezone_name="Asia/Shanghai",
                         start=START, end=END, account_id=identity, regions=["us-east-1"],
                         errors=[] if complete else ["fictional incomplete region"],
                         window_mode="configured_daily")
    value["metadata"].update(account_name=f"account-{number}", account_tag=f"测试账号{number}")
    return value


class PageStructure(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.search_ids = 0
        self.event_rows = 0
        self.articles = 0
        self.scripts = []
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.search_ids += attrs.get("id") == "search"
        self.event_rows += tag == "tr" and "event" in attrs.get("class", "").split()
        self.articles += tag == "article" and attrs.get("class") == "account-report"
        if tag == "script":
            self.scripts.append(attrs.get("src"))


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.web = self.root / "index"

    def test_latest_overwrites_previous_and_keeps_only_public_assets(self):
        first = publication.publish_latest_reports([report(description="i-previous")], self.web)
        self.assertIn("i-previous", first.read_text(encoding="utf-8"))
        second = publication.publish_latest_reports([report(description="i-latest")], self.web)
        content = second.read_text(encoding="utf-8")
        self.assertEqual(first, second)
        self.assertIn("i-latest", content)
        self.assertNotIn("i-previous", content)
        self.assertNotIn(SECRET, content)
        self.assertEqual({path.name for path in self.web.iterdir()}, {"index.html", *report_assets()})
        for name, source in report_assets().items():
            self.assertEqual((self.web / name).read_text(encoding="utf-8"), source)

    def test_multiple_accounts_escape_metadata_keep_incomplete_events_and_one_search(self):
        reports = [report(), report(2, complete=False)]
        reports[1]["metadata"]["account_tag"] = '<script>alert("tag")</script>&测试'
        reports[1]["events"][0]["actor"] = '<img src=x onerror="alert(1)">'
        path = publication.publish_latest_reports(reports, self.web)
        content = path.read_text(encoding="utf-8")
        page = PageStructure(content)
        self.assertEqual(page.articles, 2)
        self.assertEqual(page.search_ids, 1)
        self.assertEqual(page.event_rows, 2)
        self.assertEqual(len(page.scripts), 1)
        self.assertIn("000000000001", content)
        self.assertIn("000000000002", content)
        self.assertIn("数据不完整", content)
        self.assertIn("2026-11-06 10:00:00", content)
        self.assertIn("2026-11-07 10:00:00", content)
        self.assertIn("&lt;script&gt;", content)
        self.assertIn("&lt;img", content)
        self.assertNotIn('<script>alert', content)
        self.assertNotIn('<img src=x', content)

    def test_render_failure_preserves_previous_index_and_cleans_temporary_files(self):
        path = publication.publish_latest_reports([report()], self.web)
        previous = path.read_bytes()
        broken = report(2)
        del broken["events"][0]["identity"]
        with self.assertRaises(KeyError):
            publication.publish_latest_reports([report(), broken], self.web)
        self.assertEqual(path.read_bytes(), previous)
        self.assertFalse(list(self.web.glob(".audit-publication-*")))

    def test_index_commit_failure_preserves_previous_page(self):
        path = publication.publish_latest_reports([report()], self.web)
        previous = path.read_bytes()
        replace = os.replace

        def fail_index(source, target):
            if Path(target).name == "index.html":
                raise OSError("fictional disk write failure")
            return replace(source, target)

        with patch.object(publication.os, "replace", side_effect=fail_index), self.assertRaises(OSError):
            publication.publish_latest_reports([report(description="i-uncommitted")], self.web)
        self.assertEqual(path.read_bytes(), previous)
        self.assertFalse(list(self.web.glob(".audit-publication-*")))

    def test_refuses_archive_and_private_state_directories(self):
        self.web.mkdir()
        (self.web / "report.json").write_text('{"private":true}', encoding="utf-8")
        with self.assertRaises(ValueError):
            publication.publish_latest_reports([report()], self.web)
        with self.assertRaises(ValueError):
            publication.publish_latest_reports([report()], self.root / ".state" / "web")
        self.assertFalse((self.web / "index.html").exists())

    def test_rejects_symlink_directory_and_destination(self):
        actual = self.root / "actual"
        actual.mkdir()
        linked = self.root / "linked"
        try:
            linked.symlink_to(actual, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable on this host")
        with self.assertRaises(ValueError):
            publication.publish_latest_reports([report()], linked)
        self.web.mkdir()
        private = self.root / "private.txt"
        private.write_text("unchanged", encoding="utf-8")
        (self.web / "index.html").symlink_to(private)
        with self.assertRaises(ValueError):
            publication.publish_latest_reports([report()], self.web)
        self.assertEqual(private.read_text(encoding="utf-8"), "unchanged")

    @unittest.skipUnless(os.name == "posix", "POSIX modes are not meaningful on Windows")
    def test_public_files_remain_readable_with_private_service_umask(self):
        self.web = self.root / "public" / "latest"
        original_parent_mode = self.root.stat().st_mode & 0o777
        previous = os.umask(0o077)
        try:
            publication.publish_latest_reports([report()], self.web)
        finally:
            os.umask(previous)
        self.assertEqual(self.web.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.web.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.root.stat().st_mode & 0o777, original_parent_mode)
        for path in self.web.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = {"LARK_REPORT_ENABLED": True, "LARK_ALERTS_ENABLED": False,
                       "REPORT_URL": "https://audit.example.test/audit/",
                       "STATE_DIRECTORY": str(self.root / ".state"),
                       "OUTPUT_DIRECTORY": str(self.root / "reports"),
                       "LARK_WEBHOOK_URL": WEBHOOK, "LARK_SIGNING_SECRET": "FICTIONAL_SIGNING_SECRET"}
        self.reports = [report(), report(2, complete=False)]
        self.path = publication.publish_latest_reports(self.reports, self.root / "index")
        self.send = patch("lark_notify._send_payload")
        self.transport = self.send.start()
        self.addCleanup(self.send.stop)

    def notify(self, reports=None, path=None, config=None):
        return publication.notify_report(config or self.config,
                                         reports if reports is not None else self.reports,
                                         self.path if path is None else path, now=NOW)

    def test_independent_opt_in_defaults_to_disabled(self):
        for disabled in ({}, {"LARK_ALERTS_ENABLED": True}, {"LARK_REPORT_ENABLED": False}):
            result = publication.notify_report(disabled, [], None)
            self.assertEqual(result, {"sent": False, "failed": False, "suppressed": False})
        self.transport.assert_not_called()

    def test_one_signed_summary_link_without_parameters_and_private_receipt(self):
        result = self.notify()
        self.assertTrue(result["sent"])
        self.assertFalse(result["failed"])
        self.transport.assert_called_once()
        payload, webhook, opener = self.transport.call_args.args
        text = payload["content"]["text"]
        self.assertEqual(webhook, WEBHOOK)
        self.assertIsNone(opener)
        self.assertIn("2 个账号", text)
        self.assertIn("不完整账号 1", text)
        self.assertIn(self.config["REPORT_URL"], text)
        self.assertNotIn("instanceId", text)
        self.assertNotIn("i-current", text)
        self.assertNotIn(SECRET, text)
        self.assertNotIn("FICTIONAL_SIGNING_SECRET", text)
        self.assertIn("timestamp", payload)
        self.assertIn("sign", payload)
        self.assertLess(len(json.dumps(payload, ensure_ascii=False).encode("utf-8")), 20 * 1024)
        state = Path(self.config["STATE_DIRECTORY"]) / "lark-report.json"
        receipt = json.loads(state.read_text(encoding="utf-8"))
        self.assertEqual(set(receipt), {"signature", "sent_at"})
        self.assertNotIn("PRIVATE", state.read_text(encoding="utf-8"))
        self.assertFalse(list(self.path.parent.glob("*.json")))
        if os.name == "posix":
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)

    def test_identical_data_is_suppressed_across_regeneration_changed_data_can_send(self):
        self.assertTrue(self.notify()["sent"])
        regenerated = deepcopy(self.reports)
        for item in regenerated:
            item["metadata"]["generated_at"] = (NOW + timedelta(hours=1)).isoformat()
        publication.publish_latest_reports(regenerated, self.path.parent)
        result = self.notify(regenerated)
        self.assertTrue(result["suppressed"])
        self.assertEqual(self.transport.call_count, 1)
        changed = [report(description="i-changed"), report(2, complete=False)]
        publication.publish_latest_reports(changed, self.path.parent)
        self.assertTrue(self.notify(changed)["sent"])
        self.assertEqual(self.transport.call_count, 2)

    def test_failed_transport_does_not_record_success_and_next_call_retries(self):
        self.transport.side_effect = OSError("fictional token-bearing provider error")
        self.assertEqual(self.notify(), {"sent": False, "failed": True, "suppressed": False})
        state = Path(self.config["STATE_DIRECTORY"]) / "lark-report.json"
        self.assertFalse(state.exists())
        self.assertFalse(list(state.parent.glob(".audit-publication-*")))
        self.transport.side_effect = None
        self.assertTrue(self.notify()["sent"])
        self.assertEqual(self.transport.call_count, 2)

    def test_missing_stale_or_uncommitted_page_never_notifies(self):
        changed = [report(description="i-unpublished")]
        self.assertTrue(self.notify(changed)["failed"])
        self.assertTrue(self.notify(path=self.path.parent / "missing.html")["failed"])
        self.transport.assert_not_called()

    def test_rejects_overlap_and_oversized_payload_without_network(self):
        overlap = {**self.config, "STATE_DIRECTORY": str(self.path.parent / "state")}
        self.assertTrue(self.notify(config=overlap)["failed"])
        oversized = {**self.config, "REPORT_URL": "https://audit.example.test/" + "a" * 22000}
        self.assertTrue(self.notify(config=oversized)["failed"])
        self.transport.assert_not_called()

    def test_many_accounts_stay_in_one_bounded_message(self):
        reports = [report(number) for number in range(1, 160)]
        for value in reports:
            value["metadata"]["account_tag"] = "测试账号" * 30
        publication.publish_latest_reports(reports, self.path.parent)
        self.assertTrue(self.notify(reports)["sent"])
        payload = self.transport.call_args.args[0]
        self.assertIn("共 159 个账号", payload["content"]["text"])
        self.assertIn("另有 129 个账号", payload["content"]["text"])
        self.assertLess(len(json.dumps(payload, ensure_ascii=False).encode("utf-8")), 20 * 1024)
        self.transport.assert_called_once()


if __name__ == "__main__":
    unittest.main()
