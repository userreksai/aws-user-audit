"""Multi-account integration checks with fictional AWS events and mocked transports."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from pypdf import PdfReader

from audit_config import load_config
import aws_audit_multi as multi
from aws_daily_audit import resolve_window


NOW = datetime(2026, 11, 4, 0, 1, tzinfo=timezone.utc)
SECRET = "TEST_AWS_SECRET_MUST_NOT_APPEAR"
EVENT_SECRET = "TEST_EVENT_PASSWORD_MUST_NOT_APPEAR"
PROVIDER_SECRET = "TEST_PROVIDER_RESPONSE_SECRET_MUST_NOT_APPEAR"


def account(number=1, **overrides):
    value = {"NAME": f"account-{number}", "ACCOUNT_ID": f"{number:012d}", "ENABLED": True,
             "AWS_ACCESS_KEY_ID": f"TESTKEY-{number}", "AWS_SECRET_ACCESS_KEY": SECRET,
             "AWS_SESSION_TOKEN": "", "AWS_PROFILE": "", "REGIONS": ["eu-north-1"]}
    value.update(overrides)
    return value


def event(account_id, region="eu-north-1"):
    return {"eventID": account_id + "-" + region + "-change", "eventTime": "2026-11-03T04:15:00Z",
            "eventSource": "ec2.amazonaws.com", "eventName": "ModifyInstanceAttribute",
            "awsRegion": region, "readOnly": False,
            "userIdentity": {"type": "IAMUser", "userName": "hhjgx",
                             "arn": f"arn:aws:iam::{account_id}:user/hhjgx", "accountId": account_id},
            "requestParameters": {"instanceId": "i-fictional", "instanceType": {"value": "t3.medium"},
                                  "password": EVENT_SECRET},
            "responseElements": {"_return": True}, "sourceIPAddress": "203.0.113.4",
            "recipientAccountId": account_id}


class FakeCloudTrail:
    def __init__(self, account_id, region):
        self.account_id, self.region = account_id, region
        self.calls = []

    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        rows = [event(self.account_id, self.region)] if kwargs["LookupAttributes"][0]["AttributeKey"] == "ReadOnly" else []
        return {"Events": [{"EventId": row["eventID"], "CloudTrailEvent": json.dumps(row)} for row in rows]}


class FakeSession:
    def __init__(self, account_id, *, identity=None, regions=None, partition="aws"):
        self.account_id = account_id
        self.identity = account_id if identity is None else identity
        self.region_name = "eu-north-1"
        self.partition = partition
        self.regions = regions if regions is not None else [{"RegionName": "eu-north-1", "OptInStatus": "opt-in-not-required"}]
        self.clients, self.cloudtrails = [], {}
        self.sts = Mock()
        self.sts.get_caller_identity.return_value = {"Account": self.identity}
        self.ec2 = Mock()
        self.ec2.describe_regions.return_value = {"Regions": self.regions}

    def get_partition_for_region(self, region):
        return self.partition

    def client(self, service, **kwargs):
        self.clients.append((service, kwargs))
        if service == "sts":
            return self.sts
        if service == "ec2":
            return self.ec2
        if service == "cloudtrail":
            region = kwargs["region_name"]
            return self.cloudtrails.setdefault(region, FakeCloudTrail(self.account_id, region))
        raise AssertionError("Unexpected AWS client")


class MultiAccountTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="aws-multi-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.addCleanup(patch.stopall)
        self.pace = patch("aws_daily_audit.Pacer", return_value=lambda: None).start()

    def config(self, accounts=None, **overrides):
        value = {"ACCOUNTS": accounts or [account()], "OUTPUT_DIRECTORY": "reports", "PUBLISH_DIRECTORY": "index",
                 "STATE_DIRECTORY": ".state", "ACCOUNT_CONCURRENCY": 7, "TIMEZONE": "Asia/Shanghai",
                 "DAILY_MAIL_TIME": "08:01", "REPORT_START_TIME": "07:00", "REPORT_END_TIME": "08:00",
                 "SMTP_HOST": "smtp.example.invalid", "SMTP_PORT": 465, "SMTP_USERNAME": "sender@example.invalid",
                 "SMTP_AUTH_CODE": "TEST_SMTP_SECRET", "MAIL_RECIPIENTS": ["recipient@example.invalid"],
                 "MAIL_CC": ["copy@example.invalid"], "MAIL_SUBJECT": "AWS操作审计日报",
                 "REPORT_URL": "https://reports.example.invalid/audit/", "AUTO_MAIL_MAX_PER_DAY": 1}
        value.update(overrides)
        path = self.root / "private-config.json"
        path.write_text("// Fictional configuration; no real credentials.\n" + json.dumps(value), encoding="utf-8")
        path.chmod(0o600)
        return load_config(path), path

    def factory(self, accounts, *, failed=None):
        sessions = {row["AWS_ACCESS_KEY_ID"]: FakeSession(row["ACCOUNT_ID"]) for row in accounts}
        def create(**kwargs):
            key = kwargs["aws_access_key_id"]
            if failed and key == failed:
                raise RuntimeError(PROVIDER_SECRET)
            return sessions[key]
        return Mock(side_effect=create), sessions

    def execute_report(self, config, factory, **options):
        with patch("boto3.Session", factory), redirect_stdout(self.stdout), redirect_stderr(self.stderr):
            return multi.run_report(config, "2026-11-04", now=NOW, **options)

    def test_7_accounts_produce_separate_real_pdfs_and_one_combined_mail_with_no_secret_leak(self):
        accounts = [account(number) for number in range(1, 8)]
        config, _ = self.config(accounts)
        factory, sessions = self.factory(accounts)
        with patch("audit_mail.send_reports", return_value={"smtp_accepted": True}) as smtp, \
             patch("lark_notify._send_payload") as lark:
            result = self.execute_report(config, factory, send_mail=True, automatic_mail=True)
        self.assertEqual(result, 0, self.stderr.getvalue())
        self.assertEqual(factory.call_count, 7)
        smtp.assert_called_once()
        self.assertEqual(len(smtp.call_args.args[1]), 7)
        names = [path.name for path in smtp.call_args.args[1]]
        self.assertEqual(len(set(names)), 7)
        for row in accounts:
            expected = row["ACCOUNT_ID"]
            archive = Path(config["OUTPUT_DIRECTORY"]) / expected / "2026-11-04"
            html = archive / "2026-11-04-aws操作审计.html"
            structured = json.loads((archive / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(structured["metadata"]["account_id"], expected)
            self.assertEqual(structured["metadata"]["counts"]["修改"], 1)
            self.assertEqual(len(structured["events"]), 1)
            self.assertEqual(structured["events"][0]["actor"], "hhjgx")
            self.assertEqual(structured["events"][0]["parameters"]["password"], "[REDACTED]")
            pdf = archive / f"{expected}-2026-11-04-aws操作审计.pdf"
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))
            text = "\n".join(page.extract_text() for page in PdfReader(pdf).pages)
            self.assertIn(expected, text)
            self.assertEqual(len(PdfReader(pdf).pages), 1)
            for detail in ("hhjgx", "ModifyInstanceAttribute", "t3.medium", "i-fictional", "203.0.113.4"):
                self.assertNotIn(detail, text)
                self.assertIn(detail, html.read_text(encoding="utf-8"))
            self.assertTrue(html.is_file())
            self.assertTrue((Path(config["PUBLISH_DIRECTORY"]) / expected / "index.html").is_file())
            for content in (html.read_text(encoding="utf-8"), json.dumps(structured), text):
                for secret in (SECRET, EVENT_SECRET, PROVIDER_SECRET, "TEST_SMTP_SECRET", row["AWS_ACCESS_KEY_ID"]):
                    self.assertNotIn(secret, content)
        overview = (Path(config["PUBLISH_DIRECTORY"]) / "index.html").read_text(encoding="utf-8")
        for row in accounts:
            self.assertIn(row["ACCOUNT_ID"] + "/", overview)
        for session in sessions.values():
            for client in session.cloudtrails.values():
                for call in client.calls:
                    self.assertEqual(call["EndTime"] - call["StartTime"], timedelta(hours=25))
                    self.assertEqual(call["StartTime"], datetime(2026, 11, 2, 23, tzinfo=timezone.utc))
                    self.assertEqual(call["EndTime"], datetime(2026, 11, 4, 0, tzinfo=timezone.utc))
        lark.assert_not_called()

    def test_identity_mismatch_stops_region_discovery_and_cloudtrail_before_reading_other_account(self):
        selected = account(REGIONS="all")
        session = FakeSession(selected["ACCOUNT_ID"], identity="999999999999")
        factory = Mock(return_value=session)
        day, start, end, _ = resolve_window("2026-11-04", "Asia/Shanghai", now=NOW, daily=True)
        value = multi.collect_account(selected, day, start, end, session_factory=factory)
        self.assertFalse(value["metadata"]["complete"])
        self.assertEqual(value["metadata"]["account_id"], selected["ACCOUNT_ID"])
        self.assertEqual(value["events"], [])
        self.assertEqual([kind for kind, options in session.clients], ["sts"])
        session.ec2.describe_regions.assert_not_called()

    def test_each_account_uses_its_own_explicit_credentials_or_profile(self):
        day, start, end, _ = resolve_window("2026-11-04", "Asia/Shanghai", now=NOW, daily=True)
        selected = account(AWS_SESSION_TOKEN="TEST_TEMPORARY_TOKEN")
        session = FakeSession(selected["ACCOUNT_ID"])
        factory = Mock(return_value=session)
        multi.collect_account(selected, day, start, end, session_factory=factory)
        factory.assert_called_once_with(aws_access_key_id=selected["AWS_ACCESS_KEY_ID"],
                                       aws_secret_access_key=SECRET, aws_session_token="TEST_TEMPORARY_TOKEN")
        profile = account(AWS_ACCESS_KEY_ID="", AWS_SECRET_ACCESS_KEY="", AWS_PROFILE="audit-other")
        factory.reset_mock()
        multi.collect_account(profile, day, start, end, session_factory=factory)
        factory.assert_called_once_with(profile_name="audit-other")

    def test_enabled_region_discovery_excludes_not_opted_in_and_adds_global_events_region(self):
        selected = account(REGIONS="all")
        session = FakeSession(selected["ACCOUNT_ID"], regions=[
            {"RegionName": "eu-north-1", "OptInStatus": "opt-in-not-required"},
            {"RegionName": "ap-southeast-7", "OptInStatus": "opted-in"},
            {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"}])
        day, start, end, _ = resolve_window("2026-11-04", "Asia/Shanghai", now=NOW, daily=True)
        value = multi.collect_account(selected, day, start, end, session_factory=lambda **kwargs: session)
        self.assertEqual(value["metadata"]["regions"], ["ap-southeast-7", "eu-north-1", "us-east-1"])
        self.assertEqual(set(session.cloudtrails), {"ap-southeast-7", "eu-north-1", "us-east-1"})
        session.ec2.describe_regions.assert_called_once_with(AllRegions=False)

    def test_region_failure_preserves_other_region_events_without_sdk_error_text(self):
        selected = account(REGIONS=["eu-north-1", "us-east-1"])
        session = FakeSession(selected["ACCOUNT_ID"])
        original = session.client
        def client(kind, **kwargs):
            if kind == "cloudtrail" and kwargs["region_name"] == "eu-north-1":
                raise RuntimeError(PROVIDER_SECRET)
            return original(kind, **kwargs)
        session.client = client
        day, start, end, _ = resolve_window("2026-11-04", "Asia/Shanghai", now=NOW, daily=True)
        value = multi.collect_account(selected, day, start, end, session_factory=lambda **kwargs: session)
        self.assertFalse(value["metadata"]["complete"])
        self.assertEqual(len(value["events"]), 1)
        self.assertEqual(value["events"][0]["region"], "us-east-1")
        self.assertNotIn(PROVIDER_SECRET, json.dumps(value))

    def test_failed_account_does_not_block_other_accounts_or_the_combined_incomplete_pdf_mail(self):
        accounts = [account(1), account(2)]
        config, _ = self.config(accounts)
        factory, _ = self.factory(accounts, failed=accounts[0]["AWS_ACCESS_KEY_ID"])
        with patch("audit_mail.send_reports", return_value={"smtp_accepted": True}) as smtp, \
             patch("audit_alerts.notify_issues", return_value={"failed": False}) as alerts:
            code = self.execute_report(config, factory, send_mail=True)
        self.assertEqual(code, 2)
        smtp.assert_called_once()
        self.assertEqual(len(smtp.call_args.args[1]), 2)
        self.assertIn("不完整", smtp.call_args.kwargs["subject"])
        failed = json.loads((Path(config["OUTPUT_DIRECTORY"]) / accounts[0]["ACCOUNT_ID"] / "2026-11-04/report.json").read_text(encoding="utf-8"))
        healthy = json.loads((Path(config["OUTPUT_DIRECTORY"]) / accounts[1]["ACCOUNT_ID"] / "2026-11-04/report.json").read_text(encoding="utf-8"))
        self.assertFalse(failed["metadata"]["complete"])
        self.assertTrue(healthy["metadata"]["complete"])
        self.assertEqual(healthy["metadata"]["counts"]["修改"], 1)
        self.assertNotIn(PROVIDER_SECRET, json.dumps(failed) + self.stderr.getvalue() + smtp.call_args.args[2])
        self.assertEqual(alerts.call_args.args[2], [{"account_id": accounts[0]["ACCOUNT_ID"], "stage": "collection"}])

    def test_default_execution_generates_reports_without_sending_normal_mail_or_lark(self):
        config, _ = self.config()
        factory, _ = self.factory(config["ACCOUNTS"])
        with patch("audit_mail.send_reports") as smtp, patch("lark_notify._send_payload") as lark:
            self.assertEqual(self.execute_report(config, factory), 0)
        smtp.assert_not_called()
        lark.assert_not_called()
        self.assertTrue(list(Path(config["OUTPUT_DIRECTORY"]).glob("*/*/*.pdf")))

    def test_requested_1005_schedule_collects_exact_24_hours_and_formats_real_bounds(self):
        config, _ = self.config(DAILY_MAIL_TIME="10:05", REPORT_START_TIME="10:00", REPORT_END_TIME="10:00")
        selected = config["ACCOUNTS"][0]
        session = FakeSession(selected["ACCOUNT_ID"])
        cloudtrail = FakeCloudTrail(selected["ACCOUNT_ID"], "eu-north-1")
        start = datetime(2026, 11, 3, 2, tzinfo=timezone.utc)
        end = datetime(2026, 11, 4, 2, tzinfo=timezone.utc)
        records = []
        for key, stamp in (("before-start", start - timedelta(seconds=1)), ("at-start", start),
                           ("before-end", end - timedelta(seconds=1)), ("at-end", end)):
            record = event(selected["ACCOUNT_ID"])
            record.update(eventID=key, eventTime=stamp.isoformat())
            records.append(record)

        def lookup(**kwargs):
            cloudtrail.calls.append(kwargs)
            values = records if kwargs["LookupAttributes"][0]["AttributeKey"] == "ReadOnly" else []
            return {"Events": [{"EventId": item["eventID"], "CloudTrailEvent": json.dumps(item)} for item in values]}

        cloudtrail.lookup_events = lookup
        session.cloudtrails["eu-north-1"] = cloudtrail
        with patch("boto3.Session", return_value=session), \
             patch("audit_mail.send_reports", return_value={"smtp_accepted": True}) as smtp, \
             patch("lark_notify._send_payload") as lark, \
             redirect_stdout(self.stdout), redirect_stderr(self.stderr):
            result = multi.run_report(config, "2026-11-04", now=datetime(2026, 11, 4, 2, 5, tzinfo=timezone.utc),
                                      send_mail=True, automatic_mail=True)
        self.assertEqual(result, 0, self.stderr.getvalue())
        archive = Path(config["OUTPUT_DIRECTORY"]) / selected["ACCOUNT_ID"] / "2026-11-04"
        report = json.loads((archive / "report.json").read_text(encoding="utf-8"))
        self.assertEqual([row["event_id"] for row in report["events"]], ["at-start", "before-end"])
        self.assertEqual(report["metadata"]["counts"]["修改"], 2)
        self.assertEqual(report["metadata"]["overlap_hours"], 0)
        self.assertIn("24小时", report["metadata"]["period_label"])
        self.assertNotIn("25小时", report["metadata"]["period_label"])
        pdf = archive / f"{selected['ACCOUNT_ID']}-2026-11-04-aws操作审计.pdf"
        pdf_text = "\n".join(page.extract_text() or "" for page in PdfReader(pdf).pages)
        for text in (pdf_text, smtp.call_args.args[2]):
            self.assertIn("2026-11-03 10:00:00", text)
            self.assertIn("2026-11-04 10:00:00", text)
            self.assertNotIn("25小时", text)
        for call in cloudtrail.calls:
            self.assertEqual(call["StartTime"], start)
            self.assertEqual(call["EndTime"], end)
            self.assertEqual(call["EndTime"] - call["StartTime"], timedelta(hours=24))
        smtp.assert_called_once()
        lark.assert_not_called()

    def test_custom_1000_window_not_finished_at_0959_never_resolves_credentials(self):
        config, _ = self.config(DAILY_MAIL_TIME="10:05", REPORT_START_TIME="10:00", REPORT_END_TIME="10:00")
        with patch("boto3.Session") as factory:
            with self.assertRaises(ValueError):
                multi.run_report(config, "2026-11-04", now=datetime(2026, 11, 4, 1, 59, tzinfo=timezone.utc))
        factory.assert_not_called()

    def test_web_failure_does_not_prevent_mail_and_omits_stale_web_link(self):
        config, _ = self.config()
        factory, _ = self.factory(config["ACCOUNTS"])
        with patch.object(multi, "publish_accounts", side_effect=OSError(PROVIDER_SECRET)), \
             patch("audit_mail.send_reports", return_value={"smtp_accepted": True}) as smtp:
            self.assertEqual(self.execute_report(config, factory, send_mail=True), 4)
        smtp.assert_called_once()
        self.assertNotIn(config["REPORT_URL"], smtp.call_args.args[2])
        self.assertNotIn(PROVIDER_SECRET, self.stderr.getvalue())

    def test_failed_pdf_prevents_partial_account_mail_but_other_pdf_is_retained(self):
        import audit_pdf
        accounts = [account(1), account(2)]
        config, _ = self.config(accounts)
        factory, _ = self.factory(accounts)
        original = audit_pdf.render_report_pdf
        def render(report, path, font):
            if report["metadata"]["account_id"] == accounts[0]["ACCOUNT_ID"]:
                raise OSError(PROVIDER_SECRET)
            return original(report, path, font)
        with patch("audit_pdf.render_report_pdf", side_effect=render), patch("audit_mail.send_reports") as smtp:
            self.assertEqual(self.execute_report(config, factory, send_mail=True), 5)
        smtp.assert_not_called()
        self.assertEqual(len(list(Path(config["OUTPUT_DIRECTORY"]).glob("*/*/*.pdf"))), 1)
        self.assertNotIn(PROVIDER_SECRET, self.stderr.getvalue())

    def test_check_config_does_not_resolve_credentials_or_contact_aws_smtp_lark(self):
        _, path = self.config()
        with patch("boto3.Session") as aws, patch("audit_mail.send_reports") as smtp, \
             patch("lark_notify._send_payload") as lark, patch("socket.create_connection") as network, \
             redirect_stdout(self.stdout), redirect_stderr(self.stderr):
            self.assertEqual(multi.main(["--config", str(path), "--check-config"]), 0)
        aws.assert_not_called()
        smtp.assert_not_called()
        lark.assert_not_called()
        network.assert_not_called()
        self.assertNotIn(SECRET, self.stdout.getvalue() + self.stderr.getvalue())

    @unittest.skipUnless(os.name == "posix", "Linux state directory creation with inherited umask")
    def test_first_run_with_normal_umask_creates_private_parent_state_before_job_lock(self):
        config, _ = self.config()
        factory, _ = self.factory(config["ACCOUNTS"])
        previous = os.umask(0o022)
        try:
            with patch("audit_mail.send_reports", return_value={"smtp_accepted": True}) as smtp:
                result = self.execute_report(config, factory, send_mail=True)
        finally:
            os.umask(previous)
        self.assertEqual(result, 0, self.stderr.getvalue())
        self.assertEqual(Path(config["STATE_DIRECTORY"]).stat().st_mode & 0o777, 0o700)
        smtp.assert_called_once()

    def test_disabled_accounts_do_not_create_sessions_or_report_files(self):
        accounts = [account(1), account(2, ENABLED=False)]
        config, _ = self.config(accounts)
        factory, _ = self.factory(accounts)
        self.assertEqual(self.execute_report(config, factory), 0)
        self.assertEqual(factory.call_count, 1)
        self.assertFalse((Path(config["OUTPUT_DIRECTORY"]) / accounts[1]["ACCOUNT_ID"]).exists())

    def test_unfinished_window_is_rejected_before_resolving_any_aws_credentials(self):
        config, _ = self.config()
        with patch("boto3.Session") as factory:
            with self.assertRaises(ValueError):
                multi.run_report(config, "2026-11-04", now=datetime(2026, 11, 3, 23, 59, tzinfo=timezone.utc))
        factory.assert_not_called()

    def test_jsonc_relative_paths_duplicate_ids_and_exposed_private_paths(self):
        config, path = self.config()
        self.assertEqual(Path(config["OUTPUT_DIRECTORY"]), self.root / "reports")
        self.assertEqual(Path(config["STATE_DIRECTORY"]), self.root / ".state")
        raw = json.loads(path.read_text(encoding="utf-8").split("\n", 1)[1])
        for updates in ({"ACCOUNTS": [account(1), account(2, ACCOUNT_ID=account(1)["ACCOUNT_ID"])]},
                        {"PUBLISH_DIRECTORY": "."}, {"STATE_DIRECTORY": "index/private"},
                        {"TIMEZONE": "UTC"}, {"ACCOUNTS": [account(AWS_PROFILE="other")]},
                        {"ACCOUNTS": [account(AWS_SECRET_ACCESS_KEY="")]}):
            candidate = deepcopy(raw)
            candidate.update(updates)
            path.write_text(json.dumps(candidate), encoding="utf-8")
            with self.subTest(updates=updates), self.assertRaises(ValueError) as caught:
                load_config(path)
            self.assertNotIn(SECRET, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
