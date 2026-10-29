"""Offline correctness checks. No AWS credentials or network are required."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from zoneinfo import ZoneInfo

import aws_daily_audit as audit

try:
    import boto3
    from botocore.stub import Stubber
except ImportError:
    boto3 = None
    Stubber = None


def sample_event(**overrides):
    event = {
        "eventID": "evt-change",
        "eventTime": "2026-10-27T03:15:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "ModifyInstanceAttribute",
        "awsRegion": "eu-north-1",
        "readOnly": False,
        "userIdentity": {
            "type": "IAMUser",
            "userName": "hhjgx",
            "arn": "arn:aws:iam::123456789012:user/hhjgx",
            "principalId": "AIDAEXAMPLE",
        },
        "requestParameters": {
            "instanceId": "i-example",
            "instanceType": {"value": "t3.medium"},
        },
        "responseElements": {"_return": True},
        "sourceIPAddress": "203.0.113.10",
        "recipientAccountId": "123456789012",
    }
    event.update(overrides)
    return event


class DateWindowTests(unittest.TestCase):
    def test_yesterday_uses_requested_timezone(self):
        # UTC still Oct 27, while Bangkok has already reached Oct 28.
        now = datetime(2026, 10, 27, 20, 0, tzinfo=timezone.utc)
        day, start, end = audit.make_window(None, "Asia/Bangkok", now=now)
        self.assertEqual(day, "2026-10-27")
        self.assertEqual(start, datetime(2026, 10, 26, 17, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 10, 27, 17, tzinfo=timezone.utc))

    def test_explicit_day_and_timezone(self):
        day, start, end = audit.make_window("2026-10-27", "Asia/Shanghai")
        self.assertEqual(day, "2026-10-27")
        self.assertEqual(start.hour, 16)
        self.assertEqual(start.day, 26)
        self.assertEqual(end.hour, 16)
        self.assertEqual(end.day, 27)
        self.assertEqual(start.utcoffset().total_seconds(), 0)

    def test_dst_day_is_calendar_day_not_fixed_24_hours(self):
        _, start, end = audit.make_window("2026-11-01", "America/New_York")
        self.assertEqual((end - start).total_seconds(), 25 * 3600)

    def test_invalid_calendar_date_rejected(self):
        with self.assertRaises(ValueError):
            audit.make_window("2026-02-30", "UTC")


class ResolvedWindowTests(unittest.TestCase):
    def setUp(self):
        # UTC is still Oct 27, while Shanghai is already Oct 28.
        self.now = datetime(2026, 10, 27, 20, 10, 30, 123456, tzinfo=timezone.utc)

    def test_default_remains_complete_yesterday(self):
        day, start, end, in_progress = audit.resolve_window(None, "Asia/Shanghai", now=self.now)
        self.assertEqual((day, start, end), audit.make_window(None, "Asia/Shanghai", now=self.now))
        self.assertEqual(day, "2026-10-27")
        self.assertFalse(in_progress)

    def test_today_uses_local_midnight_and_exact_fixed_now(self):
        day, start, end, in_progress = audit.resolve_window(None, "Asia/Shanghai", today=True, now=self.now)
        self.assertEqual(day, "2026-10-28")
        self.assertEqual(start, datetime(2026, 10, 27, 16, tzinfo=timezone.utc))
        self.assertEqual(end, self.now)
        self.assertEqual(end.microsecond, 123456)
        self.assertTrue(in_progress)

    def test_explicit_current_local_date_matches_today(self):
        explicit = audit.resolve_window("2026-10-28", "Asia/Shanghai", now=self.now)
        flag = audit.resolve_window(None, "Asia/Shanghai", today=True, now=self.now)
        self.assertEqual(explicit, flag)

    def test_historical_date_is_not_clipped_to_query_clock(self):
        day, start, end, in_progress = audit.resolve_window("2026-10-25", "Asia/Shanghai", now=self.now)
        self.assertEqual((day, start, end), audit.make_window("2026-10-25", "Asia/Shanghai", now=self.now))
        self.assertEqual((end - start).total_seconds(), 24 * 3600)
        self.assertFalse(in_progress)

    def test_future_local_date_is_rejected(self):
        with self.assertRaises(ValueError):
            audit.resolve_window("2026-10-29", "Asia/Shanghai", now=self.now)

    def test_today_dst_day_starts_at_calendar_midnight(self):
        now = datetime(2026, 11, 1, 20, 0, tzinfo=timezone.utc)
        day, start, end, in_progress = audit.resolve_window(None, "America/New_York", today=True, now=now)
        self.assertEqual(day, "2026-11-01")
        self.assertEqual(start, datetime(2026, 11, 1, 4, tzinfo=timezone.utc))
        self.assertEqual(end, now)
        self.assertTrue(in_progress)

    def test_timezone_naive_query_clock_is_rejected(self):
        with self.assertRaises(ValueError):
            audit.resolve_window(None, "Asia/Shanghai", today=True, now=datetime(2026, 10, 28, 9))


class ClassificationTests(unittest.TestCase):
    def test_ordinary_reads_ignored(self):
        category, _ = audit.classify_event(sample_event(
            eventName="DescribeInstances", readOnly=True
        ))
        self.assertIsNone(category)

    def test_readonly_flag_has_priority_over_name_prefix(self):
        category, _ = audit.classify_event(sample_event(
            eventName="GetAndChangeSomething", readOnly=False
        ))
        self.assertIsNotNone(category)

    def test_secret_reads_kept(self):
        for name in ("GetSecretValue", "BatchGetSecretValue", "ListSecrets",
                     "DescribeSecret", "GetResourcePolicy"):
            with self.subTest(name=name):
                category, _ = audit.classify_event(sample_event(
                    eventSource="secretsmanager.amazonaws.com",
                    eventName=name, readOnly=True
                ))
                self.assertEqual(category, "Secrets Manager 查看")

    def test_crud_examples(self):
        expected = {
            "CreateUser": "新增",
            "AuthorizeSecurityGroupIngress": "新增",
            "ModifyInstanceAttribute": "修改",
            "DeleteSecret": "删除",
            "RevokeSecurityGroupIngress": "删除",
            "TerminateInstances": "删除",
        }
        for name, category in expected.items():
            with self.subTest(name=name):
                actual, _ = audit.classify_event(sample_event(eventName=name))
                self.assertEqual(actual, category)

    def test_secret_modification_is_modification(self):
        category, _ = audit.classify_event(sample_event(
            eventSource="secretsmanager.amazonaws.com", eventName="UpdateSecret"
        ))
        self.assertEqual(category, "修改")

    def test_unknown_write_is_retained_as_other_operation_not_login(self):
        category, _ = audit.classify_event(sample_event(eventName="Frobnicate"))
        self.assertEqual(category, "其他操作")

    def test_real_sign_in_names_and_event_type_are_classified_as_login(self):
        for name in ("ConsoleLogin", "CheckMfa", "GetSigninToken"):
            with self.subTest(name=name):
                category, _ = audit.classify_event(sample_event(
                    eventName=name, eventSource="signin.amazonaws.com", readOnly=True
                ))
                self.assertEqual(category, "登录信息")
        category, _ = audit.classify_event(sample_event(
            eventName="FutureSigninEvent", eventType="AwsConsoleSignIn", readOnly=True
        ))
        self.assertEqual(category, "登录信息")

    def test_login_like_name_from_unrelated_service_is_not_treated_as_sign_in(self):
        category, _ = audit.classify_event(sample_event(
            eventName="GetSigninToken", eventSource="custom-service.amazonaws.com", readOnly=False
        ))
        self.assertEqual(category, "其他操作")

    def test_put_is_retained_without_claiming_exact_create(self):
        category, basis = audit.classify_event(sample_event(eventName="PutBucketPolicy"))
        self.assertEqual(category, "修改")
        self.assertTrue(basis)


class RedactionTests(unittest.TestCase):
    def test_sensitive_values_removed_at_any_depth(self):
        payload = {
            "name": "database-production",
            "secretString": "secret-value-123",
            "nested": [{"Password": "password-value-456"}],
            "credentials": {
                "accessKeyId": "key-value-789",
                "secretAccessKey": "secret-access-value-012",
                "sessionToken": "session-token-value-345",
            },
            "userData": "base64-user-data-678",
        }
        result = audit.redact(payload)
        encoded = json.dumps(result, ensure_ascii=False)
        for secret in ("secret-value-123", "password-value-456", "key-value-789",
                       "secret-access-value-012", "session-token-value-345",
                       "base64-user-data-678"):
            self.assertNotIn(secret, encoded)
        self.assertIn("database-production", encoded)
        # Caller-owned input must not be rewritten in memory.
        self.assertEqual(payload["secretString"], "secret-value-123")

    def test_json_encoded_nested_sensitive_fields_are_redacted(self):
        payload = {"document": json.dumps({"nested": {"password": "nested-json-secret"}})}
        self.assertNotIn("nested-json-secret", json.dumps(audit.redact(payload)))


class NormalizationTests(unittest.TestCase):
    def test_console_login_success_failure_and_unknown_results(self):
        for response, expected, failed in (({"ConsoleLogin": "Success"}, "登录成功", False),
                                            ({"ConsoleLogin": "Failure"}, "登录失败", True),
                                            (None, "登录结果未提供", False)):
            with self.subTest(response=response):
                row = audit.normalize_event(sample_event(
                    eventName="ConsoleLogin", eventSource="signin.amazonaws.com",
                    eventType="AwsConsoleSignIn", requestParameters=None,
                    responseElements=response, additionalEventData={"MFAUsed": "Yes"}
                ), {}, ZoneInfo("Asia/Shanghai"))
                self.assertEqual(row["category"], "登录信息")
                self.assertIn("登录 AWS 控制台", row["description"])
                self.assertEqual(row["result"], expected)
                self.assertEqual(row["failed"], failed)
                self.assertIn("控制台登录", row["parameter_summary"])
                self.assertIn("Yes", json.dumps(row["login_details"]))

    def test_actor_time_target_and_submitted_change(self):
        row = audit.normalize_event(sample_event(), {}, ZoneInfo("Asia/Bangkok"))
        self.assertIn("hhjgx", row["actor"])
        self.assertEqual(row["event_name"], "ModifyInstanceAttribute")
        self.assertEqual(row["category"], "修改")
        self.assertIn("10:15:00", row["time_local"])
        self.assertIn("i-example", json.dumps(row["resources"]))
        self.assertIn("t3.medium", json.dumps(row["parameters"]))
        self.assertEqual(row["region"], "eu-north-1")
        self.assertEqual(row["event_id"], "evt-change")

    def test_access_denied_is_not_reported_as_success(self):
        row = audit.normalize_event(sample_event(
            errorCode="AccessDenied", errorMessage="Not authorized"
        ), {}, ZoneInfo("UTC"))
        self.assertIn("失败", row["result"])

    def test_role_session_is_marked_as_unverified_person(self):
        row = audit.normalize_event(sample_event(userIdentity={
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/hhjgx",
            "principalId": "AROAXYZ:hhjgx",
            "sessionContext": {
                "sessionIssuer": {"userName": "AdminRole", "arn": "arn:aws:iam::123456789012:role/AdminRole"},
                "sourceIdentity": "directory-subject-123",
            },
        }), {}, ZoneInfo("UTC"))
        self.assertIn("角色", row["actor"])
        self.assertIn("会话", row["actor"])
        self.assertEqual(row["identity"]["type"], "AssumedRole")
        self.assertIn("自然人", row["identity"]["note"])
        self.assertEqual(row["identity"]["source_identity"], "directory-subject-123")

    def test_batch_partial_failure_is_marked(self):
        row = audit.normalize_event(sample_event(responseElements={
            "successful": [{"id": "item-1"}],
            "failed": [{"id": "item-2", "code": "AccessDenied"}],
        }), {}, ZoneInfo("UTC"))
        self.assertTrue(row["failed"])
        self.assertIn("失败", row["result"])

    def test_explicit_false_return_is_marked_as_failure(self):
        for field in ("return", "_return", "success"):
            with self.subTest(field=field):
                row = audit.normalize_event(sample_event(responseElements={field: False}),
                                            {}, ZoneInfo("UTC"))
                self.assertTrue(row["failed"])
                self.assertIn("失败", row["result"])


def envelope(event):
    return {"EventId": event["eventID"], "EventTime": audit.parse_time(event["eventTime"]),
            "EventName": event["eventName"], "CloudTrailEvent": json.dumps(event)}


def report_for(events, **overrides):
    day, start, end = audit.make_window("2026-10-27", "Asia/Bangkok")
    options = {"audit_date": day, "timezone_name": "Asia/Bangkok", "start": start,
               "end": end, "account_id": "123456789012", "regions": ["eu-north-1", "us-east-1"],
               "offline": True}
    options.update(overrides)
    return audit.build_report(events, **options)


class CollectionAndReportTests(unittest.TestCase):
    def test_today_report_labels_partial_day_and_preserves_fixed_cutoff(self):
        now = datetime(2026, 10, 28, 4, 10, 30, 123456, tzinfo=timezone.utc)
        day, start, end, in_progress = audit.resolve_window(None, "Asia/Shanghai", today=True, now=now)
        report = audit.build_report([], audit_date=day, timezone_name="Asia/Shanghai", start=start, end=end,
                                    in_progress=in_progress, offline=True, regions=["eu-north-1", "us-east-1"])
        meta = report["metadata"]
        self.assertTrue(meta["in_progress"])
        self.assertEqual(meta["period_label"], "当日截至查询时刻")
        self.assertEqual(meta["window_end_utc_exclusive"], now.isoformat())
        rendered = audit.render_html(report)
        # Today is still distinguished by its title; query details remain in JSON.
        title = rendered.split("<title>", 1)[1].split("</title>", 1)[0]
        self.assertIn("当日", title)
        self.assertIn("快报", title)
        self.assertNotIn("日报", title)
        self.assertNotIn("报告范围：", rendered)
        self.assertNotIn("完整日报", rendered)

    def test_historical_report_keeps_complete_calendar_day_label(self):
        meta = report_for([sample_event()])["metadata"]
        self.assertFalse(meta["in_progress"])
        self.assertEqual(meta["period_label"], "完整自然日")

    def test_china_region_secret_source_keeps_standard_event_source(self):
        class Client:
            def __init__(self):
                self.calls = []

            def lookup_events(self, **kwargs):
                self.calls.append(kwargs)
                if kwargs["LookupAttributes"][0]["AttributeKey"] == "EventSource":
                    return {"Events": [envelope(sample_event(
                        eventName="GetSecretValue", eventSource="secretsmanager.amazonaws.com",
                        awsRegion="cn-north-1", readOnly=True
                    ))]}
                return {"Events": []}

        _, start, end = audit.make_window("2026-10-27", "Asia/Bangkok")
        client = Client()
        events, errors, _ = audit.collect_region(client, "cn-north-1", start, end, pace=lambda: None)
        self.assertFalse(errors)
        self.assertEqual(len(events), 1)
        self.assertEqual(client.calls[1]["LookupAttributes"], [{
            "AttributeKey": "EventSource", "AttributeValue": "secretsmanager.amazonaws.com"
        }])

    def test_both_queries_paginate_and_overlapping_events_deduplicate(self):
        change = sample_event()
        secret_write = sample_event(eventID="evt-secret-write", eventName="UpdateSecret",
                                    eventSource="secretsmanager.amazonaws.com")
        secret_read = sample_event(eventID="evt-secret-read", eventName="GetSecretValue",
                                   eventSource="secretsmanager.amazonaws.com", readOnly=True)
        responses = {
            ("ReadOnly", None): {"Events": [envelope(change)], "NextToken": "writes-page-2"},
            ("ReadOnly", "writes-page-2"): {"Events": [envelope(secret_write)]},
            ("EventSource", None): {"Events": [envelope(secret_write)], "NextToken": "secrets-page-2"},
            ("EventSource", "secrets-page-2"): {"Events": [envelope(secret_read)]},
        }

        class Client:
            def __init__(self):
                self.calls = []

            def lookup_events(self, **kwargs):
                self.calls.append(kwargs)
                attr = kwargs["LookupAttributes"][0]
                return responses[(attr["AttributeKey"], kwargs.get("NextToken"))]

        client = Client()
        _, start, end = audit.make_window("2026-10-27", "Asia/Bangkok")
        events, errors, stats = audit.collect_region(client, "eu-north-1", start, end, pace=lambda: None)
        self.assertFalse(errors)
        self.assertEqual(len(client.calls), 4)
        self.assertEqual(stats["queries"]["write"]["pages"], 2)
        self.assertEqual(stats["queries"]["secrets"]["pages"], 2)
        self.assertEqual(client.calls[0]["LookupAttributes"], [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}])
        self.assertEqual(client.calls[2]["LookupAttributes"], [{"AttributeKey": "EventSource", "AttributeValue": "secretsmanager.amazonaws.com"}])
        self.assertTrue(all(call["MaxResults"] == 50 for call in client.calls))
        report = report_for(events)
        self.assertEqual(report["metadata"]["total"], 3)
        self.assertEqual(report["metadata"]["duplicates_removed"], 1)
        self.assertEqual(report["metadata"]["counts"]["Secrets Manager 查看"], 1)

    def test_daily_window_is_half_open_during_collection_and_report(self):
        # Bangkok day Oct 27 starts at Oct 26 17:00 UTC, ends Oct 27 17:00 UTC.
        events = [sample_event(eventID="at-start", eventTime="2026-10-26T17:00:00Z"),
                  sample_event(eventID="before-end", eventTime="2026-10-27T16:59:59Z"),
                  sample_event(eventID="at-end", eventTime="2026-10-27T17:00:00Z"),
                  sample_event(eventID="before-start", eventTime="2026-10-26T16:59:59Z")]

        class Client:
            def lookup_events(self, **kwargs):
                return {"Events": [envelope(x) for x in events]} if kwargs["LookupAttributes"][0]["AttributeKey"] == "ReadOnly" else {"Events": []}

        _, start, end = audit.make_window("2026-10-27", "Asia/Bangkok")
        collected, errors, stats = audit.collect_region(Client(), "eu-north-1", start, end, pace=lambda: None)
        self.assertFalse(errors)
        self.assertEqual({x["eventID"] for x in collected}, {"at-start", "before-end"})
        self.assertEqual(stats["outside_window"], 2)
        report = report_for(events)
        self.assertEqual({x["event_id"] for x in report["events"]}, {"at-start", "before-end"})
        self.assertEqual(report["metadata"]["outside_window"], 2)

    def test_page_failure_preserves_collected_events_and_marks_incomplete(self):
        class Client:
            def lookup_events(self, **kwargs):
                if kwargs.get("NextToken"):
                    raise RuntimeError("AccessDenied: denied for test")
                if kwargs["LookupAttributes"][0]["AttributeKey"] == "ReadOnly":
                    return {"Events": [envelope(sample_event())], "NextToken": "page-2"}
                return {"Events": []}

        _, start, end = audit.make_window("2026-10-27", "Asia/Bangkok")
        events, errors, stats = audit.collect_region(Client(), "eu-north-1", start, end, pace=lambda: None)
        self.assertEqual(len(events), 1)
        self.assertTrue(errors)
        self.assertFalse(stats["queries"]["write"]["complete"])
        self.assertTrue(stats["queries"]["secrets"]["complete"])
        report = report_for(events, errors=errors, region_stats=[stats], offline=False)
        self.assertFalse(report["metadata"]["complete"])
        self.assertTrue(report["metadata"]["errors"])

    def test_repeated_pagination_token_does_not_loop_forever(self):
        class Client:
            def __init__(self):
                self.calls = 0

            def lookup_events(self, **kwargs):
                self.calls += 1
                if self.calls > 4:
                    raise AssertionError("Unexpected infinite pagination")
                return {"Events": [], "NextToken": "same-token"}

        _, start, end = audit.make_window("2026-10-27", "Asia/Bangkok")
        client = Client()
        _, errors, _ = audit.collect_region(client, "eu-north-1", start, end, pace=lambda: None)
        self.assertEqual(client.calls, 4)
        self.assertEqual(len(errors), 2)

    def test_malformed_event_marks_report_incomplete(self):
        report = report_for([sample_event(eventTime="not-a-time")])
        self.assertFalse(report["metadata"]["complete"])
        self.assertEqual(report["metadata"]["total"], 0)
        self.assertTrue(report["metadata"]["errors"])

    def test_report_html_escapes_untrusted_event_fields(self):
        attack = '<img src=x onerror="alert(1)">'
        event = sample_event(requestParameters={"name": attack},
                             userIdentity={"type": "IAMUser", "userName": attack})
        rendered = audit.render_html(report_for([event]))
        self.assertNotIn(attack, rendered)
        self.assertNotIn("<img", rendered)
        self.assertIn("&lt;img", rendered)

    def test_offline_integrity_stays_in_json_without_html_banner(self):
        report = report_for([sample_event()])
        rendered = audit.render_html(report)
        self.assertTrue(report["metadata"]["offline"])
        self.assertIn("离线", report["metadata"]["data_mode"])
        self.assertNotIn("离线文件处理完成", rendered)
        self.assertNotIn("AWS 覆盖范围未经验证", rendered)
        self.assertNotIn("所列查询完成", rendered)

    def test_html_omits_query_metadata_even_when_error_text_contains_it(self):
        error_text = "ERROR_PAYLOAD_47: Asia/Shanghai UTC 范围 数据来源 查询状态与覆盖范围"
        warning_text = "WARNING_PAYLOAD_83: 报告范围 eu-north-1 全局区域扫描不完整"
        report = report_for([sample_event()], errors=[error_text], warnings=[warning_text],
                            region_stats=[{"region": "eu-north-1", "private_status": "REGION_STATS_PAYLOAD_29"}])
        rendered = audit.render_html(report)
        self.assertFalse(report["metadata"]["complete"])
        self.assertIn(error_text, report["metadata"]["errors"])
        self.assertIn(warning_text, report["metadata"]["warnings"])
        self.assertEqual(report["metadata"]["timezone"], "Asia/Bangkok")
        for removed in ("ERROR_PAYLOAD_47", "WARNING_PAYLOAD_83", "REGION_STATS_PAYLOAD_29",
                        "Asia/Shanghai", "Asia/Bangkok", "UTC 范围", "查询状态与覆盖范围", "报告范围：",
                        "普通查看操作忽略", "不保证包含旧值", "本地报告范围", "数据来源"):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, rendered)
        self.assertIn("按操作者汇总", rendered)
        self.assertIn("hhjgx", rendered)
        self.assertIn("t3.medium", rendered)

    def test_html_times_are_beijing_time_without_offset_or_iana_label(self):
        report = report_for([sample_event()])
        report["metadata"]["generated_at"] = "2026-10-28T10:00:00+07:00"
        rendered = audit.render_html(report)
        self.assertIn("2026-10-27 11:15:00", rendered)
        self.assertIn("2026-10-28 11:00:00", rendered)
        self.assertNotIn("2026-10-27 10:15:00", rendered)
        self.assertNotIn("+07:00", rendered)
        self.assertNotIn("+08:00", rendered)
        self.assertNotIn("Asia/Bangkok", rendered)
        self.assertIn("操作时间（北京时间）", rendered)
        self.assertIn("操作信息", rendered)

    def test_empty_other_operations_section_is_hidden_but_unknown_write_is_shown(self):
        self.assertNotIn("其他操作", audit.render_html(report_for([sample_event()])))
        unknown_report = report_for([sample_event(eventName="Frobnicate")])
        self.assertIn("其他操作", audit.render_html(unknown_report))
        self.assertEqual(unknown_report["metadata"]["counts"]["其他操作"], 1)
        self.assertEqual(unknown_report["metadata"]["counts"]["登录信息"], 0)

    def test_console_login_html_has_login_description_and_no_unknown_resource_hint(self):
        report = report_for([sample_event(eventName="ConsoleLogin", eventSource="signin.amazonaws.com",
                                          eventType="AwsConsoleSignIn", requestParameters=None,
                                          responseElements={"ConsoleLogin": "Failure"})])
        rendered = audit.render_html(report)
        self.assertIn("登录 AWS 控制台", rendered)
        self.assertIn("登录失败", rendered)
        self.assertIn("控制台登录", rendered)
        self.assertIn("—", rendered)
        self.assertNotIn("日志未提供可识别资源", rendered)
        self.assertNotIn("字段值未知", rendered)
        self.assertEqual(report["metadata"]["failed_or_partial"], 1)


class TodayCliTests(unittest.TestCase):
    def test_incomplete_report_keeps_nonzero_cli_exit_after_html_cleanup(self):
        day, start, end = audit.make_window("2026-10-27", "Asia/Shanghai")
        errors = io.StringIO()
        with patch.object(audit, "resolve_window", return_value=(day, start, end, False)), \
             patch.object(audit, "load_input", return_value=[sample_event(eventTime="invalid-time")]), \
             patch.object(audit, "write_report", return_value=Path("offline-test-output")) as write, \
             redirect_stdout(io.StringIO()), redirect_stderr(errors):
            exit_code = audit.main(["--input-file", "unused.json"])
        self.assertEqual(exit_code, 2)
        self.assertFalse(write.call_args.args[0]["metadata"]["complete"])
        self.assertTrue(write.call_args.args[0]["metadata"]["errors"])
        self.assertIn("不完整", errors.getvalue())

    def test_cli_selects_daily_window_without_today_flag(self):
        day, start, end = audit.make_window("2026-10-27", "Asia/Shanghai")
        with patch.object(audit, "resolve_window", return_value=(day, start, end, False)) as resolve, \
             patch.object(audit, "load_input", return_value=[]), \
             patch.object(audit, "write_report", return_value=Path("offline-test-output")) as write, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            exit_code = audit.main(["--input-file", "unused.json"])
        self.assertEqual(exit_code, 0)
        resolve.assert_called_once()
        self.assertIsNone(resolve.call_args.args[0])
        self.assertFalse(resolve.call_args.kwargs["today"])
        self.assertTrue(resolve.call_args.kwargs["daily"])
        self.assertFalse(write.call_args.args[0]["metadata"]["in_progress"])

    def test_today_and_explicit_date_are_mutually_exclusive_before_aws_access(self):
        with patch.object(audit, "load_input") as load, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                audit.main(["--today", "--date", "2026-10-27", "--input-file", "unused.json"])
        self.assertEqual(caught.exception.code, 2)
        load.assert_not_called()

    def test_today_offline_cli_passes_fixed_window_into_report(self):
        fixed = ("2026-10-28", datetime(2026, 10, 27, 16, tzinfo=timezone.utc),
                 datetime(2026, 10, 28, 4, 10, 30, 123456, tzinfo=timezone.utc), True)
        with patch.object(audit, "resolve_window", return_value=fixed) as resolve, \
             patch.object(audit, "load_input", return_value=[]) as load, \
             patch.object(audit, "write_report", return_value=Path("offline-test-output")) as write, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            exit_code = audit.main(["--today", "--timezone", "Asia/Shanghai", "--input-file", "unused.json"])
        self.assertEqual(exit_code, 0)
        resolve.assert_called_once()
        self.assertTrue(resolve.call_args.kwargs["today"])
        self.assertIsNotNone(resolve.call_args.kwargs["now"].tzinfo)
        load.assert_called_once_with("unused.json")
        meta = write.call_args.args[0]["metadata"]
        self.assertTrue(meta["in_progress"])
        self.assertEqual(meta["window_end_utc_exclusive"], fixed[2].isoformat())

    @unittest.skipUnless(boto3 is not None, "boto3 not installed; SDK-backed CLI orchestration test skipped")
    def test_all_regions_share_one_resolved_query_cutoff(self):
        fixed = ("2026-10-28", datetime(2026, 10, 27, 16, tzinfo=timezone.utc),
                 datetime(2026, 10, 28, 4, 10, 30, 123456, tzinfo=timezone.utc), True)
        fake_session = Mock()
        fake_session.region_name = "eu-north-1"
        fake_session.client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
        with patch.object(audit, "resolve_window", return_value=fixed) as resolve, \
             patch.object(boto3, "Session", return_value=fake_session), \
             patch.object(audit, "collect_region", return_value=([], [], {})) as collect, \
             patch.object(audit, "write_report", return_value=Path("offline-test-output")) as write, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            exit_code = audit.main(["--today", "--regions", "eu-north-1,us-east-1", "--no-publish"])
        self.assertEqual(exit_code, 0)
        resolve.assert_called_once()
        self.assertEqual(collect.call_count, 2)
        for call in collect.call_args_list:
            self.assertEqual(call.args[2:4], fixed[1:3])
        self.assertTrue(write.call_args.args[0]["metadata"]["in_progress"])


@unittest.skipUnless(boto3 is not None and Stubber is not None, "boto3 not installed; SDK-contract tests skipped")
class BotocoreContractTests(unittest.TestCase):
    """Stubber enforces the real AWS model while intercepting every request offline."""

    def make_client(self):
        # Explicit, invented credentials prevent EC2 metadata or any credential-provider traffic.
        return boto3.client("cloudtrail", region_name="eu-north-1",
                            aws_access_key_id="AKIAOFFLINETEST000001",
                            aws_secret_access_key="offline-test-secret-not-a-real-aws-credential",
                            aws_session_token="offline-test-session-token")

    def params(self, key, value, token=None):
        _, start, end = audit.make_window("2026-10-27", "Asia/Bangkok")
        result = {"StartTime": start, "EndTime": end, "MaxResults": 50,
                  "LookupAttributes": [{"AttributeKey": key, "AttributeValue": value}]}
        if token:
            result["NextToken"] = token
        return result

    def test_lookup_parameters_pagination_and_response_use_real_sdk_model(self):
        client = self.make_client()
        write_event = sample_event()
        secret_event = sample_event(eventID="secret-read-evt", eventName="GetSecretValue",
                                    eventSource="secretsmanager.amazonaws.com", readOnly=True)
        with Stubber(client) as stub:
            stub.add_response("lookup_events", {"Events": [envelope(write_event)], "NextToken": "next-write-page"},
                              self.params("ReadOnly", "false"))
            stub.add_response("lookup_events", {"Events": []},
                              self.params("ReadOnly", "false", "next-write-page"))
            stub.add_response("lookup_events", {"Events": [envelope(secret_event)]},
                              self.params("EventSource", "secretsmanager.amazonaws.com"))
            _, start, end = audit.make_window("2026-10-27", "Asia/Bangkok")
            events, errors, stats = audit.collect_region(client, "eu-north-1", start, end, pace=lambda: None)
            stub.assert_no_pending_responses()
        self.assertFalse(errors)
        self.assertEqual({item["eventID"] for item in events}, {"evt-change", "secret-read-evt"})
        self.assertEqual(stats["queries"]["write"]["pages"], 2)
        report = report_for(events)
        self.assertEqual(report["metadata"]["counts"]["修改"], 1)
        self.assertEqual(report["metadata"]["counts"]["Secrets Manager 查看"], 1)

    def test_real_sdk_client_error_marks_report_incomplete(self):
        client = self.make_client()
        with Stubber(client) as stub:
            stub.add_response("lookup_events", {"Events": [envelope(sample_event())]},
                              self.params("ReadOnly", "false"))
            stub.add_client_error("lookup_events", service_error_code="AccessDeniedException",
                                  service_message="Offline test permission denied", http_status_code=403,
                                  expected_params=self.params("EventSource", "secretsmanager.amazonaws.com"))
            _, start, end = audit.make_window("2026-10-27", "Asia/Bangkok")
            events, errors, stats = audit.collect_region(client, "eu-north-1", start, end, pace=lambda: None)
            stub.assert_no_pending_responses()
        self.assertEqual(len(events), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("AccessDeniedException", errors[0])
        self.assertFalse(stats["queries"]["secrets"]["complete"])
        report = report_for(events, errors=errors, region_stats=[stats], offline=False)
        self.assertFalse(report["metadata"]["complete"])


if __name__ == "__main__":
    unittest.main()
