"""Lark summary tests: invented webhook, injected transport, no real messages."""

import base64
import copy
import hashlib
import hmac
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import quote

import aws_daily_audit as audit
import lark_notify as notify


FAKE_WEBHOOK = "https://open.larksuite.com/open-apis/bot/v2/hook/TEST-ONLY-NOT-A-REAL-WEBHOOK"
FAKE_SECRET = "TEST-ONLY-NOT-A-REAL-SIGNING-SECRET"


def sample_report(**metadata_overrides):
    categories = ("新增", "修改", "删除", "Secrets Manager 查看", "登录信息", "其他操作")
    metadata = {
        "audit_date": "2026-10-27", "account_id": "123456789012", "timezone": "Asia/Shanghai",
        "window_start_utc": "2026-10-26T16:00:00+00:00",
        "window_end_utc_exclusive": "2026-10-27T08:15:30+00:00",
        "window_start_local": "2026-10-27 00:00:00+08:00",
        "window_end_local_exclusive": "2026-10-27 16:15:30+08:00",
        "generated_at": "2026-10-27T08:16:00+00:00",
        "period_label": "当日截至查询时刻", "in_progress": True,
        "complete": True, "offline": False, "total": 1, "failed_or_partial": 2,
        "counts": {name: index + 1 for index, name in enumerate(categories)},
        "errors": [], "warnings": [],
    }
    metadata.update(metadata_overrides)
    return {"metadata": metadata, "events": [{
        "event_id": "TEST-EVENT-ID-001", "time_utc": "2026-10-27T03:15:00+00:00",
        "time_local": "2026-10-27 11:15:00+08:00", "actor": "hhjgx", "category": "修改",
        "event_name": "ModifyInstanceAttribute", "description": "修改 EC2 实例属性",
        "resources": ["i-test-instance"], "region": "eu-north-1", "source_ip": "203.0.113.10",
        "result": "请求无报错", "failed": False,
        "parameters": {"password": "DO_NOT_INCLUDE_REQUEST_SECRET"},
        "parameter_summary": "DO_NOT_INCLUDE_PARAMETER_SUMMARY",
        "response": {"SecretString": "DO_NOT_INCLUDE_RESPONSE_SECRET"},
        "identity": {"arn": "arn:aws:iam::123456789012:user/hhjgx", "type": "IAMUser"},
    }]}


class WebhookValidationTests(unittest.TestCase):
    def test_common_url_mistakes_have_distinct_safe_diagnostics(self):
        cases = (
            (FAKE_WEBHOOK.rsplit("/", 1)[0] + "/REPLACE_WITH_YOUR_TOKEN", "占位"),
            (FAKE_WEBHOOK + "\n", "空白|不可见"),
            (FAKE_WEBHOOK + "?token=PRIVATE_QUERY_TOKEN", "查询|query"),
            (FAKE_WEBHOOK.replace("open.larksuite.com", "untrusted.example.invalid"), "域名"),
        )
        messages = []
        for url, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason), self.assertRaises(ValueError) as caught:
                notify.validate_webhook_url(url)
            message = str(caught.exception)
            messages.append(message)
            self.assertRegex(message, expected_reason)
            self.assertNotIn(FAKE_WEBHOOK, message)
            self.assertNotIn("TEST-ONLY-NOT-A-REAL-WEBHOOK", message)
            self.assertNotIn("PRIVATE_QUERY_TOKEN", message)
        self.assertEqual(len(set(messages)), len(cases))

    def test_only_official_https_webhook_endpoints_are_accepted(self):
        for url in (FAKE_WEBHOOK, FAKE_WEBHOOK.replace("open.larksuite.com", "open.feishu.cn"),
                    FAKE_WEBHOOK.replace("open.larksuite.com", "open.larksuite.com:443")):
            with self.subTest(url=url):
                self.assertEqual(notify.validate_webhook_url(url), url)

    def test_rejects_spoofed_hosts_credentials_ports_and_extra_url_components(self):
        invalid = (
            FAKE_WEBHOOK.replace("https://", "http://"),
            FAKE_WEBHOOK.replace("open.larksuite.com", "open.larksuite.com.evil.invalid"),
            FAKE_WEBHOOK.replace("open.larksuite.com", "evil.invalid"),
            FAKE_WEBHOOK.replace("https://", "https://user:password@"),
            FAKE_WEBHOOK.replace("https://", "https://@"),
            FAKE_WEBHOOK.replace("https://", "https://:@"),
            FAKE_WEBHOOK.replace("open.larksuite.com", "open.larksuite.com:8443"),
            FAKE_WEBHOOK + "?token=test", FAKE_WEBHOOK + "#fragment",
            "https://open.larksuite.com/open-apis/bot/v2/hook/",
            "https://open.larksuite.com/anything/else/TEST-ONLY",
            FAKE_WEBHOOK + "/extra-path-segment",
        )
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(ValueError):
                notify.validate_webhook_url(url)


class ConfigTests(unittest.TestCase):
    def test_local_config_check_reports_override_source_without_sending_or_exposing_tokens(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"LARK_WEBHOOK_URL": FAKE_WEBHOOK}), \
             patch.object(notify, "load_lark_config", return_value={"webhook_url": FAKE_WEBHOOK,
                                                                    "signing_secret": FAKE_SECRET,
                                                                    "message_mode": "full"}) as load, \
             patch.object(notify, "send_lark_notification") as send, \
             patch.object(notify.urllib.request, "urlopen") as transport, redirect_stdout(output):
            exit_code = notify.main(["--check-config", "--config", "invented-do-not-read.json"])
        self.assertEqual(exit_code, 0)
        load.assert_called_once()
        self.assertEqual(Path(load.call_args.args[0]).resolve(), Path("invented-do-not-read.json").resolve())
        send.assert_not_called()
        transport.assert_not_called()
        self.assertIn("LARK_WEBHOOK_URL", output.getvalue())
        self.assertIn("open.larksuite.com", output.getvalue())
        self.assertIn("未发送", output.getvalue())
        self.assertNotIn(FAKE_WEBHOOK, output.getvalue())
        self.assertNotIn("TEST-ONLY-NOT-A-REAL-WEBHOOK", output.getvalue())
        self.assertNotIn(FAKE_SECRET, output.getvalue())

    def test_empty_environment_override_diagnoses_source_and_absolute_config_path_on_failure(self):
        with tempfile.TemporaryDirectory(prefix="audit-lark-diagnostic-test-") as folder:
            path = Path(folder) / "invented-valid-file.json"
            path.write_text(json.dumps({"webhook_url": FAKE_WEBHOOK, "signing_secret": FAKE_SECRET}), encoding="utf-8")
            output = io.StringIO()
            with patch.dict(os.environ, {"LARK_WEBHOOK_URL": "", "LARK_SIGNING_SECRET": ""}), \
                 patch.object(notify, "send_lark_notification") as send, \
                 patch.object(notify.urllib.request, "urlopen") as transport, redirect_stdout(output):
                with self.assertRaises(ValueError) as caught:
                    notify.load_lark_config(path)
                self.assertIn("LARK_WEBHOOK_URL", str(caught.exception))
                self.assertNotIn("TEST-ONLY-NOT-A-REAL-WEBHOOK", str(caught.exception))
                exit_code = notify.main(["--check-config", "--config", str(path)])
            self.assertEqual(exit_code, 1)
            send.assert_not_called()
            transport.assert_not_called()
            text = output.getvalue()
            self.assertIn(str(path.resolve()), text)
            self.assertIn("LARK_WEBHOOK_URL", text)
            self.assertIn("空", text)
            self.assertIn("覆盖", text)
            self.assertNotIn(FAKE_WEBHOOK, text)
            self.assertNotIn("TEST-ONLY-NOT-A-REAL-WEBHOOK", text)
            self.assertNotIn(FAKE_SECRET, text)

    def test_missing_file_can_use_environment_only_credentials(self):
        with tempfile.TemporaryDirectory(prefix="audit-lark-test-") as folder:
            nonexistent = Path(folder) / "does-not-exist.json"
            with patch.dict(os.environ, {"LARK_WEBHOOK_URL": FAKE_WEBHOOK,
                                         "LARK_SIGNING_SECRET": FAKE_SECRET}):
                config = notify.load_lark_config(nonexistent)
        self.assertEqual(config["webhook_url"], FAKE_WEBHOOK)
        self.assertEqual(config["signing_secret"], FAKE_SECRET)

    def test_existing_configuration_must_be_a_json_object(self):
        for contents in ("[1, 2]", "not-json", '"json string"'):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory(prefix="audit-lark-test-") as folder:
                path = Path(folder) / "invented-config.json"
                path.write_text(contents, encoding="utf-8")
                with patch.dict(os.environ, {"LARK_WEBHOOK_URL": FAKE_WEBHOOK,
                                             "LARK_SIGNING_SECRET": FAKE_SECRET}):
                    with self.assertRaises(ValueError):
                        notify.load_lark_config(path)

    def test_environment_overrides_json_without_touching_real_configuration(self):
        with tempfile.TemporaryDirectory(prefix="audit-lark-test-") as folder:
            path = Path(folder) / "invented-config.json"
            path.write_text(json.dumps({"webhook_url": FAKE_WEBHOOK, "signing_secret": FAKE_SECRET,
                                        "title_prefix": "Test audit"}), encoding="utf-8")
            override_url = FAKE_WEBHOOK.replace("TEST-ONLY-NOT-A-REAL-WEBHOOK", "OVERRIDE-TEST-TOKEN")
            with patch.dict(os.environ, {"LARK_WEBHOOK_URL": override_url,
                                         "LARK_SIGNING_SECRET": "OVERRIDE-TEST-SECRET"}):
                config = notify.load_lark_config(path)
            self.assertEqual(config["webhook_url"], override_url)
            self.assertEqual(config["signing_secret"], "OVERRIDE-TEST-SECRET")
            self.assertEqual(config["title_prefix"], "Test audit")

    def test_invalid_configuration_url_is_rejected_before_any_send(self):
        with tempfile.TemporaryDirectory(prefix="audit-lark-test-") as folder:
            path = Path(folder) / "invented-invalid-config.json"
            path.write_text(json.dumps({"webhook_url": "https://evil.invalid/collect"}), encoding="utf-8")
            with patch.dict(os.environ, {"LARK_WEBHOOK_URL": "", "LARK_SIGNING_SECRET": ""}):
                with self.assertRaises(ValueError):
                    notify.load_lark_config(path)


class PayloadTests(unittest.TestCase):
    def test_summary_contains_audit_identity_beijing_cutoff_and_counts_without_parameters(self):
        report = sample_report()
        before = copy.deepcopy(report)
        payload = notify.build_lark_payload(report)
        self.assertEqual(payload["msg_type"], "text")
        text = payload["content"]["text"]
        self.assertIn("2026-10-27", text)
        self.assertIn("123456789012", text)
        self.assertIn("2026-10-27 16:15:30", text)
        self.assertIn("北京", text)
        self.assertIn("hhjgx", text)
        for category in report["metadata"]["counts"]:
            self.assertIn(category, text)
            self.assertRegex(text, re.escape(category) + r"\s*[:：]?\s*" + str(report["metadata"]["counts"][category]) + r"\b")
        self.assertIn("失败", text)
        self.assertRegex(text, r"失败.{0,15}2\b")
        self.assertNotIn("DO_NOT_INCLUDE_REQUEST_SECRET", text)
        self.assertNotIn("DO_NOT_INCLUDE_RESPONSE_SECRET", text)
        self.assertNotIn("DO_NOT_INCLUDE_PARAMETER_SUMMARY", text)
        self.assertEqual(report, before)

    def test_incomplete_and_offline_reports_are_prominently_identified(self):
        payload = notify.build_lark_payload(sample_report(complete=False, offline=True,
                                                          errors=["DO_NOT_INCLUDE_INTERNAL_ERROR"]))
        text = payload["content"]["text"]
        self.assertIn("不完整", text)
        self.assertIn("示例", text)
        self.assertNotIn("DO_NOT_INCLUDE_INTERNAL_ERROR", text)

    def test_operation_excerpt_is_bounded_to_eight_rows_and_180_characters_each(self):
        report = sample_report()
        report["events"] = []
        for index in range(12):
            row = copy.deepcopy(sample_report()["events"][0])
            row["actor"] = f"operator-{index:02d}"
            row["description"] = "操作描述" * 100
            row["resources"] = ["resource-name-" * 100]
            report["events"].append(row)
        report["metadata"]["total"] = 12
        text = notify.build_lark_payload(report)["content"]["text"]
        lines = [line for line in text.splitlines() if re.search(r"operator-\d\d", line)]
        self.assertTrue(lines)
        self.assertLessEqual(len(lines), 8)
        self.assertTrue(all(len(line) <= 180 for line in lines))

    def test_report_link_accepts_only_http_and_https(self):
        url = "https://reports.example.invalid/audit.html"
        self.assertIn(url, notify.build_lark_payload(sample_report(), report_url=url)["content"]["text"])
        for url in ("file:///tmp/audit.html", "javascript:alert(1)", "ftp://example.invalid/audit",
                    "https:///missing-host", "https://user:password@reports.example.invalid/audit",
                    "https://@reports.example.invalid/audit", "https://:@reports.example.invalid/audit"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                notify.build_lark_payload(sample_report(), report_url=url)

    def test_report_url_template_encodes_filename_and_replaces_supported_fields(self):
        report = sample_report()
        result = notify.format_report_url("https://reports.example.invalid/{account_id}/{date}/{filename}", report)
        filename = quote("2026-10-27-aws操作审计.html", safe="")
        self.assertEqual(result, "https://reports.example.invalid/123456789012/2026-10-27/" + filename)

    def test_empty_url_template_remains_optional_and_account_component_is_escaped(self):
        self.assertEqual(notify.format_report_url("", sample_report()), "")
        result = notify.format_report_url("https://reports.example.invalid/{account_id}/{filename}",
                                          sample_report(account_id="team/account name"))
        self.assertIn("team%2Faccount%20name", result)

    def test_event_names_cannot_inject_group_mentions_or_extra_message_lines(self):
        report = sample_report()
        report["events"][0]["actor"] = '<at user_id="all">EVERYONE</at>\nINJECTED_LINE'
        text = notify.build_lark_payload(report)["content"]["text"]
        self.assertNotIn("<at ", text)
        self.assertNotIn("</at>", text)
        self.assertNotIn("\nINJECTED_LINE", text)


class SignatureTests(unittest.TestCase):
    def test_signature_matches_lark_empty_message_hmac_convention(self):
        timestamp = "1793088000"
        key = (timestamp + "\n" + FAKE_SECRET).encode("utf-8")
        expected = base64.b64encode(hmac.new(key, b"", hashlib.sha256).digest()).decode("ascii")
        self.assertEqual(notify.make_lark_signature(FAKE_SECRET, timestamp), expected)


class FakeResponse:
    def __init__(self, body, status=200):
        self.status = status
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")

    def getcode(self):
        return self.status

    def read(self, limit=-1):
        return self.body if limit < 0 else self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class DeliveryTests(unittest.TestCase):
    def test_success_uses_injected_transport_once_with_timeout_and_optional_signature(self):
        config = {"webhook_url": FAKE_WEBHOOK, "signing_secret": FAKE_SECRET}
        report = sample_report()
        opener = Mock(return_value=FakeResponse({"code": 0, "msg": "success"}))
        now = 1793088000
        result = notify.send_lark_notification(report, config, opener=opener, now=now)
        self.assertEqual(result, {"code": 0, "msg": "success"})
        opener.assert_called_once()
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, FAKE_WEBHOOK)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(opener.call_args.kwargs["timeout"], 20)
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["msg_type"], "text")
        self.assertEqual(str(payload["timestamp"]), str(now))
        self.assertEqual(payload["sign"], notify.make_lark_signature(FAKE_SECRET, str(now)))
        self.assertNotIn("DO_NOT_INCLUDE_REQUEST_SECRET", payload["content"]["text"])

    def test_unsigned_legacy_success_is_supported(self):
        opener = Mock(return_value=FakeResponse({"StatusCode": 0, "StatusMessage": "success"}))
        result = notify.send_lark_notification(sample_report(), {"webhook_url": FAKE_WEBHOOK}, opener=opener)
        self.assertEqual(result["StatusCode"], 0)
        payload = json.loads(opener.call_args.args[0].data.decode("utf-8"))
        self.assertNotIn("sign", payload)

    def test_http_and_business_failures_and_missing_codes_are_not_success(self):
        responses = (
            FakeResponse({"code": 0}, status=503),
            FakeResponse({"code": 19024, "msg": "DO_NOT_INCLUDE_PRIVATE_RESPONSE"}),
            FakeResponse({"msg": "no status code"}),
            FakeResponse({"StatusCode": 19024}),
            FakeResponse(b"not-json DO_NOT_INCLUDE_PRIVATE_RESPONSE"),
        )
        for response in responses:
            opener = Mock(return_value=response)
            with self.subTest(status=response.status, body=response.body), self.assertRaises(RuntimeError) as caught:
                notify.send_lark_notification(sample_report(), {"webhook_url": FAKE_WEBHOOK}, opener=opener)
            opener.assert_called_once()
            self.assertNotIn("DO_NOT_INCLUDE_PRIVATE_RESPONSE", str(caught.exception))
            self.assertNotIn("TEST-ONLY-NOT-A-REAL-WEBHOOK", str(caught.exception))

    def test_unknown_transport_failure_does_not_retry_or_expose_request_secrets(self):
        message = "timeout " + FAKE_WEBHOOK + " " + FAKE_SECRET + " DO_NOT_INCLUDE_REQUEST_SECRET"
        opener = Mock(side_effect=URLError(message))
        with self.assertRaises(RuntimeError) as caught:
            notify.send_lark_notification(sample_report(), {"webhook_url": FAKE_WEBHOOK,
                                                           "signing_secret": FAKE_SECRET}, opener=opener, now=1793088000)
        opener.assert_called_once()
        error = str(caught.exception)
        for sensitive in (FAKE_WEBHOOK, "TEST-ONLY-NOT-A-REAL-WEBHOOK", FAKE_SECRET,
                          "DO_NOT_INCLUDE_REQUEST_SECRET"):
            self.assertNotIn(sensitive, error)

    def test_http_error_exception_is_safe_and_never_retried(self):
        failure = HTTPError(FAKE_WEBHOOK, 403, "PRIVATE_HTTP_REASON " + FAKE_SECRET,
                            hdrs=None, fp=io.BytesIO(b"PRIVATE_HTTP_RESPONSE"))
        opener = Mock(side_effect=failure)
        with self.assertRaises(RuntimeError) as caught:
            notify.send_lark_notification(sample_report(), {"webhook_url": FAKE_WEBHOOK}, opener=opener)
        opener.assert_called_once()
        self.assertIn("403", str(caught.exception))
        for secret in (FAKE_WEBHOOK, FAKE_SECRET, "PRIVATE_HTTP_REASON", "PRIVATE_HTTP_RESPONSE"):
            self.assertNotIn(secret, str(caught.exception))

    def test_boolean_or_sensitive_status_code_is_not_success_and_is_not_echoed(self):
        for code in (False, FAKE_WEBHOOK + " " + FAKE_SECRET):
            opener = Mock(return_value=FakeResponse({"code": code}))
            with self.subTest(code=code), self.assertRaises(RuntimeError) as caught:
                notify.send_lark_notification(sample_report(), {"webhook_url": FAKE_WEBHOOK}, opener=opener)
            opener.assert_called_once()
            self.assertNotIn(FAKE_WEBHOOK, str(caught.exception))
            self.assertNotIn(FAKE_SECRET, str(caught.exception))

    def test_oversized_response_does_not_confirm_success_or_echo_response(self):
        opener = Mock(return_value=FakeResponse(b"PRIVATE_RESPONSE_" * 5000))
        with self.assertRaises(RuntimeError) as caught:
            notify.send_lark_notification(sample_report(), {"webhook_url": FAKE_WEBHOOK}, opener=opener)
        opener.assert_called_once()
        self.assertNotIn("PRIVATE_RESPONSE_", str(caught.exception))

    def test_invalid_url_is_rejected_before_transport(self):
        opener = Mock(side_effect=AssertionError("No network call should occur"))
        with self.assertRaises(ValueError):
            notify.send_lark_notification(sample_report(), {"webhook_url": "https://evil.invalid/collect"}, opener=opener)
        opener.assert_not_called()

    def test_19001_invalid_token_response_gives_safe_webhook_reconfiguration_hint(self):
        opener = Mock(return_value=FakeResponse({
            "code": 19001,
            "msg": "incoming webhook access token invalid " + FAKE_WEBHOOK + " " + FAKE_SECRET,
        }))
        with self.assertRaises(RuntimeError) as caught:
            notify.send_lark_notification(sample_report(), {"webhook_url": FAKE_WEBHOOK}, opener=opener)
        opener.assert_called_once()
        error = str(caught.exception)
        self.assertIn("19001", error)
        self.assertIn("Webhook", error)
        self.assertIn("无效", error)
        self.assertIn("重新", error)
        self.assertNotIn(FAKE_WEBHOOK, error)
        self.assertNotIn(FAKE_SECRET, error)

    def test_19001_without_specific_evidence_does_not_claim_token_is_invalid(self):
        for response in ({"code": 19001}, {"code": 19001, "msg": "PRIVATE_UNRECOGNIZED_DIAGNOSTIC " + FAKE_WEBHOOK}):
            opener = Mock(return_value=FakeResponse(response))
            with self.subTest(response=response), self.assertRaises(RuntimeError) as caught:
                notify.send_lark_notification(sample_report(), {"webhook_url": FAKE_WEBHOOK}, opener=opener)
            opener.assert_called_once()
            error = str(caught.exception)
            self.assertIn("19001", error)
            self.assertIn("参数", error)
            self.assertIn("不能仅凭错误码", error)
            self.assertNotIn("Webhook 无效", error)
            self.assertNotIn("PRIVATE_UNRECOGNIZED_DIAGNOSTIC", error)
            self.assertNotIn(FAKE_WEBHOOK, error)


class FullPayloadTests(unittest.TestCase):
    def full_config(self, **overrides):
        config = {"webhook_url": FAKE_WEBHOOK, "message_mode": "full"}
        config.update(overrides)
        return config

    def large_report(self):
        report = sample_report()
        report["events"][0]["parameters"] = {
            "safeLongValue": "BEGIN_LONG_VALUE_" + "汉🚀" * 15000 + "_END_LONG_VALUE",
        }
        return report

    def test_summary_mode_preserves_original_single_message_behavior(self):
        report = sample_report()
        config = {"webhook_url": FAKE_WEBHOOK}
        self.assertIn("详细报告：", notify.build_lark_payloads(report, config)[0]["content"]["text"])
        config["message_mode"] = "summary"
        self.assertEqual(notify.build_lark_payloads(report, config), [notify.build_lark_payload(report)])

    def test_full_mode_includes_all_events_and_complete_operation_fields(self):
        report = sample_report()
        report["events"] = []
        for index in range(12):
            row = copy.deepcopy(sample_report()["events"][0])
            row.update({"event_id": f"event-{index:02d}", "actor": f"full-operator-{index:02d}",
                        "description": "完整操作描述" * 45 + f"DESCRIPTION_END_{index:02d}",
                        "parameters": {"publicField": f"REQUEST_VALUE_{index:02d}"},
                        "response": {"publicResponse": f"RESPONSE_VALUE_{index:02d}"}})
            report["events"].append(row)
        report["metadata"]["total"] = len(report["events"])
        payloads = notify.build_lark_payloads(report, self.full_config())
        text = "\n".join(payload["content"]["text"] for payload in payloads)
        for index in range(12):
            self.assertIn(f"full-operator-{index:02d}", text)
            self.assertIn(f"DESCRIPTION_END_{index:02d}", text)
            self.assertIn(f"REQUEST_VALUE_{index:02d}", text)
        for expected in ("2026-10-27 11:15:00", "修改", "ModifyInstanceAttribute", "i-test-instance",
                         "eu-north-1", "203.0.113.10", "请求无报错"):
            self.assertIn(expected, text)
        self.assertNotIn("仅列最近 8 条", text)

    def test_unicode_parameters_are_split_without_loss_and_final_signed_messages_fit_limit(self):
        report = self.large_report()
        config = self.full_config(signing_secret=FAKE_SECRET)
        payloads = notify.build_lark_payloads(report, config)
        self.assertGreater(len(payloads), 2)
        text = "\n".join(payload["content"]["text"] for payload in payloads)
        self.assertIn("BEGIN_LONG_VALUE_", text)
        self.assertIn("_END_LONG_VALUE", text)
        self.assertEqual(text.count("汉"), 15000)
        self.assertEqual(text.count("🚀"), 15000)
        self.assertNotIn("\ufffd", text)
        self.assertTrue(all(len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) <= 20 * 1024 for payload in payloads))
        opener = Mock(return_value=FakeResponse({"code": 0}))
        sleep = Mock()
        result = notify.send_lark_notification(report, config, opener=opener, now=1793088000, sleep=sleep)
        self.assertEqual(result, {"code": 0, "messages_sent": len(payloads)})
        self.assertEqual(opener.call_count, len(payloads))
        self.assertEqual(sleep.call_count, len(payloads) - 1)
        self.assertTrue(all(call.args == (0.7,) for call in sleep.call_args_list))
        for call in opener.call_args_list:
            self.assertLessEqual(len(call.args[0].data), 20 * 1024)
            actual_payload = json.loads(call.args[0].data.decode("utf-8"))
            self.assertIn("sign", actual_payload)
            self.assertIn("timestamp", actual_payload)

    def test_full_mode_redacts_requests_responses_identity_and_json_encoded_secrets(self):
        report = sample_report()
        report["events"][0].update({
            "actor": '<at user_id="all">FULL_MODE_MENTION</at>',
            "parameters": {"publicField": "KEEP_PUBLIC_REQUEST", "secretString": "PRIVATE_REQUEST_SECRET",
                           "nestedJson": json.dumps({"password": "PRIVATE_NESTED_SECRET"})},
            "response": {"publicResponse": "KEEP_PUBLIC_RESPONSE", "sessionToken": "PRIVATE_RESPONSE_TOKEN"},
            "identity": {"type": "IAMUser", "arn": "KEEP_PUBLIC_IDENTITY", "secretAccessKey": "PRIVATE_IDENTITY_SECRET"},
        })
        text = "\n".join(payload["content"]["text"] for payload in notify.build_lark_payloads(report, self.full_config()))
        self.assertIn("KEEP_PUBLIC_REQUEST", text)
        self.assertNotIn("<at ", text)
        self.assertNotIn("</at>", text)
        for private in ("PRIVATE_REQUEST_SECRET", "PRIVATE_NESTED_SECRET", "PRIVATE_RESPONSE_TOKEN", "PRIVATE_IDENTITY_SECRET"):
            self.assertNotIn(private, text)

    def test_full_messages_mark_offline_incomplete_and_each_numbered_part(self):
        report = self.large_report()
        report["metadata"].update({"offline": True, "complete": False,
                                    "errors": ["DO_NOT_INCLUDE_INTERNAL_RAW_ERROR"]})
        payloads = notify.build_lark_payloads(report, self.full_config())
        self.assertGreater(len(payloads), 1)
        all_text = "\n".join(payload["content"]["text"] for payload in payloads)
        self.assertIn("示例", all_text)
        self.assertIn("不完整", all_text)
        for index, payload in enumerate(payloads, start=1):
            text = payload["content"]["text"]
            self.assertIn("2026-10-27", text)
            self.assertIn("123456789012", text)
            self.assertRegex(text, rf"第\s*{index}\s*/\s*(?:共\s*)?{len(payloads)}\s*条")
            self.assertNotIn("DO_NOT_INCLUDE_INTERNAL_RAW_ERROR", text)

    def test_partial_delivery_stops_at_first_failure_without_retrying_or_sending_remainder(self):
        report = self.large_report()
        config = self.full_config()
        payloads = notify.build_lark_payloads(report, config)
        self.assertGreater(len(payloads), 2)
        opener = Mock(side_effect=[FakeResponse({"code": 0}), FakeResponse({"code": 19024, "msg": FAKE_WEBHOOK})])
        sleep = Mock()
        with self.assertRaises(RuntimeError) as caught:
            notify.send_lark_notification(report, config, opener=opener, now=1793088000, sleep=sleep)
        self.assertEqual(opener.call_count, 2)
        error = str(caught.exception)
        self.assertRegex(error, rf"已成功(?:发送)?\s*1\s*/\s*{len(payloads)}\s*条")
        self.assertNotIn(FAKE_WEBHOOK, error)
        for index, call in enumerate(opener.call_args_list):
            sent = json.loads(call.args[0].data.decode("utf-8"))
            self.assertEqual(sent["content"]["text"], payloads[index]["content"]["text"])

    def test_all_payload_sizes_are_checked_before_sending_any_part(self):
        payloads = [{"msg_type": "text", "content": {"text": "Safe first message"}},
                    {"msg_type": "text", "content": {"text": "汉" * 8000}}]
        opener = Mock(side_effect=AssertionError("No message may be sent before full preflight validation"))
        with patch.object(notify, "build_lark_payloads", return_value=payloads), self.assertRaises(RuntimeError):
            notify.send_lark_notification(sample_report(), self.full_config(signing_secret=FAKE_SECRET),
                                          opener=opener, now=1793088000, sleep=Mock())
        opener.assert_not_called()


class CliDeliveryTests(unittest.TestCase):
    def run_cli(self, *, send=False, broken_event=False, delivery_error=None):
        day, start, end = audit.make_window("2026-10-27", "Asia/Shanghai")
        event = {"eventID": "TEST-EVENT", "eventTime": "invalid-time" if broken_event else "2026-10-27T03:15:00Z",
                 "recipientAccountId": "123456789012", "eventSource": "ec2.amazonaws.com",
                 "eventName": "ModifyInstanceAttribute", "readOnly": False}
        errors = io.StringIO()
        with patch.object(audit, "resolve_window", return_value=(day, start, end, False)), \
             patch.object(audit, "load_input", return_value=[event]), \
             patch.object(audit, "write_report", return_value=Path("offline-test-output")) as write, \
             patch.object(notify, "load_lark_config", return_value={"webhook_url": FAKE_WEBHOOK}) as config, \
             patch.object(notify, "send_lark_notification", return_value={"code": 0}, side_effect=delivery_error) as delivery, \
             redirect_stdout(io.StringIO()), redirect_stderr(errors):
            arguments = ["--input-file", "unused.json"] + (["--send-lark"] if send else [])
            result = audit.main(arguments)
        return result, write, config, delivery, errors.getvalue()

    def test_default_cli_does_not_read_configuration_or_send(self):
        result, write, config, delivery, _ = self.run_cli()
        self.assertEqual(result, 0)
        write.assert_called_once()
        config.assert_not_called()
        delivery.assert_not_called()

    def test_send_failure_keeps_written_report_and_returns_exit_three(self):
        result, write, config, delivery, _ = self.run_cli(send=True, delivery_error=RuntimeError("safe test delivery error"))
        self.assertEqual(result, 3)
        write.assert_called_once()
        config.assert_called_once()
        delivery.assert_called_once()

    def test_incomplete_audit_stays_exit_two_even_if_delivery_also_fails(self):
        result, write, _, delivery, _ = self.run_cli(send=True, broken_event=True,
                                                    delivery_error=RuntimeError("safe test delivery error"))
        self.assertEqual(result, 2)
        write.assert_called_once()
        self.assertFalse(write.call_args.args[0]["metadata"]["complete"])
        delivery.assert_called_once()

    def test_incomplete_audit_can_send_marked_report_but_stays_exit_two(self):
        result, write, _, delivery, _ = self.run_cli(send=True, broken_event=True)
        self.assertEqual(result, 2)
        self.assertFalse(write.call_args.args[0]["metadata"]["complete"])
        delivery.assert_called_once()
        self.assertFalse(delivery.call_args.args[0]["metadata"]["complete"])


if __name__ == "__main__":
    unittest.main()
