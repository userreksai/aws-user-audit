"""Offline PDF checks: actual text, long content, redaction and atomic output."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pypdf import PdfReader

import audit_pdf
from aws_daily_audit import build_report
from test_aws_daily_audit import sample_event


def report_fixture(events=None, errors=None):
    return build_report([sample_event()] if events is None else events,
                        audit_date="2026-10-28", timezone_name="Asia/Shanghai",
                        start=datetime(2026, 10, 26, 23, tzinfo=timezone.utc),
                        end=datetime(2026, 10, 28, 0, tzinfo=timezone.utc),
                        account_id="123456789012", regions=["eu-north-1", "us-east-1"],
                        errors=errors, offline=True, window_mode="daily_25h")


def extract(path):
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


class AuditPdfTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "2026-10-28-aws操作审计.pdf"

    def test_portable_chinese_operation_details_and_beijing_clock(self):
        report = report_fixture()
        original = deepcopy(report)
        target = audit_pdf.render_report_pdf(report, self.path)
        self.assertEqual(target, self.path)
        self.assertTrue(self.path.read_bytes().startswith(b"%PDF-"))
        text = extract(self.path)
        for value in ("AWS 账号操作审计日报", "123456789012", "hhjgx", "2026-10-27 11:15:00",
                      "ModifyInstanceAttribute", "t3.medium", "i-example", "203.0.113.10",
                      "提交参数", "身份信息", "按操作者汇总", "离线输入报告"):
            self.assertIn(value, text)
        self.assertEqual(report, original)

    def test_long_json_spans_many_pages_without_truncating_tail(self):
        report = report_fixture()
        report["events"][0]["parameters"] = {"notes": "长提交参数-" * 10000 + "END_OF_FULL_PARAMETERS"}
        audit_pdf.render_report_pdf(report, self.path)
        reader = PdfReader(self.path)
        self.assertGreater(len(reader.pages), 3)
        self.assertIn("END_OF_FULL_PARAMETERS", extract(self.path))
        self.assertIn("evt-change", extract(self.path))

    def test_markup_and_control_characters_are_display_text(self):
        report = report_fixture()
        report["events"][0]["parameters"] = {"notes": '<script>alert("x")</script>&value=1\x01'}
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertIn("<script>", text)
        self.assertIn("</script>", text)
        self.assertIn("&value=1", text)
        self.assertIn("\\u0001", text)

    def test_cid_fallback_and_many_actors_keep_all_events(self):
        report = report_fixture()
        base = report["events"][0]
        report["events"] = [dict(deepcopy(base), actor="用户" + str(index),
                                 event_id="event-" + str(index)) for index in range(50)]
        with patch.object(audit_pdf.Path, "is_file", return_value=False):
            font = audit_pdf._font()
        self.assertEqual(font, "STSong-Light")
        with patch.object(audit_pdf, "_font", return_value=font):
            audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertIn("用户49", text)
        self.assertIn("event-49", text)
        self.assertGreater(len(PdfReader(self.path).pages), 3)

    def test_parameters_and_identity_are_redacted_again(self):
        report = report_fixture()
        report["events"][0]["parameters"] = {"password": "NEVER_PUBLISH_PASSWORD",
                                               "nested": {"secretString": "NEVER_PUBLISH_SECRET"},
                                               "normal": "visible-field"}
        report["events"][0]["identity"]["sessionToken"] = "NEVER_PUBLISH_TOKEN"
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertIn("visible-field", text)
        self.assertIn("REDACTED", text)
        for value in ("NEVER_PUBLISH_PASSWORD", "NEVER_PUBLISH_SECRET", "NEVER_PUBLISH_TOKEN"):
            self.assertNotIn(value, text)

    def test_incomplete_zero_events_is_not_presented_as_success(self):
        report = report_fixture(events=[], errors=["PRIVATE_PROVIDER_RESPONSE_NEVER_RENDER"])
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertIn("查询或事件解析不完整", text)
        self.assertIn("未取得符合报告规则的事件", text)
        self.assertNotIn("PRIVATE_PROVIDER_RESPONSE_NEVER_RENDER", text)

    def test_failed_render_preserves_previous_pdf_and_removes_staging_file(self):
        self.path.write_bytes(b"old-pdf")
        with patch.object(audit_pdf.SimpleDocTemplate, "build", side_effect=RuntimeError("render failed")):
            with self.assertRaises(RuntimeError):
                audit_pdf.render_report_pdf(report_fixture(), self.path)
        self.assertEqual(self.path.read_bytes(), b"old-pdf")
        self.assertEqual(list(self.path.parent.glob(".audit-pdf-*")), [])

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_pdf_is_private_even_when_replacing_public_mode_file(self):
        self.path.write_bytes(b"previous")
        self.path.chmod(0o644)
        audit_pdf.render_report_pdf(report_fixture(), self.path)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_invalid_explicit_font_fails_without_replacing_report(self):
        self.path.write_bytes(b"previous")
        with self.assertRaisesRegex(ValueError, "PDF_FONT_PATH"):
            audit_pdf.render_report_pdf(report_fixture(), self.path, self.path.parent / "missing.ttf")
        self.assertEqual(self.path.read_bytes(), b"previous")


if __name__ == "__main__":
    unittest.main()
