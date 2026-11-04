"""Offline summary-only PDF checks, including deliberate event access traps."""
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


def actor_row(name, identity_type="IAMUser", counts=None, failed=0):
    counts = counts if counts is not None else {"修改": 1}
    counts = {category: counts.get(category, 0) for category in audit_pdf.CATEGORIES}
    return {"actor": name, "identity_type": identity_type, "counts": counts,
            "failed": failed, "total": sum(counts.values())}


def with_actors(report, rows):
    report["actors"] = deepcopy(rows)
    report["metadata"].update(
        counts={category: sum(row["counts"][category] for row in rows)
                for category in audit_pdf.CATEGORIES},
        total=sum(row["total"] for row in rows),
        failed_or_partial=sum(row["failed"] for row in rows))
    return report


class UnreadableEvents:
    def __iter__(self):
        raise AssertionError("PDF must not iterate detailed events")

    def __len__(self):
        raise AssertionError("PDF must not inspect detailed events")

    def __str__(self):
        raise AssertionError("PDF must not serialize detailed events")


class AuditPdfTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "2026-10-28-aws操作审计.pdf"

    def test_single_page_chinese_account_summary_and_actual_beijing_window(self):
        report = report_fixture()
        report["metadata"]["account_name"] = "生产账号"
        original = deepcopy(report)
        target = audit_pdf.render_report_pdf(report, self.path)
        self.assertEqual(target, self.path)
        self.assertTrue(self.path.read_bytes().startswith(b"%PDF-"))
        reader = PdfReader(self.path)
        self.assertEqual(len(reader.pages), 1)
        text = extract(self.path)
        for value in ("AWS 账号操作审计日报", "AWS账号：123456789012", "生产账号", "2026-10-27 07:00:00",
                      "2026-10-28 08:00:00", "按 IAM 用户 / 角色统计", "账号 / 角色", "身份类型", "账号合计",
                      "hhjgx", "新增", "修改", "删除", "Secrets Manager 查看", "报告事件 1 条", "离线输入报告"):
            self.assertIn(value, text)
        for value in ("ModifyInstanceAttribute", "t3.medium", "i-example", "203.0.113.10",
                      "提交参数", "身份信息", "按操作者汇总", "事件 ID", "evt-change"):
            self.assertNotIn(value, text)
        self.assertEqual(report, original)

    def test_multiple_iam_users_and_role_each_have_a_visible_summary_row(self):
        report = with_actors(report_fixture(), [
            actor_row("beiou", counts={"新增": 2, "修改": 3}),
            actor_row("hhjgx", counts={"修改": 12, "Secrets Manager 查看": 22}, failed=3),
            actor_row("DeployRole", "Role", {"删除": 1})])
        report["events"] = UnreadableEvents()
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertEqual(len(PdfReader(self.path).pages), 1)
        for value in ("beiou", "hhjgx", "DeployRole", "IAM 用户", "角色", "账号合计", "报告事件 40 条"):
            self.assertIn(value, text)
        self.assertEqual(text.count("DeployRole"), 1)

    def test_preaggregated_role_sessions_do_not_reintroduce_session_details(self):
        report = with_actors(report_fixture(), [actor_row("DeployRole", "Role", {"修改": 2})])
        report["events"] = [{"actor": "角色 DeployRole / 会话 PRIVATE_SESSION_ONE"},
                            {"actor": "角色 DeployRole / 会话 PRIVATE_SESSION_TWO"}]
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertEqual(text.count("DeployRole"), 1)
        self.assertNotIn("PRIVATE_SESSION", text)
        self.assertIn("同一角色的会话按角色合并统计", text)

    def test_many_identities_paginate_with_repeated_headers_and_no_omissions(self):
        rows = [actor_row(f"user-{index:03d}") for index in range(140)]
        report = with_actors(report_fixture(), rows)
        report["events"] = UnreadableEvents()
        audit_pdf.render_report_pdf(report, self.path)
        reader = PdfReader(self.path)
        self.assertGreater(len(reader.pages), 1)
        text = extract(self.path)
        for row in rows:
            self.assertIn(row["actor"], text)
        for page in reader.pages:
            self.assertIn("身份类型", page.extract_text())
        self.assertIn("账号合计", reader.pages[-1].extract_text())

    def test_missing_identity_summary_requires_regeneration(self):
        for actors in (None, [], "unknown"):
            report = report_fixture()
            report["actors"] = actors
            with self.subTest(actors=actors), self.assertRaisesRegex(ValueError, "重新生成"):
                audit_pdf.render_report_pdf(report, self.path)

    def test_invalid_identity_names_types_or_counts_do_not_replace_previous_pdf(self):
        for values in ({"actor": ""}, {"identity_type": []}, {"identity_type": "Invented"},
                       {"counts": {"修改": -1}}, {"total": 2}, {"failed": 2},
                       {"counts": {"新增": 1}, "total": 1}):
            report = report_fixture()
            report["actors"][0].update(values)
            self.path.write_bytes(b"old-pdf")
            with self.subTest(values=values), self.assertRaises(ValueError):
                audit_pdf.render_report_pdf(report, self.path)
            self.assertEqual(self.path.read_bytes(), b"old-pdf")

    def test_pdf_never_reads_or_serializes_event_details(self):
        report = report_fixture()
        report["events"] = UnreadableEvents()
        report["metadata"]["errors"] = ["PRIVATE_PROVIDER_RESPONSE_NEVER_RENDER"]
        report["metadata"]["arbitrary"] = {"secret": "NEVER_RENDER_METADATA_SECRET"}
        report["actors"][0]["parameters"] = {"secret": "NEVER_RENDER_ACTOR_PARAMETERS"}
        audit_pdf.render_report_pdf(report, self.path)
        self.assertEqual(len(PdfReader(self.path).pages), 1)
        text = extract(self.path)
        self.assertNotIn("PRIVATE_PROVIDER_RESPONSE_NEVER_RENDER", text)
        self.assertNotIn("NEVER_RENDER_METADATA_SECRET", text)
        self.assertNotIn("NEVER_RENDER_ACTOR_PARAMETERS", text)

    def test_large_report_and_very_long_parameters_do_not_expand_pdf(self):
        report = report_fixture()
        base = report["events"][0]
        base["parameters"] = {"notes": "PRIVATE_LONG_VALUE-" * 10000 + "DO_NOT_RENDER_TAIL"}
        report["events"] = [base] * 100000
        report["metadata"]["counts"]["修改"] = 100000
        report["metadata"]["total"] = 100000
        report["actors"][0]["counts"]["修改"] = 100000
        report["actors"][0]["total"] = 100000
        audit_pdf.render_report_pdf(report, self.path)
        self.assertEqual(len(PdfReader(self.path).pages), 1)
        text = extract(self.path)
        self.assertIn("100,000", text)
        self.assertNotIn("PRIVATE_LONG_VALUE", text)
        self.assertNotIn("DO_NOT_RENDER_TAIL", text)
        self.assertIn("hhjgx", text)

    def test_summary_counts_and_failure_subset_are_preserved_exactly(self):
        report = report_fixture()
        report["metadata"].update(counts={"新增": 2, "修改": 12, "删除": 4,
                                         "Secrets Manager 查看": 22, "登录信息": 3, "其他操作": 2},
                                  total=45, failed_or_partial=5)
        report["actors"][0].update(counts=deepcopy(report["metadata"]["counts"]), total=45, failed=5)
        report.pop("events")
        summary = audit_pdf._summary(report)
        self.assertEqual(summary["counts"], report["metadata"]["counts"])
        self.assertEqual(summary["total"], 45)
        self.assertEqual(summary["failed"], 5)
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertIn("报告事件 45 条", text)
        self.assertIn("其中失败或含失败响应 5 条", text)
        self.assertEqual(len(PdfReader(self.path).pages), 1)

    def test_same_account_name_and_id_are_not_duplicated_in_account_heading(self):
        report = report_fixture()
        report["metadata"]["account_name"] = report["metadata"]["account_id"]
        audit_pdf.render_report_pdf(report, self.path)
        line = next(line for line in extract(self.path).splitlines() if line.startswith("AWS账号："))
        self.assertEqual(line.count("123456789012"), 1)

    def test_metadata_markup_is_literal_and_detail_secrets_are_absent(self):
        report = report_fixture()
        report["metadata"]["account_name"] = "<b>演示账号</b>&report"
        report["events"][0]["parameters"] = {"password": "NEVER_PUBLISH_PASSWORD",
                                               "normal": "DO_NOT_INCLUDE_EVENT_TEXT"}
        report["events"][0]["identity"]["sessionToken"] = "NEVER_PUBLISH_TOKEN"
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertIn("<b>演示账号</b>&report", text)
        for value in ("NEVER_PUBLISH_PASSWORD", "NEVER_PUBLISH_TOKEN", "DO_NOT_INCLUDE_EVENT_TEXT"):
            self.assertNotIn(value, text)

    def test_cid_fallback_renders_the_same_one_page_summary(self):
        with patch.object(audit_pdf.Path, "is_file", return_value=False):
            font = audit_pdf._font()
        self.assertEqual(font, "STSong-Light")
        with patch.object(audit_pdf, "_font", return_value=font):
            audit_pdf.render_report_pdf(report_fixture(), self.path)
        self.assertEqual(len(PdfReader(self.path).pages), 1)
        self.assertIn("按 IAM 用户 / 角色统计", extract(self.path))

    def test_invalid_counts_and_totals_rejected_without_replacing_old_pdf(self):
        for patch_values in ({"counts": {"新增": True}}, {"counts": {"新增": -1}},
                             {"counts": {"新增": "1"}}, {"total": 2},
                             {"failed_or_partial": 2}, {"failed_or_partial": -1},
                             {"complete": "true"}):
            report = report_fixture()
            report["metadata"].update(patch_values)
            self.path.write_bytes(b"old-pdf")
            with self.subTest(patch=patch_values), self.assertRaises(ValueError):
                audit_pdf.render_report_pdf(report, self.path)
            self.assertEqual(self.path.read_bytes(), b"old-pdf")

    def test_incomplete_zero_events_is_not_presented_as_success(self):
        report = report_fixture(events=[], errors=["PRIVATE_PROVIDER_RESPONSE_NEVER_RENDER"])
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertIn("查询或事件解析不完整", text)
        self.assertIn("未取得符合报告规则的事件", text)
        self.assertNotIn("查询状态：所列查询完成", text)
        self.assertNotIn("PRIVATE_PROVIDER_RESPONSE_NEVER_RENDER", text)
        self.assertEqual(len(PdfReader(self.path).pages), 1)

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
