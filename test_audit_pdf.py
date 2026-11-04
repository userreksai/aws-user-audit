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
    report = build_report([sample_event()] if events is None else events,
                          audit_date="2026-10-28", timezone_name="Asia/Shanghai",
                          start=datetime(2026, 10, 26, 23, tzinfo=timezone.utc),
                          end=datetime(2026, 10, 28, 0, tzinfo=timezone.utc),
                          account_id="123456789012", regions=["eu-north-1", "us-east-1"],
                          errors=errors, offline=True, window_mode="daily_25h")
    return with_actors(report, report["actors"])


def extract(path):
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


def actor_row(name, identity_type="IAMUser", counts=None, failed=0):
    counts = counts if counts is not None else {"修改": 1}
    counts = {category: counts.get(category, 0) for category in audit_pdf.CATEGORIES}
    return {"actor": name, "identity_type": identity_type, "counts": counts,
            "failed": failed, "total": sum(counts.values())}


def event_row(name, category="修改", total=1, failed=0, identity_type="IAMUser", **values):
    row = {"actor": name, "identity_type": identity_type, "source": "ec2.amazonaws.com",
           "event_name": "ModifyInstanceAttribute", "event_label": "修改 EC2 实例属性",
           "translation_status": "reviewed",
           "operation_reference": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceAttribute.html",
           "category": category, "total": total, "failed": failed}
    row.update(values)
    return row


def with_actors(report, rows):
    report["actors"] = deepcopy(rows)
    report["metadata"].update(
        counts={category: sum(row["counts"][category] for row in rows)
                for category in audit_pdf.CATEGORIES},
        total=sum(row["total"] for row in rows),
        failed_or_partial=sum(row["failed"] for row in rows))
    report["actor_events"] = []
    for row in rows:
        remaining_failed = row["failed"]
        for category, count in row["counts"].items():
            if count:
                failed = min(count, remaining_failed)
                remaining_failed -= failed
                report["actor_events"].append(event_row(
                    row["actor"], category, count, failed, row["identity_type"],
                    event_name="Example" + str(audit_pdf.CATEGORIES.index(category)),
                    event_label={"新增": "创建 EC2 实例", "修改": "修改 EC2 实例属性",
                                 "删除": "删除 EC2 实例", "Secrets Manager 查看": "读取 Secrets Manager 密钥值",
                                 "登录信息": "登录 AWS 控制台", "其他操作": "启动 EC2 实例"}[category]))
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
                      "hhjgx", "新增", "修改", "删除", "用户操作与事件汇总", "中文事件", "调用次数",
                      "修改 EC2 实例属性", "Secret", "查看", "报告事件 1 条", "离线输入报告"):
            self.assertIn(value, text)
        for value in ("ModifyInstanceAttribute", "t3.medium", "i-example", "203.0.113.10",
                      "提交参数", "身份信息", "按操作者汇总", "事件 ID", "evt-change",
                      "Secret 查看指 Secrets Manager 查看；失败数是分类次数的子集。",
                      "同一角色的会话按角色合并统计，角色身份不直接认定为自然人。"):
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
        self.assertEqual(text.count("DeployRole"), 2)

    def test_preaggregated_role_sessions_do_not_reintroduce_session_details(self):
        report = with_actors(report_fixture(), [actor_row("DeployRole", "Role", {"修改": 2})])
        report["events"] = [{"actor": "角色 DeployRole / 会话 PRIVATE_SESSION_ONE"},
                            {"actor": "角色 DeployRole / 会话 PRIVATE_SESSION_TWO"}]
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertEqual(text.count("DeployRole"), 2)
        self.assertNotIn("PRIVATE_SESSION", text)
        self.assertNotIn("同一角色的会话按角色合并统计", text)

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
            if "user-" in page.extract_text():
                self.assertIn("身份类型", page.extract_text())
        self.assertIn("账号合计", text)

    def test_missing_identity_summary_requires_regeneration(self):
        for actors in (None, [], "unknown"):
            report = report_fixture()
            report["actors"] = actors
            with self.subTest(actors=actors), self.assertRaisesRegex(ValueError, "重新生成"):
                audit_pdf.render_report_pdf(report, self.path)

    def test_official_chinese_events_are_aggregated_per_identity_with_failures(self):
        report = with_actors(report_fixture(), [actor_row("hhjgx", counts={"修改": 3}, failed=1),
                                                actor_row("beiou", counts={"删除": 2}, failed=1)])
        dashboard_label = "保存 CloudWatch 监控仪表盘配置（新建或整体覆盖）"
        report["actor_events"] = [
            event_row("hhjgx", total=2, failed=1, source="monitoring.amazonaws.com",
                      event_name="PutDashboard", event_label=dashboard_label),
            event_row("hhjgx", total=1),
            event_row("beiou", category="删除", total=2, failed=1,
                      event_name="DeleteDashboard", event_label="删除 CloudWatch 监控仪表盘")]
        report["events"] = UnreadableEvents()
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        self.assertEqual(len(PdfReader(self.path).pages), 1)
        for value in ("按 IAM 用户 / 角色统计", "用户操作与事件汇总", "调用次数", "失败次数",
                      dashboard_label, "修改 EC2 实例属性", "删除 CloudWatch 监控仪表盘",
                      "报告事件 5 条", "其中失败或含失败响应 2 条"):
            self.assertIn(value, text)
        self.assertEqual(text.count(dashboard_label), 1)
        for value in ("PutDashboard", "DeleteDashboard", "ModifyInstanceAttribute", "monitoring.amazonaws.com"):
            self.assertNotIn(value, text)
        summary = audit_pdf._summary(report)
        self.assertEqual([(row["actor"], row["total"], row["failed"])
                          for row in summary["actor_events"]],
                         [("hhjgx", 2, 1), ("hhjgx", 1, 0), ("beiou", 2, 1)])

    def test_unknown_event_keeps_original_api_and_service_with_pending_label(self):
        report = report_fixture()
        report["actor_events"] = [event_row("hhjgx", event_name="FutureUnknownAction",
            source="example.amazonaws.com", event_label="FutureUnknownAction",
            translation_status="untranslated")]
        audit_pdf.render_report_pdf(report, self.path)
        text = extract(self.path)
        for value in ("待补中文", "FutureUnknownAction", "example.amazonaws.com"):
            self.assertIn(value, text)

    def test_same_translation_for_distinct_service_or_api_does_not_merge_rows(self):
        report = with_actors(report_fixture(), [actor_row("hhjgx", counts={"修改": 3})])
        report["actor_events"] = [event_row("hhjgx", event_name="SetConfiguration", source=source,
                                           event_label="修改服务配置")
                                  for source in ("service-a.amazonaws.com", "service-b.amazonaws.com")]
        report["actor_events"].append(event_row("hhjgx", event_name="UpdateConfiguration",
                                                event_label="修改服务配置"))
        audit_pdf.render_report_pdf(report, self.path)
        self.assertEqual(extract(self.path).count("修改服务配置"), 3)

    def test_event_table_paginates_repeats_headers_and_keeps_full_labels(self):
        report = with_actors(report_fixture(), [actor_row("hhjgx", counts={"修改": 100})])
        report["actor_events"] = [event_row("hhjgx", event_name=f"Event{index:03d}",
                                            event_label=f"更新监控配置事件 {index:03d}（保留完整事件语义）")
                                  for index in range(100)]
        audit_pdf.render_report_pdf(report, self.path)
        reader = PdfReader(self.path)
        self.assertGreater(len(reader.pages), 2)
        text = extract(self.path)
        for index in range(100):
            self.assertIn(f"更新监控配置事件 {index:03d}（保留完整事件语义）", text)
        for page in reader.pages:
            if "更新监控配置事件" in page.extract_text():
                self.assertIn("中文事件", page.extract_text())
                self.assertIn("调用次数", page.extract_text())

    def test_long_semantic_event_label_wraps_without_truncation(self):
        report = report_fixture()
        long_label = "保存监控仪表盘配置（新建或整体覆盖）" + "保留完整事件说明。" * 110 + "完整语义结束标记"
        report["actor_events"] = [event_row("hhjgx", event_label=long_label)]
        audit_pdf.render_report_pdf(report, self.path)
        compact_text = "".join(extract(self.path).split())
        self.assertIn("完整语义结束标记", compact_text)
        # A row can span a page, interrupting extracted text with footer/header.
        self.assertEqual(compact_text.count("说"), 110)
        self.assertEqual(compact_text.count("明"), 110)

    def test_missing_user_event_summary_requires_regeneration_for_nonempty_report(self):
        for rows in (None, [], "unknown"):
            report = report_fixture()
            report["actor_events"] = rows
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, "用户操作与事件汇总.*重新生成"):
                audit_pdf.render_report_pdf(report, self.path)

    def test_invalid_user_event_summary_does_not_replace_previous_pdf(self):
        cases = [{"actor": "other-user"}, {"identity_type": "Role"}, {"category": "新增"},
                 {"total": 2}, {"failed": 1}, {"failed": 2}, {"total": True},
                 {"event_name": ""}, {"source": ""}, {"event_label": ""},
                 {"translation_status": "invented"}, {"translation_status": []}, {"category": []}]
        for values in cases:
            report = report_fixture()
            report["actor_events"][0].update(values)
            self.path.write_bytes(b"old-pdf")
            with self.subTest(values=values), self.assertRaises(ValueError):
                audit_pdf.render_report_pdf(report, self.path)
            self.assertEqual(self.path.read_bytes(), b"old-pdf")

    def test_same_display_name_identity_groups_are_validated_by_type_and_name(self):
        report = with_actors(report_fixture(), [actor_row("shared", counts={"修改": 1}),
                                                actor_row("shared", counts={"修改": 2}),
                                                actor_row("shared", "Role", {"修改": 3})])
        report["actor_events"] = [event_row("shared", total=3),
                                   event_row("shared", total=3, identity_type="Role")]
        self.assertEqual(audit_pdf._summary(report)["total"], 6)
        report["actor_events"][0]["total"] = 2
        report["actor_events"][1]["total"] = 4
        with self.assertRaisesRegex(ValueError, "各身份"):
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
        report["actor_events"][0]["parameters"] = UnreadableEvents()
        report["actor_events"][0]["resources"] = "NEVER_RENDER_EVENT_RESOURCE"
        report["actor_events"][0]["source_ip"] = "192.0.2.123"
        report["actor_events"][0]["time_local"] = "2026-10-27 16:19:12"
        audit_pdf.render_report_pdf(report, self.path)
        self.assertEqual(len(PdfReader(self.path).pages), 1)
        text = extract(self.path)
        self.assertNotIn("PRIVATE_PROVIDER_RESPONSE_NEVER_RENDER", text)
        self.assertNotIn("NEVER_RENDER_METADATA_SECRET", text)
        self.assertNotIn("NEVER_RENDER_ACTOR_PARAMETERS", text)
        for value in ("NEVER_RENDER_EVENT_RESOURCE", "192.0.2.123", "2026-10-27 16:19:12"):
            self.assertNotIn(value, text)

    def test_large_report_and_very_long_parameters_do_not_expand_pdf(self):
        report = report_fixture()
        base = report["events"][0]
        base["parameters"] = {"notes": "PRIVATE_LONG_VALUE-" * 10000 + "DO_NOT_RENDER_TAIL"}
        report["events"] = [base] * 100000
        with_actors(report, [actor_row("hhjgx", counts={"修改": 100000})])
        audit_pdf.render_report_pdf(report, self.path)
        self.assertEqual(len(PdfReader(self.path).pages), 1)
        text = extract(self.path)
        self.assertIn("100,000", text)
        self.assertNotIn("PRIVATE_LONG_VALUE", text)
        self.assertNotIn("DO_NOT_RENDER_TAIL", text)
        self.assertIn("hhjgx", text)

    def test_summary_counts_and_failure_subset_are_preserved_exactly(self):
        report = report_fixture()
        with_actors(report, [actor_row("hhjgx", counts={"新增": 2, "修改": 12, "删除": 4,
                                                      "Secrets Manager 查看": 22, "登录信息": 3, "其他操作": 2},
                                      failed=5)])
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
