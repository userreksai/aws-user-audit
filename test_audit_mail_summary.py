"""Email-only resource tables use normalized aggregates, never raw events."""
from copy import deepcopy
from html.parser import HTMLParser
import unittest
from unittest.mock import patch

import audit_mail_summary as mail_summary
from audit_resource_summary import RESOURCE_COLUMNS, summarize_resource_operations


def report(account="123456789012", tag="prod", *, complete=True):
    return {"metadata": {"account_id": account, "account_tag": tag, "complete": complete}}


def row(actor="alice", identity_type="IAMUser", **counts):
    return {"actor": actor, "identity_type": identity_type,
            "counts": {column: counts.get(column, 0) for column in RESOURCE_COLUMNS}}


def summary(*rows, available=True):
    return {"available": available, "rows": list(rows),
            "counts": {column: sum(item["counts"][column] for item in rows)
                       for column in RESOURCE_COLUMNS}}


class Tables(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tables = []
        self.current = None
        self.current_row = None
        self.current_cell = None
        self.tags = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)
        if tag == "table":
            self.current = []
            self.tables.append(self.current)
        elif tag == "tr":
            self.current_row = []
            self.current.append(self.current_row)
        elif tag in {"th", "td"}:
            self.current_cell = ""

    def handle_data(self, data):
        if self.current_cell is not None:
            self.current_cell += data

    def handle_endtag(self, tag):
        if tag in {"th", "td"}:
            self.current_row.append(self.current_cell)
            self.current_cell = None


class MailResourceSummaryTests(unittest.TestCase):
    def render(self, method, reports, *summaries):
        with patch.object(mail_summary, "summarize_resource_operations", side_effect=summaries) as helper:
            value = getattr(mail_summary, method)(reports)
        expected = [reports] if isinstance(reports, dict) else reports
        self.assertEqual(helper.call_args_list, [unittest.mock.call(item) for item in expected])
        return value

    def test_fixed_eight_columns_and_exact_count_placement(self):
        expected_columns = ("安全组", "负载均衡", "弹性IP申请/绑定", "VPC", "路由表", "EC2", "RDS")
        self.assertEqual(RESOURCE_COLUMNS, expected_columns)
        identity = row(**dict(zip(RESOURCE_COLUMNS, (1, 2, 3, 4, 5, 6, 7))))
        html = self.render("render_resource_tables_html", report(), summary(identity))
        parsed = Tables()
        parsed.feed(html)
        self.assertEqual(parsed.tables, [[["具体用户", *RESOURCE_COLUMNS],
                                          ["alice", "1", "2", "3", "4", "5", "6", "7"]]])
        text = self.render("render_resource_tables_text", report(), summary(identity))
        self.assertIn("alice | 1 | 2 | 3 | 4 | 5 | 6 | 7", text)
        self.assertIn("具体用户 | " + " | ".join(RESOURCE_COLUMNS), text)

    def test_dynamic_accounts_are_independent_and_order_id_before_tag(self):
        for count in (1, 3, 9):
            with self.subTest(count=count):
                reports = [report(f"{123456789012 + index}", f"TAG{index}") for index in range(count)]
                summaries = [summary(row(f"user{index}", EC2=1)) for index in range(count)]
                text = self.render("render_resource_tables_text", reports, *summaries)
                html = self.render("render_resource_tables_html", reports, *summaries)
                parsed = Tables()
                parsed.feed(html)
                self.assertEqual(len(parsed.tables), count)
                for index in range(count):
                    heading = f"{123456789012 + index}-TAG{index}"
                    self.assertIn(heading, text)
                    self.assertIn(heading, html)
                    self.assertNotIn(f"TAG{index}-{123456789012 + index}", text)
                    self.assertEqual(parsed.tables[index][1][0], f"user{index}")

    def test_missing_tag_uses_only_id(self):
        value = report(tag="")
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            text = self.render(method, value, summary(row()))
            self.assertIn("123456789012", text)
            self.assertNotIn("123456789012-", text)
            self.assertNotIn("None", text)

    def test_other_operation_only_users_are_hidden_in_both_formats(self):
        value = summary(row("other-only"), row("other2"), row("active-user", EC2=1))
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            rendered = self.render(method, report(), value)
            self.assertIn("active-user", rendered)
            self.assertNotIn("other-only", rendered)
            self.assertNotIn("other2", rendered)
        parsed = Tables()
        parsed.feed(self.render("render_resource_tables_html", report(), value))
        self.assertEqual(parsed.tables[0][1:], [["active-user", "0", "0", "0", "0", "0", "1", "0"]])

    def test_all_zero_accounts_retain_heading_status_and_resource_specific_message(self):
        reports = [report(), report("210987654321", "stage", complete=False)]
        values = [summary(row("zero-user")), summary(row("zero-role", "Role"))]
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            rendered = self.render(method, reports, *values)
            self.assertIn("123456789012-prod", rendered)
            self.assertIn("210987654321-stage", rendered)
            self.assertIn("查询状态：所列查询完成。", rendered)
            self.assertIn("查询状态：不完整", rendered)
            self.assertEqual(rendered.count("本账号在上述七类资源中无操作。"), 2)
            self.assertNotIn("无报告事件", rendered)
            self.assertNotIn("zero-user", rendered)
            self.assertNotIn("zero-role", rendered)
            self.assertNotIn("<table", rendered)
            self.assertNotIn("具体用户", rendered)

    def test_one_positive_column_is_enough_for_each_of_the_seven_columns(self):
        rows = [row("resource-" + str(index), **{column: 1}) for index, column in enumerate(RESOURCE_COLUMNS)]
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            rendered = self.render(method, report(), summary(row("all-zero"), *rows))
            self.assertNotIn("all-zero", rendered)
            for item in rows:
                self.assertIn(item["actor"], rendered)

    def test_all_matching_users_are_retained_without_truncation(self):
        rows = [row(f"user-{index:03}", EC2=1) for index in range(320)]
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            value = self.render(method, report(), summary(*rows))
            for item in rows:
                self.assertIn(item["actor"], value)
            self.assertNotIn("省略", value)
            self.assertNotIn("截断", value)

    def test_same_name_iam_user_and_other_identity_types_remain_distinct(self):
        rows = [row("Shared", kind, RDS=1) for kind in ("IAMUser", "Role", "Root", "AWSService",
                                                  "IdentityCenterUser", "FederatedUser", "Unknown")]
        html = self.render("render_resource_tables_html", report(), summary(*rows))
        parsed = Tables()
        parsed.feed(html)
        names = [cells[0] for cells in parsed.tables[0][1:]]
        self.assertEqual(names[0], "Shared")
        self.assertEqual(len(set(names)), len(rows))
        for name, item in zip(names[1:], rows[1:]):
            self.assertIn(item["identity_type"], name)
            self.assertIn("Shared", name)

    def test_zero_filter_treats_all_identity_types_the_same(self):
        kinds = ("IAMUser", "Role", "Root", "AWSService", "IdentityCenterUser", "FederatedUser", "Unknown")
        rows = [item for kind in kinds for item in (row("zero-" + kind, kind), row("active-" + kind, kind, VPC=2))]
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            rendered = self.render(method, report(), summary(*rows))
            for kind in kinds:
                self.assertNotIn("zero-" + kind, rendered)
                self.assertIn("active-" + kind, rendered)

    def test_case_distinct_users_are_not_merged(self):
        value = summary(row("Jeterry", EC2=1), row("jeterry", RDS=2))
        text = self.render("render_resource_tables_text", report(), value)
        self.assertIn("Jeterry | 0 | 0 | 0 | 0 | 0 | 1 | 0", text)
        self.assertIn("jeterry | 0 | 0 | 0 | 0 | 0 | 0 | 2", text)
        parsed = Tables()
        parsed.feed(self.render("render_resource_tables_html", report(), value))
        self.assertEqual(parsed.tables[0][1:], [["Jeterry", "0", "0", "0", "0", "0", "1", "0"],
                                               ["jeterry", "0", "0", "0", "0", "0", "0", "2"]])

    def test_failed_resource_attempts_remain_visible_using_the_real_summary(self):
        value = report()
        categories = ("新增", "修改", "删除", "Secrets Manager 查看", "登录信息", "其他操作")
        counts = {category: 2 if category == "修改" else 0 for category in categories}
        value["metadata"].update(total=2, failed_or_partial=2, counts=counts.copy())
        value["actors"] = [{"actor": "failed-only", "identity_type": "Role", "total": 2,
                             "failed": 2, "counts": counts.copy()}]
        value["actor_events"] = [{"actor": "failed-only", "identity_type": "Role", "source": "ec2.amazonaws.com",
                                   "event_name": "StopInstances", "category": "修改", "total": 2, "failed": 2}]
        before = deepcopy(value)
        aggregate = summarize_resource_operations(value)
        self.assertEqual(aggregate["rows"][0]["counts"]["EC2"], 2)
        for render in (mail_summary.render_resource_tables_text, mail_summary.render_resource_tables_html):
            rendered = render(value)
            self.assertIn("failed-only", rendered)
            self.assertNotIn("本账号在上述七类资源中无操作", rendered)
        self.assertEqual(value, before)
        self.assertEqual(summarize_resource_operations(value), aggregate)

    def test_filter_does_not_change_the_full_summary_or_report(self):
        value = report()
        aggregate = summary(row("hidden-user"), row("visible-user", EC2=3))
        before_report, before_summary = deepcopy(value), deepcopy(aggregate)
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            self.render(method, value, aggregate)
            self.assertEqual(value, before_report)
            self.assertEqual(aggregate, before_summary)

    def test_unavailable_is_not_silently_presented_as_zero_or_no_events(self):
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            value = self.render(method, report(), summary(available=False))
            self.assertIn("资源操作统计不可用", value)
            self.assertNotIn("本账号无报告事件", value)
            self.assertNotIn("本账号在上述七类资源中无操作", value)
            self.assertNotIn("<table", value)
            self.assertNotIn("0 | 0", value)

    def test_no_event_report_is_explicit_and_has_no_placeholder_user(self):
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            value = self.render(method, report(), summary())
            self.assertIn("本账号在上述七类资源中无操作。", value)
            self.assertNotIn("无报告事件", value)
            self.assertNotIn("资源操作统计不可用", value)
            self.assertNotIn("未知身份", value)

    def test_partial_status_is_scoped_to_its_own_account(self):
        reports = [report(), report("210987654321", "stage", complete=False)]
        text = self.render("render_resource_tables_text", reports, summary(row()), summary(row()))
        first, second = text.split("\n\n")
        self.assertNotIn("不完整", first)
        self.assertIn("210987654321-stage\n查询状态：不完整", second)
        html = self.render("render_resource_tables_html", reports, summary(row()), summary(row()))
        self.assertEqual(html.count("不完整"), 1)

    def test_html_escapes_account_tag_actor_and_unknown_type_and_has_no_resources(self):
        payload = '<script src="https://evil.invalid/a">&\'"</script>'
        value = self.render("render_resource_tables_html", report(payload, payload),
                            summary(row(payload, payload, EC2=1)))
        parsed = Tables()
        parsed.feed(value)
        self.assertNotIn("script", parsed.tags)
        self.assertNotIn("a", parsed.tags)
        self.assertNotIn("img", parsed.tags)
        self.assertTrue(all(key in {"style", "scope"} for key, _ in parsed.attributes))
        self.assertIn("&lt;script", value)
        self.assertIn("&amp;", value)
        self.assertIn("&quot;", value)
        self.assertIn("&#x27;", value)
        self.assertTrue(all("style" in dict(attrs) for tag, attrs in self._table_attributes(value)))

    @staticmethod
    def _table_attributes(value):
        result = []
        class Parser(HTMLParser):
            def handle_starttag(self, tag, attrs):
                if tag in {"table", "th", "td"}:
                    result.append((tag, attrs))
        Parser().feed(value)
        return result

    def test_plain_text_labels_cannot_create_columns_or_rows(self):
        value = self.render("render_resource_tables_text", report(), summary(row("a|b\nforged", EC2=2)))
        self.assertIn("a\\|b forged | 0 | 0 | 0 | 0 | 0 | 2 | 0", value)
        self.assertNotIn("\nforged", value)

    def test_renderer_never_reads_raw_events_or_unrelated_metadata(self):
        class NoRead:
            def __iter__(self):
                raise AssertionError("raw events accessed")
        value = report()
        value.update(events=NoRead(), request_parameters={"password": "NEVER_RENDER_REQUEST"})
        value["metadata"].update(errors=["NEVER_RENDER_PROVIDER"], account_name="NEVER_RENDER_NAME")
        meta = deepcopy(value["metadata"])
        for method in ("render_resource_tables_text", "render_resource_tables_html"):
            rendered = self.render(method, value, summary(row()))
            self.assertNotIn("NEVER_RENDER", rendered)
        self.assertEqual(value["metadata"], meta)

    def test_invalid_report_container_rejected(self):
        for reports in (None, [], "report", [None], [{}]):
            for render in (mail_summary.render_resource_tables_text, mail_summary.render_resource_tables_html):
                with self.subTest(reports=reports, render=render.__name__):
                    with self.assertRaises(ValueError):
                        render(reports)


if __name__ == "__main__":
    unittest.main()
