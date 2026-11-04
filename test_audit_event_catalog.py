import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit_event_catalog as catalog


class EventCatalogTests(unittest.TestCase):
    def tearDown(self):
        catalog._catalog.cache_clear()

    def event(self, source="monitoring.amazonaws.com", name="PutDashboard"):
        return {"eventSource": source, "eventName": name}

    def test_put_dashboard_preserves_create_and_overwrite_meaning(self):
        result = catalog.translate_event(self.event())
        self.assertEqual(result["event_label"], "保存 CloudWatch 监控仪表盘配置（新建或整体覆盖）")
        self.assertEqual(result["translation_status"], "reviewed")
        self.assertEqual(result["operation_reference"], "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutDashboard.html")

    def test_service_scoped_and_china_partition(self):
        expected = catalog.translate_event(self.event())
        self.assertEqual(expected, catalog.translate_event(self.event("monitoring.amazonaws.com.cn")))
        for source in ("s3.amazonaws.com", "monitoring.amazonaws.com.evil.test", "monitoring.amazon.com"):
            self.assertEqual(catalog.translate_event(self.event(source))["translation_status"], "untranslated")

    def test_existing_labels_are_scoped_to_actual_services(self):
        self.assertEqual(catalog.translate_event(self.event("ec2.amazonaws.com", "ModifyInstanceAttribute"))["event_label"], "修改 EC2 实例属性")
        self.assertEqual(catalog.translate_event(self.event("secretsmanager.amazonaws.com", "GetSecretValue"))["translation_status"], "reviewed")
        self.assertEqual(catalog.translate_event(self.event("signin.amazonaws.com", "ConsoleLogin"))["event_label"], "登录 AWS 控制台")
        self.assertEqual(catalog.translate_event(self.event("ec2.amazonaws.com", "GetSecretValue"))["translation_status"], "untranslated")

    def test_unknown_and_permission_only_actions_stay_untranslated(self):
        for source, name in (("ec2.amazonaws.com", "FutureNewOperation"), ("iam.amazonaws.com", "PassRole")):
            result = catalog.translate_event(self.event(source, name))
            self.assertEqual(result["translation_status"], "untranslated")
            self.assertIn(source + " / " + name, result["event_label"])

    def test_malformed_catalog_does_not_break_reviewed_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for raw in ("[]", "not json", '{"schema_version":1,"entries":{}}'):
                path.write_text(raw, encoding="utf-8")
                with patch.object(catalog, "CATALOG_PATH", path):
                    catalog._catalog.cache_clear()
                    result = catalog.translate_event(self.event("kms.amazonaws.com", "Decrypt"))
                    self.assertEqual(result["translation_status"], "reviewed")
            broken = {"schema_version": 1, "entries": {"monitoring.amazonaws.com": {
                "PutDashboard": {"translation_status": [], "event_label": "wrong"}}}}
            path.write_text(json.dumps(broken), encoding="utf-8")
            with patch.object(catalog, "CATALOG_PATH", path):
                catalog._catalog.cache_clear()
                self.assertEqual(catalog.translate_event(self.event())["translation_status"], "untranslated")

    def test_snapshot_has_sources_and_valid_metadata(self):
        data = json.loads(catalog.CATALOG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], 1)
        self.assertGreaterEqual(data["statistics"]["reviewed"], 100)
        records = 0
        for source, operations in data["entries"].items():
            self.assertRegex(source, r"^[a-z0-9-]+\.amazonaws\.com$")
            for name, record in operations.items():
                records += 1
                self.assertIsNotNone(catalog._valid_record(record), (source, name))
                self.assertNotIn("category", record)
                if record["translation_status"] == "official_zh":
                    self.assertEqual(record["sdk_operation"], name)
                    self.assertIn("/zh_cn/service-authorization/", record["operation_reference"])
        self.assertEqual(records, data["statistics"]["event_labels"])

    def test_returned_record_is_defensive_copy_and_needs_no_sdk_client(self):
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            first = catalog.translate_event(self.event())
            first["event_label"] = "changed"
            self.assertNotEqual(first, catalog.translate_event(self.event()))


class CatalogBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("build_event_catalog", Path(__file__).parent / "tools" / "build_event_catalog.py")
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)

    def test_permission_boilerplate_removal_is_not_machine_translation(self):
        self.assertEqual(self.builder.short_label("授予权限以创建测试资源。"), "创建测试资源")
        self.assertEqual(self.builder.short_label("授予删除测试资源的权限。"), "删除测试资源")
        self.assertEqual(self.builder.short_label("授予权限，以将 EBS 卷附加到实例。"), "将 EBS 卷附加到实例")
        self.assertEqual(self.builder.short_label("授予创建客户网关的权限，该网关提供连接信息。"), "创建客户网关，该网关提供连接信息")
        self.assertEqual(self.builder.short_label("授予创建权限 CloudWatch 仪表盘"), "创建 CloudWatch 仪表盘")
        self.assertEqual(self.builder.short_label("授予创建网络接口权限的权限。"), "创建网络接口权限")
        self.assertEqual(self.builder.short_label("Grants permission to create a resource"), "")
        self.assertEqual(self.builder.short_label("授予权限以" + "测试" * 100), "")

    def test_chinese_actions_require_sdk_operation_and_official_page(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "list_iam.html"
            html = ('<link rel="canonical" href="' + self.builder.DOC_ROOT + path.name + '">'
                    '<table><tr><td><span id="iam-CreateUser"><a>CreateUser</a></span></td><td>授予权限以创建 IAM 用户。</td><td>Write</td></tr>'
                    '<tr><td>PassRole</td><td>授予权限以将角色传递给服务。</td><td>Write</td></tr></table>')
            path.write_text(html, encoding="utf-8")
            models = [{"sdk": "iam", "source": "iam.amazonaws.com", "prefixes": {"iam"},
                       "display": "AWS IAM", "operations": {"CreateUser"}}]
            records, status = self.builder.parse_official_page(path, models)
            self.assertEqual(status, "matched")
            self.assertEqual([item[1] for item in records], ["CreateUser"])
            self.assertEqual(records[0][2]["translation_status"], "official_zh")
            self.assertTrue(records[0][2]["operation_reference"].endswith("#iam-CreateUser"))
            path.write_text(html.replace(self.builder.DOC_ROOT, "https://evil.example/"), encoding="utf-8")
            self.assertEqual(self.builder.parse_official_page(path, models)[0], [])

    def test_sdk_name_is_prioritized_over_shared_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "list_rds.html"
            path.write_text('<link rel="canonical" href="' + self.builder.DOC_ROOT + path.name + '">'
                            '<table><tr><td>CreateDBCluster</td><td>授予权限以创建数据库集群。</td><td>Write</td></tr></table>', encoding="utf-8")
            models = [{"sdk": sdk, "source": "rds.amazonaws.com", "prefixes": {"rds", sdk},
                       "display": display, "operations": {"CreateDBCluster"}}
                      for sdk, display in (("docdb", "Amazon DocDB"), ("rds", "Amazon RDS"))]
            records, _ = self.builder.parse_official_page(path, models)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0][2]["sdk_service"], "rds")

    def test_missing_cache_never_replaces_catalog_with_reviewed_only(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "拒绝覆盖"):
                self.builder.build(Path(directory))
            with self.assertRaisesRegex(ValueError, "拒绝覆盖"):
                self.builder.build(Path(directory) / "missing")


if __name__ == "__main__":
    unittest.main()
