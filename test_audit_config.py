"""Configuration boundaries, using fictional credentials only."""
import json
from pathlib import Path
import tempfile
import unittest

from audit_config import load_config
from lark_notify import DEFAULT_REPORT_URL


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aws-multi-config-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "aws-audit-config.json"
        self.account = {"NAME": "demo", "ACCOUNT_ID": "123456789012", "AWS_PROFILE": "audit"}
        self.raw = {"ACCOUNTS": [self.account]}

    def load(self, raw=None, **options):
        self.path.write_text(json.dumps(self.raw if raw is None else raw), encoding="utf-8")
        return load_config(self.path, **options)

    def test_paths_defaults_and_profile(self):
        config = self.load()
        self.assertEqual(config["OUTPUT_DIRECTORY"], str(self.root / "reports"))
        self.assertEqual(config["PUBLISH_DIRECTORY"], str(self.root / "index"))
        self.assertEqual(config["REPORT_URL"], DEFAULT_REPORT_URL)
        self.assertTrue(config["HTML_REPORT_ENABLED"])
        self.assertFalse(config["LARK_REPORT_ENABLED"])
        self.assertEqual(config["STATE_DIRECTORY"], str(self.root / ".state"))
        self.assertEqual(config["ACCOUNTS"][0]["AWS_PROFILE"], "audit")
        self.assertEqual(config["ACCOUNTS"][0]["TAG"], "")
        self.assertEqual(config["TIMEZONE"], "Asia/Shanghai")
        self.assertEqual(config["DAILY_MAIL_TIME"], "10:05")
        self.assertEqual(config["REPORT_START_TIME"], "10:00")
        self.assertEqual(config["REPORT_END_TIME"], "10:00")

    def test_time_fields_are_configurable_and_invalid_values_never_echo(self):
        config = self.load({**self.raw, "DAILY_MAIL_TIME": "11:20", "REPORT_START_TIME": "09:15", "REPORT_END_TIME": "10:30"})
        self.assertEqual(config["DAILY_MAIL_TIME"], "11:20")
        for key in ("DAILY_MAIL_TIME", "REPORT_START_TIME", "REPORT_END_TIME"):
            for value in ("FAKE_SECRET_INVALID", "24:00", "8:01", "10:60", True):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError) as caught:
                    self.load({**self.raw, key: value})
                self.assertNotIn("FAKE_SECRET_INVALID", str(caught.exception))

    def test_daily_mail_cannot_start_before_report_window_has_ended(self):
        with self.assertRaisesRegex(ValueError, "DAILY_MAIL_TIME"):
            self.load({**self.raw, "DAILY_MAIL_TIME": "09:59", "REPORT_END_TIME": "10:00"})
        config = self.load({**self.raw, "DAILY_MAIL_TIME": "00:05", "REPORT_START_TIME": "00:00", "REPORT_END_TIME": "00:00"})
        self.assertEqual(config["REPORT_END_TIME"], "00:00")

    def test_template_is_jsonc_with_seven_unique_accounts_and_no_secrets(self):
        config = load_config(Path(__file__).parent / "aws-audit-config.example.json")
        self.assertEqual(len(config["ACCOUNTS"]), 7)
        self.assertEqual(sum(a["ENABLED"] for a in config["ACCOUNTS"]), 1)
        self.assertFalse(config["SMTP_AUTH_CODE"])
        self.assertFalse(config["LARK_WEBHOOK_URL"])
        self.assertTrue(all(not a["AWS_SECRET_ACCESS_KEY"] for a in config["ACCOUNTS"]))
        self.assertTrue(all(a["TAG"] for a in config["ACCOUNTS"]))
        self.assertEqual(Path(config["PUBLISH_DIRECTORY"]), Path(__file__).parent / "index")
        self.assertEqual(config["REPORT_URL"], DEFAULT_REPORT_URL)
        self.assertTrue(config["HTML_REPORT_ENABLED"])
        self.assertFalse(config["LARK_REPORT_ENABLED"])

    def test_account_tag_supports_chinese_and_missing_tag_does_not_modify_file(self):
        config = self.load({"ACCOUNTS": [{**self.account, "TAG": "  prod-支付  "}]})
        self.assertEqual(config["ACCOUNTS"][0]["TAG"], "prod-支付")
        self.assertEqual(config["ACCOUNTS"][0]["NAME"], "demo")
        self.load()
        original = self.path.read_bytes()
        self.assertEqual(load_config(self.path)["ACCOUNTS"][0]["TAG"], "")
        self.assertEqual(self.path.read_bytes(), original)
        self.assertNotIn("TAG", json.loads(original)["ACCOUNTS"][0])

    def test_account_tag_length_type_and_control_characters(self):
        self.assertEqual(self.load({"ACCOUNTS": [{**self.account, "TAG": "中" * 120}]})["ACCOUNTS"][0]["TAG"], "中" * 120)
        for tag in ("中" * 121, None, 1, [], "bad\nFAKE_SECRET", "bad\x00FAKE_SECRET", "bad\u0085FAKE_SECRET", "bad\u202eFAKE_SECRET", "\u0085FAKE_SECRET", "FAKE_SECRET\u2028"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "TAG") as caught:
                self.load({"ACCOUNTS": [{**self.account, "TAG": tag}]})
            self.assertNotIn("FAKE_SECRET", str(caught.exception))

    def test_blank_smtp_only_allowed_when_not_requiring_delivery(self):
        self.load()
        with self.assertRaisesRegex(ValueError, "SMTP_"):
            self.load(require_mail=True)

    def test_multiple_accounts_normalized_keys_and_region_lists(self):
        second = {"NAME": "second", "ACCOUNT_ID": "123456789013", "AWS_ACCESS_KEY_ID": "FAKE_ID",
                  "AWS_SECRET_ACCESS_KEY": "FAKE_SECRET", "REGIONS": "us-east-1,eu-north-1"}
        config = self.load({"ACCOUNTS": [self.account, second]})
        self.assertEqual(config["ACCOUNTS"][1]["REGIONS"], ["eu-north-1", "us-east-1"])

    def test_conflicting_or_incomplete_credentials_rejected_without_echo(self):
        for patch in ({"AWS_ACCESS_KEY_ID": "FAKE_PRIVATE_VALUE"},
                      {"AWS_ACCESS_KEY_ID": "FAKE_ID", "AWS_SECRET_ACCESS_KEY": "FAKE_PRIVATE_VALUE"},
                      {"AWS_SESSION_TOKEN": "FAKE_PRIVATE_VALUE"}):
            with self.subTest(patch=patch), self.assertRaises(ValueError) as caught:
                self.load({"ACCOUNTS": [{**self.account, **patch}]})
            self.assertNotIn("FAKE_PRIVATE_VALUE", str(caught.exception))

    def test_duplicate_account_id_and_casefold_name_rejected(self):
        for second in ({**self.account, "NAME": "other"},
                       {**self.account, "NAME": "DEMO", "ACCOUNT_ID": "123456789013"}):
            with self.subTest(second=second), self.assertRaises(ValueError):
                self.load({"ACCOUNTS": [self.account, second]})

    def test_account_id_cannot_inject_paths(self):
        with self.assertRaises(ValueError):
            self.load({"ACCOUNTS": [{**self.account, "ACCOUNT_ID": "../secrets"}]})

    def test_no_enabled_accounts_and_non_boolean_enabled_rejected(self):
        for enabled in (False, "true", 1):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                self.load({"ACCOUNTS": [{**self.account, "ENABLED": enabled}]})

    def test_aws_invalid_regions_and_concurrency_rejected(self):
        for regions in ([], [""], [123], "ALL", "badregion"):
            with self.subTest(regions=regions), self.assertRaises(ValueError):
                self.load({"ACCOUNTS": [{**self.account, "REGIONS": regions}]})
        for concurrency in (0, True, 33, "7"):
            with self.subTest(concurrency=concurrency), self.assertRaises(ValueError):
                self.load({**self.raw, "ACCOUNT_CONCURRENCY": concurrency})

    def test_report_and_state_paths_protect_private_config(self):
        for patch in ({"OUTPUT_DIRECTORY": "."}, {"STATE_DIRECTORY": "."},
                      {"OUTPUT_DIRECTORY": self.path.name}, {"STATE_DIRECTORY": self.path.name},
                      {"STATE_DIRECTORY": "reports"}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                self.load({**self.raw, **patch})

    def test_fixed_beijing_timezone(self):
        with self.assertRaises(ValueError):
            self.load({**self.raw, "TIMEZONE": "UTC"})

    def test_publication_fields_resolve_existing_config_without_rewriting_it(self):
        config = self.load({**self.raw, "PUBLISH_DIRECTORY": "public/latest", "REPORT_URL": "https://audit.example.com/audit/"})
        before = self.path.read_bytes()
        self.assertEqual(config["PUBLISH_DIRECTORY"], str(self.root / "public" / "latest"))
        self.assertEqual(config["REPORT_URL"], "https://audit.example.com/audit/")
        self.assertEqual(load_config(self.path), config)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse((self.root / "public").exists())
        self.load()
        before = self.path.read_bytes()
        load_config(self.path)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertNotIn("PUBLISH_DIRECTORY", json.loads(before))

    def test_publication_directory_cannot_expose_config_reports_or_state(self):
        for patch in ({"PUBLISH_DIRECTORY": "."}, {"PUBLISH_DIRECTORY": self.path.name},
                      {"PUBLISH_DIRECTORY": self.path.name + "/public"},
                      {"PUBLISH_DIRECTORY": "reports"}, {"PUBLISH_DIRECTORY": ".state"},
                      {"PUBLISH_DIRECTORY": "reports/public"}, {"PUBLISH_DIRECTORY": ".state/public"},
                      {"OUTPUT_DIRECTORY": "index/reports"}, {"STATE_DIRECTORY": "index/.state"}):
            with self.subTest(patch=patch), self.assertRaisesRegex(ValueError, "PUBLISH_DIRECTORY"):
                self.load({**self.raw, **patch})
        for destination in ("/", "/usr/local", "/etc/audit", "/root/.aws/public", "/safe/../etc/public"):
            with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, "PUBLISH_DIRECTORY"):
                self.load({**self.raw, "PUBLISH_DIRECTORY": destination})

    def test_publication_directory_rejects_symlinks_and_regular_files(self):
        target = self.root / "public-target"
        target.mkdir()
        link = self.root / "public-link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("platform cannot create test directory symlinks")
        for destination in (str(link), str(link / "child")):
            with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, "PUBLISH_DIRECTORY"):
                self.load({**self.raw, "PUBLISH_DIRECTORY": destination})

    def test_publication_directory_rejects_regular_files_and_invalid_values(self):
        file = self.root / "ordinary-file"
        file.write_text("existing", encoding="utf-8")
        for value in (str(file), [], None, "", "public\nFAKE_SECRET"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "PUBLISH_DIRECTORY") as caught:
                self.load({**self.raw, "PUBLISH_DIRECTORY": value})
            self.assertNotIn("FAKE_SECRET", str(caught.exception))

    def test_report_urls_are_plain_http_links_and_never_echo_private_values(self):
        self.assertEqual(self.load({**self.raw, "REPORT_URL": ""})["REPORT_URL"], "")
        self.assertEqual(self.load({**self.raw, "REPORT_URL": "http://audit.example.com:8080/audit/"})["REPORT_URL"],
                         "http://audit.example.com:8080/audit/")
        for value in (None, [], "file:///FAKE_SECRET", "https://user:FAKE_SECRET@example.com/audit/",
                      "https://example.com/audit/?token=FAKE_SECRET", "https://example.com/audit/#FAKE_SECRET",
                      "https://example.com/{FAKE_SECRET}", "https://example.com/FAKE_SECRET\n",
                      "https://example.com/FAKE_SECRET\u200b", "https://example.com:bad/FAKE_SECRET"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "REPORT_URL") as caught:
                self.load({**self.raw, "REPORT_URL": value})
            self.assertNotIn("FAKE_SECRET", str(caught.exception))

    def test_daily_lark_is_independent_and_requires_a_published_report(self):
        robot = "https://open.larksuite.com/open-apis/bot/v2/hook/FICTIONAL_TEST_ROBOT"
        config = self.load({**self.raw, "LARK_REPORT_ENABLED": True, "LARK_WEBHOOK_URL": robot})
        self.assertTrue(config["LARK_REPORT_ENABLED"])
        self.assertFalse(config["LARK_ALERTS_ENABLED"])
        config = self.load({**self.raw, "LARK_ALERTS_ENABLED": True, "LARK_WEBHOOK_URL": robot})
        self.assertTrue(config["LARK_ALERTS_ENABLED"])
        self.assertFalse(config["LARK_REPORT_ENABLED"])
        for patch in ({"LARK_REPORT_ENABLED": True},
                      {"LARK_REPORT_ENABLED": True, "LARK_WEBHOOK_URL": robot, "HTML_REPORT_ENABLED": False},
                      {"LARK_REPORT_ENABLED": True, "LARK_WEBHOOK_URL": robot, "REPORT_URL": ""}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                self.load({**self.raw, **patch})
        for key in ("HTML_REPORT_ENABLED", "LARK_REPORT_ENABLED"):
            for value in (1, "true", None):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, key):
                    self.load({**self.raw, key: value})
        self.assertFalse(self.load({**self.raw, "HTML_REPORT_ENABLED": False})["HTML_REPORT_ENABLED"])

    def test_enabled_lark_requires_valid_robot_but_disabled_may_be_blank(self):
        with self.assertRaisesRegex(ValueError, "LARK_WEBHOOK_URL"):
            self.load({**self.raw, "LARK_ALERTS_ENABLED": True})
        with self.assertRaises(ValueError) as caught:
            self.load({**self.raw, "LARK_WEBHOOK_URL": "https://untrusted.example/FAKE_SECRET"})
        self.assertNotIn("FAKE_SECRET", str(caught.exception))

    def test_jsonc_url_strings_and_duplicate_fields(self):
        self.path.write_text('// comment\n{"ACCOUNTS":'+json.dumps([self.account])+', "REPORT_URL":"https://example.com/audit/"}', encoding="utf-8")
        self.assertEqual(load_config(self.path)["REPORT_URL"], "https://example.com/audit/")
        self.path.write_text('{"ACCOUNTS":[],"ACCOUNTS":[]}', encoding="utf-8")
        with self.assertRaises(ValueError):
            load_config(self.path)


if __name__ == "__main__":
    unittest.main()
