"""Configuration boundaries, using fictional credentials only."""
import json
from pathlib import Path
import tempfile
import unittest

from audit_config import load_config


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
        self.assertEqual(config["STATE_DIRECTORY"], str(self.root / ".state"))
        self.assertEqual(config["ACCOUNTS"][0]["AWS_PROFILE"], "audit")
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

    def test_unified_config_private_paths_cannot_be_published(self):
        for patch in ({"PUBLISH_DIRECTORY": "."}, {"OUTPUT_DIRECTORY": "index/reports"},
                      {"STATE_DIRECTORY": "index/.state"}, {"STATE_DIRECTORY": "reports"}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                self.load({**self.raw, **patch})

    def test_fixed_beijing_timezone_and_https_details(self):
        for patch in ({"TIMEZONE": "UTC"}, {"REPORT_URL": "http://example.com/audit/"}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                self.load({**self.raw, **patch})

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
