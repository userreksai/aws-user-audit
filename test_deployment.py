"""Offline deployment checks; no AWS, SMTP, Lark, Nginx, or systemd calls."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, call, patch
from zoneinfo import ZoneInfo

from deploy import install_support, run_scheduled
import audit_config

try:
    import boto3
except ImportError:
    boto3 = None

INSTALL = "/usr/local/aws-user-audit"


class SystemdUnitRenderTests(unittest.TestCase):
    def test_default_timer_runs_at_0801_beijing_and_catches_up(self):
        units = install_support.render_units()
        self.assertEqual(set(units), {"aws-user-audit.service", "aws-user-audit.timer"})
        timer = units["aws-user-audit.timer"]
        self.assertRegex(timer, r"(?m)^OnCalendar=.*08:01(?::00)?\s+Asia/Shanghai\s*$")
        self.assertRegex(timer, r"(?m)^Persistent=true\s*$")
        self.assertIn("aws-user-audit.service", timer)
        self.assertNotIn("UTC+8", timer)

    def test_service_uses_private_config_and_has_no_legacy_lark_or_password_options(self):
        service = install_support.render_units()["aws-user-audit.service"]
        self.assertRegex(service, r"(?m)^Type=oneshot\s*$")
        self.assertIn(INSTALL + "/.venv/bin/python", service)
        self.assertIn(INSTALL + "/deploy/run_scheduled.py", service)
        self.assertIn(INSTALL + "/aws-audit-config.json", service)
        self.assertIn("\nWorkingDirectory=" + INSTALL + "\n", service)
        self.assertRegex(service, r"(?m)^UMask=0*77\s*$")
        for obsolete in ("--profile", "--lark-config", "--send-lark", "--auth-state-dir", "audit_web.py",
                         "aws-audit-web.service", "SuccessExitStatus=2", "SuccessExitStatus=3", "/usr/local/shenji"):
            self.assertNotIn(obsolete, service)

    def test_custom_install_and_config_paths_are_explicit(self):
        service = install_support.render_units(install_dir="/opt/cloud-audit", publish_dir="/srv/www/audit",
                                               config_path="/etc/aws-user-audit/private.json")["aws-user-audit.service"]
        for expected in ("/opt/cloud-audit/.venv/bin/python", "/opt/cloud-audit/deploy/run_scheduled.py",
                         "/etc/aws-user-audit/private.json"):
            self.assertIn(expected, service)
        self.assertNotIn(INSTALL, service)
        self.assertNotIn("open.larksuite.com", service)

    def test_paths_reject_unit_injection_and_system_parents(self):
        for install_dir in ("/", "/usr/local", "/opt/audit/../another", "/opt/audit\nExecStart=unsafe"):
            with self.subTest(install_dir=install_dir), self.assertRaises(ValueError):
                install_support.render_units(install_dir=install_dir)

    def test_public_webroot_cannot_contain_code_reports_or_private_config(self):
        for arguments in ({"publish_dir": INSTALL}, {"publish_dir": INSTALL + "/reports"},
                          {"config_path": INSTALL + "/index/aws-audit-config.json"}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                install_support.render_units(**arguments)


class LocalPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="audit-preflight-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "aws-audit-config.json"
        self.path.write_text("{}", encoding="utf-8")
        self.path.chmod(0o600)
        self.config = {"AUTO_MAIL_MAX_PER_DAY": 1, "PUBLISH_DIRECTORY": INSTALL + "/index",
                       "ACCOUNTS": [{"AWS_PROFILE": "audit", "ENABLED": True},
                                    {"AWS_PROFILE": "audit", "ENABLED": True},
                                    {"AWS_PROFILE": "ignored", "ENABLED": False}]}

    def isolated_environment(self):
        return {"LARK_WEBHOOK_URL": "TEST_STALE_OVERRIDE", "LARK_SIGNING_SECRET": "TEST_STALE_SECRET",
                "AWS_CONFIG_FILE": "TEST_ALTERNATIVE_CONFIG_NOT_READ",
                "AWS_SHARED_CREDENTIALS_FILE": "TEST_ALTERNATIVE_CREDENTIALS_NOT_READ",
                "AWS_PROFILE": "TEST_ALTERNATIVE_PROFILE", "AWS_DEFAULT_PROFILE": "TEST_DEFAULT_PROFILE",
                "AWS_ACCESS_KEY_ID": "TEST_TEMPORARY_KEY", "AWS_SECRET_ACCESS_KEY": "TEST_TEMPORARY_SECRET",
                "AWS_SESSION_TOKEN": "TEST_TEMPORARY_SESSION"}

    @unittest.skipUnless(boto3 is not None, "boto3 unavailable")
    def test_local_only_preflight_profiles_config_and_environment_restoration(self):
        fake_session = Mock()
        fake_session.available_profiles = ["audit"]
        overrides = self.isolated_environment()

        def read_config(path, *, require_mail):
            self.assertEqual(Path(path), self.path)
            for key in overrides:
                self.assertNotIn(key, os.environ)
            self.assertEqual(os.environ["HOME"], "/root")
            return self.config

        with patch.dict(os.environ, {**overrides, "HOME": "TEST_HOME", "AWS_REGION": "eu-north-1"}), \
             patch.object(audit_config, "load_config", side_effect=read_config) as load, \
             patch.object(boto3, "Session", return_value=fake_session) as session:
            install_support.local_preflight(INSTALL, self.path, INSTALL + "/index")
            for key, value in overrides.items():
                self.assertEqual(os.environ[key], value)
            self.assertEqual(os.environ["HOME"], "TEST_HOME")
            self.assertEqual(os.environ["AWS_REGION"], "eu-north-1")
        self.assertEqual(load.call_args_list, [call(self.path, require_mail=False), call(self.path, require_mail=True)])
        session.assert_called_once_with(profile_name="audit")
        fake_session.client.assert_not_called()
        fake_session.get_credentials.assert_not_called()

    @unittest.skipUnless(boto3 is not None, "boto3 unavailable")
    def test_key_accounts_need_no_root_profile_and_zero_quota_needs_no_smtp(self):
        self.config.update(AUTO_MAIL_MAX_PER_DAY=0, ACCOUNTS=[{"ENABLED": True, "AWS_PROFILE": "",
                                  "AWS_ACCESS_KEY_ID": "TEST_KEY", "AWS_SECRET_ACCESS_KEY": "TEST_SECRET"}])
        with patch.object(audit_config, "load_config", return_value=self.config) as load, \
             patch.object(boto3, "Session") as session:
            result = install_support.local_preflight(INSTALL, self.path, INSTALL + "/index")
        self.assertEqual(result, self.config)
        load.assert_called_once_with(self.path, require_mail=False)
        session.assert_not_called()

    @unittest.skipUnless(boto3 is not None, "boto3 unavailable")
    def test_failure_restores_overrides_and_missing_home(self):
        overrides = self.isolated_environment()
        fake_session = Mock(available_profiles=[])
        for stage in ("config", "profile"):
            with self.subTest(stage=stage), patch.dict(os.environ, overrides, clear=True), \
                 patch.object(audit_config, "load_config", side_effect=ValueError("TEST_CONFIG") if stage == "config" else None,
                              return_value=self.config), \
                 patch.object(boto3, "Session", return_value=fake_session) as session:
                with self.assertRaises(ValueError):
                    install_support.local_preflight(INSTALL, self.path)
                self.assertEqual(dict(os.environ), overrides)
                fake_session.client.assert_not_called()
                fake_session.get_credentials.assert_not_called()
                if stage == "config":
                    session.assert_not_called()

    def test_nginx_publish_mismatch_stops_before_credentials(self):
        with patch.object(audit_config, "load_config", return_value=self.config), self.assertRaisesRegex(ValueError, "PUBLISH_DIRECTORY"):
            install_support.local_preflight(INSTALL, self.path, "/srv/other/index")

    def test_missing_configuration_fails_before_loading_anything(self):
        with patch.object(audit_config, "load_config") as load, self.assertRaises(ValueError):
            install_support.local_preflight(INSTALL, self.root / "missing.json")
        load.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX private file permissions")
    def test_world_readable_private_config_is_rejected(self):
        self.path.chmod(0o644)
        with patch.object(audit_config, "load_config") as load, self.assertRaises(ValueError):
            install_support.local_preflight(INSTALL, self.path)
        load.assert_not_called()

    def test_real_json_with_enabled_key_account_is_checked_without_network(self):
        self.path.write_text(json.dumps({"AUTO_MAIL_MAX_PER_DAY": 0, "ACCOUNTS": [{"NAME": "test",
            "ACCOUNT_ID": "123456789012", "AWS_ACCESS_KEY_ID": "TEST_KEY", "AWS_SECRET_ACCESS_KEY": "TEST_SECRET"}]}), encoding="utf-8")
        config = install_support.local_preflight(INSTALL, self.path)
        self.assertEqual(config["PUBLISH_DIRECTORY"], str((self.root / "index").resolve()))
        self.assertEqual(config["ACCOUNTS"][0]["AWS_PROFILE"], "")


class ScheduledReportDateTests(unittest.TestCase):
    def test_beijing_boundary_before_eight_and_at_eight(self):
        for moment, expected in ((datetime(2026, 10, 27, 23, 59, 59, tzinfo=timezone.utc), "2026-10-27"),
                                 (datetime(2026, 10, 28, 0, 0, tzinfo=timezone.utc), "2026-10-28"),
                                 (datetime(2026, 10, 28, 0, 1, tzinfo=timezone.utc), "2026-10-28")):
            with self.subTest(moment=moment):
                self.assertEqual(run_scheduled.report_date(moment), expected)

    def test_catchup_uses_latest_finished_beijing_window_instead_of_host_day(self):
        self.assertEqual(run_scheduled.report_date(datetime(2026, 10, 27, 18, tzinfo=timezone.utc)), "2026-10-27")
        self.assertEqual(run_scheduled.report_date(datetime(2026, 10, 27, 20, tzinfo=ZoneInfo("America/New_York"))), "2026-10-28")
        self.assertEqual(run_scheduled.report_date(datetime(2027, 1, 1, 7, 59, tzinfo=ZoneInfo("Asia/Shanghai"))), "2026-12-31")

    def test_naive_clock_is_rejected(self):
        with self.assertRaises(ValueError):
            run_scheduled.report_date(datetime(2026, 10, 28, 8, 1))


class ScheduledCommandTests(unittest.TestCase):
    def test_multi_entry_point_with_pdf_mail_and_no_normal_lark(self):
        command = run_scheduled.build_command(INSTALL, INSTALL + "/aws-audit-config.json",
                                             now=datetime(2026, 10, 28, 0, 1, tzinfo=timezone.utc))
        self.assertEqual(command, [INSTALL + "/.venv/bin/python", INSTALL + "/aws_audit_multi.py", "--config",
                                 INSTALL + "/aws-audit-config.json", "--date", "2026-10-28", "--send-mail", "--automatic-mail"])
        self.assertNotIn("--send-lark", command)
        self.assertNotIn("--force-resend", command)

    def test_runner_propagates_status_and_isolates_old_credential_overrides(self):
        overrides = LocalPreflightTests().isolated_environment()
        for code in (0, 1, 2, 3, 4):
            with self.subTest(code=code), patch.dict(os.environ, overrides), \
                 patch.object(run_scheduled.subprocess, "run", return_value=Mock(returncode=code)) as process, \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(run_scheduled.main(["--date", "2026-10-28"]), code)
                child = process.call_args.kwargs["env"]
                for key, value in overrides.items():
                    self.assertNotIn(key, child)
                    self.assertEqual(os.environ[key], value)
                self.assertEqual(process.call_args.kwargs["cwd"], INSTALL)
                self.assertFalse(process.call_args.kwargs["check"])
                self.assertFalse(process.call_args.kwargs.get("shell", False))
                self.assertEqual(process.call_args.args[0][process.call_args.args[0].index("--date") + 1], "2026-10-28")

    def test_custom_paths_are_passed_as_separate_arguments_without_shell(self):
        with patch.object(run_scheduled.subprocess, "run", return_value=Mock(returncode=0)) as process, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(run_scheduled.main(["--install-dir", "/opt/audit", "--config", "/etc/audit/private.json",
                                                 "--date", "2026-10-28"]), 0)
        command = process.call_args.args[0]
        self.assertEqual(command[0], "/opt/audit/.venv/bin/python")
        self.assertEqual(command[command.index("--config") + 1], "/etc/audit/private.json")

    def test_invalid_manual_date_does_not_spawn(self):
        with patch.object(run_scheduled.subprocess, "run") as process, redirect_stderr(io.StringIO()):
            self.assertEqual(run_scheduled.main(["--date", "2026-02-30"]), 1)
        process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
