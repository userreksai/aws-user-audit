"""Offline deployment checks; never run AWS, Lark, Nginx, or systemd."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from zoneinfo import ZoneInfo

from deploy import install_support, run_scheduled

try:
    import boto3
except ImportError:
    boto3 = None


class SystemdUnitRenderTests(unittest.TestCase):
    def test_default_timer_runs_at_0801_beijing_and_catches_up_after_downtime(self):
        units = install_support.render_units()
        self.assertEqual(set(units), {"aws-user-audit.service", "aws-user-audit.timer"})
        timer = units["aws-user-audit.timer"]
        self.assertRegex(timer, r"(?m)^OnCalendar=.*08:01(?::00)?\s+Asia/Shanghai\s*$")
        self.assertRegex(timer, r"(?m)^Persistent=true\s*$")
        self.assertIn("aws-user-audit.service", timer)
        self.assertNotIn("UTC+8", timer)

    def test_service_uses_scheduled_runner_and_keeps_private_state_out_of_public_directory(self):
        service = install_support.render_units()["aws-user-audit.service"]
        self.assertRegex(service, r"(?m)^Type=oneshot\s*$")
        self.assertIn("/usr/local/shenji/.venv/bin/python", service)
        self.assertIn("/usr/local/shenji/deploy/run_scheduled.py", service)
        self.assertIn("/usr/local/shenji/index", service)
        self.assertIn("/usr/local/shenji/lark-config.json", service)
        self.assertRegex(service, r"(?m)^UMask=0*77\s*$")
        self.assertNotIn("--auth-state-dir", service)
        self.assertNotIn("audit_web.py", service)
        self.assertNotIn("aws-audit-web.service", service)
        self.assertNotIn("SuccessExitStatus=2", service)
        self.assertNotIn("SuccessExitStatus=3", service)

    def test_rendered_units_use_explicit_custom_paths_profile_and_report_url(self):
        units = install_support.render_units(
            install_dir="/opt/cloud-audit", publish_dir="/srv/www/audit",
            profile="readonly-audit", lark_config="/etc/aws-user-audit/lark.json",
            report_url="https://reports.example.invalid/audit/",
        )
        service = units["aws-user-audit.service"]
        for expected in ("/opt/cloud-audit/.venv/bin/python", "/opt/cloud-audit/deploy/run_scheduled.py",
                         "/srv/www/audit", "readonly-audit", "/etc/aws-user-audit/lark.json",
                         "https://reports.example.invalid/audit/"):
            self.assertIn(expected, service)
        self.assertNotIn("/usr/local/shenji", service)
        self.assertNotIn("open.larksuite.com/open-apis/bot/v2/hook/", service)

    def test_paths_cannot_inject_unit_directives_or_target_system_parent_directories(self):
        for install_dir in ("/", "/usr/local", "/opt/audit/../another", "/opt/audit\nExecStart=unsafe"):
            with self.subTest(install_dir=install_dir), self.assertRaises(ValueError):
                install_support.render_units(install_dir=install_dir)

    def test_webroot_cannot_publish_code_or_private_configuration(self):
        cases = ({"publish_dir": "/usr/local/shenji"},
                 {"publish_dir": "/usr/local/shenji/reports"},
                 {"lark_config": "/usr/local/shenji/index/lark-config.json"})
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                install_support.render_units(**arguments)


class LocalPreflightTests(unittest.TestCase):
    def isolated_environment(self):
        return {"LARK_WEBHOOK_URL": "TEST_STALE_OVERRIDE", "LARK_SIGNING_SECRET": "TEST_STALE_SECRET",
                "AWS_CONFIG_FILE": "TEST_ALTERNATIVE_CONFIG_NOT_READ",
                "AWS_SHARED_CREDENTIALS_FILE": "TEST_ALTERNATIVE_CREDENTIALS_NOT_READ",
                "AWS_PROFILE": "TEST_ALTERNATIVE_PROFILE", "AWS_DEFAULT_PROFILE": "TEST_DEFAULT_PROFILE",
                "AWS_ACCESS_KEY_ID": "TEST_TEMPORARY_KEY", "AWS_SECRET_ACCESS_KEY": "TEST_TEMPORARY_SECRET",
                "AWS_SESSION_TOKEN": "TEST_TEMPORARY_SESSION"}

    @unittest.skipUnless(boto3 is not None, "boto3 not installed; mocked SDK preflight test skipped")
    def test_preflight_reads_only_temporary_file_configuration_without_sdk_or_http_calls(self):
        import lark_notify

        with tempfile.TemporaryDirectory(prefix="audit-deployment-preflight-") as temporary:
            config = Path(temporary) / "fake-private-config.json"
            config.write_text('{"webhook_url":"TEST_CONFIGURATION_NOT_USED"}', encoding="utf-8")
            config.chmod(0o600)
            fake_session = Mock()
            fake_session.available_profiles = ["audit"]
            temporary_environment = self.isolated_environment()

            def read_config(path):
                self.assertEqual(Path(path), config)
                for key in temporary_environment:
                    self.assertNotIn(key, os.environ)
                self.assertEqual(os.environ["HOME"], "/root")
                return {"webhook_url": "TEST_CONFIGURATION_NOT_USED"}

            def create_session(**kwargs):
                self.assertEqual(kwargs, {"profile_name": "audit"})
                for key in temporary_environment:
                    self.assertNotIn(key, os.environ)
                self.assertEqual(os.environ["HOME"], "/root")
                return fake_session

            with patch.dict(os.environ, {**temporary_environment, "HOME": "TEST_ORIGINAL_HOME", "AWS_REGION": "eu-north-1"}), \
                 patch.object(lark_notify, "load_lark_config", side_effect=read_config) as load, \
                 patch.object(lark_notify, "send_lark_notification") as notify, \
                 patch.object(lark_notify.urllib.request, "urlopen") as http, \
                 patch.object(boto3, "Session", side_effect=create_session) as session:
                install_support.local_preflight("/usr/local/shenji", "audit", config)
                for key, value in temporary_environment.items():
                    self.assertEqual(os.environ[key], value)
                self.assertEqual(os.environ["HOME"], "TEST_ORIGINAL_HOME")
                self.assertEqual(os.environ["AWS_REGION"], "eu-north-1")
            load.assert_called_once()
            session.assert_called_once_with(profile_name="audit")
            fake_session.client.assert_not_called()
            fake_session.get_credentials.assert_not_called()
            notify.assert_not_called()
            http.assert_not_called()

    @unittest.skipUnless(boto3 is not None, "boto3 not installed; mocked SDK preflight test skipped")
    def test_preflight_failure_restores_all_parent_overrides_and_does_not_leave_home_behind(self):
        import lark_notify

        with tempfile.TemporaryDirectory(prefix="audit-deployment-preflight-") as temporary:
            config = Path(temporary) / "fake-private-config.json"
            config.write_text("{}", encoding="utf-8")
            config.chmod(0o600)
            original = self.isolated_environment()
            for failure_stage in ("lark", "aws_profile"):
                fake_session = Mock()
                fake_session.available_profiles = []
                with self.subTest(failure_stage=failure_stage), patch.dict(os.environ, original, clear=True), \
                     patch.object(lark_notify, "load_lark_config", side_effect=ValueError("TEST_INVALID_CONFIG") if failure_stage == "lark" else None), \
                     patch.object(lark_notify.urllib.request, "urlopen") as http, \
                     patch.object(boto3, "Session", return_value=fake_session) as session:
                    self.assertNotIn("HOME", os.environ)
                    with self.assertRaises(ValueError):
                        install_support.local_preflight("/usr/local/shenji", "audit", config)
                    self.assertEqual(dict(os.environ), original)
                    http.assert_not_called()
                    fake_session.client.assert_not_called()
                    fake_session.get_credentials.assert_not_called()
                    if failure_stage == "lark":
                        session.assert_not_called()

    def test_missing_private_configuration_fails_before_loading_credentials(self):
        with tempfile.TemporaryDirectory(prefix="audit-deployment-preflight-") as temporary:
            with self.assertRaises(ValueError):
                install_support.local_preflight("/usr/local/shenji", "audit", Path(temporary) / "missing.json")


class ScheduledReportDateTests(unittest.TestCase):
    def test_0801_run_selects_today_without_changing_the_required_window(self):
        clock = datetime(2026, 10, 28, 0, 1, tzinfo=timezone.utc)
        self.assertEqual(run_scheduled.report_date(clock), "2026-10-28")

    def test_before_0800_selects_previous_finished_report(self):
        clock = datetime(2026, 10, 27, 23, 59, 59, tzinfo=timezone.utc)
        self.assertEqual(run_scheduled.report_date(clock), "2026-10-27")

    def test_exact_0800_boundary_selects_current_report(self):
        clock = datetime(2026, 10, 28, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(run_scheduled.report_date(clock), "2026-10-28")

    def test_catch_up_after_midnight_uses_beijing_day_rather_than_host_day(self):
        # UTC Oct 27 18:00 is Beijing Oct 28 02:00: today's window is not finished yet.
        clock = datetime(2026, 10, 27, 18, 0, tzinfo=timezone.utc)
        self.assertEqual(run_scheduled.report_date(clock), "2026-10-27")

    def test_aware_non_utc_clock_is_converted_before_choosing_date(self):
        clock = datetime(2026, 10, 27, 20, 0, tzinfo=ZoneInfo("America/New_York"))
        self.assertEqual(run_scheduled.report_date(clock), "2026-10-28")

    def test_new_year_rollover_before_eight(self):
        clock = datetime(2027, 1, 1, 7, 59, tzinfo=ZoneInfo("Asia/Shanghai"))
        self.assertEqual(run_scheduled.report_date(clock), "2026-12-31")

    def test_naive_clock_is_rejected_instead_of_using_machine_timezone(self):
        with self.assertRaises(ValueError):
            run_scheduled.report_date(datetime(2026, 10, 28, 8, 1))


class ScheduledCommandTests(unittest.TestCase):
    def make_command(self, now):
        return run_scheduled.build_command(
            install_dir="/usr/local/shenji", profile="audit",
            lark_config="/usr/local/shenji/lark-config.json",
            publish_dir="/usr/local/shenji/index",
            report_url="https://reports.example.invalid/audit/?source=daily&view=all",
            now=now,
        )

    def option(self, command, flag):
        self.assertIn(flag, command)
        return command[command.index(flag) + 1]

    def test_command_uses_venv_explicit_date_all_regions_overview_and_no_password_server(self):
        command = self.make_command(datetime(2026, 10, 28, 0, 1, tzinfo=timezone.utc))
        self.assertIsInstance(command, list)
        self.assertEqual(command[0], "/usr/local/shenji/.venv/bin/python")
        self.assertEqual(command[1], "/usr/local/shenji/aws_daily_audit.py")
        self.assertEqual(self.option(command, "--date"), "2026-10-28")
        self.assertEqual(self.option(command, "--regions"), "all")
        self.assertEqual(self.option(command, "--profile"), "audit")
        self.assertEqual(self.option(command, "--lark-mode"), "overview")
        self.assertEqual(self.option(command, "--lark-config"), "/usr/local/shenji/lark-config.json")
        self.assertEqual(self.option(command, "--publish-dir"), "/usr/local/shenji/index")
        self.assertIn("--send-lark", command)
        self.assertNotIn("--auth-state-dir", command)
        self.assertNotIn("--no-publish", command)
        self.assertNotIn("--input-file", command)

    def test_restart_before_eight_uses_finished_yesterday_in_explicit_date_argument(self):
        command = self.make_command(datetime(2026, 10, 27, 23, 59, tzinfo=timezone.utc))
        self.assertEqual(self.option(command, "--date"), "2026-10-27")

    def test_report_url_remains_one_argument_without_shell_interpretation(self):
        command = self.make_command(datetime(2026, 10, 28, 0, 1, tzinfo=timezone.utc))
        self.assertEqual(self.option(command, "--report-url"),
                         "https://reports.example.invalid/audit/?source=daily&view=all")
        self.assertTrue(all(isinstance(argument, str) for argument in command))

    def test_runner_propagates_child_failure_and_removes_lark_overrides_without_altering_aws_environment(self):
        environment = {"LARK_WEBHOOK_URL": "TEST_STALE_WEBHOOK", "LARK_SIGNING_SECRET": "TEST_STALE_SECRET",
                       "AWS_ACCESS_KEY_ID": "TEST_AWS_KEY", "AWS_SECRET_ACCESS_KEY": "TEST_AWS_SECRET",
                       "AWS_SESSION_TOKEN": "TEST_AWS_SESSION", "AWS_PROFILE": "TEST_AWS_PROFILE",
                       "AWS_SHARED_CREDENTIALS_FILE": "TEST_CREDENTIALS_FILE_NOT_READ"}
        for code in (0, 2, 3, 4):
            with self.subTest(returncode=code), patch.dict(os.environ, environment), \
                 patch.object(run_scheduled.subprocess, "run", return_value=Mock(returncode=code)) as process, \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                status = run_scheduled.main(["--date", "2026-10-28"])
                self.assertEqual(status, code)
                process.assert_called_once()
                child_environment = process.call_args.kwargs["env"]
                self.assertNotIn("LARK_WEBHOOK_URL", child_environment)
                self.assertNotIn("LARK_SIGNING_SECRET", child_environment)
                for key, value in environment.items():
                    if key.startswith("AWS_"):
                        self.assertEqual(child_environment[key], value)
                self.assertEqual(os.environ["LARK_WEBHOOK_URL"], "TEST_STALE_WEBHOOK")
                self.assertEqual(process.call_args.kwargs["cwd"], "/usr/local/shenji")
                self.assertFalse(process.call_args.kwargs["check"])
                self.assertFalse(process.call_args.kwargs.get("shell", False))
                self.assertEqual(self.option(process.call_args.args[0], "--date"), "2026-10-28")

    def test_invalid_manual_date_is_rejected_without_starting_child_process(self):
        with patch.object(run_scheduled.subprocess, "run") as process, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            status = run_scheduled.main(["--date", "2026-02-30"])
        self.assertEqual(status, 1)
        process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
