"""Docker scheduling and shutdown checks with local files and fake processes."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from deploy import docker_runtime as runtime


SECRET = "TEST_DOCKER_PRIVATE_SECRET_MUST_NOT_APPEAR"


def beijing(value):
    return datetime.fromisoformat(value).replace(tzinfo=runtime.BEIJING)


class FakeClock:
    def __init__(self, value):
        self.current = value
        self.elapsed = 0.0

    def now(self):
        return self.current

    def monotonic(self):
        return self.elapsed

    def advance(self, seconds):
        self.current += timedelta(seconds=seconds)
        self.elapsed += seconds

    def jump(self, value):
        self.advance((value - self.current).total_seconds())


class FakeProcess:
    def __init__(self, *, result=0, running_polls=0, ignore_term=False, on_poll=None):
        self.pid = 424242
        self.result, self.remaining = result, running_polls
        self.ignore_term, self.on_poll = ignore_term, on_poll
        self.returncode = None
        self.signals, self.waits = [], []

    def poll(self):
        if self.on_poll:
            action, self.on_poll = self.on_poll, None
            action()
        if self.returncode is None:
            if self.remaining:
                self.remaining -= 1
            else:
                self.returncode = self.result
        return self.returncode

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fictional-job", timeout)
        return self.returncode

    def signal(self, signum):
        self.signals.append(signum)
        if signum == getattr(signal, "SIGKILL", 9) or not self.ignore_term:
            self.returncode = -signum


class DockerRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="aws-docker-runtime-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config_path = self.root / "private.json"
        self.state_directory = self.root / ".state"
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.raw = {
            "ACCOUNTS": [{"NAME": "account-1", "ACCOUNT_ID": "000000000001", "TAG": "生产",
                          "AWS_ACCESS_KEY_ID": "TESTKEY", "AWS_SECRET_ACCESS_KEY": SECRET,
                          "REGIONS": ["eu-north-1"]}],
            "OUTPUT_DIRECTORY": "reports", "STATE_DIRECTORY": ".state", "TIMEZONE": "Asia/Shanghai",
            "DAILY_MAIL_TIME": "10:05", "REPORT_START_TIME": "10:00", "REPORT_END_TIME": "10:00",
            "AUTO_MAIL_MAX_PER_DAY": 1, "SMTP_HOST": "smtp.example.invalid", "SMTP_PORT": 465,
            "SMTP_USERNAME": "sender@example.invalid", "SMTP_AUTH_CODE": SECRET,
            "MAIL_RECIPIENTS": ["recipient@example.invalid"],
        }
        self.write_config()

    def write_config(self, **updates):
        self.raw.update(updates)
        self.config_path.write_text("// Local fictional settings.\n" + json.dumps(self.raw), encoding="utf-8")
        self.config_path.chmod(0o600)

    def seed(self, when):
        with redirect_stdout(self.stdout):
            runtime.init_schedule(self.config_path, now=when)

    def state(self):
        return json.loads((self.state_directory / runtime.SCHEDULE_FILE).read_text(encoding="utf-8"))

    def schedule(self, start, actions=(), *, popen=None, control=None):
        clock = FakeClock(start)
        control = control or runtime.StopRequest()
        actions = iter(actions)

        def wait(seconds):
            action = next(actions, None)
            if action is None:
                control.stop()
            elif isinstance(action, datetime):
                clock.jump(action)
            else:
                action(clock, control)

        popen = popen or Mock(side_effect=lambda *args, **kwargs: FakeProcess())
        with redirect_stdout(self.stdout), redirect_stderr(self.stderr):
            result = runtime.run_schedule(self.config_path, now=clock.now, wait=wait,
                                          monotonic=clock.monotonic, popen=popen, control=control,
                                          identity_reader=lambda pid: "fictional-process-start",
                                          signaler=lambda child, signum: child.signal(signum))
        return result, popen

    def test_first_start_before_or_after_daily_time_only_initializes_a_baseline(self):
        for suffix, current, expected in (
                ("before", "2026-11-05T10:04:59", "2026-11-04T10:05:00+08:00"),
                ("after", "2026-11-05T10:06:00", "2026-11-05T10:05:00+08:00")):
            with self.subTest(start=suffix):
                self.write_config(STATE_DIRECTORY=".state-" + suffix)
                self.state_directory = self.root / (".state-" + suffix)
                self.state_directory.mkdir(mode=0o700)
                receipt = self.state_directory / "mail-delivery.json"
                receipt.write_bytes(b"EXISTING_MAIL_RECEIPT_MUST_STAY_UNCHANGED")
                result, popen = self.schedule(beijing(current))
                self.assertEqual(result, 0)
                popen.assert_not_called()
                self.assertEqual(self.state()["last_due"], expected)
                self.assertIsNone(self.state()["last_success_report_day"])
                self.assertEqual(receipt.read_bytes(), b"EXISTING_MAIL_RECEIPT_MUST_STAY_UNCHANGED")
                self.assertFalse((self.root / "reports").exists())
                for path in self.state_directory.iterdir():
                    if path.name != "mail-delivery.json" and os.name == "posix":
                        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_1005_job_reserves_cursor_before_spawning_and_forwards_business_flags(self):
        def spawn(command, **kwargs):
            state = self.state()
            self.assertEqual(state["last_due"], "2026-11-05T10:05:00+08:00")
            self.assertIsNone(state["last_success_report_day"])
            self.assertIn("--send-mail", command)
            self.assertIn("--automatic-mail", command)
            self.assertNotIn("--force-resend", command)
            self.assertEqual(command[command.index("--date") + 1], "2026-11-05")
            self.assertEqual(command[0], runtime.sys.executable)
            self.assertEqual(Path(command[1]).name, "aws_audit_multi.py")
            return FakeProcess()
        popen = Mock(side_effect=spawn)
        self.schedule(beijing("2026-11-05T10:04:59"), [beijing("2026-11-05T10:05:00")], popen=popen)
        popen.assert_called_once()
        self.assertEqual(self.state()["last_success_report_day"], "2026-11-05")
        self.assertEqual(len(self.state()["last_success_fingerprint"]), 64)
        self.assertNotIn(SECRET, json.dumps(self.state()) + self.stdout.getvalue() + self.stderr.getvalue())

    def test_beijing_midnight_is_correct_across_utc_date_boundary(self):
        self.write_config(DAILY_MAIL_TIME="00:05", REPORT_START_TIME="00:00", REPORT_END_TIME="00:00")
        _, popen = self.schedule(datetime(2026, 11, 4, 15, 59, tzinfo=timezone.utc),
                                 [datetime(2026, 11, 4, 16, 5, tzinfo=timezone.utc)])
        self.assertEqual(popen.call_args.args[0][popen.call_args.args[0].index("--date") + 1], "2026-11-05")
        self.assertEqual(self.state()["last_due"], "2026-11-05T00:05:00+08:00")

    def test_restart_before_next_due_does_not_run_and_after_missed_days_runs_once(self):
        self.seed(beijing("2026-11-04T10:06:00"))
        _, before = self.schedule(beijing("2026-11-05T09:00:00"))
        before.assert_not_called()
        _, missed = self.schedule(beijing("2026-11-09T12:00:00"))
        missed.assert_called_once()
        command = missed.call_args.args[0]
        self.assertEqual(command[command.index("--date") + 1], "2026-11-09")
        _, repeated = self.schedule(beijing("2026-11-09T12:01:00"))
        repeated.assert_not_called()

    def test_1002_catchup_success_prevents_querying_the_same_window_again_at_1005(self):
        self.seed(beijing("2026-11-03T10:06:00"))
        _, popen = self.schedule(beijing("2026-11-05T10:02:00"), [beijing("2026-11-05T10:05:00")])
        popen.assert_called_once()
        self.assertEqual(self.state()["last_due"], "2026-11-05T10:05:00+08:00")
        self.assertEqual(self.state()["last_success_report_day"], "2026-11-05")

    def test_failed_catchup_waits_until_next_normal_due_before_retry(self):
        self.seed(beijing("2026-11-03T10:06:00"))
        popen = Mock(side_effect=lambda *args, **kwargs: FakeProcess(result=3))
        self.schedule(beijing("2026-11-05T10:02:00"),
                      [beijing("2026-11-05T10:02:05"), beijing("2026-11-05T10:05:00")], popen=popen)
        self.assertEqual(popen.call_count, 2)
        self.assertIsNone(self.state()["last_success_report_day"])
        _, repeated = self.schedule(beijing("2026-11-05T10:05:10"))
        repeated.assert_not_called()

    def test_failed_spawn_is_reserved_across_restart_without_an_immediate_retry(self):
        self.seed(beijing("2026-11-04T10:06:00"))
        popen = Mock(side_effect=OSError(SECRET))
        with self.assertRaises(runtime.RuntimeStateError):
            self.schedule(beijing("2026-11-05T10:06:00"), popen=popen)
        self.assertEqual(self.state()["last_due"], "2026-11-05T10:05:00+08:00")
        _, repeated = self.schedule(beijing("2026-11-05T10:07:00"))
        repeated.assert_not_called()
        self.assertNotIn(SECRET, self.stdout.getvalue() + self.stderr.getvalue())

    def test_time_and_window_hot_changes_reset_baseline_without_immediate_catchup(self):
        def change(clock, control):
            self.write_config(DAILY_MAIL_TIME="10:00", REPORT_START_TIME="09:00", REPORT_END_TIME="09:00")
            clock.jump(beijing("2026-11-05T10:06:00"))
        _, popen = self.schedule(beijing("2026-11-05T10:04:00"),
                                 [change, beijing("2026-11-06T10:00:00")])
        popen.assert_called_once()
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("--date") + 1], "2026-11-06")
        self.assertEqual(self.state()["schedule"]["REPORT_END_TIME"], "09:00")

    def test_account_hot_changes_apply_at_next_due_and_invalidate_success_window_match(self):
        self.seed(beijing("2026-11-03T10:06:00"))
        seen_accounts = []
        def spawn(*args, **kwargs):
            seen_accounts.append(len(runtime.load_config(self.config_path)["ACCOUNTS"]))
            return FakeProcess()
        def add_account(clock, control):
            second = deepcopy(self.raw["ACCOUNTS"][0])
            second.update(NAME="account-2", ACCOUNT_ID="000000000002", TAG="新增账号")
            self.write_config(ACCOUNTS=[self.raw["ACCOUNTS"][0], second])
            clock.jump(beijing("2026-11-05T10:03:00"))
        popen = Mock(side_effect=spawn)
        self.schedule(beijing("2026-11-05T10:02:00"),
                      [add_account, beijing("2026-11-05T10:05:00")], popen=popen)
        self.assertEqual(seen_accounts, [1, 2])

    def test_long_job_consumes_due_times_it_crossed_and_waits_for_next_future_due(self):
        self.seed(beijing("2026-11-04T10:06:00"))
        def finish_two_days_later(clock, control):
            clock.jump(beijing("2026-11-07T11:00:00"))
        popen = Mock(return_value=FakeProcess(running_polls=1))
        self.schedule(beijing("2026-11-05T10:06:00"), [finish_two_days_later], popen=popen)
        popen.assert_called_once()
        self.assertEqual(self.state()["last_due"], "2026-11-07T10:05:00+08:00")
        _, repeated = self.schedule(beijing("2026-11-07T11:01:00"))
        repeated.assert_not_called()

    def test_running_jobs_refresh_heartbeat_beyond_health_timeout(self):
        self.seed(beijing("2026-11-04T10:06:00"))
        observed = []
        def advance_and_check(clock, control):
            clock.advance(60)
            observed.append(runtime.healthy(self.config_path, now=clock.now(),
                                            identity_reader=lambda pid: "fictional-process-start"))
        child = FakeProcess(running_polls=3)
        self.schedule(beijing("2026-11-05T10:06:00"), [advance_and_check] * 3,
                      popen=Mock(return_value=child))
        self.assertEqual(observed, [True, True, True])
        self.assertEqual(json.loads((self.state_directory / runtime.HEARTBEAT_FILE).read_text())["status"], "stopped")

    def test_two_scheduler_instances_cannot_share_a_state_lock(self):
        self.state_directory.mkdir(mode=0o700)
        with runtime.scheduler_lock(self.state_directory):
            with self.assertRaises(runtime.RuntimeStateError):
                self.schedule(beijing("2026-11-05T10:06:00"))
        self.assertFalse((self.state_directory / runtime.SCHEDULE_FILE).exists())

    def test_corrupt_or_future_state_fails_closed_without_rewriting_or_running(self):
        self.seed(beijing("2026-11-04T10:06:00"))
        valid = self.state()
        future = deepcopy(valid)
        future["last_due"] = "2026-11-06T10:05:00+08:00"
        bad_success = deepcopy(valid)
        bad_success["last_success_report_day"] = "2026-11-04"
        values = ["null", "{}", "[1]", '{"schema_version":1,"schema_version":1}',
                  json.dumps(future), json.dumps(bad_success), SECRET, '{"schema_version":NaN}']
        for value in values:
            with self.subTest(state=value):
                path = self.state_directory / runtime.SCHEDULE_FILE
                path.write_text(value, encoding="utf-8")
                path.chmod(0o600)
                popen = Mock()
                with self.assertRaises((runtime.RuntimeStateError, ValueError)):
                    self.schedule(beijing("2026-11-05T10:06:00"), popen=popen)
                popen.assert_not_called()
                self.assertEqual(path.read_text(encoding="utf-8"), value)

    @unittest.skipUnless(os.name == "posix", "POSIX private directory and state permissions")
    def test_world_readable_state_is_rejected_without_changing_its_permissions(self):
        self.seed(beijing("2026-11-04T10:06:00"))
        path = self.state_directory / runtime.SCHEDULE_FILE
        path.chmod(0o644)
        with self.assertRaises(runtime.RuntimeStateError):
            self.schedule(beijing("2026-11-05T10:06:00"))
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_healthcheck_is_local_rejects_stale_process_reuse_and_stopped_status(self):
        self.state_directory.mkdir(mode=0o700)
        current = beijing("2026-11-05T10:06:00")
        runtime._heartbeat(self.state_directory, "a" * 32, "old-process-start", "running", current, 12345)
        with patch("socket.create_connection") as network, patch("boto3.Session") as aws:
            self.assertTrue(runtime.healthy(self.config_path, now=current,
                                            identity_reader=lambda pid: "old-process-start"))
            self.assertFalse(runtime.healthy(self.config_path, now=current,
                                             identity_reader=lambda pid: "new-process-start"))
            self.assertFalse(runtime.healthy(self.config_path, now=current + timedelta(seconds=91),
                                             identity_reader=lambda pid: "old-process-start"))
            self.assertFalse(runtime.healthy(self.config_path, now=current - timedelta(seconds=10),
                                             identity_reader=lambda pid: "old-process-start"))
            runtime._heartbeat(self.state_directory, "a" * 32, "old-process-start", "stopped", current)
            self.assertFalse(runtime.healthy(self.config_path, now=current,
                                             identity_reader=lambda pid: "old-process-start"))
        network.assert_not_called()
        aws.assert_not_called()

    def test_native_process_identity_is_stable_for_current_process(self):
        self.assertEqual(runtime.process_identity(os.getpid()), runtime.process_identity(os.getpid()))

    def test_sigterm_is_forwarded_and_child_is_reaped(self):
        clock = FakeClock(beijing("2026-11-05T10:06:00"))
        control = runtime.StopRequest()
        child = FakeProcess(running_polls=100)
        def stop(seconds):
            clock.advance(seconds)
            control.stop(signal.SIGTERM)
        code = runtime.run_child(["fictional-python"], control=control, popen=Mock(return_value=child),
                                 wait=stop, monotonic=clock.monotonic,
                                 signaler=lambda proc, signum: proc.signal(signum))
        self.assertEqual(code, -signal.SIGTERM)
        self.assertEqual(child.signals, [signal.SIGTERM])
        self.assertEqual(child.waits, [None])

    def test_sigint_escalates_to_kill_after_grace_for_unresponsive_child(self):
        clock = FakeClock(beijing("2026-11-05T10:06:00"))
        control = runtime.StopRequest()
        child = FakeProcess(running_polls=100, ignore_term=True)
        def stop(seconds):
            clock.advance(seconds)
            control.stop(signal.SIGINT)
        code = runtime.run_child(["fictional-python"], control=control, popen=Mock(return_value=child),
                                 wait=stop, monotonic=clock.monotonic, grace=2,
                                 signaler=lambda proc, signum: proc.signal(signum))
        self.assertEqual(code, -getattr(signal, "SIGKILL", 9))
        self.assertEqual(child.signals, [signal.SIGINT, getattr(signal, "SIGKILL", 9)])
        self.assertEqual(child.waits, [5])
        self.assertLessEqual(clock.elapsed, 4)

    def test_heartbeat_failure_kills_and_reaps_child_before_propagating(self):
        child = FakeProcess(running_polls=100)
        with self.assertRaisesRegex(RuntimeError, "fictional failure"):
            runtime.run_child(["fictional-python"], popen=Mock(return_value=child),
                              heartbeat=Mock(side_effect=RuntimeError("fictional failure")),
                              signaler=lambda proc, signum: proc.signal(signum))
        self.assertEqual(child.signals, [getattr(signal, "SIGKILL", 9)])
        self.assertEqual(child.waits, [5])

    def test_once_selects_latest_finished_window_and_preserves_explicit_flags(self):
        with patch.object(runtime, "utc_now", return_value=beijing("2026-11-05T09:00:00")), \
             patch.object(runtime, "run_child", return_value=0) as runner:
            self.assertEqual(runtime.main(["once", "--config", str(self.config_path),
                                           "--send-mail", "--automatic-mail"]), 0)
        command = runner.call_args.args[0]
        self.assertEqual(command[command.index("--date") + 1], "2026-11-04")
        self.assertIn("--automatic-mail", command)
        with patch.object(runtime, "run_child", return_value=-signal.SIGTERM) as runner:
            self.assertEqual(runtime.main(["once", "--config", str(self.config_path), "--date", "2026-11-03",
                                           "--send-mail", "--force-resend"]), 128 + signal.SIGTERM)
        command = runner.call_args.args[0]
        self.assertEqual(command[command.index("--date") + 1], "2026-11-03")
        self.assertIn("--force-resend", command)
        self.assertNotIn("--automatic-mail", command)

    def test_check_config_only_reads_local_profiles_without_resolving_credentials(self):
        selected = self.raw["ACCOUNTS"][0]
        selected.update(AWS_ACCESS_KEY_ID="", AWS_SECRET_ACCESS_KEY="", AWS_PROFILE="fictional-audit")
        self.write_config()
        session = Mock(available_profiles=["fictional-audit"])
        with patch("boto3.Session", return_value=session) as aws, \
             patch("socket.create_connection") as network, patch("audit_alerts.notify_issues") as notify, \
             redirect_stdout(self.stdout), redirect_stderr(self.stderr):
            self.assertEqual(runtime.main(["check-config", "--config", str(self.config_path)]), 0)
        aws.assert_called_once_with(profile_name="fictional-audit")
        session.get_credentials.assert_not_called()
        session.client.assert_not_called()
        network.assert_not_called()
        notify.assert_not_called()

    def test_missing_profile_and_invalid_mail_fail_offline_without_leaking_values(self):
        selected = self.raw["ACCOUNTS"][0]
        selected.update(AWS_ACCESS_KEY_ID="", AWS_SECRET_ACCESS_KEY="", AWS_PROFILE=SECRET)
        self.write_config()
        with patch("boto3.Session", return_value=Mock(available_profiles=[])), \
             patch("socket.create_connection") as network, patch("audit_alerts.notify_issues") as notify, \
             redirect_stdout(self.stdout), redirect_stderr(self.stderr):
            self.assertEqual(runtime.main(["check-config", "--config", str(self.config_path)]), 1)
            self.write_config(SMTP_HOST="https://" + SECRET)
            self.assertEqual(runtime.main(["check-config", "--config", str(self.config_path)]), 1)
        network.assert_not_called()
        notify.assert_not_called()
        self.assertNotIn(SECRET, self.stdout.getvalue() + self.stderr.getvalue())

    def test_automatic_mail_disabled_allows_blank_smtp_and_disabled_profiles_are_ignored(self):
        disabled = deepcopy(self.raw["ACCOUNTS"][0])
        disabled.update(NAME="disabled", ACCOUNT_ID="000000000002", ENABLED=False,
                        AWS_ACCESS_KEY_ID="", AWS_SECRET_ACCESS_KEY="", AWS_PROFILE="absent-profile")
        self.write_config(ACCOUNTS=[self.raw["ACCOUNTS"][0], disabled], AUTO_MAIL_MAX_PER_DAY=0,
                          SMTP_HOST="", SMTP_USERNAME="", SMTP_AUTH_CODE="", MAIL_RECIPIENTS=[])
        with patch("boto3.Session") as aws, redirect_stdout(self.stdout):
            self.assertEqual(runtime.main(["check-config", "--config", str(self.config_path)]), 0)
        aws.assert_not_called()

    def test_init_schedule_preserves_existing_cursor_and_mail_receipt_exactly(self):
        self.seed(beijing("2026-11-04T10:06:00"))
        state_path = self.state_directory / runtime.SCHEDULE_FILE
        initial = state_path.read_bytes()
        mail_path = self.state_directory / "mail-delivery.json"
        mail_path.write_bytes(b"EXISTING_PRIVATE_RECEIPT")
        self.write_config(DAILY_MAIL_TIME="11:00")
        with patch.object(runtime, "run_child") as runner, redirect_stdout(self.stdout):
            runtime.init_schedule(self.config_path, now=beijing("2026-11-05T12:00:00"))
        runner.assert_not_called()
        self.assertEqual(state_path.read_bytes(), initial)
        self.assertEqual(mail_path.read_bytes(), b"EXISTING_PRIVATE_RECEIPT")
        self.assertFalse((self.state_directory / runtime.HEARTBEAT_FILE).exists())


if __name__ == "__main__":
    unittest.main()
