"""Exercise the installer parser/dry-run without any privileged commands."""
import os
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent


def bash_path():
    candidates = [shutil.which("bash")]
    if os.name == "nt":
        candidates.append(str(Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/git/usr/bin/sh.exe"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            result = subprocess.run([candidate, "-c", 'printf "%s" "${BASH_VERSION:-}"'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                return candidate
    return None


def shell_path(path):
    value = str(Path(path).resolve()).replace("\\", "/")
    if os.name == "nt" and len(value) > 2 and value[1] == ":":
        return "/" + value[0].lower() + value[2:]
    return value


class InstallerShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell = bash_path()
        if cls.shell is None:
            raise unittest.SkipTest("Bash is unavailable; deployment integration requires Linux.")

    def environment(self, fake_bin=None):
        environment = os.environ.copy()
        paths = [str(Path(self.shell).parent)]
        if fake_bin:
            paths.insert(0, str(fake_bin))
        environment["PATH"] = os.pathsep.join(paths + [environment.get("PATH", "")])
        environment["PYTHONUTF8"] = "1"
        if os.name == "nt":
            # Windows Python needs MSYS source/temp paths converted, while the
            # Linux paths embedded in units must keep their literal values.
            environment["MSYS2_ARG_CONV_EXCL"] = "/usr/local/aws-user-audit;/etc/nginx"
        return environment

    def run_installer(self, *arguments, environment=None):
        return subprocess.run([self.shell, shell_path(ROOT / "install.sh"), *arguments],
                              cwd=ROOT, env=environment or self.environment(),
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)

    def test_bash_syntax(self):
        result = subprocess.run([self.shell, "-n", shell_path(ROOT / "install.sh")], cwd=ROOT,
                                env=self.environment(), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dry_run_update_renders_without_network_or_system_changes(self):
        with tempfile.TemporaryDirectory(prefix="installer-dry-run-test-") as directory:
            temporary = Path(directory)
            nginx = temporary / "vhost.conf"
            original = (ROOT / "deploy/nginx-audit-8889.conf.example").read_bytes()
            nginx.write_bytes(original)
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            marker = temporary / "forbidden-command-was-called"
            for command in ("systemctl", "systemd-analyze", "nginx", "flock", "curl", "git", "apt-get", "pip", "pip3", "install"):
                executable = fake_bin / command
                executable.write_text("#!/bin/sh\nprintf '%s\\n' blocked >> '" + shell_path(marker) + "'\nexit 97\n", encoding="utf-8")
                executable.chmod(0o755)
            result = self.run_installer("--dry-run", "--update", "--python", shell_path(sys.executable),
                                        "--nginx-config", shell_path(nginx), environment=self.environment(fake_bin))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(marker.exists(), "dry-run called a forbidden network/system command")
            self.assertEqual(nginx.read_bytes(), original)
            self.assertIn("Persistent=true", result.stdout)
            self.assertIn("10:05:00 Asia/Shanghai", result.stdout)
            self.assertIn("/usr/local/aws-user-audit/deploy/run_scheduled.py", result.stdout)
            self.assertIn("/usr/local/aws-user-audit/aws-audit-config.json", result.stdout)
            self.assertNotIn("--profile", result.stdout)
            self.assertNotIn("--lark-config", result.stdout)
            self.assertNotIn("--auth-state-dir", result.stdout)
            self.assertIn("已忽略", result.stdout)
            self.assertNotIn("候选配置已生成", result.stdout)
            self.assertNotIn("Nginx 配置：", result.stdout)

    def test_dry_run_needs_no_nginx_file_and_ignores_legacy_public_directory(self):
        with tempfile.TemporaryDirectory(prefix="installer-no-web-") as directory:
            public = Path(directory) / "unused-public"
            result = self.run_installer("--dry-run", "--python", shell_path(sys.executable),
                                        "--nginx-config", "/missing/vhost.conf", "--publish-dir", shell_path(public))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(public.exists())
            self.assertIn("PDF/JSON", result.stdout)
            self.assertIn("不读取或修改 Nginx", result.stdout)

    def test_required_commands_and_runtime_files_exclude_web_dependencies(self):
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        commands = re.search(r"for required in ([^;]+); do", source).group(1).split()
        self.assertNotIn("nginx", commands)
        self.assertNotIn("curl", commands)
        self.assertNotIn("nginx_config.py", source)
        self.assertNotIn("systemctl reload nginx", source)
        self.assertNotIn("aws-audit-web.service", source)
        self.assertNotIn('"$INSTALL_DIR/index"', source)
        self.assertNotIn('"$PUBLISH_DIR"', source)

    @unittest.skipUnless(os.name == "posix", "Custom Linux config path in Bash integration")
    def test_dry_run_reads_custom_schedule_without_modifying_config_or_nginx(self):
        with tempfile.TemporaryDirectory(prefix="installer-custom-clock-") as directory:
            temporary = Path(directory)
            nginx = temporary / "vhost.conf"
            original = (ROOT / "deploy/nginx-audit-8889.conf.example").read_bytes()
            nginx.write_bytes(original)
            config = temporary / "aws-audit-config.json"
            content = json.dumps({"DAILY_MAIL_TIME": "09:10", "REPORT_START_TIME": "08:00", "REPORT_END_TIME": "09:00",
                                  "AUTO_MAIL_MAX_PER_DAY": 0,
                                  "ACCOUNTS": [{"NAME": "fixture", "ACCOUNT_ID": "123456789012", "AWS_PROFILE": "audit"}]})
            config.write_text(content, encoding="utf-8")
            result = self.run_installer("--dry-run", "--python", sys.executable,
                                        "--config", str(config), "--nginx-config", str(nginx))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("OnCalendar=*-*-* 09:10:00 Asia/Shanghai", result.stdout)
            self.assertIn("前一天 08:00 至报表日 09:00", result.stdout)
            self.assertNotIn("10:05:00 Asia/Shanghai", result.stdout)
            self.assertEqual(nginx.read_bytes(), original)
            self.assertEqual(config.read_text(encoding="utf-8"), content)

    @unittest.skipUnless(os.name == "posix", "Custom Linux config path in Bash integration")
    def test_invalid_clock_in_config_stops_dry_run_before_nginx_planning(self):
        with tempfile.TemporaryDirectory(prefix="installer-invalid-clock-") as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"DAILY_MAIL_TIME": "25:10", "AUTO_MAIL_MAX_PER_DAY": 0,
                                         "ACCOUNTS": [{"NAME": "fixture", "ACCOUNT_ID": "123456789012"}]}), encoding="utf-8")
            result = self.run_installer("--dry-run", "--python", sys.executable, "--config", str(config))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DAILY_MAIL_TIME", result.stderr)
            self.assertNotIn("候选配置已生成", result.stdout)

    def test_unknown_option_stops_before_system_actions(self):
        result = self.run_installer("--unexpected-option")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--help", result.stderr)

    def test_unsafe_install_paths_stop_before_template_creation(self):
        for target in ("/tmp", "/opt/audit/../another", "/opt/audit/./child", "/opt/audit\nchild"):
            with self.subTest(target=target):
                result = self.run_installer("--install-dir", target)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("安装未完成", result.stderr)

    def test_rds_project_markers_stop_before_system_actions(self):
        with tempfile.TemporaryDirectory(prefix="audit-rds-protection-") as directory:
            temporary = Path(directory)
            (temporary / "rds_multi.py").write_text("# fictional RDS marker\n", encoding="utf-8")
            result = self.run_installer("--dry-run", "--install-dir", shell_path(temporary))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("RDS", result.stderr)
            self.assertEqual((temporary / "rds_multi.py").read_text(encoding="utf-8"), "# fictional RDS marker\n")
            self.assertFalse((temporary / ".venv").exists())


@unittest.skipUnless(sys.platform.startswith("linux"), "Isolated Linux installer lifecycle checks")
class InstallerLifecycleTests(unittest.TestCase):
    """Run the real install flow with local paths and mocked privileged tools.

    Only fixed host paths and root/host checks are redirected. Runtime copying,
    config parsing, preflight, backup, atomic replacement and rollback execute.
    """

    environment = InstallerShellTests.environment

    @classmethod
    def setUpClass(cls):
        cls.shell = bash_path()
        if cls.shell is None:
            raise unittest.SkipTest("Bash is unavailable; deployment integration requires Linux.")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="installer-lifecycle-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.install = self.root / "runtime"
        self.units = self.root / "units"
        self.units.mkdir()
        self.timer_stamp = self.root / "timers/stamp-aws-user-audit.timer"
        self.timer_stamp.parent.mkdir()
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.log = self.root / "commands.log"
        self.state = self.root / "timer-state.json"
        self.state.write_text(json.dumps({"active": False, "enabled": "disabled"}), encoding="utf-8")
        original = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.runtime_files = shlex.split(re.search(r"RUNTIME_FILES=\((.*?)\)\n", original, re.S).group(1))
        for relative in self.runtime_files:
            target = self.source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        redirected = original.replace("UNIT_DIR=/etc/systemd/system", "UNIT_DIR=" + shlex.quote(str(self.units)))
        redirected = redirected.replace("TIMER_STAMP=/var/lib/systemd/timers/stamp-aws-user-audit.timer",
                                        "TIMER_STAMP=" + shlex.quote(str(self.timer_stamp)))
        redirected = redirected.replace("((EUID == 0))", "true")
        redirected = redirected.replace("[[ -d /run/systemd/system ]]", '[[ -d "$UNIT_DIR" ]]')
        redirected = redirected.replace("exec 9>/run/lock/aws-user-audit-install.lock", 'exec 9>"$INSTALL_DIR.lock"')
        redirected = redirected.replace("install -d -m 0755 -- /var/lib/systemd/timers",
                                        "install -d -m 0755 -- " + shlex.quote(str(self.timer_stamp.parent)))
        redirected = re.sub(r"for cron_file in /etc/crontab [^\n]+; do",
                            'for cron_file in "$WORK_DIR/no-cron"; do', redirected)
        (self.source / "install.sh").write_text(redirected, encoding="utf-8")
        self.environment_values = self.environment(self.fake_bin)
        self.environment_values.update(TEST_COMMAND_LOG=str(self.log), TEST_TIMER_STATE=str(self.state),
                                       TEST_UNIT_DIR=str(self.units))
        self._executable("systemctl", "#!" + sys.executable + "\n" + r'''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["TEST_COMMAND_LOG"], "a", encoding="utf-8") as log:
    log.write("systemctl " + " ".join(args) + "\n")
state_path = pathlib.Path(os.environ["TEST_TIMER_STATE"])
state = json.loads(state_path.read_text())
command = args[0]
unit = args[-1]
if "nginx" in args or "aws-audit-web.service" in args:
    raise SystemExit(97)
if command == "show":
    if "ActiveState" in args:
        print("inactive")
    else:
        print("loaded" if (pathlib.Path(os.environ["TEST_UNIT_DIR"]) / unit).exists() else "not-found")
elif command == "is-active":
    raise SystemExit(0 if state["active"] else 3)
elif command == "is-enabled":
    print(state["enabled"])
    raise SystemExit(0 if state["enabled"] == "enabled" else 1)
elif command in {"start", "stop", "enable", "disable"}:
    if unit != "aws-user-audit.timer":
        raise SystemExit(98)
    if command == "enable" and "--now" in args and os.environ.get("TEST_FAIL_TIMER_ENABLE"):
        raise SystemExit(1)
    if command in {"start", "stop"} or "--now" in args:
        state["active"] = command in {"start", "enable"}
    if command in {"enable", "disable"}:
        state["enabled"] = "enabled" if command == "enable" else "disabled"
    state_path.write_text(json.dumps(state))
elif command == "list-timers":
    print("NEXT aws-user-audit.timer")
elif command != "daemon-reload":
    raise SystemExit(99)
''')
        self._executable("systemd-analyze", '#!/bin/sh\nprintf "systemd-analyze %s\\n" "$*" >> "$TEST_COMMAND_LOG"\nexit 0\n')
        self._executable("chown", "#!/bin/sh\nexit 0\n")
        self._executable("crontab", "#!/bin/sh\nexit 1\n")
        for command in ("nginx", "curl", "git", "apt-get"):
            self._executable(command, '#!/bin/sh\nprintf "FORBIDDEN %s\\n" "$0" >> "$TEST_COMMAND_LOG"\nexit 97\n')
        python = self.install / ".venv/bin/python"
        python.parent.mkdir(parents=True)
        python.write_text('#!/bin/sh\nif [ "$1" = -m ] && [ "$2" = pip ]; then\n'
                          'printf "pip install mocked\\n" >> "$TEST_COMMAND_LOG"\nexit 0\nfi\nexec '
                          + shlex.quote(sys.executable) + ' "$@"\n', encoding="utf-8")
        python.chmod(0o755)

    def _executable(self, name, content):
        path = self.fake_bin / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _configuration(self):
        target = self.install / "aws-audit-config.json"
        content = ('// Preserve this comment, spacing and trailing newline exactly.\n' + json.dumps({
            "AUTO_MAIL_MAX_PER_DAY": 0, "DAILY_MAIL_TIME": "10:05", "REPORT_START_TIME": "10:00",
            "REPORT_END_TIME": "10:00", "ACCOUNTS": [{"NAME": "fixture", "ACCOUNT_ID": "123456789012",
            "AWS_ACCESS_KEY_ID": "TEST_LOCAL_KEY", "AWS_SECRET_ACCESS_KEY": "TEST_LOCAL_SECRET"}]}, indent=3) + "\n").encode()
        target.write_bytes(content)
        target.chmod(0o600)
        return target, content

    def _run(self, **environment):
        values = {**self.environment_values, **environment}
        return subprocess.run([self.shell, str(self.source / "install.sh"), "--install-dir", str(self.install),
                               "--python", sys.executable, "--nginx-config", "/missing/vhost.conf",
                               "--publish-dir", str(self.root / "unused-web")], cwd=self.source,
                              env=values, capture_output=True, text=True, encoding="utf-8", timeout=60)

    def test_install_preserves_private_bytes_initializes_runtime_and_never_touches_web_or_runs_report(self):
        config, original = self._configuration()
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        for relative in self.runtime_files:
            self.assertEqual((self.install / relative).read_bytes(), (self.source / relative).read_bytes(), relative)
        self.assertFalse((self.install / "index").exists())
        self.assertFalse((self.root / "unused-web").exists())
        self.assertFalse((self.install / "reports").exists())
        commands = self.log.read_text(encoding="utf-8")
        self.assertNotIn("FORBIDDEN", commands)
        self.assertNotIn("start aws-user-audit.service", commands)
        self.assertNotIn("reload nginx", commands)
        self.assertIn("systemd-analyze verify", commands)
        self.assertIn("enable --now aws-user-audit.timer", commands)
        self.assertIn("OnCalendar=*-*-* 10:05:00 Asia/Shanghai", (self.units / "aws-user-audit.timer").read_text())
        self.assertTrue(json.loads(self.state.read_text())["active"])

    def test_timer_enable_failure_restores_old_runtime_units_stamp_and_timer_state(self):
        config, original = self._configuration()
        old_runtime = self.install / "aws_daily_audit.py"
        old_runtime.write_bytes(b"# original deployed implementation\n")
        old_units = {name: ("old " + name + "\n").encode() for name in ("aws-user-audit.service", "aws-user-audit.timer")}
        for name, data in old_units.items():
            (self.units / name).write_bytes(data)
        self.timer_stamp.write_bytes(b"old-timer-stamp\n")
        self.state.write_text(json.dumps({"active": True, "enabled": "enabled"}))
        result = self._run(TEST_FAIL_TIMER_ENABLE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("原配置和定时器状态已恢复", result.stderr)
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual(old_runtime.read_bytes(), b"# original deployed implementation\n")
        self.assertFalse((self.install / "audit_pdf.py").exists())
        for name, data in old_units.items():
            self.assertEqual((self.units / name).read_bytes(), data)
        self.assertEqual(self.timer_stamp.read_bytes(), b"old-timer-stamp\n")
        self.assertEqual(json.loads(self.state.read_text()), {"active": True, "enabled": "enabled"})
        self.assertNotIn("FORBIDDEN", self.log.read_text())

    def test_first_install_creates_complete_private_template_and_stops_before_timer_or_network(self):
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("已创建私有配置模板", result.stderr)
        config = self.install / "aws-audit-config.json"
        self.assertEqual(config.read_bytes(), (self.source / "aws-audit-config.example.json").read_bytes())
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.units / "aws-user-audit.timer").exists())
        self.assertFalse((self.install / "index").exists())
        self.assertFalse(self.timer_stamp.exists())
        commands = self.log.read_text() if self.log.exists() else ""
        self.assertNotIn("pip install", commands)
        self.assertNotIn("enable --now", commands)
        self.assertNotIn("FORBIDDEN", commands)


if __name__ == "__main__":
    unittest.main()
