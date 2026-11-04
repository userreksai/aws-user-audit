"""Exercise the installer parser/dry-run without any privileged commands."""
import os
import json
from pathlib import Path
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

    def test_rds_project_markers_stop_before_system_actions(self):
        with tempfile.TemporaryDirectory(prefix="audit-rds-protection-") as directory:
            temporary = Path(directory)
            (temporary / "rds_multi.py").write_text("# fictional RDS marker\n", encoding="utf-8")
            result = self.run_installer("--dry-run", "--install-dir", shell_path(temporary))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("RDS", result.stderr)
            self.assertEqual((temporary / "rds_multi.py").read_text(encoding="utf-8"), "# fictional RDS marker\n")
            self.assertFalse((temporary / ".venv").exists())


if __name__ == "__main__":
    unittest.main()
