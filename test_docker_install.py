"""Exercise the Docker installer with a fake daemon and forbidden host tools."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

from test_install_script import bash_path, shell_path


ROOT = Path(__file__).resolve().parent
FIXED_CONFIG = "/usr/local/aws-user-audit/aws-audit-config.json"
ENV_NAMES = ("AUDIT_CONFIG_PATH", "AUDIT_REPORTS_DIR", "AUDIT_STATE_DIR", "AUDIT_CONTAINER_REPORTS_DIR",
             "AUDIT_CONTAINER_STATE_DIR", "AUDIT_AWS_DIR", "AUDIT_FONT_SOURCE", "AUDIT_CONTAINER_FONT_PATH",
             "AUDIT_UID", "AUDIT_GID")


class DockerInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell = bash_path()
        if cls.shell is None:
            raise unittest.SkipTest("Bash unavailable; installer integration requires Linux/Bash.")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-docker-install-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "checkout source"
        (self.source / "deploy").mkdir(parents=True)
        shutil.copyfile(ROOT / "install-docker.sh", self.source / "install-docker.sh")
        shutil.copyfile(ROOT / "aws-audit-config.example.json", self.source / "aws-audit-config.example.json")
        for item in ("Dockerfile", "compose.yaml", "compose.aws-profile.yaml", "compose.font.yaml", "deploy/docker_config.py"):
            (self.source / item).write_text("# fake build asset\n", encoding="utf-8")
        self.data = self.root / "data root"
        self.config = self.data / "aws-audit-config.json"
        self.reports = self.data / "reports"
        self.state = self.data / ".state"
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.log = self.root / "docker-calls"
        self.forbidden = self.root / "forbidden-host-command"
        self.plan = self.root / "safe-plan"
        self.write_plan()
        self.environment = os.environ.copy()
        self.environment.update({"PATH": os.pathsep.join((str(self.fake_bin), str(Path(self.shell).parent),
                                                        self.environment.get("PATH", ""))),
                                 "FAKE_LOG": shell_path(self.log), "FAKE_PLAN": shell_path(self.plan),
                                 "FAKE_FORBIDDEN": shell_path(self.forbidden), "MSYS2_ARG_CONV_EXCL": "*"})
        # Using fake uname permits offline shell tests on a Windows workstation.
        self.executable("uname", "#!/bin/sh\nprintf 'Linux\\n'\n")
        if os.name == "nt":
            # The bundled review shell includes readlink -m rather than a
            # separate realpath binary; chmod has no POSIX meaning on Windows.
            self.executable("realpath", '#!/bin/sh\nexec readlink "$@"\n')
            self.executable("chmod", '#!/bin/sh\nexit 0\n')
            self.executable("chown", '#!/bin/sh\nexit 0\n')
            self.executable("stat", '#!/bin/sh\ncase "$2" in %u) echo 1000 ;; %u:%g) echo 1000:1000 ;; *) exit 1 ;; esac\n')
            self.executable("bash", '#!/bin/sh\nexec "' + shell_path(self.shell) + '" "$@"\n')
            # The Windows sandbox denies mkdir -p's attempts on read-only
            # ancestor ACLs. Create only missing descendants from a readable
            # existing parent, preserving the Linux command's actual behavior.
            self.executable("mkdir", '#!/bin/sh\n' + r'''
for destination in "$@"; do
    case $destination in -p|--) continue ;; esac
    [ ! -d "$destination" ] || continue
    parent=${destination%/*}
    relative=${destination##*/}
    while [ ! -d "$parent" ]; do
        relative=${parent##*/}/$relative
        parent=${parent%/*}
    done
    (cd -- "$parent" && "''' + shell_path(Path(self.shell).parent / "mkdir.exe") + r'''" -p -- "$relative") || exit $?
done
''')
        for command in ("systemctl", "crontab", "nginx", "apt", "apt-get", "yum", "curl", "wget", "git", "pip", "pip3", "python", "python3"):
            self.executable(command, "#!/bin/sh\nprintf 'forbidden\\n' >> \"$FAKE_FORBIDDEN\"\nexit 99\n")
        self.executable("docker", r'''#!/usr/bin/env bash
set -euo pipefail
printf 'CALL' >> "$FAKE_LOG"
printf '\t%s' "$@" >> "$FAKE_LOG"
printf '\n' >> "$FAKE_LOG"
for name in AUDIT_CONFIG_PATH AUDIT_REPORTS_DIR AUDIT_STATE_DIR AUDIT_CONTAINER_REPORTS_DIR AUDIT_CONTAINER_STATE_DIR AUDIT_AWS_DIR AUDIT_FONT_SOURCE AUDIT_CONTAINER_FONT_PATH AUDIT_UID AUDIT_GID; do
    printf 'ENV\t%s\t%s\n' "$name" "${!name:-}" >> "$FAKE_LOG"
done
if [[ ${1:-} == compose && ${2:-} == version ]]; then
    printf '%s\n' "${FAKE_COMPOSE_VERSION:-2.30.0}"
    exit 0
fi
for argument in "$@"; do
    if [[ $argument == build && ${FAKE_FAIL_BUILD:-0} == 1 ]]; then
        printf 'SECRET-AWS-KEY SECRET-SMTP-PASSWORD\n' >&2
        exit 41
    fi
    if [[ $argument == check-config && ${FAKE_FAIL_CHECK:-0} == 1 ]]; then
        printf 'SECRET-AWS-KEY SECRET-SMTP-PASSWORD\n' >&2
        exit 42
    fi
done
if [[ ${1:-} == run ]]; then
    if [[ ${FAKE_FAIL_PLAN:-0} == 1 ]]; then
        printf 'SECRET-AWS-KEY SECRET-SMTP-PASSWORD\n' >&2
        exit 43
    fi
    cat -- "$FAKE_PLAN"
fi
''')

    def executable(self, name, text):
        target = self.fake_bin / name
        target.write_text(text, encoding="utf-8", newline="\n")
        target.chmod(0o755)

    def write_config(self):
        self.data.mkdir(exist_ok=True)
        content = ('// keep these comments and bytes\n' + json.dumps({
            "OUTPUT_DIRECTORY": "reports", "STATE_DIRECTORY": ".state", "AUTO_MAIL_MAX_PER_DAY": 0,
            "SMTP_AUTH_CODE": "SECRET-SMTP-PASSWORD",
            "ACCOUNTS": [{"NAME": "fixture", "ACCOUNT_ID": "123456789012",
                          "AWS_ACCESS_KEY_ID": "SECRET-AWS-KEY", "AWS_SECRET_ACCESS_KEY": "SECRET"}]
        }, indent=3) + "\n")
        self.config.write_text(content, encoding="utf-8", newline="\n")
        self.config.chmod(0o600)
        return self.config.read_bytes()

    def write_plan(self, *, profile=0, reports=None, state=None, container_reports=None, container_state=None, font=None):
        values = [("AUDIT_REPORTS_DIR", shell_path(reports or self.reports)),
                  ("AUDIT_STATE_DIR", shell_path(state or self.state)),
                  ("AUDIT_CONTAINER_REPORTS_DIR", container_reports or "/usr/local/aws-user-audit/reports"),
                  ("AUDIT_CONTAINER_STATE_DIR", container_state or "/usr/local/aws-user-audit/.state"),
                  ("AUDIT_REQUIRES_PROFILE", str(profile))]
        if font is not None:
            values += [("AUDIT_FONT_SOURCE", shell_path(font)), ("AUDIT_CONTAINER_FONT_PATH", "/custom/fonts/chinese.ttf")]
        self.plan.write_text("".join(key + "\t" + value + "\n" for key, value in values), encoding="utf-8", newline="\n")

    def run_installer(self, *arguments):
        result = subprocess.run([self.shell, shell_path(self.source / "install-docker.sh"),
                                 "--data-dir", shell_path(self.data), *arguments], cwd=self.source,
                                env=self.environment, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=25)
        self.assertFalse(self.forbidden.exists(), result.stdout + result.stderr)
        self.assertNotIn("SECRET-AWS-KEY", result.stdout + result.stderr)
        self.assertNotIn("SECRET-SMTP-PASSWORD", result.stdout + result.stderr)
        return result

    def calls(self):
        return [line.split("\t")[1:] for line in self.log.read_text(encoding="utf-8").splitlines()
                if line.startswith("CALL\t")] if self.log.exists() else []

    def test_bash_syntax(self):
        result = subprocess.run([self.shell, "-n", shell_path(ROOT / "install-docker.sh")],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_first_run_copies_complete_template_then_stops_without_docker(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(self.config.read_bytes(), (ROOT / "aws-audit-config.example.json").read_bytes())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.assertFalse(self.log.exists())
        self.assertFalse((self.data / "docker.env").exists())
        self.assertIn("重新运行", result.stdout)

    def test_dry_run_does_not_call_docker_or_write_any_data(self):
        self.environment["FAKE_FAIL_BUILD"] = "1"
        result = self.run_installer("--dry-run", "--no-start", "--profile-dir", "/root/.aws")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.data.exists())
        self.assertFalse(self.log.exists())
        self.assertIn("aws-user-audit-docker", result.stdout)
        self.assertIn("compose.aws-profile.yaml", result.stdout)

    def test_existing_config_and_ledger_preserved_and_only_audit_service_started(self):
        original = self.write_config()
        self.reports.mkdir()
        self.state.mkdir()
        ledger = self.state / "mail-ledger.json"
        ledger.write_bytes(b'{"sent_days":["2026-11-05"]}\n')
        old_ledger = ledger.read_bytes()
        marker = self.reports / "old-report.pdf"
        marker.write_bytes(b"ORIGINAL-PDF")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(ledger.read_bytes(), old_ledger)
        self.assertEqual(marker.read_bytes(), b"ORIGINAL-PDF")
        calls = self.calls()
        build = next(call for call in calls if "build" in call)
        self.assertEqual(build[-2:], ["build", "audit"])
        self.assertEqual(build[build.index("--project-name") + 1], "aws-user-audit-docker")
        check = next(call for call in calls if "check-config" in call)
        self.assertEqual(check[-8:], ["run", "--rm", "--no-deps", "-T", "audit", "check-config", "--config", FIXED_CONFIG])
        self.assertEqual(calls[-1][-5:], ["up", "-d", "--no-deps", "--force-recreate", "audit"])
        self.assertFalse(any(word in call for call in calls for word in ("stop", "down", "once", "--send-mail", "--automatic")))
        preflight = next(call for call in calls if call[0] == "run")
        uid = str(os.getuid()) if os.name == "posix" else "1000"
        gid = str(os.getgid()) if os.name == "posix" else "1000"
        self.assertEqual(preflight[preflight.index("--user") + 1], uid + ":" + gid)
        self.assertEqual(preflight[preflight.index("--network") + 1], "none")
        self.assertIn("--read-only", preflight)
        self.assertIn("type=bind,src=" + shell_path(self.config) + ",dst=" + FIXED_CONFIG + ",readonly", preflight)
        self.assertEqual(preflight[preflight.index("--entrypoint") + 1], "/app/.venv/bin/python")
        env = (self.data / "docker.env").read_text(encoding="utf-8")
        self.assertIn("COMPOSE_PROJECT_NAME='aws-user-audit-docker'", env)
        self.assertIn("AUDIT_UID='" + uid + "'", env)
        self.assertIn("AUDIT_GID='" + gid + "'", env)
        self.assertIn("AUDIT_CONFIG_PATH='" + shell_path(self.config) + "'", env)
        self.assertIn("AUDIT_CONTAINER_REPORTS_DIR='/usr/local/aws-user-audit/reports'", env)
        self.assertNotIn("SECRET", env)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((self.data / "docker.env").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)

    def test_no_start_builds_and_checks_but_does_not_replace_service(self):
        self.write_config()
        result = self.run_installer("--no-start")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(any("build" in call for call in self.calls()))
        self.assertTrue(any("check-config" in call for call in self.calls()))
        self.assertFalse(any("up" in call or "stop" in call or "down" in call for call in self.calls()))
        self.assertTrue((self.data / "docker.env").is_file())

    def test_mismatched_existing_directory_owner_stops_without_reownership(self):
        original = self.write_config()
        self.reports.mkdir()
        marker = self.reports / "existing.pdf"
        marker.write_bytes(b"original")
        self.executable("stat", '#!/bin/sh\ncase "$2" in %u:%g) echo 1000:1000 ;; %u) echo 2000 ;; *) exit 1 ;; esac\n')
        self.executable("chown", '#!/bin/sh\nprintf "forbidden\\n" >> "$FAKE_FORBIDDEN"\nexit 99\n')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("所有者", result.stderr)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(marker.read_bytes(), b"original")
        self.assertFalse(self.forbidden.exists())
        self.assertFalse((self.data / "docker.env").exists())
        self.assertFalse(any("up" in call for call in self.calls()))

    def test_absolute_custom_paths_are_passed_unchanged_to_compose(self):
        original = self.write_config()
        reports, state = self.root / "archive custom", self.root / "delivery state"
        self.write_plan(reports=reports, state=state, container_reports="/srv/archive custom", container_state="/srv/delivery state")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.read_bytes(), original)
        env = (self.data / "docker.env").read_text(encoding="utf-8")
        self.assertIn("AUDIT_REPORTS_DIR='" + shell_path(reports) + "'", env)
        self.assertIn("AUDIT_CONTAINER_REPORTS_DIR='/srv/archive custom'", env)
        self.assertIn("AUDIT_CONTAINER_STATE_DIR='/srv/delivery state'", env)
        self.assertTrue(reports.is_dir())
        self.assertTrue(state.is_dir())

    def test_required_profile_without_explicit_mount_has_actionable_message(self):
        original = self.write_config()
        self.write_plan(profile=1)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--profile-dir /root/.aws", result.stderr)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse(self.reports.exists())
        self.assertFalse(any("check-config" in call or "up" in call for call in self.calls()))

    def test_profile_and_font_overlays_in_order_and_sources_preserved(self):
        original = self.write_config()
        profile = self.root / "aws profile"
        profile.mkdir()
        credential = profile / "credentials"
        credential.write_bytes(b"PRIVATE PROFILE\n")
        credential.chmod(0o600)
        font = self.root / "Chinese.ttf"
        font.write_bytes(b"FONT")
        self.write_plan(profile=1, font=font)
        result = self.run_installer("--profile-dir", shell_path(profile))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(credential.read_bytes(), b"PRIVATE PROFILE\n")
        up = self.calls()[-1]
        files = [up[index + 1] for index, item in enumerate(up) if item == "-f"]
        self.assertEqual(files, [shell_path(self.source / name) for name in ("compose.yaml", "compose.aws-profile.yaml", "compose.font.yaml")])
        env = (self.data / "docker.env").read_text(encoding="utf-8")
        self.assertIn("AUDIT_AWS_DIR='" + shell_path(profile) + "'", env)
        self.assertIn("AUDIT_FONT_SOURCE='" + shell_path(font) + "'", env)
        self.assertNotIn("PRIVATE PROFILE", env)

    def test_build_failure_keeps_running_container_and_existing_deployment_env(self):
        original = self.write_config()
        env_file = self.data / "docker.env"
        env_file.write_bytes(b"ORIGINAL DEPLOYMENT ENV\n")
        self.environment["FAKE_FAIL_BUILD"] = "1"
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("未停止或更新", result.stderr)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(env_file.read_bytes(), b"ORIGINAL DEPLOYMENT ENV\n")
        self.assertFalse(any("run" in call or "stop" in call or "down" in call or "up" in call for call in self.calls()))

    def test_preflight_and_runtime_errors_are_sanitized_and_do_not_start(self):
        self.write_config()
        for setting in ("FAKE_FAIL_PLAN", "FAKE_FAIL_CHECK"):
            with self.subTest(stage=setting):
                self.environment[setting] = "1"
                self.log.unlink(missing_ok=True)
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any("up" in call or "stop" in call or "down" in call for call in self.calls()))
                self.assertFalse((self.data / "docker.env").exists())
                del self.environment[setting]

    def test_invalid_or_duplicate_plan_is_not_executed(self):
        self.write_config()
        for suffix in ("UNKNOWN\tvalue\n", "AUDIT_REPORTS_DIR\t/tmp/duplicate\n", "$(touch HACKED)\tvalue\n"):
            with self.subTest(suffix=suffix):
                self.write_plan()
                with self.plan.open("a", encoding="utf-8") as stream:
                    stream.write(suffix)
                self.log.unlink(missing_ok=True)
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.source / "HACKED").exists())
                self.assertFalse(any("up" in call for call in self.calls()))

    def test_plan_cannot_mount_sensitive_system_tree(self):
        self.write_config()
        for directory in ("/etc/audit-reports", "/app/reports", "/root/.aws/cache"):
            with self.subTest(directory=directory):
                self.write_plan()
                content = self.plan.read_text(encoding="utf-8")
                content = content.replace("AUDIT_REPORTS_DIR\t" + shell_path(self.reports), "AUDIT_REPORTS_DIR\t" + directory)
                self.plan.write_text(content, encoding="utf-8", newline="\n")
                self.log.unlink(missing_ok=True)
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any("check-config" in call or "up" in call for call in self.calls()))

    def test_missing_font_does_not_start_and_never_rewrites_config(self):
        original = self.write_config()
        self.write_plan(font=self.root / "missing.ttf")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PDF_FONT_PATH", result.stderr)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse(any("up" in call for call in self.calls()))

    def test_compose_v1_is_rejected_without_build(self):
        self.write_config()
        self.environment["FAKE_COMPOSE_VERSION"] = "1.29.2"
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Compose V2", result.stderr)
        self.assertFalse(any("build" in call for call in self.calls()))

    def test_newer_compose_plugin_major_is_supported(self):
        self.write_config()
        self.environment["FAKE_COMPOSE_VERSION"] = "v5.0.0"
        result = self.run_installer("--no-start")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(any("build" in call for call in self.calls()))
        self.assertTrue(any("check-config" in call for call in self.calls()))

    def test_path_values_cannot_execute_shell_or_interpolate_in_saved_env(self):
        self.write_config()
        reports = self.root / "literal $(touch HACKED) O'Brien"
        self.write_plan(reports=reports)
        result = self.run_installer("--no-start")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(reports.is_dir())
        self.assertFalse((self.source / "HACKED").exists())
        env = (self.data / "docker.env").read_text(encoding="utf-8")
        self.assertIn("AUDIT_REPORTS_DIR='" + shell_path(reports).replace("'", "\\'") + "'", env)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink and mode semantics")
    def test_resolved_host_symlink_cannot_cover_config_or_profiles(self):
        original = self.write_config()
        alias = self.root / "output-alias"
        alias.symlink_to(self.data, target_is_directory=True)
        self.write_plan(reports=alias)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse(any("up" in call for call in self.calls()))

    @unittest.skipUnless(os.name == "posix", "POSIX symlink and mode semantics")
    def test_existing_parent_and_descendant_permissions_are_not_recursively_changed(self):
        self.write_config()
        self.data.chmod(0o750)
        self.reports.mkdir()
        self.state.mkdir()
        child = self.reports / "existing"
        child.mkdir()
        child.chmod(0o755)
        ledger = self.state / "mail-delivery.json"
        ledger.write_bytes(b"existing ledger\n")
        ledger.chmod(0o640)
        result = self.run_installer("--no-start")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(stat.S_IMODE(self.data.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o640)
        self.assertEqual(ledger.read_bytes(), b"existing ledger\n")

    def test_unsafe_paths_and_unknown_flags_stop_before_changes(self):
        for arguments in (("--unexpected",), ("--data-dir", "/"), ("--data-dir", "/tmp"),
                          ("--data-dir", "/opt/audit/../other"), ("--config", "/opt/audit,bad.json"),
                          ("--profile-dir", "/root/.aws\nOTHER=bad")):
            with self.subTest(arguments=arguments):
                result = self.run_installer("--dry-run", *arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.data.exists())
                self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
