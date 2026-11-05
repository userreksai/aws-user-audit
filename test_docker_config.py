"""Offline tests for immutable JSONC-based Linux Docker bind-mount planning."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch

from deploy import docker_config


CONTAINER_CONFIG = "/usr/local/aws-user-audit/aws-audit-config.json"
HOST_CONFIG = "/srv/audit data/aws-audit-config.json"


def config(**values):
    return {"OUTPUT_DIRECTORY": "reports", "STATE_DIRECTORY": ".state", "PDF_FONT_PATH": "",
            "SMTP_AUTH_CODE": "TEST_SECRET_SMTP_NEVER_OUTPUT",
            "ACCOUNTS": [{"NAME": "fictional", "ACCOUNT_ID": "123456789012", "ENABLED": True,
                          "AWS_ACCESS_KEY_ID": "TEST_SECRET_ACCESS", "AWS_SECRET_ACCESS_KEY": "TEST_SECRET_AWS"}],
            **values}


class DockerConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-docker-plan-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "private config.json"
        self.addCleanup(self.temporary.cleanup)
        self.write_config(config())

    def write_config(self, raw):
        self.source.write_text("// 私有配置，保持原样\n" + json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.source.chmod(0o600)

    def plan(self, **options):
        options.setdefault("container_config_path", CONTAINER_CONFIG)
        return docker_config.create_plan(self.source, HOST_CONFIG, **options)

    def pure_plan(self, raw, *, host=HOST_CONFIG, container=CONTAINER_CONFIG):
        return docker_config.build_plan(raw, raw, host_config_path=host, container_config_path=container)

    def test_relative_paths_follow_both_config_parents_and_leave_config_unchanged(self):
        before = self.source.read_bytes()
        entries_before = set(self.root.iterdir())
        result = self.plan()
        self.assertEqual(result, {"AUDIT_REPORTS_DIR": "/srv/audit data/reports",
                                  "AUDIT_STATE_DIR": "/srv/audit data/.state",
                                  "AUDIT_CONTAINER_REPORTS_DIR": "/usr/local/aws-user-audit/reports",
                                  "AUDIT_CONTAINER_STATE_DIR": "/usr/local/aws-user-audit/.state",
                                  "AUDIT_REQUIRES_PROFILE": "0"})
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(set(self.root.iterdir()), entries_before)
        self.assertNotIn("TEST_SECRET", json.dumps(result))

    def test_absolute_paths_keep_identical_sources_and_targets(self):
        self.write_config(config(OUTPUT_DIRECTORY="/opt/audit-data/report files", STATE_DIRECTORY="/var/lib/audit-data/state"))
        result = self.plan()
        self.assertEqual(result["AUDIT_REPORTS_DIR"], "/opt/audit-data/report files")
        self.assertEqual(result["AUDIT_CONTAINER_REPORTS_DIR"], result["AUDIT_REPORTS_DIR"])
        self.assertEqual(result["AUDIT_STATE_DIR"], "/var/lib/audit-data/state")
        self.assertEqual(result["AUDIT_CONTAINER_STATE_DIR"], result["AUDIT_STATE_DIR"])

    def test_custom_data_root_and_unicode_spaces(self):
        result = self.pure_plan(config(OUTPUT_DIRECTORY="日报 文件", STATE_DIRECTORY="私有 状态"),
                                host="/data/审计 项目/private.json", container="/config/审计 项目/private.json")
        self.assertEqual(result["AUDIT_REPORTS_DIR"], "/data/审计 项目/日报 文件")
        self.assertEqual(result["AUDIT_CONTAINER_REPORTS_DIR"], "/config/审计 项目/日报 文件")
        self.assertEqual(result["AUDIT_STATE_DIR"], "/data/审计 项目/私有 状态")
        self.assertEqual(result["AUDIT_CONTAINER_STATE_DIR"], "/config/审计 项目/私有 状态")

    def test_default_paths_when_raw_fields_are_absent(self):
        raw = config()
        raw.pop("OUTPUT_DIRECTORY")
        raw.pop("STATE_DIRECTORY")
        self.write_config(raw)
        self.assertEqual(self.plan()["AUDIT_REPORTS_DIR"], "/srv/audit data/reports")
        self.assertEqual(self.plan()["AUDIT_STATE_DIR"], "/srv/audit data/.state")

    def test_whitespace_only_font_keeps_existing_empty_font_semantics(self):
        self.write_config(config(PDF_FONT_PATH="   "))
        self.assertEqual(len(self.plan()), 5)

    def test_relative_parent_components_are_normalized_before_safety_checks(self):
        result = self.pure_plan(config(OUTPUT_DIRECTORY="../reports", STATE_DIRECTORY="../state"))
        self.assertEqual(result["AUDIT_REPORTS_DIR"], "/srv/reports")
        self.assertEqual(result["AUDIT_CONTAINER_REPORTS_DIR"], "/usr/local/reports")
        for path in ("../../../../etc/audit", "../../../app/reports"):
            with self.subTest(path=path):
                with self.assertRaises(docker_config.DockerConfigError):
                    self.pure_plan(config(OUTPUT_DIRECTORY=path))

    def test_enabled_profile_only_exposes_a_boolean(self):
        raw = config()
        raw["ACCOUNTS"][0].update(AWS_ACCESS_KEY_ID="", AWS_SECRET_ACCESS_KEY="", AWS_PROFILE="SECRET_PROFILE_NAME")
        raw["ACCOUNTS"].append({"NAME": "disabled", "ACCOUNT_ID": "210987654321", "ENABLED": False,
                                 "AWS_PROFILE": "DISABLED_PROFILE"})
        self.write_config(raw)
        result = self.plan()
        self.assertEqual(result["AUDIT_REQUIRES_PROFILE"], "1")
        self.assertNotIn("SECRET_PROFILE_NAME", json.dumps(result))
        raw["ACCOUNTS"][0]["AWS_PROFILE"] = ""
        self.write_config(raw)
        self.assertEqual(self.plan()["AUDIT_REQUIRES_PROFILE"], "0")

    def test_no_credential_lookup_network_or_profile_file_reading(self):
        raw = config()
        raw["ACCOUNTS"][0].update(AWS_ACCESS_KEY_ID="", AWS_SECRET_ACCESS_KEY="", AWS_PROFILE="nonexistent-profile")
        self.write_config(raw)
        with patch.object(socket, "socket", side_effect=AssertionError("network contacted")), \
                patch.dict(os.environ, {"AWS_SHARED_CREDENTIALS_FILE": str(self.root / "missing-profile")}), \
                patch.object(docker_config, "load_config", wraps=docker_config.load_config) as validate:
            result = self.plan()
        validate.assert_called_once_with(self.source, require_mail=False)
        self.assertEqual(result["AUDIT_REQUIRES_PROFILE"], "1")

    def test_rejects_sensitive_paths_in_either_directory(self):
        paths = ("/", "/etc", "/etc/private", "/app", "/app/reports", "/root/.aws",
                 "/root/.aws/backups", "/root", "/proc/data", "/sys/data", "/dev/data",
                 "/usr/bin/audit", "/usr/share/audit", "/var/run/audit", "/opt", "/tmp")
        for key in ("OUTPUT_DIRECTORY", "STATE_DIRECTORY"):
            for path in paths:
                with self.subTest(key=key, path=path):
                    with self.assertRaises(docker_config.DockerConfigError):
                        self.pure_plan(config(**{key: path}))

    def test_rejects_same_or_nested_mounts_on_both_host_and_container(self):
        cases = (("reports", "reports"), ("reports", "reports/private"),
                 ("state/reports", "state"), ("/srv/audit data/reports", "reports/state"),
                 ("reports", "/usr/local/aws-user-audit/reports/state"))
        for reports, state in cases:
            with self.subTest(reports=reports, state=state):
                with self.assertRaisesRegex(docker_config.DockerConfigError, "STATE_DIRECTORY"):
                    self.pure_plan(config(OUTPUT_DIRECTORY=reports, STATE_DIRECTORY=state))

    def test_directory_cannot_cover_config_on_host_or_container(self):
        for output in (".", "aws-audit-config.json", "/srv/audit data", "/srv/audit data/aws-audit-config.json",
                       "/usr/local/aws-user-audit", "/usr/local/aws-user-audit/aws-audit-config.json/reports"):
            with self.subTest(output=output):
                with self.assertRaises(docker_config.DockerConfigError):
                    self.pure_plan(config(OUTPUT_DIRECTORY=output))

    def test_linux_paths_reject_controls_separators_windows_and_tilde(self):
        invalid = ("reports\nsecret", "reports\tsecret", "rep\x00orts", "reports,ro", "C:/reports",
                   "reports:ro", "\\reports", "~/reports", "//server/reports", "reports\u2028forged", "reports\u202ereverse")
        for output in invalid:
            with self.subTest(output=repr(output)):
                with self.assertRaises(docker_config.DockerConfigError):
                    self.pure_plan(config(OUTPUT_DIRECTORY=output))
        for host in ("relative/config.json", "C:/private.json", "/data/secrets,ro/config.json", "/data/new\nline/config.json"):
            with self.subTest(host=repr(host)):
                with self.assertRaises(docker_config.DockerConfigError):
                    self.pure_plan(config(), host=host)

    def test_readonly_font_plan_supports_relative_absolute_and_system_fonts(self):
        for font, expected_source, expected_target in (
                ("字体/中文 字体.ttf", "/srv/audit data/字体/中文 字体.ttf", "/usr/local/aws-user-audit/字体/中文 字体.ttf"),
                ("/opt/audit-fonts/中文.ttf", "/opt/audit-fonts/中文.ttf", "/opt/audit-fonts/中文.ttf"),
                ("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc", "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
                 "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc")):
            with self.subTest(font=font):
                self.write_config(config(PDF_FONT_PATH=font))
                result = self.plan()
                self.assertEqual(result["AUDIT_FONT_SOURCE"], expected_source)
                self.assertEqual(result["AUDIT_CONTAINER_FONT_PATH"], expected_target)
                self.assertEqual(len(result), 7)

    def test_font_cannot_cover_private_config_code_system_or_writable_mounts(self):
        for font in ("/app/aws_audit_multi.py", "/etc/passwd", "/proc/a", "/sys/a", "/dev/a", "/root/.aws/config",
                     "aws-audit-config.json", "reports/font.ttf", ".state/font.ttf", "/srv/audit data/reports/font.ttf",
                     "/usr/local/aws-user-audit/.state/font.ttf"):
            with self.subTest(font=font):
                with self.assertRaises(docker_config.DockerConfigError):
                    self.pure_plan(config(PDF_FONT_PATH=font))

    def test_symlink_configuration_is_rejected_without_reading(self):
        with patch.object(Path, "is_symlink", return_value=True), \
                patch.object(docker_config, "load_config", side_effect=AssertionError("read symlink")):
            with self.assertRaisesRegex(docker_config.DockerConfigError, "符号链接"):
                self.plan()

    def test_non_regular_configuration_is_rejected(self):
        with self.assertRaisesRegex(docker_config.DockerConfigError, "普通文件"):
            docker_config.create_plan(self.root, HOST_CONFIG, container_config_path=CONTAINER_CONFIG)

    def test_private_posix_permissions_are_checked_without_fixing_them(self):
        for mode, accepted in ((0o600, True), (0o400, True), (0o640, False), (0o644, False), (0o666, False), (0o200, False)):
            info = os.stat_result((stat.S_IFREG | mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            with self.subTest(mode=oct(mode)), \
                    patch.object(docker_config, "_CHECK_POSIX_PERMISSIONS", True), \
                    patch.object(Path, "stat", return_value=info), \
                    patch.object(Path, "is_symlink", return_value=False), \
                    patch.object(Path, "chmod", side_effect=AssertionError("permissions modified")):
                if accepted:
                    docker_config._private_file(self.source)
                else:
                    with self.assertRaisesRegex(docker_config.DockerConfigError, "chmod 600"):
                        docker_config._private_file(self.source)

    def test_errors_do_not_disclose_configuration_values_or_original_exceptions(self):
        for failure in (ValueError("TEST_SECRET_ORIGINAL_EXCEPTION"), PermissionError("TEST_SECRET_PERMISSION")):
            with self.subTest(failure=type(failure).__name__), patch.object(docker_config, "load_config", side_effect=failure):
                with self.assertRaises(docker_config.DockerConfigError) as captured:
                    self.plan()
                self.assertNotIn("TEST_SECRET", str(captured.exception))
        self.source.write_text('{"SMTP_AUTH_CODE":"TEST_SECRET_BROKEN_JSON",', encoding="utf-8")
        with self.assertRaises(docker_config.DockerConfigError) as captured:
            self.plan()
        self.assertNotIn("TEST_SECRET", str(captured.exception))

    def test_cli_outputs_only_the_five_tab_separated_plan_fields(self):
        plan = self.plan()
        out, err = io.StringIO(), io.StringIO()
        with patch.object(docker_config, "create_plan", return_value=plan) as create, redirect_stdout(out), redirect_stderr(err):
            code = docker_config.main(["--config", CONTAINER_CONFIG, "--host-config-path", HOST_CONFIG, "--format", "env"])
        create.assert_called_once_with(CONTAINER_CONFIG, HOST_CONFIG)
        self.assertEqual(code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(out.getvalue().splitlines(), [key + "\t" + plan[key] for key in docker_config._ENV_KEYS])
        self.assertNotIn("TEST_SECRET", out.getvalue())

    def test_cli_font_fields_are_optional_and_json_format_is_secret_free(self):
        plan = self.pure_plan(config(PDF_FONT_PATH="fonts/chinese.ttf"))
        for format_name in ("env", "json"):
            out, err = io.StringIO(), io.StringIO()
            with patch.object(docker_config, "create_plan", return_value=plan), redirect_stdout(out), redirect_stderr(err):
                code = docker_config.main(["--config", CONTAINER_CONFIG, "--host-config-path", HOST_CONFIG, "--format", format_name])
            self.assertEqual(code, 0)
            self.assertEqual(err.getvalue(), "")
            self.assertNotIn("TEST_SECRET", out.getvalue())
            if format_name == "env":
                self.assertEqual(len(out.getvalue().splitlines()), 7)
            else:
                self.assertEqual(json.loads(out.getvalue()), plan)

    def test_cli_failure_has_no_stdout_and_generic_sanitized_stderr(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(docker_config, "create_plan", side_effect=docker_config.DockerConfigError("OUTPUT_DIRECTORY 路径无效。")), \
                redirect_stdout(out), redirect_stderr(err):
            code = docker_config.main(["--config", CONTAINER_CONFIG, "--host-config-path", HOST_CONFIG])
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("OUTPUT_DIRECTORY", err.getvalue())
        self.assertNotIn("TEST_SECRET", err.getvalue())

    def test_input_mappings_remain_unchanged(self):
        raw = config()
        before = deepcopy(raw)
        self.pure_plan(raw)
        self.assertEqual(raw, before)


if __name__ == "__main__":
    unittest.main()
