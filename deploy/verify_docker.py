"""Build/run the production image on a Docker-enabled Linux CI runner."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "aws-user-audit:ci"
CONTAINER_CONFIG = "/usr/local/aws-user-audit/aws-audit-config.json"


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, cwd=ROOT, **kwargs)


def fixture(path, *, mail=False):
    config = {"AUTO_MAIL_MAX_PER_DAY": int(mail), "ACCOUNTS": [
        {"NAME": f"smoke-{index}", "TAG": f"演示-{index}", "ACCOUNT_ID": f"{index:012d}",
         "AWS_ACCESS_KEY_ID": f"SMOKE-{index:012d}", "AWS_SECRET_ACCESS_KEY": "SMOKE_PRIVATE",
         "REGIONS": ["eu-north-1"]} for index in (1, 2)]}
    if mail:
        config.update(SMTP_HOST="smtp.example.invalid", SMTP_USERNAME="smoke@example.invalid",
                      SMTP_AUTH_CODE="SMOKE_SMTP_PRIVATE", MAIL_RECIPIENTS=["recipient@example.invalid"])
    else:
        # Keep the next daemon deadline far from this smoke test, including if
        # CI happens to start immediately before the production 10:05 boundary.
        config.update(DAILY_MAIL_TIME=(datetime.now(ZoneInfo("Asia/Shanghai")) + timedelta(minutes=30)).strftime("%H:%M"),
                      REPORT_START_TIME="00:00", REPORT_END_TIME="00:00")
    path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
    path.chmod(0o600)


def main():
    run("docker", "build", "--tag", IMAGE, ".")
    # Verify the image really excludes Git-ignored inputs and test projects.
    run("docker", "run", "--rm", "--network", "none", "--entrypoint", "/app/.venv/bin/python", IMAGE,
        "-c", "from pathlib import Path; p=Path('/app'); assert not any((p/n).exists() for n in "
        "['.git','.aws','.venv-host','aws-audit-config.json','lark-config.json','aws-rds-audit','test_audit_pdf.py']); "
        "assert (p/'audit_publication.py').is_file(); from audit_publication import publish_latest_reports; "
        "from audit_pdf import _font; assert _font().startswith('AuditCjk-'); print('Image allowlist and embedded Chinese font verified')")
    with tempfile.TemporaryDirectory(prefix="audit docker-ci-") as directory:
        root = Path(directory)
        config, reports, state, publish = root / "config.json", root / "reports", root / "state", root / "index"
        reports.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        publish.mkdir(mode=0o755)
        fixture(config)
        mounts = ["--mount", f"type=bind,src={config},dst={CONTAINER_CONFIG},readonly",
                  "--mount", f"type=bind,src={reports},dst=/usr/local/aws-user-audit/reports",
                  "--mount", f"type=bind,src={state},dst=/usr/local/aws-user-audit/.state",
                  "--mount", f"type=bind,src={publish},dst=/usr/local/aws-user-audit/index"]
        base = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--user", f"{os.getuid()}:{os.getgid()}", *mounts]
        original = config.read_bytes()
        run(*base, IMAGE, "check-config", "--config", CONTAINER_CONFIG)
        plan = run(*base, "--entrypoint", "/app/.venv/bin/python", IMAGE, "/app/deploy/docker_config.py",
                   "--config", CONTAINER_CONFIG, "--host-config-path", str(config), "--format", "json",
                   capture_output=True, text=True)
        assert json.loads(plan.stdout)["AUDIT_REQUIRES_PROFILE"] == "0"
        name = "audit-schedule-ci-" + str(os.getpid())
        def start():
            run("docker", "run", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--user", f"{os.getuid()}:{os.getgid()}",
                *mounts, IMAGE, "schedule", "--config", CONTAINER_CONFIG,
                stdout=subprocess.DEVNULL)
        try:
            start()
            deadline = time.monotonic() + 30
            while not (state / "docker-schedule.json").exists() and time.monotonic() < deadline:
                time.sleep(0.2)
            assert (state / "docker-schedule.json").is_file(), "Scheduler did not initialize"
            saved = (state / "docker-schedule.json").read_bytes()
            deadline = time.monotonic() + 30
            health = None
            while time.monotonic() < deadline:
                health = subprocess.run(["docker", "exec", name, "/app/.venv/bin/python", "/app/deploy/docker_runtime.py",
                                         "healthcheck", "--config", CONTAINER_CONFIG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if health.returncode == 0:
                    break
                time.sleep(0.2)
            assert health is not None and health.returncode == 0, "Scheduler heartbeat never became healthy"
            assert not any(reports.iterdir()), "First start must not collect or send"
            run("docker", "stop", "--time", "25", name, stdout=subprocess.DEVNULL)
            result = run("docker", "inspect", "--format", "{{.State.ExitCode}}", name, capture_output=True, text=True)
            assert result.stdout.strip() in {"0", "143"}, "Unclean scheduler termination"
            run("docker", "rm", name, stdout=subprocess.DEVNULL)
            start()
            time.sleep(2)
            assert (state / "docker-schedule.json").read_bytes() == saved
            assert not any(reports.iterdir())
            assert config.read_bytes() == original
            run("docker", "exec", name, "/app/.venv/bin/python", "/app/deploy/docker_runtime.py", "healthcheck", "--config", CONTAINER_CONFIG)
        finally:
            subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Check real read-only profile and custom font binds without credential
        # retrieval. Public package data and local INI files are sufficient.
        aws = root / "aws"
        aws.mkdir(mode=0o700)
        (aws / "config").write_text("[profile audit]\nregion=eu-north-1\n", encoding="utf-8")
        (aws / "credentials").write_text("[audit]\naws_access_key_id=SMOKE_PROFILE\naws_secret_access_key=SMOKE_SECRET\n", encoding="utf-8")
        for path in aws.iterdir():
            path.chmod(0o600)
        fonts = root / "fonts"
        fonts.mkdir()
        font_data = run("docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", IMAGE,
                        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc", capture_output=True).stdout
        font_file = fonts / "custom.ttc"
        font_file.write_bytes(font_data)
        profile_config = json.loads(config.read_text(encoding="utf-8"))
        profile_config["PDF_FONT_PATH"] = "fonts/custom.ttc"
        for account in profile_config["ACCOUNTS"]:
            account.pop("AWS_ACCESS_KEY_ID")
            account.pop("AWS_SECRET_ACCESS_KEY")
            account["AWS_PROFILE"] = "audit"
        config.write_text(json.dumps(profile_config), encoding="utf-8")
        profile_mounts = ["--mount", f"type=bind,src={aws},dst=/root/.aws,readonly",
                          "--mount", f"type=bind,src={font_file},dst=/usr/local/aws-user-audit/fonts/custom.ttc,readonly"]
        run(*base, *profile_mounts, IMAGE, "check-config", "--config", CONTAINER_CONFIG)
        run(*base, *profile_mounts, "--entrypoint", "/app/.venv/bin/python", IMAGE, "-c",
            "import sys; sys.path.insert(0,'/app'); from audit_pdf import _font; "
            "assert _font('/usr/local/aws-user-audit/fonts/custom.ttc').startswith('AuditCjk-')")
        fixture(config, mail=True)
        run(*base, "--mount", f"type=bind,src={ROOT / 'deploy/docker_smoke.py'},dst=/tmp/docker_smoke.py,readonly",
            "--entrypoint", "/app/.venv/bin/python", IMAGE, "/tmp/docker_smoke.py")
        from pypdf import PdfReader
        for account in ("000000000001", "000000000002"):
            pdf = reports / account / "2026-11-05" / f"{account}-2026-11-05-aws操作审计.pdf"
            text = "\n".join(page.extract_text() or "" for page in PdfReader(pdf).pages)
            assert "AI 对话：发送消息" in text and "newest-smoke-actor" in text
            assert "角色身份不直接认定为自然人" not in text
        assert (state / "mail-delivery.json").stat().st_mode & 0o777 == 0o600
        env = {**os.environ, "AUDIT_CONFIG_PATH": str(config), "AUDIT_REPORTS_DIR": str(reports),
               "AUDIT_STATE_DIR": str(state), "AUDIT_PUBLISH_DIR": str(publish), "AUDIT_IMAGE": IMAGE}
        run("docker", "compose", "-f", "compose.yaml", "config", "--quiet", env=env)
        env.update(AUDIT_AWS_DIR=str(root / "aws"), AUDIT_FONT_SOURCE="/usr/share/fonts/fake.ttf",
                   AUDIT_CONTAINER_FONT_PATH="/usr/share/fonts/fake.ttf")
        run("docker", "compose", "-f", "compose.yaml", "-f", "compose.aws-profile.yaml", "-f", "compose.font.yaml",
            "config", "--quiet", env=env)
        # Run the shipped installer against the real daemon, without starting a
        # scheduler. Its output env file must work from outside the checkout.
        install_env = {**os.environ, "AUDIT_IMAGE": IMAGE}
        try:
            before_install = config.read_bytes()
            run("bash", "install-docker.sh", "--data-dir", str(root), "--config", str(config), "--no-start", env=install_env)
            assert config.read_bytes() == before_install
            subprocess.run(["docker", "compose", "--env-file", str(root / "docker.env"), "config", "--quiet"],
                           cwd="/tmp", env=install_env, check=True)
        finally:
            if (root / "docker.env").exists():
                subprocess.run(["docker", "compose", "--env-file", str(root / "docker.env"), "down", "--remove-orphans"],
                               cwd="/tmp", env=install_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Production Docker image, scheduler restart/health, offline mail and Compose verified.")


if __name__ == "__main__":
    main()
