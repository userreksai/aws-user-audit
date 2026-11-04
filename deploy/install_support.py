#!/usr/bin/env python3
"""Render systemd units and validate local configuration; never query or notify."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

DEFAULT_INSTALL_DIR = "/usr/local/aws-user-audit"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from audit_schedule import (DEFAULT_MAIL_TIME as DEFAULT_DAILY_MAIL_TIME,
                            DEFAULT_START_TIME as DEFAULT_REPORT_START_TIME,
                            DEFAULT_END_TIME as DEFAULT_REPORT_END_TIME, parse_clock)


def configured_schedule(config_path):
    """Read only local validated configuration; missing first-install files use defaults."""
    path = Path(config_path)
    if path.is_symlink():
        raise ValueError("统一配置不能为符号链接。")
    if path.exists():
        from audit_config import load_config
        config = load_config(path, require_mail=False)
    else:
        config = {}
    return {"daily_mail_time": config.get("DAILY_MAIL_TIME", DEFAULT_DAILY_MAIL_TIME),
            "report_start_time": config.get("REPORT_START_TIME", DEFAULT_REPORT_START_TIME),
            "report_end_time": config.get("REPORT_END_TIME", DEFAULT_REPORT_END_TIME)}


def linux_path(value):
    value = os.fspath(value)
    if (not re.fullmatch(r"/[A-Za-z0-9_./-]+", value) or value.startswith("//")
            or any(part in {".", ".."} for part in value.split("/"))):
        raise ValueError("部署路径必须是明确的 Linux 绝对路径，只能使用字母、数字、下划线、点、短横线和斜杠。")
    result = str(PurePosixPath(value))
    if result in {"/", "/etc", "/usr", "/usr/local", "/var", "/root", "/home", "/tmp"}:
        raise ValueError("不能直接将系统根目录或公共父目录作为部署目录。")
    return result


def validate_profile(value):
    if not re.fullmatch(r"[A-Za-z0-9_.@+-]+", value):
        raise ValueError("AWS profile 名称只能包含字母、数字和 _.@+-。")
    return value


def unit_arg(value):
    # systemd interprets percent specifiers and $ENV independently of shell.
    value = str(value).replace("%", "%%").replace("$", "$$")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_units(install_dir=DEFAULT_INSTALL_DIR, publish_dir=None, config_path=None, *, catch_up=True,
                 daily_mail_time=DEFAULT_DAILY_MAIL_TIME):
    """Render PDF/mail units; ``publish_dir`` is ignored for old callers."""
    parse_clock(daily_mail_time, "DAILY_MAIL_TIME")
    install_dir = linux_path(install_dir)
    config_path = linux_path(config_path or str(PurePosixPath(install_dir) / "aws-audit-config.json"))
    install = PurePosixPath(install_dir)
    arguments = [str(install / ".venv/bin/python"), str(install / "deploy/run_scheduled.py"),
                 "--install-dir", install_dir, "--config", config_path]
    service = """[Unit]
Description=AWS daily multi-account operation audit and PDF email
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
Group=root
Environment=HOME=/root
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=""" + install_dir + "\nExecStart=" + " ".join(map(unit_arg, arguments)) + """
TimeoutStartSec=2h
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
StandardOutput=journal
StandardError=journal
"""
    timer = """[Unit]
Description=AWS audit every day at """ + daily_mail_time + """ Beijing time

[Timer]
OnCalendar=*-*-* """ + daily_mail_time + """:00 Asia/Shanghai
AccuracySec=1s
RandomizedDelaySec=0
Persistent=""" + ("true" if catch_up else "false") + """
Unit=aws-user-audit.service

[Install]
WantedBy=timers.target
"""
    return {"aws-user-audit.service": service, "aws-user-audit.timer": timer}


def local_preflight(install_dir, config_path, publish_dir=None, *, expected_schedule=None):
    """Validate locally; legacy ``publish_dir`` no longer controls a webroot."""
    linux_path(install_dir)
    target = Path(config_path)
    if not target.is_file() or target.is_symlink():
        raise ValueError("缺少普通私有 aws-audit-config.json；请配置后重试，安装不会启用任务。")
    if os.name == "posix" and target.stat().st_mode & 0o077:
        raise ValueError("统一配置须仅任务用户可读写；请设置为 0600。")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from audit_config import load_config
    isolated = ("LARK_WEBHOOK_URL", "LARK_SIGNING_SECRET", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
                "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
    old_environment = {key: os.environ.pop(key) for key in isolated if key in os.environ}
    previous_home = os.environ.get("HOME")
    os.environ["HOME"] = "/root"
    try:
        config = load_config(target, require_mail=False)
        if config.get("AUTO_MAIL_MAX_PER_DAY", 1):
            config = load_config(target, require_mail=True)
        if expected_schedule is not None:
            actual = (config.get("DAILY_MAIL_TIME", DEFAULT_DAILY_MAIL_TIME),
                      config.get("REPORT_START_TIME", DEFAULT_REPORT_START_TIME),
                      config.get("REPORT_END_TIME", DEFAULT_REPORT_END_TIME))
            if tuple(expected_schedule) != actual:
                raise ValueError("生成计划后时间配置已变化，请重新运行安装器；未修改 systemd。")
        profiles = sorted({validate_profile(account["AWS_PROFILE"])
                           for account in config["ACCOUNTS"]
                           if account.get("ENABLED", True) and account.get("AWS_PROFILE")})
        if not profiles:
            return config
        try:
            import boto3
            for profile in profiles:
                session = boto3.Session(profile_name=profile)
                if profile not in session.available_profiles:
                    raise ValueError
        except ImportError:
            raise ValueError("虚拟环境缺少 boto3，请先安装 requirements.txt。") from None
        except Exception:
            raise ValueError("无法在 /root/.aws 本地配置中加载启用账号的 profile；请配置 root 凭据。未调用 AWS API。") from None
        return config
    finally:
        os.environ.update(old_environment)
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render")
    check = commands.add_parser("preflight")
    for command in (render, check):
        command.add_argument("--install-dir", required=True)
        command.add_argument("--config", required=True)
        command.add_argument("--publish-dir", help="兼容旧命令；已忽略，不创建网页或操作 Nginx")
    render.add_argument("--catch-up", choices=("yes", "no"), default="yes")
    render.add_argument("--output-dir", required=True)
    check.add_argument("--daily-mail-time", help="安装器已生成计划中的发送时刻，用于检查并发修改")
    check.add_argument("--report-start-time")
    check.add_argument("--report-end-time")
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            expected = (args.daily_mail_time, args.report_start_time, args.report_end_time)
            if any(value is not None for value in expected) and not all(value is not None for value in expected):
                raise ValueError("安装计划的三个时间字段必须一起提供。")
            local_preflight(args.install_dir, args.config, args.publish_dir,
                            expected_schedule=expected if all(value is not None for value in expected) else None)
            print("多账号与邮件私有配置检查通过；未查询 AWS、未发送邮件或 Lark。")
            return 0
        schedule = configured_schedule(args.config)
        units = render_units(args.install_dir, args.publish_dir, args.config, catch_up=args.catch_up == "yes",
                             daily_mail_time=schedule["daily_mail_time"])
        directory = Path(args.output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        for name, value in units.items():
            (directory / name).write_text(value, encoding="utf-8", newline="\n")
        plan = {"install_dir": args.install_dir,
                "config": args.config, "timezone": "Asia/Shanghai", "time": schedule["daily_mail_time"] + ":00",
                **schedule,
                "catch_up": args.catch_up == "yes", "installation_runs_report": False,
                "report_formats": ["pdf", "json"], "html_publication": False}
        (directory / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # A validated, single-line settings subset for the Bash installer; never secrets.
        (directory / "schedule.env").write_text(
            "DAILY_MAIL_TIME=" + schedule["daily_mail_time"] + "\n"
            + "REPORT_START_TIME=" + schedule["report_start_time"] + "\n"
            + "REPORT_END_TIME=" + schedule["report_end_time"] + "\n", encoding="utf-8", newline="\n")
        print("部署计划与 systemd 单元已生成；未修改系统服务。")
        return 0
    except (OSError, ValueError) as exc:
        print("部署配置检查失败：" + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
