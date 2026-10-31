#!/usr/bin/env python3
"""Render systemd units and validate local configuration; never query or notify."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

DEFAULT_REPORT_URL = "https://zybocedata-pass.v668live.com/audit/"


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


def render_units(install_dir="/usr/local/shenji", publish_dir="/usr/local/shenji/index",
                 profile="audit", lark_config="/usr/local/shenji/lark-config.json",
                 report_url=DEFAULT_REPORT_URL, *, catch_up=True):
    install_dir, publish_dir, lark_config = map(linux_path, (install_dir, publish_dir, lark_config))
    validate_profile(profile)
    public = PurePosixPath(publish_dir)
    for private in (PurePosixPath(install_dir), PurePosixPath(install_dir) / "reports", PurePosixPath(lark_config)):
        if private == public or public in private.parents:
            raise ValueError("网页目录不能包含代码、归档报告或 Lark 私有配置。")
    from urllib.parse import urlsplit
    try:
        url = urlsplit(report_url)
        if (url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None
                or any(ord(ch) < 33 or ord(ch) == 127 for ch in report_url)):
            raise ValueError
        url.port
    except (ValueError, TypeError):
        raise ValueError("报告详情链接必须是有效的 HTTPS 地址。") from None
    install = PurePosixPath(install_dir)
    arguments = [str(install / ".venv/bin/python"), str(install / "deploy/run_scheduled.py"),
                 "--install-dir", install_dir, "--publish-dir", publish_dir,
                 "--profile", profile, "--lark-config", lark_config, "--report-url", report_url]
    service = """[Unit]
Description=AWS daily account operation audit and Lark overview
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
Description=AWS audit every day at 08:01 Beijing time

[Timer]
OnCalendar=*-*-* 08:01:00 Asia/Shanghai
AccuracySec=1s
RandomizedDelaySec=0
Persistent=""" + ("true" if catch_up else "false") + """
Unit=aws-user-audit.service

[Install]
WantedBy=timers.target
"""
    return {"aws-user-audit.service": service, "aws-user-audit.timer": timer}


def local_preflight(install_dir, profile, lark_config):
    """Use file-based configuration just as the system service does; no AWS API."""
    linux_path(install_dir)
    validate_profile(profile)
    target = Path(lark_config)
    if not target.is_file():
        raise ValueError("缺少私有 lark-config.json；请配置后重试，安装不会启用任务。")
    if os.name == "posix" and target.stat().st_mode & 0o077:
        raise ValueError("Lark 配置须仅任务用户可读写；请设置为 0600。")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from lark_notify import load_lark_config
    isolated = ("LARK_WEBHOOK_URL", "LARK_SIGNING_SECRET", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
                "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
    old_environment = {key: os.environ.pop(key) for key in isolated if key in os.environ}
    previous_home = os.environ.get("HOME")
    os.environ["HOME"] = "/root"
    try:
        load_lark_config(target)
        try:
            import boto3
            session = boto3.Session(profile_name=profile)
            if profile not in session.available_profiles:
                raise ValueError
        except ImportError:
            raise ValueError("虚拟环境缺少 boto3，请先安装 requirements.txt。") from None
        except Exception:
            raise ValueError("无法在 /root/.aws 本地配置中加载指定 profile；请先配置 root 凭据。未调用 AWS API。") from None
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
        command.add_argument("--profile", required=True)
        command.add_argument("--lark-config", required=True)
    render.add_argument("--publish-dir", required=True)
    render.add_argument("--report-url", default=DEFAULT_REPORT_URL)
    render.add_argument("--catch-up", choices=("yes", "no"), default="yes")
    render.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            local_preflight(args.install_dir, args.profile, args.lark_config)
            print("AWS profile 和 Lark 文件配置检查通过；未查询 AWS、未发送 Lark。")
            return 0
        units = render_units(args.install_dir, args.publish_dir, args.profile, args.lark_config,
                             args.report_url, catch_up=args.catch_up == "yes")
        directory = Path(args.output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        for name, value in units.items():
            (directory / name).write_text(value, encoding="utf-8", newline="\n")
        plan = {"install_dir": args.install_dir, "publish_dir": args.publish_dir,
                "profile": args.profile, "lark_config": args.lark_config,
                "report_url": args.report_url, "timezone": "Asia/Shanghai", "time": "08:01:00",
                "catch_up": args.catch_up == "yes", "installation_runs_report": False,
                "password_authentication": False}
        (directory / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("部署计划与 systemd 单元已生成；未修改系统服务。")
        return 0
    except (OSError, ValueError) as exc:
        print("部署配置检查失败：" + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
