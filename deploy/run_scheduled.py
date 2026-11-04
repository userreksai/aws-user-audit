#!/usr/bin/env python3
"""Run the most recent completed Beijing audit window, including boot catch-up."""
from __future__ import annotations

import argparse
from datetime import date, datetime, time, timedelta, timezone
import os
from pathlib import PurePosixPath
import subprocess
import sys
from zoneinfo import ZoneInfo


def report_date(now=None):
    now = now if now is not None else datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("执行时间必须带时区。")
    local = now.astimezone(ZoneInfo("Asia/Shanghai"))
    target = local.date() if local.time() >= time(8) else local.date() - timedelta(days=1)
    return target.isoformat()


def build_command(install_dir, config_path, now=None):
    install = PurePosixPath(install_dir)
    return [str(install / ".venv/bin/python"), str(install / "aws_audit_multi.py"),
            "--config", str(config_path), "--date", report_date(now), "--send-mail", "--automatic-mail"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", default="/usr/local/aws-user-audit")
    parser.add_argument("--config", help="统一私有 JSON/JSONC；默认 INSTALL_DIR/aws-audit-config.json")
    parser.add_argument("--date", help="手工补指定报表结束日期；不指定则最近已结束窗口")
    args = parser.parse_args(argv)
    try:
        config_path = args.config or str(PurePosixPath(args.install_dir) / "aws-audit-config.json")
        command = build_command(args.install_dir, config_path)
        if args.date:
            if date.fromisoformat(args.date).isoformat() != args.date:
                raise ValueError("日期须为 YYYY-MM-DD。")
            command[command.index("--date") + 1] = args.date
        selected = command[command.index("--date") + 1]
        print(f"开始多账号北京时间报表 {selected}：前一天07:00至该日08:00；生成 PDF 后合并邮件，Lark 仅异常。", flush=True)
        environment = os.environ.copy()
        # Honor the unified private file rather than inherited shell credentials.
        for key in ("LARK_WEBHOOK_URL", "LARK_SIGNING_SECRET", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                    "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
            environment.pop(key, None)
        return subprocess.run(command, cwd=args.install_dir, env=environment, check=False).returncode
    except (OSError, ValueError) as exc:
        print(f"日报任务启动失败：{type(exc).__name__}；请检查部署路径和参数。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
