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


def build_command(install_dir, profile, lark_config, publish_dir,
                  report_url="https://zybocedata-pass.v668live.com/audit/", now=None):
    install = PurePosixPath(install_dir)
    return [str(install / ".venv/bin/python"), str(install / "aws_daily_audit.py"),
            "--profile", profile, "--regions", "all", "--timezone", "Asia/Shanghai",
            "--date", report_date(now), "--output-dir", str(install / "reports"),
            "--publish-dir", str(publish_dir), "--send-lark", "--lark-mode", "overview",
            "--lark-config", str(lark_config), "--report-url", report_url]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", default="/usr/local/shenji")
    parser.add_argument("--publish-dir", default="/usr/local/shenji/index")
    parser.add_argument("--profile", default="audit")
    parser.add_argument("--lark-config", default="/usr/local/shenji/lark-config.json")
    parser.add_argument("--report-url", default="https://zybocedata-pass.v668live.com/audit/")
    parser.add_argument("--date", help="手工补指定报表结束日期；不指定则最近已结束窗口")
    args = parser.parse_args(argv)
    try:
        command = build_command(args.install_dir, args.profile, args.lark_config, args.publish_dir, args.report_url)
        if args.date:
            if date.fromisoformat(args.date).isoformat() != args.date:
                raise ValueError("日期须为 YYYY-MM-DD。")
            command[command.index("--date") + 1] = args.date
        selected = command[command.index("--date") + 1]
        print(f"开始审计北京时间报表 {selected}：前一天07:00至该日08:00；发布后通知 Lark。", flush=True)
        environment = os.environ.copy()
        # The deployment explicitly preserves lark-config.json; stale shell
        # overrides must not silently point scheduled delivery at another bot.
        environment.pop("LARK_WEBHOOK_URL", None)
        environment.pop("LARK_SIGNING_SECRET", None)
        return subprocess.run(command, cwd=args.install_dir, env=environment, check=False).returncode
    except (OSError, ValueError) as exc:
        print(f"日报任务启动失败：{type(exc).__name__}；请检查部署路径和参数。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
