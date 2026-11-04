#!/usr/bin/env python3
"""Multi-account CloudTrail reports, one PDF per account, one combined email."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import html
import os
from pathlib import Path
import sys
import tempfile

from audit_config import DEFAULT_INSTALL_DIR, load_config
from aws_daily_audit import (CATEGORIES, build_report, collect_region, publish_report,
                             report_assets, resolve_window, write_report)

UTC = timezone.utc


def collect_account(account, audit_date, start, end, *, session_factory=None):
    """Verify the configured account before reading its enabled-region events."""
    errors, events, regions, stats = [], [], [], []
    try:
        import boto3
        from botocore.config import Config
        arguments = {}
        if account["AWS_PROFILE"]:
            arguments["profile_name"] = account["AWS_PROFILE"]
        if account["AWS_ACCESS_KEY_ID"]:
            arguments.update(aws_access_key_id=account["AWS_ACCESS_KEY_ID"],
                             aws_secret_access_key=account["AWS_SECRET_ACCESS_KEY"])
            if account["AWS_SESSION_TOKEN"]:
                arguments["aws_session_token"] = account["AWS_SESSION_TOKEN"]
        session = (session_factory or boto3.Session)(**arguments)
        sdk = Config(retries={"mode": "standard", "total_max_attempts": 8}, connect_timeout=10, read_timeout=60)
        seed = session.region_name or "eu-north-1"
        identity = session.client("sts", region_name=seed, config=sdk).get_caller_identity()
        if identity.get("Account") != account["ACCOUNT_ID"]:
            raise ValueError("ConfiguredAccountMismatch")
        if account["REGIONS"] == "all":
            partition = session.get_partition_for_region(seed)
            found = session.client("ec2", region_name=seed, config=sdk).describe_regions(AllRegions=False)
            regions = sorted({r["RegionName"] for r in found["Regions"]
                              if r.get("OptInStatus") in (None, "opt-in-not-required", "opted-in")})
            if not regions:
                raise ValueError("NoEnabledRegions")
            if partition == "aws":
                regions = sorted(set(regions) | {"us-east-1"})
        else:
            regions = list(account["REGIONS"])
        for region in regions:
            print(f"账号 {account['ACCOUNT_ID']} 查询 {region}", file=sys.stderr, flush=True)
            try:
                client = session.client("cloudtrail", region_name=region, config=sdk)
                rows, failures, region_stat = collect_region(client, region, start, end)
                events.extend(rows)
                stats.append(region_stat)
                if failures:
                    errors.append(f"{region}：CloudTrail 查询或解析失败 {len(failures)} 项；请检查权限及网络")
            except Exception as exc:
                errors.append(f"{region}：CloudTrail 查询失败（{type(exc).__name__}）")
    except Exception as exc:
        # Do not include arbitrary SDK messages or Access Keys in saved reports.
        errors.append(f"账号身份核验或区域发现失败（{type(exc).__name__}）；请核对配置账号、凭据、权限及网络")
    report = build_report(events, audit_date=audit_date, timezone_name="Asia/Shanghai", start=start, end=end,
                          account_id=account["ACCOUNT_ID"], regions=regions, errors=errors,
                          region_stats=stats, window_mode="daily_25h")
    report["metadata"]["account_name"] = account["NAME"]
    return report


def _public_file(target, content):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor, temporary = tempfile.mkstemp(prefix=".audit-index-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
        Path(temporary).chmod(0o644)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def publish_accounts(reports, folders, public_dir):
    """Publish each account and commit an overview after all detail pages succeed."""
    public = Path(public_dir)
    rows = []
    for report, folder in zip(reports, folders):
        meta = report["metadata"]
        account_id = meta["account_id"]
        publish_report(folder / f"{meta['audit_date']}-aws操作审计.html", public / account_id)
        counts = meta["counts"]
        cells = "".join(f"<td>{counts.get(category, 0)}</td>" for category in CATEGORIES)
        name = html.escape(str(meta.get("account_name", "")))
        state = "查询完成" if meta["complete"] else "采集不完整"
        rows.append(f'<tr><td><a href="{account_id}/">{name} ({account_id})</a></td>{cells}<td>{state}</td></tr>')
    for name, content in report_assets().items():
        _public_file(public / name, content)
    headers = "".join(f"<th>{html.escape(category)}</th>" for category in CATEGORIES)
    day = html.escape(str(reports[0]["metadata"]["audit_date"]))
    page = ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>AWS 多账号操作审计日报</title><link rel="stylesheet" href="audit-report.css"></head><body>'
            f'<h1>AWS 多账号操作审计日报 · {day}</h1><section><h2>账号总览</h2><div class="scroll"><table>'
            f'<thead><tr><th>账号（点击查看操作明细）</th>{headers}<th>查询状态</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div></section></body></html>')
    _public_file(public / "index.html", page)


def run_report(config, day, *, send_mail=False, automatic_mail=False, force_resend=False,
               no_publish=False, now=None):
    """Collect the same finished 25-hour window for every enabled account."""
    from audit_alerts import notify_issues
    from audit_mail_delivery import _locked, deliver_reports
    from audit_pdf import render_report_pdf

    supplied_clock = now
    now = now or datetime.now(UTC)
    audit_date, start, end, _ = resolve_window(day, "Asia/Shanghai", now=now, daily=True)
    if start < now - timedelta(days=90):
        raise ValueError("窗口超出 CloudTrail LookupEvents 90 天范围")
    accounts = [account for account in config["ACCOUNTS"] if account["ENABLED"]]
    issues = []
    state = Path(config["STATE_DIRECTORY"])
    if state.is_symlink():
        raise ValueError("状态目录不能为符号链接")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not state.is_dir() or (os.name == "posix" and state.stat().st_mode & 0o077):
        raise ValueError("状态目录须仅任务用户可访问，请设置为 0700")
    # A job lock keeps reports, web publication and notifications from racing.
    with _locked(state / "job"):
        archive = Path(config["OUTPUT_DIRECTORY"])
        archive.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            archive.chmod(0o700)
        with ThreadPoolExecutor(max_workers=min(config["ACCOUNT_CONCURRENCY"], len(accounts))) as pool:
            reports = list(pool.map(lambda account: collect_account(account, audit_date, start, end), accounts))
        folders, pdfs = [], []
        for report in reports:
            meta = report["metadata"]
            account = meta["account_id"]
            if not meta["complete"]:
                issues.append({"account_id": account, "stage": "collection"})
            try:
                folder = write_report(report, config["OUTPUT_DIRECTORY"])
                folders.append(folder)
                pdf = folder / f"{account}-{audit_date}-aws操作审计.pdf"
                render_report_pdf(report, pdf, config.get("PDF_FONT_PATH") or None)
                pdfs.append(pdf)
                print(f"账号 {account} PDF 已生成：{pdf}", flush=True)
            except Exception as exc:
                issues.append({"account_id": account, "stage": "pdf"})
                print(f"账号 {account} 报告生成失败（{type(exc).__name__}）；其他账号继续。", file=sys.stderr)
        if not no_publish and len(folders) == len(reports):
            try:
                publish_accounts(reports, folders, config["PUBLISH_DIRECTORY"])
                print("多账号网页已更新。", flush=True)
            except Exception as exc:
                issues.append({"stage": "publish"})
                print(f"网页发布失败（{type(exc).__name__}）；仍尝试发送完整 PDF 附件。", file=sys.stderr)
        if send_mail:
            if len(pdfs) != len(reports):
                issues.append({"stage": "mail"})
                print("邮件未发送：部分账号 PDF 生成失败，已保留其他报告。", file=sys.stderr)
            else:
                result = deliver_reports(reports, pdfs, config, config["STATE_DIRECTORY"],
                                         automatic=automatic_mail, force_resend=force_resend,
                                         now=supplied_clock or datetime.now(UTC),
                                         report_url="" if no_publish or any(i["stage"] == "publish" for i in issues)
                                         else config["REPORT_URL"])
                status = result["status"]
                if status in {"failed", "uncertain"}:
                    issues.append({"stage": "mail"})
                print({"accepted": "邮件服务器已接受所有账号的 PDF 附件。",
                       "suppressed": "邮件未重复发送：已存在投递记录或已用完当日自动额度。",
                       "disabled": "自动邮件已关闭；本地报告已更新。",
                       "failed": "邮件发送失败；PDF 已保留，请检查 SMTP 配置和网络。",
                       "uncertain": "邮件投递结果未确认；PDF 已保留，请核实后再手动重发。"}.get(status, "邮件状态未确认。"), flush=True)
        alert = notify_issues(config, audit_date, issues, now=supplied_clock or datetime.now(UTC))
        if alert["failed"]:
            print("Lark 异常告警投递失败；请检查机器人配置。", file=sys.stderr)
        if any(item["stage"] == "collection" for item in issues):
            return 2
        if any(item["stage"] == "pdf" for item in issues):
            return 5
        if any(item["stage"] == "mail" for item in issues) or alert["failed"]:
            return 3
        return 4 if issues else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_INSTALL_DIR + "/aws-audit-config.json")
    parser.add_argument("--date", help="北京时间报表结束日期；前一天07:00至该日08:00")
    parser.add_argument("--send-mail", action="store_true", help="所有账号 PDF 合并一封邮件发送")
    parser.add_argument("--automatic-mail", action="store_true", help="应用北京时间每日最多一封的自动额度")
    parser.add_argument("--force-resend", action="store_true", help="核实历史投递后显式手动重发")
    parser.add_argument("--no-publish", action="store_true")
    parser.add_argument("--check-config", action="store_true", help="只校验本地配置，不调用 AWS/SMTP/Lark")
    args = parser.parse_args(argv)
    config = None
    try:
        if (args.automatic_mail and not args.send_mail) or (args.force_resend and (not args.send_mail or args.automatic_mail)):
            raise ValueError("自动额度必须配合 --send-mail；--force-resend 仅用于手动发送")
        config = load_config(args.config)
        require_mail = args.send_mail and (not args.automatic_mail or config["AUTO_MAIL_MAX_PER_DAY"] != 0)
        if require_mail or (args.check_config and config["AUTO_MAIL_MAX_PER_DAY"]):
            config = load_config(args.config, require_mail=True)
        if args.check_config:
            print("多账号、邮件与异常告警配置本地检查通过；未查询 AWS、未发送通知。")
            return 0
        return run_report(config, args.date, send_mail=args.send_mail, automatic_mail=args.automatic_mail,
                          force_resend=args.force_resend, no_publish=args.no_publish)
    except Exception as exc:
        # Only field validation errors are trusted; SDK/transport text is omitted.
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(f"日报任务失败：{message}；报告如已生成则保留。", file=sys.stderr)
        if config:
            from audit_alerts import notify_issues
            notify_issues(config, "任务启动失败", [{"stage": "job"}])
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
