"""Publish one current multi-account page and optionally notify its Lark link.

The publisher renders normalized reports; it never copies report archives or
private configuration into the web root. Notification is separate from failure
alerts and is allowed only for the exact report already committed to index.html.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from aws_daily_audit import CATEGORIES, asset_url, render_html, report_assets


_PRIVATE_NAMES = {"aws-audit-config.json", "rds-audit-config.json", "lark-config.json",
                  "report.json", "lark-report.json", "credentials", "docker.env"}
_PRIVATE_DIRECTORIES = {".aws", ".git", ".state", ".installer-backups"}
_MARKER = "<!-- audit-publication:{signature} -->"


def _linked(path):
    if path.is_symlink():
        return True
    try:
        return bool(path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (AttributeError, FileNotFoundError):
        return False


def _safe_path(value):
    path = Path(value).expanduser().absolute()
    for component in (path, *path.parents):
        if _linked(component):
            raise ValueError("网页及状态路径不能经过符号链接或 junction")
    return path.resolve()


def _overlap(first, second):
    return first == second or first in second.parents or second in first.parents


def _public_directory(value):
    directory = _safe_path(value)
    if directory == Path(directory.anchor) or any(part in _PRIVATE_DIRECTORIES for part in directory.parts):
        raise ValueError("网页须使用独立公开子目录")
    if directory.exists():
        if not directory.is_dir():
            raise ValueError("网页路径必须为目录")
        # Refuse accidentally publishing an existing archive/configuration tree.
        # Never follow links while inspecting a pre-existing web root.
        for root, directories, files in os.walk(directory, followlinks=False):
            for name in directories + files:
                child = Path(root) / name
                if _linked(child) or name in _PRIVATE_NAMES or name in _PRIVATE_DIRECTORIES:
                    raise ValueError("网页目录包含私有文件或链接，请使用独立公开目录")
    return directory


def _reports(reports):
    if not isinstance(reports, list) or not reports:
        raise ValueError("网页至少需要一份账号报告")
    identities = set()
    for report in reports:
        if not isinstance(report, dict) or not isinstance(report.get("metadata"), dict):
            raise ValueError("网页报告格式无效")
        identity = report["metadata"].get("account_id")
        if not isinstance(identity, str) or not identity or identity in identities:
            raise ValueError("网页账号标识必须非空且不能重复")
        identities.add(identity)
    return reports


def _signature(reports):
    # Regenerating the same report changes only generated_at; it is not a new
    # report notification. The digest includes events but exposes no event text.
    normalized = [{**report, "metadata": {key: value for key, value in report["metadata"].items()
                                          if key != "generated_at"}}
                  for report in reports]
    normalized.sort(key=lambda report: report["metadata"]["account_id"])
    return hashlib.sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True,
                                     default=str).encode("utf-8")).hexdigest()


def _label(meta):
    name = meta.get("account_tag") or meta.get("account_name") or ""
    return f"{name} - {meta['account_id']}" if name else meta["account_id"]


def _render_page(reports):
    esc = lambda value: html.escape(str(value), quote=True)
    sections = []
    for report in reports:
        meta = report["metadata"]
        document = render_html(report)
        match = re.search(r"<body>(.*)</body>", document, re.DOTALL)
        if match is None:
            raise ValueError("详细报告缺少有效网页主体")
        body = re.sub(r'<label for="search">.*?</label><br><input id="search"[^>]*>', "",
                      match.group(1), count=1, flags=re.DOTALL)
        if 'id="search"' in body:
            raise ValueError("详细报告搜索控件格式发生变化")
        complete = meta.get("complete") is True
        status = "采集与解析完整" if complete else "数据不完整，请核查日志、权限与查询失败"
        sections.append('<article class="account-report"><header><h2>' + esc(_label(meta)) + '</h2>'
                        + '<p class="' + ("complete" if complete else "failed") + '">' + status + '</p>'
                        + '<p>查询范围（北京时间，结束时刻不含）：' + esc(meta["window_start_local"])
                        + ' 至 ' + esc(meta["window_end_local_exclusive"]) + '</p></header>' + body + '</article>')
    return ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>AWS 多账号最新操作审计报告</title><link rel="stylesheet" href="'
            + asset_url("audit-report.css") + '"><script src="' + asset_url("audit-report.js")
            + '" defer></script></head><body>' + _MARKER.format(signature=_signature(reports))
            + '<h1>AWS 多账号最新操作审计报告</h1><p>账号总数：' + str(len(reports))
            + '；本页在每次成功发布后覆盖为最新结果。</p>'
            '<label for="search">搜索所有账号的用户、资源、API、IP 或参数：</label><br>'
            '<input id="search" placeholder="搜索所有账号的操作记录" autocomplete="off">'
            + "".join(sections) + '</body></html>')


def _stage_file(directory, contents, mode):
    descriptor, filename = tempfile.mkstemp(prefix=".audit-publication-", suffix=".tmp", dir=directory)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def publish_latest_reports(reports, publish_dir):
    """Atomically replace index.html only after all account rendering succeeds."""
    reports = _reports(reports)
    directory = _public_directory(publish_dir)
    page = _render_page(reports)
    assets = report_assets()
    if set(assets) != {"audit-report.css", "audit-report.js"}:
        raise ValueError("网页静态资源白名单发生变化")
    missing = []
    ancestor = directory
    while not ancestor.exists():
        missing.append(ancestor)
        ancestor = ancestor.parent
    # Only directories created by this publication are made traversable. Never
    # recursively change a pre-existing private configuration/data parent.
    for component in reversed(missing):
        component.mkdir(exist_ok=True, mode=0o755)
        component.chmod(0o755)
    # systemd uses UMask=0077; creation's requested mode alone is insufficient.
    directory.chmod(0o755)
    staged = []
    try:
        for name, content in [*assets.items(), ("index.html", page)]:
            target = directory / name
            if _linked(target) or (target.exists() and not target.is_file()):
                raise ValueError("网页目标必须为普通文件")
            staged.append((_stage_file(directory, content, 0o644), target))
        # Assets precede the index commit, so a newly visible page never points
        # at absent CSS/JS. Rendering/staging failures leave the previous index.
        for temporary, target in staged:
            os.replace(temporary, target)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
    return directory / "index.html"


def _notification_payload(reports, url):
    from lark_notify import _fragment

    first = reports[0]["metadata"]
    total = sum(int(report["metadata"].get("total", 0)) for report in reports)
    failed = sum(int(report["metadata"].get("failed_or_partial", 0)) for report in reports)
    incomplete = sum(report["metadata"].get("complete") is not True for report in reports)
    lines = ["AWS多账号操作审计报告", "报表日期：" + _fragment(first["audit_date"], 20),
             "查询范围（北京时间，结束时刻不含）：",
             _fragment(first["window_start_local"], 40) + " 至 " + _fragment(first["window_end_local_exclusive"], 40),
             f"共 {len(reports)} 个账号；事件 {total} 条；失败或含失败响应 {failed} 条；不完整账号 {incomplete} 个。"]
    for category in CATEGORIES:
        count = sum(int(report["metadata"].get("counts", {}).get(category, 0)) for report in reports)
        if category != "其他操作" or count:
            lines.append(f"{category}：{count}")
    for report in reports[:30]:
        meta = report["metadata"]
        lines.append(_fragment(_label(meta), 80) + "：" + ("完整" if meta.get("complete") is True else "不完整"))
    if len(reports) > 30:
        lines.append(f"另有 {len(reports) - 30} 个账号，完整账号列表见网页。")
    lines.append("查看最新详细报告：" + url)
    return {"msg_type": "text", "content": {"text": "\n".join(lines)}}


def notify_report(config, reports, published_path, *, now=None):
    """Notify a committed page; persist deduplication only after Lark accepts it."""
    if not config.get("LARK_REPORT_ENABLED", False):
        return {"sent": False, "failed": False, "suppressed": False}
    from lark_notify import _payload_bytes, _send_payload, _signed_payload, _validate_report_url, validate_webhook_url

    try:
        reports = _reports(reports)
        published = _safe_path(published_path)
        if published.name != "index.html" or not published.is_file():
            raise ValueError("最新网页未成功发布")
        directory = _safe_path(config["STATE_DIRECTORY"])
        protected = [directory]
        if config.get("OUTPUT_DIRECTORY"):
            protected.append(_safe_path(config["OUTPUT_DIRECTORY"]))
        if any(_overlap(published.parent, path) for path in protected):
            raise ValueError("网页目录不能与私有报告或状态目录重叠")
        marker = _MARKER.format(signature=_signature(reports))
        # Read only the initial marker, not a potentially large detailed page.
        with published.open(encoding="utf-8") as stream:
            if marker not in stream.read(4096):
                raise ValueError("公开网页与本次报告不一致")
        url = _validate_report_url(config.get("REPORT_URL", ""))
        webhook = validate_webhook_url(config.get("LARK_WEBHOOK_URL", ""))
        payload = _notification_payload(reports, url)
        signature = hashlib.sha256(json.dumps([_signature(reports), payload], ensure_ascii=False,
                                              sort_keys=True).encode("utf-8")).hexdigest()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / "lark-report.json"
        if _linked(path) or (path.exists() and not path.is_file()):
            raise ValueError("通知状态必须为普通文件")
        if path.exists():
            if path.stat().st_size > 4096:
                raise ValueError("通知状态大小无效")
            prior = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(prior, dict):
                raise ValueError("通知状态格式无效")
            if prior.get("signature") == signature:
                return {"sent": False, "failed": False, "suppressed": True}
        clock = now or datetime.now(timezone.utc)
        signed = _signed_payload(payload, config.get("LARK_SIGNING_SECRET", ""), clock)
        if len(_payload_bytes(signed)) >= 20 * 1024:
            raise ValueError("报告摘要超出单条消息大小限制")
        # Stage a private success receipt before contacting Lark, but do not
        # commit it until the API accepts the message. Failed calls can retry.
        receipt = json.dumps({"signature": signature, "sent_at": clock.timestamp()}, sort_keys=True)
        temporary = _stage_file(directory, receipt, 0o600)
        try:
            _send_payload(signed, webhook, None)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return {"sent": True, "failed": False, "suppressed": False}
    except Exception:
        # Configuration, provider bodies, credentials and report details must
        # never be echoed by a notification failure.
        return {"sent": False, "failed": True, "suppressed": False}
