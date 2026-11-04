"""Send bounded operational failures to Lark; normal reports are email only."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile


def notify_issues(config, report_day, issues, *, now=None):
    """Called with the job lock held. Failed webhooks are retried on the next run."""
    if not config.get("LARK_ALERTS_ENABLED", False) or not issues:
        return {"sent": False, "failed": False}
    from lark_notify import _send_payload, _signed_payload, validate_webhook_url

    now = now or datetime.now(timezone.utc)
    stages = {"collection": "采集或解析不完整", "pdf": "PDF 生成失败", "publish": "网页发布失败",
              "mail": "邮件投递失败或未确认", "job": "任务执行失败"}
    # Provider errors, request parameters and credentials never enter this payload.
    safe = []
    for item in issues:
        account = str(item.get("account_id", "全部账号"))
        if not re.fullmatch(r"[0-9]{12}", account):
            account = "全部账号"
        stage = stages.get(item.get("stage"), stages["job"])
        safe.append(f"账号 {account}：{stage}")
    safe = sorted(set(safe))
    signature = hashlib.sha256(json.dumps([report_day, safe], ensure_ascii=False).encode()).hexdigest()
    directory = Path(config["STATE_DIRECTORY"])
    path = directory / "lark-failure.json"
    try:
        prior = json.loads(path.read_text(encoding="utf-8")) if path.is_file() and not path.is_symlink() else {}
        if (isinstance(prior, dict) and prior.get("signature") == signature
                and isinstance(prior.get("sent_at"), (int, float))
                and 0 <= now.timestamp() - prior["sent_at"] < 3600):
            return {"sent": False, "failed": False, "suppressed": True}
    except (OSError, ValueError):
        pass
    payload = {"msg_type": "text", "content": {"text": "AWS账号审计异常\n报表日期：" + report_day
               + "\n" + "\n".join(safe[:50]) + (f"\n另有 {len(safe)-50} 项" if len(safe) > 50 else "")
               + "\n请检查：journalctl -u aws-user-audit.service -n 100 --no-pager"}}
    try:
        _send_payload(_signed_payload(payload, config.get("LARK_SIGNING_SECRET", ""), now),
                      validate_webhook_url(config["LARK_WEBHOOK_URL"]), None)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary = tempfile.mkstemp(prefix=".lark-failure-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump({"signature": signature, "sent_at": now.timestamp()}, stream)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return {"sent": True, "failed": False}
    except Exception:
        # Do not echo a token-bearing URL, provider response or secret value.
        return {"sent": False, "failed": True}
