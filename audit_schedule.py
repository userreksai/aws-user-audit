"""Beijing wall-clock validation and selection of completed report windows."""
from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
import re
from zoneinfo import ZoneInfo

DEFAULT_MAIL_TIME = "10:05"
DEFAULT_START_TIME = "10:00"
DEFAULT_END_TIME = "10:00"


def parse_clock(value, name="时间"):
    """Accept one unambiguous HH:MM without leaking the supplied value."""
    if not isinstance(value, str) or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value):
        raise ValueError(name + " 必须为 HH:MM，范围 00:00-23:59（北京时间）")
    hour, minute = map(int, value.split(":"))
    return time(hour, minute)


def latest_report_date(now=None, end_time=DEFAULT_END_TIME):
    """Select the most recent report-day boundary that has already ended."""
    now = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("执行时间必须带时区")
    local = now.astimezone(ZoneInfo("Asia/Shanghai"))
    target = local.date() if local.time() >= parse_clock(end_time, "REPORT_END_TIME") else local.date() - timedelta(days=1)
    return target.isoformat()
