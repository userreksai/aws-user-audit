"""Offline, service-specific Chinese labels for CloudTrail events.

Only checked-in labels and reviewed API rules are used. This module never
constructs an SDK client, resolves credentials, or makes network requests.
"""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from audit_actions import SERVICES, lookup_action

CATALOG_PATH = Path(__file__).with_name("aws-event-translations.json")
_SOURCE = re.compile(r"([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{0,159}\Z")
_STATUSES = {"reviewed", "official_zh"}


def _safe_reference(value):
    if not isinstance(value, str):
        return ""
    try:
        url = urlsplit(value)
        if (url.scheme == "https" and url.hostname == "docs.aws.amazon.com"
                and not url.username and not url.password and url.port in (None, 443)
                and not url.query and not url.fragment.startswith("javascript:")):
            return value
    except ValueError:
        pass
    return ""


def _valid_record(record):
    if (not isinstance(record, dict) or not isinstance(record.get("translation_status"), str)
            or record.get("translation_status") not in _STATUSES):
        return None
    label = record.get("event_label")
    reference = _safe_reference(record.get("operation_reference"))
    if (not isinstance(label, str) or not label.strip() or len(label) > 600
            or any(ord(char) < 32 for char in label) or not reference):
        return None
    service = record.get("service_name")
    return {"event_label": label, "translation_status": record["translation_status"],
            "operation_reference": reference,
            "service_name": service if isinstance(service, str) and len(service) <= 200 else "AWS"}


@lru_cache(maxsize=1)
def _catalog():
    try:
        if CATALOG_PATH.stat().st_size > 32 * 1024 * 1024:
            return {}
        data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        if data.get("schema_version") != 1 or not isinstance(data.get("entries"), dict):
            return {}
        return data["entries"]
    except (OSError, ValueError, AttributeError):
        # A missing optional catalog must not prevent the daily audit.
        return {}


def translate_event(event):
    """Return a label and provenance for exactly this service and API name.

    China event sources share the API meanings of their standard partition.
    Unknown operations retain their original names and visibly lack a Chinese
    translation. A dictionary match cannot change event filtering or category.
    """
    event = event if isinstance(event, dict) else {}
    source = event.get("eventSource")
    source = source.lower() if isinstance(source, str) else "未知服务"
    name = event.get("eventName")
    name = name if isinstance(name, str) else "未知事件"
    found = _SOURCE.fullmatch(source)
    prefix = found[1] if found else ""
    display = SERVICES[prefix][1] if prefix in SERVICES else source
    fallback = {"event_label": f"待补中文：{source} / {name}",
                "translation_status": "untranslated", "operation_reference": "",
                "service_name": display}
    if not found or not _NAME.fullmatch(name):
        return fallback
    canonical = prefix + ".amazonaws.com"
    service_entries = _catalog().get(canonical, {})
    record = _valid_record(service_entries.get(name)) if isinstance(service_entries, dict) else None
    if record and record["translation_status"] == "reviewed":
        return record
    reviewed = lookup_action({"eventSource": canonical, "eventName": name})
    if reviewed:
        return {"event_label": reviewed["description"], "translation_status": "reviewed",
                "operation_reference": reviewed["reference"], "service_name": display}
    return record or fallback
