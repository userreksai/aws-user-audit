"""Aggregate normalized CloudTrail identities without retaining event details.

Role sessions are combined by their issuing role, not by a session name. The
event summary uses normalized service/API names and pretranslated labels, never
request/response bodies, resource identifiers, timestamps or addresses.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

CATEGORIES = ("新增", "修改", "删除", "Secrets Manager 查看", "登录信息", "其他操作")


def _text(value):
    if not isinstance(value, str):
        return ""
    return "".join(char for char in value.strip() if ord(char) >= 32 and ord(char) != 127)


def _label(value, limit=240):
    value = _text(value)
    return value if len(value) <= limit else value[:limit - 1] + "…"


def _role(arn):
    """Return canonical IAM role ARN/name from an issuer or STS session ARN."""
    role = re.fullmatch(r"arn:([^:]+):iam::([0-9]{12}):role/(.+)", arn)
    if role:
        return arn, role[3]
    session = re.fullmatch(r"arn:([^:]+):sts::([0-9]{12}):assumed-role/(.+)/[^/]+", arn)
    if session:
        return f"arn:{session[1]}:iam::{session[2]}:role/{session[3]}", session[3]
    return "", ""


def _identity(row):
    identity = row.get("identity")
    identity = identity if isinstance(identity, dict) else {}
    kind = _text(identity.get("type"))
    arn = _text(identity.get("arn"))
    principal = _text(identity.get("principal_id"))
    actor = _text(row.get("actor"))
    behalf = identity.get("on_behalf_of")
    behalf = behalf if isinstance(behalf, dict) else {}

    if kind in {"AssumedRole", "Role"}:
        issuer = _text(identity.get("role_arn"))
        key, name = _role(issuer)
        if not key:
            key, name = _role(arn)
        if not key:
            # An assumed-role principal ID has role-ID:session-name form.
            role_id = principal.split(":", 1)[0] if principal else ""
            key = issuer or arn or role_id
            name = actor.removeprefix("角色 ").split(" / 会话 ", 1)[0]
        return ("Role", key or "unidentified-role"), "Role", _label(name or "未知角色")

    if kind == "Root":
        return ("Root", arn or principal or _text(row.get("account_id")) or "root"), "Root", "Root"

    if kind == "IdentityCenterUser" or behalf:
        user = _text(behalf.get("userId"))
        store = _text(behalf.get("identityStoreArn"))
        identifier = user or principal or arn
        name = "Identity Center 用户 " + user if user else actor or "未知身份中心用户"
        if user and store:
            name += "（" + store.rsplit("/", 1)[-1] + "）"
        return ("IdentityCenterUser", store, identifier or "unidentified"), "IdentityCenterUser", _label(name)

    if kind == "AWSService":
        service = actor.removeprefix("AWS 服务 ") or principal or arn or "未知 AWS 服务"
        return ("AWSService", service.casefold()), "AWSService", _label(service)

    if kind in {"IAMUser", "FederatedUser"}:
        resource = "user/" if kind == "IAMUser" else "federated-user/"
        name = arn.split(":" + resource, 1)[-1] if ":" + resource in arn else actor
        if not name:
            name = principal or ("未知 IAM 用户" if kind == "IAMUser" else "未知联合身份用户")
        # CloudTrail userName is account-unique when an IAM ARN/ID was omitted.
        fallback = ("name", actor) if actor else ("unidentified",)
        return (kind, arn or principal or fallback), kind, _label(name)

    # Unknown callers stay visibly unknown; no request attributes infer a person.
    key = arn or principal or actor or "unidentified"
    name = actor or "未知身份"
    return ("Unknown", kind, key), "Unknown", _label(name)


def summarize_identities(rows):
    """Return identity-only category totals for valid normalized report rows.

    Failure counts are a subset of category totals. Non-report categories are
    ignored, matching the ordinary-read filtering in the report builder.
    """
    if not isinstance(rows, list):
        raise ValueError("身份汇总需要已规范化的事件数组")
    groups = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("category") not in CATEGORIES:
            continue
        key, identity_type, actor = _identity(row)
        if key not in groups:
            groups[key] = {"actor": actor, "identity_type": identity_type,
                           "counts": {category: 0 for category in CATEGORIES}, "failed": 0, "total": 0}
        item = groups[key]
        # Keep display labels deterministic if a stable identity had aliases.
        item["actor"] = min(item["actor"], actor, key=lambda value: (value.casefold(), value))
        item["counts"][row["category"]] += 1
        item["failed"] += row.get("failed") is True
        item["total"] += 1
    ordered = sorted(groups.items(), key=lambda pair: (pair[1]["identity_type"], pair[1]["actor"].casefold(),
                                                      pair[1]["actor"], repr(pair[0])))
    return [item for _, item in ordered]


def _event_metadata(row, source, name):
    """Select a bounded label and official link, without examining event bodies."""
    status = row.get("translation_status")
    label = _text(row.get("event_label"))
    if label.startswith("尝试："):
        label = label[len("尝试："):].strip()
    if not isinstance(status, str) or status not in {"reviewed", "official_zh", "untranslated"} or not label:
        status = "untranslated"
    if status == "untranslated":
        label = "待补中文：" + source + " / " + name
    reference = _text(row.get("operation_reference"))
    if reference:
        try:
            url = urlsplit(reference)
            if (url.scheme != "https" or url.hostname != "docs.aws.amazon.com"
                    or url.username or url.password or url.port not in (None, 443)
                    or url.query):
                reference = ""
        except ValueError:
            reference = ""
    return _label(label, 600), status, reference


def summarize_identity_events(rows):
    """Aggregate normalized service/API counts for each stable IAM identity.

    Successful and failed calls share one row; ``failed`` is a subset of
    ``total``. The original identity summary remains independent and unchanged.
    Missing or untrusted translation metadata is visibly marked as untranslated.
    """
    if not isinstance(rows, list):
        raise ValueError("身份事件汇总需要已规范化的事件数组")
    groups, identities = {}, {}
    ranks = {"reviewed": 0, "official_zh": 1, "untranslated": 2}
    for row in rows:
        if not isinstance(row, dict) or row.get("category") not in CATEGORIES:
            continue
        identity_key, identity_type, actor = _identity(row)
        if identity_key not in identities:
            identities[identity_key] = actor
        else:
            identities[identity_key] = min(identities[identity_key], actor,
                                           key=lambda value: (value.casefold(), value))
        source = _text(row.get("source")) or _text(row.get("eventSource")) or "未提供服务"
        name = _text(row.get("event_name")) or _text(row.get("eventName")) or "未知事件"
        category = row["category"]
        label, status, reference = _event_metadata(row, source, name)
        key = (identity_key, source, name, category)
        if key not in groups:
            groups[key] = {"actor": actor, "identity_type": identity_type,
                           "source": source, "event_name": name, "event_label": label,
                           "translation_status": status, "operation_reference": reference,
                           "category": category, "total": 0, "failed": 0}
        item = groups[key]
        # Metadata may differ after translating a mixed-version offline input;
        # pick the most specific reviewed label deterministically, not by order.
        current = (ranks[item["translation_status"]], item["event_label"],
                   not bool(item["operation_reference"]), item["operation_reference"])
        candidate = (ranks[status], label, not bool(reference), reference)
        if candidate < current:
            item.update(event_label=label, translation_status=status, operation_reference=reference)
        item["total"] += 1
        item["failed"] += row.get("failed") is True
    for key, item in groups.items():
        item["actor"] = identities[key[0]]
    ordered = sorted(groups.items(), key=lambda pair: (pair[1]["identity_type"],
        pair[1]["actor"].casefold(), pair[1]["actor"], pair[1]["source"],
        pair[1]["event_name"], pair[1]["category"], repr(pair[0][0])))
    return [item for _, item in ordered]
