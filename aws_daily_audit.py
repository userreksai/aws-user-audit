#!/usr/bin/env python3
"""CloudTrail 管理操作日报，可选通过 Lark 群机器人推送摘要。"""
from __future__ import annotations

import argparse
import hashlib
import html
from html.parser import HTMLParser
import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import date, datetime, time as day_time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = timezone.utc
CATEGORIES = ("新增", "修改", "删除", "Secrets Manager 查看", "登录信息", "其他操作")
READ_PREFIXES = ("Get", "List", "Describe", "Lookup", "Search", "BatchGet", "BatchDescribe", "Head", "Check", "Validate", "Preview", "Scan", "Query")
CREATE_PREFIXES = ("Create", "Add", "Allocate", "Associate", "Attach", "Authorize", "Register", "Import", "Copy", "Purchase", "Subscribe", "Assign", "Upload")
DELETE_PREFIXES = ("Delete", "Remove", "Revoke", "Detach", "Disassociate", "Deregister", "Terminate", "Release", "Unassign", "Unsubscribe")
MODIFY_PREFIXES = ("Update", "Modify", "Put", "Set", "Enable", "Disable", "Start", "Stop", "Reboot", "Reset", "Restore", "Rotate", "Tag", "Untag", "Cancel", "Apply", "Accept", "Reject", "Replace", "Change", "Renew", "Confirm", "Promote", "Revoke", "Execute", "Send", "Invoke", "Publish", "Deploy")
EXACT_CATEGORIES = {"RunInstances": "新增", "RunTask": "新增", "RunJobFlow": "新增"}
RESOURCE_KEYS = {"secretid", "secretidlist", "instanceid", "instanceids", "groupid", "groupname", "username", "rolename", "policyarn", "functionname", "bucketname", "tablename", "dbinstanceidentifier", "dbclusteridentifier", "loadbalancerarn", "resourcearn", "resourceid", "trailname", "keyid", "loggroupname", "name"}
SENSITIVE_KEYS = {"secretstring", "secretbinary", "secretaccesskey", "accesskeyid", "sessiontoken", "securitytoken", "password", "plaintext", "privatekey", "authorization", "apikey", "userdata", "accesstoken", "refreshtoken", "clientsecret", "keymaterial", "credentials", "credential", "secret", "token", "tokenvalue", "binarysecret"}
ACTION_TEXT = {
    "ModifyInstanceAttribute": "修改 EC2 实例属性", "RunInstances": "创建 EC2 实例",
    "TerminateInstances": "终止 EC2 实例", "StopInstances": "停止 EC2 实例", "StartInstances": "启动 EC2 实例",
    "AuthorizeSecurityGroupIngress": "新增安全组入站规则", "AuthorizeSecurityGroupEgress": "新增安全组出站规则",
    "RevokeSecurityGroupIngress": "删除安全组入站规则", "RevokeSecurityGroupEgress": "删除安全组出站规则",
    "ModifySecurityGroupRules": "修改安全组规则", "CreateUser": "创建 IAM 用户", "DeleteUser": "删除 IAM 用户",
    "CreateAccessKey": "创建访问密钥（密钥内容脱敏）", "DeleteAccessKey": "删除访问密钥",
    "UpdateAccessKey": "修改访问密钥状态", "AttachUserPolicy": "给用户添加托管策略",
    "DetachUserPolicy": "移除用户的托管策略", "PutUserPolicy": "设置用户内联策略（创建或覆盖）",
    "PutRolePolicy": "设置角色内联策略（创建或覆盖）", "UpdateAssumeRolePolicy": "修改角色信任策略",
    "CreateSecret": "创建 Secret", "UpdateSecret": "修改 Secret 配置或值（敏感值不可见）",
    "PutSecretValue": "写入 Secret 版本（敏感值不可见）", "DeleteSecret": "删除或计划删除 Secret",
    "RestoreSecret": "恢复 Secret", "RotateSecret": "轮换 Secret", "GetSecretValue": "读取 Secret 值（报告不含值）",
    "BatchGetSecretValue": "批量读取 Secret 值（报告不含值）", "DescribeSecret": "查看 Secret 元数据",
    "ListSecrets": "查看 Secret 列表", "GetResourcePolicy": "查看资源策略", "CreateBucket": "创建 S3 存储桶",
    "DeleteBucket": "删除 S3 存储桶", "PutBucketPolicy": "设置存储桶策略（创建或覆盖）",
    "UpdateFunctionConfiguration": "修改 Lambda 函数配置", "UpdateFunctionCode": "修改 Lambda 函数代码",
    "ModifyDBInstance": "修改 RDS 实例配置", "DeleteDBInstance": "删除 RDS 实例",
    "ConsoleLogin": "登录 AWS 控制台", "CheckMfa": "检查登录 MFA 验证",
    "GetSigninToken": "获取控制台登录令牌", "SwitchRole": "切换控制台登录角色",
}

REPORT_CSS = '''
:root{font-family:system-ui,"Microsoft YaHei",sans-serif;color:#182739;background:#f3f6fa}body{max-width:1700px;margin:0 auto;padding:32px}h1{margin:0 0 12px}h2{font-size:20px}p{line-height:1.65}small{color:#536579}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}.card{background:#fff;padding:18px 24px;min-width:140px;border:1px solid #dce4ef;border-radius:10px}.card strong{display:block;font-size:30px;color:#145e9f}.card span{font-size:14px}section{background:white;border:1px solid #dde5ef;border-radius:10px;margin:20px 0;padding:20px}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;border-bottom:1px solid #e0e7ee;padding:12px;vertical-align:top;min-width:90px;overflow-wrap:anywhere}th{background:#f3f7fc}.failed{background:#fff4ef}details{min-width:200px}summary{cursor:pointer;color:#165da4}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:650px;max-height:500px;overflow:auto;background:#f3f6fa;padding:12px;font-size:12px}input{padding:12px;width:min(600px,90%);border:1px solid #aab9cc;border-radius:6px}code{font-size:12px}@media print{body{padding:0}input{display:none}details{display:block}.scroll{overflow:visible}section{break-inside:auto}.card{padding:8px}}
'''
REPORT_JS = '''"use strict";
const search = document.getElementById("search");
if (search) {
  search.addEventListener("input", function () {
    const query = this.value.toLowerCase();
    document.querySelectorAll("tr.event").forEach(function (row) {
      row.hidden = !row.textContent.toLowerCase().includes(query);
    });
  });
}
'''


def report_assets():
    return {"audit-report.css": REPORT_CSS, "audit-report.js": REPORT_JS}


def asset_url(name):
    version = hashlib.sha256(report_assets()[name].encode("utf-8")).hexdigest()[:12]
    return f"{name}?v={version}"


def parse_time(value):
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, (int, float)):
        result = datetime.fromtimestamp(value, UTC)
    else:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("事件时间缺少 UTC/时区标识")
    return result.astimezone(UTC)


def make_window(date_text, timezone_name, now=None):
    zone = ZoneInfo(timezone_name)
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("now 必须带时区")
    target = date.fromisoformat(date_text) if date_text else now.astimezone(zone).date() - timedelta(days=1)
    if date_text and target.isoformat() != date_text:
        raise ValueError("日期必须为 YYYY-MM-DD")
    start = datetime.combine(target, day_time.min, zone).astimezone(UTC)
    end = datetime.combine(target + timedelta(days=1), day_time.min, zone).astimezone(UTC)
    return target.isoformat(), start, end


def resolve_window(date_text, timezone_name, *, today=False, now=None, daily=False):
    """daily=True 为固定北京时间07:00→次日08:00；其余为自然日辅助模式。"""
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("now 必须带时区")
    now = now.astimezone(UTC)
    if today and date_text:
        raise ValueError("--today 和 --date 不能同时使用")
    if daily:
        if timezone_name != "Asia/Shanghai":
            raise ValueError("定时日报固定使用北京时间 Asia/Shanghai。")
        zone = ZoneInfo("Asia/Shanghai")
        target = date.fromisoformat(date_text) if date_text else now.astimezone(zone).date()
        if date_text and target.isoformat() != date_text:
            raise ValueError("日期必须为 YYYY-MM-DD")
        start = datetime.combine(target - timedelta(days=1), day_time(hour=7), zone).astimezone(UTC)
        end = datetime.combine(target, day_time(hour=8), zone).astimezone(UTC)
        if end > now:
            raise ValueError("该日报窗口尚未结束；请在报表日期的北京时间 08:00 之后执行，或用 --date 指定已结束的报表日期。")
        return target.isoformat(), start, end, False
    current_date = now.astimezone(ZoneInfo(timezone_name)).date().isoformat()
    day, start, end = make_window(current_date if today else date_text, timezone_name, now=now)
    if start > now:
        raise ValueError("不能查询未来日期；可用 --today 查询当日至当前时刻")
    in_progress = day == current_date
    return day, start, now if in_progress else end, in_progress


def key_name(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def sensitive_key(key):
    name = key_name(key)
    return name in SENSITIVE_KEYS or any(part in name for part in ("password", "privatekey", "secretaccesskey", "sessiontoken"))


def redact(value):
    """字段级最小化；自定义自由文本仍应由持有人按敏感报告保管。"""
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            name = key_name(key)
            if sensitive_key(key):
                result[key] = "[REDACTED]"
            elif name in {"environment", "environmentvariables", "variables", "env"}:
                result[key] = "[REDACTED: environment values]"
            elif name == "value" and sensitive_key(value.get("key", value.get("name", ""))):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact(child)
        return result
    if isinstance(value, list):
        return [redact(child) for child in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                return json.dumps(redact(json.loads(value)), ensure_ascii=False)
            except (ValueError, TypeError):
                pass
        value = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED_ACCESS_KEY]", value)
        return re.sub(r"(?i)((?:password|secretaccesskey|sessiontoken|authorization)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", value)
    return value


def is_secrets(event):
    return str(event.get("eventSource", "")).startswith("secretsmanager.")


def is_login(event):
    return event.get("eventType") == "AwsConsoleSignIn" or (
        str(event.get("eventSource", "")).startswith("signin.")
        and event.get("eventName") in {"ConsoleLogin", "CheckMfa", "GetSigninToken", "SwitchRole"}
    )


def classify_event(event):
    name = event.get("eventName", "")
    if is_login(event):
        return "登录信息", "AWS 控制台登录事件"
    read_only = event.get("readOnly")
    if isinstance(read_only, str):
        read_only = {"true": True, "false": False}.get(read_only.lower())
    if read_only is True:
        return ("Secrets Manager 查看", "CloudTrail readOnly=true") if is_secrets(event) else (None, "忽略普通只读")
    confirmed_write = read_only is False or event.get("_matched_write_query") is True
    if not confirmed_write and name.startswith(READ_PREFIXES):
        return ("Secrets Manager 查看", "readOnly 缺失，按 API 名称推断") if is_secrets(event) else (None, "readOnly 缺失，按 API 名称忽略只读")
    basis = "CloudTrail readOnly=false；增删改按 API 名称推断" if confirmed_write else "readOnly 缺失；增删改按 API 名称推断"
    if name in EXACT_CATEGORIES:
        return EXACT_CATEGORIES[name], basis
    for prefixes, category in ((CREATE_PREFIXES, "新增"), (DELETE_PREFIXES, "删除"), (MODIFY_PREFIXES, "修改")):
        if name.startswith(prefixes):
            if name.startswith("Put"):
                basis += "；Put 可能创建或覆盖，不能证明已有资源发生修改"
            return category, basis
    return "其他操作", basis + "；未匹配分类规则"


def actor_info(event, lookup):
    identity = event.get("userIdentity") or {}
    context = identity.get("sessionContext") or {}
    issuer = context.get("sessionIssuer") or {}
    kind = identity.get("type", "Unknown")
    arn = identity.get("arn", "")
    behalf = identity.get("onBehalfOf") or {}
    if kind == "IAMUser":
        actor = identity.get("userName") or lookup.get("Username") or arn
    elif kind == "Root":
        actor = "Root"
    elif kind == "AssumedRole":
        role = issuer.get("userName") or issuer.get("arn") or "角色未知"
        actor = f"角色 {role} / 会话 {arn.rsplit('/', 1)[-1] or identity.get('principalId', '未知')}"
    elif kind == "IdentityCenterUser" or behalf:
        actor = "Identity Center 用户ID " + str(behalf.get("userId") or identity.get("principalId") or "未知")
    elif kind == "AWSService" or identity.get("invokedBy"):
        actor = "AWS 服务 " + str(identity.get("invokedBy") or identity.get("principalId") or "未知")
    else:
        actor = identity.get("userName") or lookup.get("Username") or arn or identity.get("principalId") or "未知身份"
    return actor, {"type": kind, "arn": arn, "principal_id": identity.get("principalId", ""),
                   "role_arn": issuer.get("arn", ""), "source_identity": context.get("sourceIdentity", ""),
                   "on_behalf_of": behalf, "note": "角色会话名不等同于已确认的自然人" if kind == "AssumedRole" else ""}


def resource_names(event, lookup):
    names = []
    for item in (event.get("resources") or []) + (lookup.get("Resources") or []):
        if isinstance(item, dict):
            value = item.get("ARN") or item.get("arn") or item.get("ResourceName")
            if value:
                names.append(str(value))

    def visit(value):
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = key_name(key)
                if not sensitive_key(key) and (normalized in RESOURCE_KEYS or normalized.endswith("arn")):
                    if isinstance(child, (str, int)):
                        names.append(f"{key}={child}")
                    elif isinstance(child, list) and all(isinstance(x, (str, int)) for x in child):
                        names.extend(f"{key}={x}" for x in child)
                if not sensitive_key(key) and normalized not in {"environment", "variables", "env", "policydocument", "policy", "tags"}:
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(redact(event.get("requestParameters")))
    # 新建资源的 ID 经常只在响应中。只提取已知 ID，不获取资源当前配置。
    visit(redact(event.get("responseElements")))
    return list(dict.fromkeys(names)) or ["日志未提供可识别资源；请查看请求参数"]


def has_response_failure(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key_name(key) in {"errors", "error", "errorcode", "unsuccessful", "failures", "failed"} and child:
                return True
            if key_name(key) in {"success", "return"} and child is False:
                return True
            if key_name(key) in {"consolelogin", "checkmfa", "getsignintoken", "switchrole"} and str(child).lower() in {"failure", "failed"}:
                return True
            if has_response_failure(child):
                return True
    elif isinstance(value, list):
        return any(has_response_failure(child) for child in value)
    return False


def parameter_summary(parameters):
    """提供易读的提交值摘要；不把请求参数冒充配置前后差异。"""
    if not parameters:
        return "日志未提供请求参数；无法确认具体字段值。"
    labels = {"instanceType": "实例类型", "instanceId": "实例 ID", "groupId": "安全组 ID",
              "fromPort": "起始端口", "toPort": "结束端口", "ipProtocol": "协议", "cidrIp": "来源网段",
              "secretId": "Secret", "userName": "目标用户", "roleName": "目标角色", "policyArn": "策略 ARN",
              "recoveryWindowInDays": "删除恢复期（天）", "status": "状态", "functionName": "函数名",
              "dBInstanceIdentifier": "数据库实例", "versionStage": "Secret 版本阶段"}
    leaves = []

    def visit(value, path=""):
        if len(leaves) >= 10:
            return
        if isinstance(value, dict):
            if set(value) == {"value"}:
                visit(value["value"], path)
            else:
                for key, child in value.items():
                    visit(child, (path + "." if path else "") + labels.get(key, key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")
        else:
            text_value = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
            leaves.append(f"{path}={text_value[:120]}{'…' if len(text_value) > 120 else ''}")
    visit(parameters)
    return "提交值：" + "；".join(leaves[:8]) + ("；更多参数见详情。" if len(leaves) > 8 else "。")


def normalize_event(event, lookup, zone):
    category, basis = classify_event(event)
    actor, identity = actor_info(event, lookup)
    occurred = parse_time(event.get("eventTime") or lookup.get("EventTime"))
    failed = bool(event.get("errorCode") or event.get("errorMessage"))
    partial = has_response_failure(event.get("responseElements"))
    result = "失败" if failed else "响应包含失败（可能部分失败）" if partial else "请求无报错"
    name = event.get("eventName", lookup.get("EventName", "未知 API"))
    description = ACTION_TEXT.get(name, ("调用 " + name))
    parameters = redact(event.get("requestParameters"))
    summary = parameter_summary(parameters)
    resources = resource_names(event, lookup)
    login_details = None
    if category == "登录信息":
        response = event.get("responseElements") or {}
        status = str(response.get(name, "")).lower() if isinstance(response, dict) else ""
        statuses = {
            "ConsoleLogin": ("登录成功", "登录失败", "登录结果未提供"),
            "CheckMfa": ("MFA 检查通过", "MFA 检查失败", "MFA 检查结果未提供"),
            "GetSigninToken": ("登录令牌获取成功", "登录令牌获取失败", "登录令牌结果未提供"),
        }
        success_text, failure_text, unknown_text = statuses.get(name, ("登录流程成功", "登录流程失败", "登录流程结果未提供"))
        result = failure_text if failed or partial else success_text if status == "success" else unknown_text
        mfa = (event.get("additionalEventData") or {}).get("MFAUsed")
        login_details = {"result": result, "mfa_used": mfa}
        summary = "控制台登录" if name == "ConsoleLogin" else description
        if mfa is not None:
            summary += "；MFA：" + {"yes": "已使用", "no": "未使用"}.get(str(mfa).lower(), str(mfa))
        if resources == ["日志未提供可识别资源；请查看请求参数"]:
            resources = ["—"]
    if name.startswith("Put") and name not in ACTION_TEXT:
        description += "（创建或覆盖）"
    if failed or partial:
        description = "尝试：" + description
    return {"event_id": event.get("eventID") or lookup.get("EventId", ""),
            "time_local": occurred.astimezone(zone).isoformat(sep=" ", timespec="seconds"),
            "time_utc": occurred.isoformat(timespec="seconds"), "actor": actor, "identity": redact(identity),
            "account_id": event.get("recipientAccountId", ""), "region": event.get("awsRegion") or event.get("_query_region", ""),
            "source": event.get("eventSource", ""), "event_name": name, "category": category,
            "classification_basis": basis, "description": description, "resources": resources,
            "parameters": parameters, "parameter_summary": summary, "login_details": login_details,
            "response": redact(event.get("responseElements")),
            "result": result, "failed": failed or partial, "error_code": event.get("errorCode", ""),
            "error_message": redact(event.get("errorMessage", "")), "source_ip": event.get("sourceIPAddress", ""),
            "user_agent": redact(event.get("userAgent", "")), "event_type": event.get("eventType", ""),
            "details_note": "请求参数是提交值；日志可能省略字段，未采集修改前快照，不推断旧值。"}


class Pacer:
    def __init__(self, interval=0.6):
        self.interval, self.last = interval, None

    def __call__(self):
        if self.last is not None:
            time.sleep(max(0, self.interval - (time.monotonic() - self.last)))
        self.last = time.monotonic()


def collect_region(client, region, start, end, pace=None):
    pace = pace or Pacer()
    events, errors = [], []
    stats = {"region": region, "queries": {}, "fetched": 0, "outside_window": 0}
    queries = (("write", "ReadOnly", "false"), ("secrets", "EventSource", "secretsmanager.amazonaws.com"))
    for label, key, value in queries:
        pages, token, previous_tokens = 0, None, set()
        count = 0
        try:
            while True:
                kwargs = {"StartTime": start, "EndTime": end, "MaxResults": 50,
                          "LookupAttributes": [{"AttributeKey": key, "AttributeValue": value}]}
                if token:
                    kwargs["NextToken"] = token
                pace()
                page = client.lookup_events(**kwargs)
                pages += 1
                for item in page.get("Events", []):
                    count += 1
                    try:
                        event = json.loads(item["CloudTrailEvent"])
                        if not isinstance(event, dict):
                            raise ValueError("CloudTrailEvent 必须为对象")
                        occurred = parse_time(event.get("eventTime") or item.get("EventTime"))
                        if not start <= occurred < end:
                            stats["outside_window"] += 1
                            continue
                        if not (event.get("eventID") or item.get("EventId")):
                            raise ValueError("事件缺少 EventID")
                        event["_lookup"] = {k: v for k, v in item.items() if k != "CloudTrailEvent"}
                        event["_query_region"] = region
                        event["_matched_write_query"] = label == "write"
                        events.append(event)
                    except (ValueError, TypeError, KeyError) as exc:
                        errors.append(f"{region}/{label}: 第 {pages} 页事件无法解析（{redact(str(exc))}）")
                token = page.get("NextToken")
                if not token:
                    break
                if token in previous_tokens:
                    raise ValueError("API 返回重复分页 token，已停止以避免死循环")
                previous_tokens.add(token)
            stats["queries"][label] = {"pages": pages, "fetched": count, "complete": True}
        except Exception as exc:
            errors.append(f"{region}/{label}: {type(exc).__name__}: {redact(str(exc))}")
            stats["queries"][label] = {"pages": pages, "fetched": count, "complete": False}
        stats["fetched"] += count
    return events, errors, stats


def load_input(path):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    records = data if isinstance(data, list) else data.get("Records", data.get("Events"))
    if not isinstance(records, list):
        raise ValueError("输入需为事件数组、{Records:[...]} 或 LookupEvents 的 {Events:[...]}（JSON）")
    events = []
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("输入事件必须为对象")
        if "CloudTrailEvent" in item:
            event = json.loads(item["CloudTrailEvent"])
            if not isinstance(event, dict):
                raise ValueError("CloudTrailEvent 必须为对象")
            event["_lookup"] = {k: v for k, v in item.items() if k != "CloudTrailEvent"}
        else:
            event = dict(item)
        # 不接受离线输入伪装成由在线查询确认的写操作。
        event.pop("_matched_write_query", None)
        events.append(event)
    return events


def build_report(events, *, audit_date, timezone_name, start, end, account_id="unknown", regions=None,
                 errors=None, region_stats=None, offline=False, warnings=None, in_progress=False, window_mode="calendar"):
    rows, seen = [], set()
    ignored, duplicates, outside = 0, 0, 0
    errors = list(errors or [])
    warnings = list(warnings or [])
    for event in events:
        lookup = event.get("_lookup") or {}
        try:
            occurred = parse_time(event.get("eventTime") or lookup.get("EventTime"))
            if not start <= occurred < end:
                outside += 1
                continue
            eid = event.get("eventID") or lookup.get("EventId")
            dedup = (event.get("recipientAccountId", account_id), eid) if eid else hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()
            if dedup in seen:
                duplicates += 1
                continue
            seen.add(dedup)
            row = normalize_event(event, lookup, ZoneInfo(timezone_name))
            if row["category"] is None:
                ignored += 1
            else:
                rows.append(row)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            errors.append(f"输入事件无法解析：{type(exc).__name__}: {redact(str(exc))}")
    rows.sort(key=lambda row: (row["time_utc"], row["actor"], row["event_id"]))
    if in_progress:
        warnings.append("当日尚未结束：本报告仅包含当日零点至本次查询开始时刻的事件，不是全天日报；CloudTrail 事件存在到达延迟，请稍后重跑。")
    if not offline and end > datetime.now(UTC) - timedelta(minutes=30):
        warnings.append("查询结束时间距离现在不足 30 分钟，CloudTrail 事件可能尚未全部到达；请稍后重跑。")
    if "us-east-1" not in (regions or []) and not any(r.startswith(("cn-", "us-gov-")) for r in (regions or [])):
        warnings.append("未覆盖 us-east-1，可能遗漏 IAM 等全局服务事件；固定区域报告不能视为全账号审计。")
    counts = Counter(row["category"] for row in rows)
    return {"metadata": {"audit_date": audit_date, "timezone": timezone_name, "account_id": account_id,
            "in_progress": in_progress, "window_mode": window_mode,
            "period_label": "北京时间前一天07:00至报表日08:00（25小时）" if window_mode == "daily_25h" else "当日截至查询时刻" if in_progress else "完整自然日",
            "overlap_hours": 1 if window_mode == "daily_25h" else 0,
            "window_start_local": start.astimezone(ZoneInfo(timezone_name)).isoformat(sep=" ", timespec="seconds"),
            "window_end_local_exclusive": end.astimezone(ZoneInfo(timezone_name)).isoformat(sep=" ", timespec="seconds"),
            "window_start_utc": start.isoformat(), "window_end_utc_exclusive": end.isoformat(),
            "generated_at": datetime.now(UTC).astimezone(ZoneInfo(timezone_name)).isoformat(timespec="seconds"),
            "offline": offline, "data_mode": "离线输入（完整性未经 AWS 验证）" if offline else "AWS CloudTrail LookupEvents",
            "complete": not errors, "scope": "单账号、所列区域的 CloudTrail 管理事件；不包含数据事件",
            "regions": regions or [], "errors": errors, "warnings": warnings,
            "region_stats": region_stats or [], "input_records": len(events), "ignored_read_events": ignored,
            "duplicates_removed": duplicates, "outside_window": outside, "total": len(rows),
            "failed_or_partial": sum(row["failed"] for row in rows),
            "counts": {category: counts[category] for category in CATEGORIES},
            "count_note": "按独立 CloudTrail EventID 计数，不等于人工操作次数；批量 Secret 读取可能产生多个事件。"},
            "events": rows}


def render_html(report):
    meta = report["metadata"]
    esc = lambda value: html.escape(str(value), quote=True)
    pretty = lambda value: esc(json.dumps(value, ensure_ascii=False, indent=2, default=str))
    beijing = lambda value: parse_time(value).astimezone(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    title = "AWS 账号当日审计快报" if meta.get("in_progress", False) else "AWS 账号操作审计日报"
    categories = tuple(category for category in CATEGORIES if category != "其他操作" or meta["counts"].get(category, 0))
    cards = "".join(f'<div class="card"><strong>{meta["counts"].get(cat, 0)}</strong><span>{esc(cat)}</span></div>' for cat in categories)
    by_actor = defaultdict(Counter)
    for row in report["events"]:
        by_actor[row["actor"]][row["category"]] += 1
    actor_rows = "".join("<tr><td>" + esc(actor) + "</td>" + "".join(f"<td>{counts[c]}</td>" for c in categories) + "</tr>" for actor, counts in sorted(by_actor.items()))
    sections = []
    for category in categories:
        event_rows = []
        for row in report["events"]:
            if row["category"] != category:
                continue
            details = {"身份": row["identity"], "请求参数": row["parameters"],
                       "响应字段（脱敏）": row["response"], "错误码": row["error_code"], "错误信息": row["error_message"],
                       "UserAgent": row["user_agent"]}
            if row.get("login_details"):
                details["登录信息"] = row["login_details"]
            resources = "<br>".join(esc(x) for x in row["resources"])
            css = "failed" if row["failed"] else ""
            event_rows.append(f'<tr class="event {css}"><td>{esc(beijing(row.get("time_utc") or row["time_local"]))}</td><td>{esc(row["actor"])}<br><small>{esc(row["identity"]["type"])}</small></td>'
                              f'<td><b>{esc(row["description"])}</b><br><code>{esc(row["event_name"])}</code><br>{esc(row["parameter_summary"])}<br><small>{esc(row["source"])}</small></td>'
                              f'<td>{resources}<br><small>{esc(row["region"])} / {esc(row["source_ip"])}</small></td>'
                              f'<td>{esc(row["result"])}</td><td><details><summary>查看操作参数和身份</summary><pre>{pretty(details)}</pre></details><small>EventID: {esc(row["event_id"])}</small></td></tr>')
        body = "".join(event_rows) or '<tr><td colspan="6">无记录</td></tr>'
        sections.append(f'<section><h2>{esc(category)} · {meta["counts"].get(category, 0)}</h2><div class="scroll"><table><thead><tr><th>操作时间（北京时间）</th><th>操作者</th><th>操作信息</th><th>资源 / 区域 / 来源 IP</th><th>请求结果</th><th>具体修改内容</th></tr></thead><tbody>{body}</tbody></table></div></section>')
    return '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>''' + title + f'''</title>
<link rel="stylesheet" href="{asset_url('audit-report.css')}">
<script src="{asset_url('audit-report.js')}" defer></script>
</head><body><h1>{title} · {esc(meta["audit_date"])}</h1>
<p>账号：<b>{esc(meta["account_id"])}</b>　生成时间（北京时间）：{esc(beijing(meta["generated_at"]))}</p>
<div class="cards">{cards}</div>
<section><h2>按操作者汇总</h2><div class="scroll"><table><thead><tr><th>操作者</th>{''.join('<th>'+esc(x)+'</th>' for x in categories)}</tr></thead><tbody>{actor_rows or '<tr><td colspan="'+str(len(categories)+1)+'">无记录</td></tr>'}</tbody></table></div></section>
<label for="search">搜索用户、资源、API、IP 或参数：</label><br><input id="search" placeholder="例如 hhjgx、ModifyInstanceAttribute、sg-" autocomplete="off">
{''.join(sections)}
</body></html>'''


def write_report(report, output_dir):
    meta = report["metadata"]
    safe_account = re.sub(r"[^a-zA-Z0-9_-]", "_", str(meta["account_id"]))
    folder = Path(output_dir) / safe_account / meta["audit_date"]
    folder.mkdir(parents=True, exist_ok=True)
    files = list(report_assets().items()) + [("report.json", json.dumps(report, ensure_ascii=False, indent=2, default=str)),
                                           (f"{meta['audit_date']}-aws操作审计.html", render_html(report))]
    for name, content in files:
        target = folder / name
        temp = folder / (name + ".tmp")
        temp.write_text(content, encoding="utf-8")
        temp.replace(target)
    return folder.resolve()


def _atomic_publish_copy(source, target):
    directory = target.parent
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".index-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
        shutil.copyfile(source, temporary)
        if os.name == "posix":
            temporary.chmod(0o644)
        temporary.replace(target)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


class _ReportAssetReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.files = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        reference = ""
        if tag == "link" and "stylesheet" in attrs.get("rel", "").split():
            reference = attrs.get("href", "")
        elif tag == "script":
            reference = attrs.get("src", "")
        name = reference.split("?", 1)[0]
        if name in report_assets():
            self.files.add(name)


def publish_report(html_path, publish_dir):
    """先发布同源 CSS/JS，再原子更新 index.html；保留原日期归档。"""
    source = Path(html_path)
    directory = Path(publish_dir)
    directory.mkdir(parents=True, exist_ok=True)
    references = _ReportAssetReferences()
    references.feed(source.read_text(encoding="utf-8"))
    # 先确认全部依赖存在，防止发布到缺少样式/脚本的目录。
    for name in references.files:
        if not (source.parent / name).is_file():
            raise FileNotFoundError(f"报告缺少静态文件：{name}")
    for name in sorted(references.files):
        _atomic_publish_copy(source.parent / name, directory / name)
    target = directory / "index.html"
    _atomic_publish_copy(source, target)
    return target.resolve()


def publish_with_access(report, html_path, args, publish_dir):
    """认证启用后的发布/换码/通知共用文件锁；新密码生效后允许失败重发。"""
    from audit_access import AccessRotation, AccessError
    from lark_notify import load_lark_config, send_lark_notification, build_lark_payloads

    complete = report["metadata"]["complete"]
    try:
        config = load_lark_config(args.lark_config)
        config["message_mode"] = args.lark_mode
        config["report_url_template"] = args.report_url
        with AccessRotation(args.auth_state_dir, publish_dir, report["metadata"]["audit_date"], args.output_dir) as access:
            # 验证链接/消息/配置后才能发布或切换密码；密码不进入 report 或持久配置。
            build_lark_payloads(report, config, access_password=access.password)
            if html_path is None:
                # 归档写入也须在发布锁内，防止并发任务覆盖源文件后发出不一致的统计。
                folder = write_report(report, args.output_dir)
                html_path = folder / f"{report['metadata']['audit_date']}-aws操作审计.html"
                print(f"报告已生成：{html_path}")
                print(f"结构化明细：{folder / 'report.json'}")
                print(json.dumps(report["metadata"]["counts"], ensure_ascii=False))
            try:
                published = publish_report(html_path, publish_dir)
            except OSError:
                print("网页副本更新失败；现有密码未更换，日期报告已保留，本次未发送 Lark。", file=sys.stderr)
                return 2 if not complete else 4
            access.activate()
            print(f"网页副本已更新：{published}；单密码状态已准备。")
            try:
                send_lark_notification(report, config, access_password=access.password)
            except Exception as exc:
                # 网络超时可能已送达；保留有效密码，同日重跑会重发同一个密码。
                reason = str(exc) if isinstance(exc, (RuntimeError, ValueError)) else type(exc).__name__
                # 防止未来适配器异常把本次密码带入日志。
                reason = reason.replace(access.password, "[REDACTED]")
                print(f"Lark 推送失败：{reason} 已保留本次有效密码；使用相同报表日期重跑可重发。报告文件已保留。", file=sys.stderr)
                return 2 if not complete else 3
            print("Lark 数量总览、报告链接和访问密码已推送。")
            return 0 if complete else 2
    except (AccessError, ValueError, OSError) as exc:
        print(f"密码认证发布失败：{exc} 已生成的日期报告将保留；请检查私有状态、权限及 Lark 配置。", file=sys.stderr)
        return 2 if not complete else 4


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", help="AWS CLI profile；不填则使用 SDK 默认凭据链/EC2 角色")
    parser.add_argument("--regions", default="all", help="all 或逗号分隔区域；默认扫描同分区所有已启用区域")
    parser.add_argument("--timezone", default="Asia/Shanghai", choices=["Asia/Shanghai"], help="固定北京时间 Asia/Shanghai (UTC+8)")
    period = parser.add_mutually_exclusive_group()
    period.add_argument("--date", help="报表结束日期 YYYY-MM-DD；查询前一天07:00至该日08:00，默认今天")
    period.add_argument("--today", action="store_true", help="以今天为报表结束日期（默认行为），查询昨天07:00至今天08:00")
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument("--input-file", help="离线 JSON 事件文件；不会连接 AWS")
    parser.add_argument("--send-lark", action="store_true", help="生成报告后，通过配置的 Lark 群机器人推送审计信息")
    parser.add_argument("--lark-config", default="lark-config.json", help="Lark 私有 JSON 配置文件；仅 --send-lark 时读取")
    parser.add_argument("--lark-mode", choices=["overview", "summary", "full"], default="overview", help="Lark 默认数量总览和详情链接；覆盖配置中的 message_mode")
    parser.add_argument("--report-url", default="https://zybocedata-pass.v668live.com/audit/", help="Lark 通知中的详细报告链接")
    publication = parser.add_mutually_exclusive_group()
    publication.add_argument("--publish-dir", help="复制 HTML 为目录中的 index.html；Linux 联网运行默认 /usr/local/shenji/index/，离线模式默认不发布")
    publication.add_argument("--no-publish", action="store_true", help="仅保存日期归档，不更新 index.html")
    parser.add_argument("--auth-state-dir", help="启用单密码访问；私有状态目录（例如 /usr/local/shenji/auth），必须同时发布网页、--send-lark 并使用 overview")
    args = parser.parse_args(argv)
    try:
        if args.auth_state_dir and (not args.send_lark or args.no_publish or args.lark_mode != "overview"
                                    or (args.input_file and not args.publish_dir)):
            raise ValueError("--auth-state-dir 必须同时启用网页发布、--send-lark 和 --lark-mode overview。")
        query_started_at = datetime.now(UTC)
        audit_date, start, end, in_progress = resolve_window(args.date, args.timezone, today=args.today, now=query_started_at, daily=True)
        warnings, errors, stats = [], [], []
        if args.input_file:
            events = load_input(args.input_file)
            accounts = sorted({str(e.get("recipientAccountId") or (e.get("userIdentity") or {}).get("accountId")) for e in events if e.get("recipientAccountId") or (e.get("userIdentity") or {}).get("accountId")})
            account = accounts[0] if len(accounts) == 1 else "offline-multiple-accounts" if accounts else "offline-unknown"
            regions = sorted({e.get("awsRegion") for e in events if e.get("awsRegion")})
            warnings.append("这是离线输入报告；未向 AWS 验证输入文件是否覆盖全部事件或全部区域。")
        else:
            if start < query_started_at - timedelta(days=90):
                raise ValueError("日期已超出 LookupEvents 的 90 天范围；请使用 Trail/S3 历史日志离线输入")
            try:
                import boto3
                from botocore.config import Config
            except ImportError as exc:
                raise ValueError("缺少 boto3；先使用虚拟环境 Python 运行 -m pip install -r requirements.txt") from exc
            session = boto3.Session(profile_name=args.profile)
            config = Config(retries={"mode": "standard", "total_max_attempts": 8}, connect_timeout=10, read_timeout=60)
            seed = session.region_name or "eu-north-1"
            if args.regions == "all":
                partition = session.get_partition_for_region(seed)
                region_data = session.client("ec2", region_name=seed, config=config).describe_regions(AllRegions=False)
                regions = sorted({r["RegionName"] for r in region_data["Regions"] if r.get("OptInStatus") in (None, "opt-in-not-required", "opted-in")})
                if partition == "aws":
                    regions = sorted(set(regions) | {"us-east-1"})
                if not regions:
                    raise ValueError("未发现已启用区域，不能生成完整报告；可用 --regions 显式指定")
            else:
                regions = sorted({r.strip() for r in args.regions.split(",") if r.strip()})
                if not regions or any(not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", r) for r in regions):
                    raise ValueError("--regions 需为 all 或有效区域名称（用英文逗号分隔）")
            account = session.client("sts", region_name=regions[0], config=config).get_caller_identity()["Account"]
            events = []
            for region in regions:
                print(f"查询 {region}：非只读管理事件 + Secrets Manager 事件", file=sys.stderr)
                try:
                    client = session.client("cloudtrail", region_name=region, config=config)
                    rows, failures, region_stat = collect_region(client, region, start, end)
                    events.extend(rows)
                    errors.extend(failures)
                    stats.append(region_stat)
                except Exception as exc:
                    errors.append(f"{region}: {type(exc).__name__}: {redact(str(exc))}")
        report = build_report(events, audit_date=audit_date, timezone_name=args.timezone, start=start, end=end,
                              account_id=account, regions=regions, errors=errors, region_stats=stats,
                              offline=bool(args.input_file), warnings=warnings, in_progress=in_progress, window_mode="daily_25h")
        publish_dir = args.publish_dir
        if args.no_publish:
            publish_dir = None
        elif publish_dir is None and os.name == "posix" and not args.input_file:
            publish_dir = "/usr/local/shenji/index/"
        if args.auth_state_dir:
            if not publish_dir:
                raise ValueError("密码认证需要 --publish-dir 指定网页目录。")
            return publish_with_access(report, None, args, publish_dir)
        folder = write_report(report, args.output_dir)
        html_path = folder / f"{audit_date}-aws操作审计.html"
        print(f"报告已生成：{html_path}")
        print(f"结构化明细：{folder / 'report.json'}")
        print(f"报告范围：{report['metadata']['period_label']}；{report['metadata']['window_start_local']} 至 {report['metadata']['window_end_local_exclusive']}（结束时刻不含）")
        print(json.dumps(report["metadata"]["counts"], ensure_ascii=False))
        if publish_dir:
            try:
                published = publish_report(html_path, publish_dir)
                print(f"网页副本已更新：{published}")
            except OSError as exc:
                print(f"网页副本更新失败：{type(exc).__name__}；日期报告已保留，请检查发布目录写入权限。本次不发送 Lark，避免指向旧报告。", file=sys.stderr)
                return 2 if not report["metadata"]["complete"] else 4
        notification_failed = False
        if args.send_lark:
            try:
                from lark_notify import load_lark_config, send_lark_notification
                lark_config = load_lark_config(args.lark_config)
                lark_config["message_mode"] = args.lark_mode
                lark_config["report_url_template"] = args.report_url
                notification = send_lark_notification(report, lark_config)
                if notification.get("messages_sent") is not None:
                    print(f"Lark 日报信息已推送，共 {notification['messages_sent']} 条消息。")
                else:
                    print("Lark 日报摘要已推送。")
            except ImportError:
                notification_failed = True
                print("Lark 推送失败：缺少 lark_notify.py，请更新完整代码包。报告文件已保留。", file=sys.stderr)
            except (RuntimeError, ValueError) as exc:
                notification_failed = True
                print(f"Lark 推送失败：{exc} 报告文件已保留。", file=sys.stderr)
            except Exception as exc:
                notification_failed = True
                print(f"Lark 推送失败：{type(exc).__name__}。报告文件已保留。", file=sys.stderr)
        if not report["metadata"]["complete"]:
            print("注意：部分查询/事件解析失败，报告不完整。请查看报告中的错误并补跑。", file=sys.stderr)
            return 2
        if notification_failed:
            return 3
        return 0
    except (ValueError, OSError, ZoneInfoNotFoundError) as exc:
        print(f"错误：{redact(str(exc))}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"AWS 查询失败：{type(exc).__name__}: {redact(str(exc))}。未生成新报告，请检查凭据和权限。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
