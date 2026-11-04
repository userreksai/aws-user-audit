"""Build the offline catalog from reviewed rules and cached AWS Chinese docs.

Usage: python tools/build_event_catalog.py --cache-dir tmp/catalog-cache --offline
The input pages must be the official Chinese Service Authorization Reference
pages (list_*.html). Only action names also present in the installed public SDK
operation models are admitted; permission-only actions such as PassRole are not
CloudTrail APIs. No CRUD classification is inferred from permission metadata.
Downloading documentation is deliberately separate from this offline builder.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from audit_actions import ACTIONS, SERVICES  # noqa: E402

DOC_ROOT = "https://docs.aws.amazon.com/zh_cn/service-authorization/latest/reference/"
NON_API_REFERENCE = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-non-api-events.html"


class ActionTable(HTMLParser):
    """Extract table cells, their IDs, and documentation links without deps."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows, self.row, self.cell, self.depth = [], None, None, 0
        self.canonical = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonical = attrs.get("href", "")
        if tag == "tr":
            self.row = []
        if tag in {"td", "th"} and self.row is not None:
            self.cell = {"parts": [], "id": attrs.get("id", ""), "links": []}
            self.depth = 1
        elif self.cell is not None:
            if tag in {"td", "th"}:
                self.depth += 1
            if tag == "a" and attrs.get("href"):
                self.cell["links"].append(attrs["href"])
            if attrs.get("id") and not self.cell["id"]:
                self.cell["id"] = attrs["id"]

    def handle_data(self, data):
        if self.cell is not None:
            self.cell["parts"].append(data)

    def handle_endtag(self, tag):
        if tag in {"td", "th"} and self.cell is not None:
            self.depth -= 1
            if not self.depth:
                self.cell["text"] = re.sub(r"\s+", " ", "".join(self.cell.pop("parts"))).strip()
                self.row.append(self.cell)
                self.cell = None
        if tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row, self.cell = None, None


def short_label(description):
    """Remove permission boilerplate, preserving the official Chinese meaning.

    Long/multisentence descriptions are excluded instead of copied or guessed.
    A concise official functional phrase is a label, not a claim of API success.
    """
    text = re.sub(r"\s+", " ", description).strip()
    permission_wrapper = text.startswith("授予")
    for prefix in ("授予权限以", "授予以下权限：", "授予以下权限:", "授予权限来", "授予权限", "授予"):
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
            break
    if permission_wrapper:
        # The official translation sometimes puts the permission wrapper in
        # the middle, before a purpose clause or an English product name.
        # Remove the wrapper once; preserve the actual permission object in
        # phrases such as “创建网络接口权限的权限”.
        if "的权限" in text:
            text = text.replace("的权限", "", 1)
        else:
            text = re.sub(r"(创建|删除|启用|禁用|检索|描述|链接|更新|修改|获取|列出|读取|查看)权限(?=\s)", r"\1", text, count=1)
    text = text.strip(" 。.：:，,；;")
    if text.startswith("以"):
        text = text[1:].strip(" 。.：:，,；;")
    # Never label an English fallback page as an official Chinese translation.
    if not re.search(r"[\u3400-\u9fff]", text) or not text or len(text) > 110:
        return ""
    if "。" in text or re.search(r"[.!?] +[A-Z]", text):
        return ""
    return text


def sdk_models():
    """Load installed package data directly, never user paths or credentials."""
    import botocore
    from botocore.loaders import Loader
    package_data = Path(botocore.__file__).resolve().parent / "data"
    loader = Loader(extra_search_paths=[str(package_data)], include_default_search_paths=False)
    models = []
    known_sources = {details[0]: prefix for prefix, details in SERVICES.items()}
    known_owners = {prefix: details[0] for prefix, details in SERVICES.items()}
    for sdk in loader.list_available_services("service-2"):
        model = loader.load_service_model(sdk, "service-2")
        metadata = model["metadata"]
        endpoint = metadata.get("endpointPrefix", "")
        source_prefix = known_sources.get(sdk, endpoint)
        if not re.fullmatch(r"[a-z0-9-]+", source_prefix):
            continue
        # Some SDKs share an endpoint for transport (DocDB/Neptune use rds).
        # That cannot establish the CloudTrail source or overwrite RDS labels.
        if source_prefix in known_owners and sdk != known_owners[source_prefix]:
            continue
        prefixes = {sdk, endpoint, metadata.get("signingName", ""), source_prefix}
        display = (SERVICES[known_sources[sdk]][1] if sdk in known_sources else
                   metadata.get("serviceAbbreviation") or metadata.get("serviceFullName") or sdk)
        models.append({"sdk": sdk, "prefixes": prefixes, "source": source_prefix + ".amazonaws.com",
                       "display": display,
                       "operations": frozenset(model.get("operations", {}))})
    return botocore.__version__, models


def reviewed_entries():
    entries = {}
    def add(prefix, name, label, reference, display=None):
        entries.setdefault(prefix + ".amazonaws.com", {})[name] = {
            "event_label": label, "translation_status": "reviewed",
            "operation_reference": reference,
            "service_name": display or SERVICES[prefix][1]}
    for (prefix, name), action in ACTIONS.items():
        add(prefix, name, action["description"], action["reference"])
    # Preserve existing reviewed translations, explicitly scoped to a service.
    tree = ast.parse((ROOT / "aws_daily_audit.py").read_text(encoding="utf-8"))
    labels = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "ACTION_TEXT" for t in node.targets):
            labels = ast.literal_eval(node.value)
            break
    names = {
        "ec2": "ModifyInstanceAttribute RunInstances TerminateInstances StopInstances StartInstances AuthorizeSecurityGroupIngress AuthorizeSecurityGroupEgress RevokeSecurityGroupIngress RevokeSecurityGroupEgress ModifySecurityGroupRules",
        "iam": "CreateUser DeleteUser CreateAccessKey DeleteAccessKey UpdateAccessKey AttachUserPolicy DetachUserPolicy PutUserPolicy PutRolePolicy UpdateAssumeRolePolicy",
        "secretsmanager": "CreateSecret UpdateSecret PutSecretValue DeleteSecret RestoreSecret RotateSecret GetSecretValue BatchGetSecretValue DescribeSecret ListSecrets GetResourcePolicy",
        "s3": "CreateBucket DeleteBucket PutBucketPolicy",
        "lambda": "UpdateFunctionConfiguration UpdateFunctionCode",
        "rds": "ModifyDBInstance DeleteDBInstance",
    }
    for prefix, operations in names.items():
        for name in operations.split():
            if name in labels:
                reference = "https://docs.aws.amazon.com/" + SERVICES[prefix][2] + "/API_" + name + ".html"
                add(prefix, name, labels[name], reference)
    add("monitoring", "PutDashboard", "保存 CloudWatch 监控仪表盘配置（新建或整体覆盖）",
        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutDashboard.html")
    add("monitoring", "PutMetricAlarm", "创建或更新 CloudWatch 指标告警配置",
        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html")
    add("signin", "ConsoleLogin", "登录 AWS 控制台", NON_API_REFERENCE, "AWS 控制台登录")
    # Q Developer chat events are documented CloudTrail actions even though
    # these console APIs are absent from the public SDK operation model.
    q_reference = "https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/security_iam_permissions.html"
    add("q", "SendMessage", "AI 对话：发送消息", q_reference, "Amazon Q Developer")
    add("q", "StartConversation", "AI 对话：发起会话", q_reference, "Amazon Q Developer")
    return entries


def parse_official_page(path, models):
    parser = ActionTable()
    parser.feed(path.read_text(encoding="utf-8"))
    # Accept only the exact official Chinese page, never a fallback index.
    expected = DOC_ROOT + path.name
    if parser.canonical != expected:
        return [], "not_official_chinese_page"
    prefix = path.stem.removeprefix("list_")
    candidates = [model for model in models if prefix in model["prefixes"]]
    exact = [model for model in candidates if model["sdk"] == prefix]
    if exact:
        candidates = exact
    if not candidates:
        return [], "no_confirmed_sdk_service"
    result = []
    for row in parser.rows:
        if len(row) < 3:
            continue
        name = row[0]["text"]
        # Permission-only / resource-only rows and footnoted permission actions
        # cannot satisfy this strict operation name check.
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,159}", name):
            continue
        label = short_label(row[1]["text"])
        if not label:
            continue
        for model in candidates:
            if name not in model["operations"]:
                continue
            reference = expected + ("#" + row[0]["id"] if row[0]["id"] else "")
            result.append((model["source"], name, {
                "event_label": label, "translation_status": "official_zh",
                "operation_reference": reference, "service_name": model["display"],
                "sdk_service": model["sdk"], "sdk_operation": name,
            }))
    return result, "matched" if result else "no_matching_chinese_api_labels"


def build(cache_dir):
    if not cache_dir.is_dir() or not any(cache_dir.glob("list_*.html")):
        raise ValueError("缓存目录不存在或没有 list_*.html；拒绝覆盖已有离线词典")
    sdk_version, models = sdk_models()
    entries, page_status, conflicts = reviewed_entries(), Counter(), set()
    seen_pages = []
    for path in sorted(cache_dir.glob("list_*.html")):
        records, status = parse_official_page(path, models)
        page_status[status] += 1
        if records:
            seen_pages.append(DOC_ROOT + path.name)
        for source, name, record in records:
            key = (source, name)
            if key in conflicts:
                continue
            current = entries.setdefault(source, {}).get(name)
            if current is None:
                entries[source][name] = record
            elif current["translation_status"] != "reviewed" and current["event_label"] != record["event_label"]:
                # The source/API tuple cannot disambiguate these service
                # aliases. Keep neither translation until reviewed.
                conflicts.add(key)
                del entries[source][name]
    statuses = Counter(record["translation_status"] for service in entries.values() for record in service.values())
    if not statuses["official_zh"]:
        raise ValueError("缓存中没有可确认的官方中文 API 标签；拒绝覆盖已有离线词典")
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_policy": "Reviewed API meanings plus Chinese AWS Service Authorization labels intersected with installed public SDK operations. Permission access levels do not define CRUD. Endpoint-based source coverage is not a complete CloudTrail event inventory.",
        "sdk_version": sdk_version,
        "statistics": {"service_sources": len(entries), "event_labels": sum(statuses.values()),
                       **dict(sorted(statuses.items())), "cached_pages": sum(page_status.values()),
                       "page_results": dict(sorted(page_status.items())), "conflicting_labels": len(conflicts)},
        "unresolved_conflicts": [{"eventSource": source, "eventName": name} for source, name in sorted(conflicts)],
        "official_sources": seen_pages,
        "entries": {source: dict(sorted(records.items())) for source, records in sorted(entries.items())},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "tmp" / "catalog-cache")
    parser.add_argument("--output", type=Path, default=ROOT / "aws-event-translations.json")
    parser.add_argument("--offline", action="store_true", help="Document explicit offline operation (the builder never downloads)")
    args = parser.parse_args()
    try:
        catalog = build(args.cache_dir)
    except ValueError as error:
        parser.exit(2, str(error) + "\n")
    args.output.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(catalog["statistics"], ensure_ascii=False))


if __name__ == "__main__":
    main()
