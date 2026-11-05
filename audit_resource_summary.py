"""Resource-operation counts for the mail body, from precomputed summaries only.

The collector already filters ordinary reads, de-duplicates API requests and
combines role sessions. A call's ``total`` includes its failed attempts; it is
neither a count of affected resources nor a count of successful changes. This
module never reads the detailed ``events`` collection or request attributes.
"""
from __future__ import annotations


RESOURCE_COLUMNS = ("安全组", "负载均衡", "弹性IP申请/绑定", "VPC", "路由表", "EC2", "RDS")
_CATEGORIES = ("新增", "修改", "删除", "Secrets Manager 查看", "登录信息", "其他操作")
_IDENTITY_TYPES = frozenset(("IAMUser", "Role", "Root", "AWSService", "IdentityCenterUser",
                             "FederatedUser", "Unknown"))

# Explicit API ownership, checked against AWS's official action groups and the
# local botocore 1.43.120 EC2 model (API version 2016-11-15):
# https://docs.aws.amazon.com/ec2/latest/devguide/OperationList-query-ec2.html
# https://docs.aws.amazon.com/ec2/latest/devguide/OperationList-query-vpc.html
# Per-operation reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_<Name>.html
# VPC endpoints/encryption and deprecated ClassicLink actions are also confirmed
# in botocore's operation documentation. No SDK or credentials are needed here.
_SECURITY_GROUP_APIS = frozenset((
    "CreateSecurityGroup", "DeleteSecurityGroup", "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
    "ModifySecurityGroupRules", "UpdateSecurityGroupRuleDescriptionsIngress",
    "UpdateSecurityGroupRuleDescriptionsEgress", "AssociateSecurityGroupVpc",
    "DisassociateSecurityGroupVpc",
))

_VPC_APIS = frozenset((
    "CreateVpc", "CreateDefaultVpc", "DeleteVpc", "ModifyVpcAttribute", "ModifyVpcTenancy",
    "AssociateVpcCidrBlock", "DisassociateVpcCidrBlock", "AssociateDhcpOptions",
    "EnableVpcClassicLink", "DisableVpcClassicLink", "EnableVpcClassicLinkDnsSupport",
    "DisableVpcClassicLinkDnsSupport", "CreateVpcPeeringConnection", "AcceptVpcPeeringConnection",
    "RejectVpcPeeringConnection", "DeleteVpcPeeringConnection", "ModifyVpcPeeringConnectionOptions",
    "CreateVpcEndpoint", "DeleteVpcEndpoints", "ModifyVpcEndpoint", "AcceptVpcEndpointConnections",
    "RejectVpcEndpointConnections", "CreateVpcEndpointServiceConfiguration",
    "DeleteVpcEndpointServiceConfigurations", "ModifyVpcEndpointServiceConfiguration",
    "ModifyVpcEndpointServicePermissions", "CreateVpcEndpointConnectionNotification",
    "DeleteVpcEndpointConnectionNotifications", "ModifyVpcEndpointConnectionNotification",
    "StartVpcEndpointServicePrivateDnsVerification", "ModifyVpcEndpointPayerResponsibility",
    "ModifyVpcEndpointServicePayerResponsibility", "CreateVpcBlockPublicAccessExclusion",
    "DeleteVpcBlockPublicAccessExclusion", "ModifyVpcBlockPublicAccessExclusion",
    "ModifyVpcBlockPublicAccessOptions", "CreateVpcEncryptionControl", "DeleteVpcEncryptionControl",
    "ModifyVpcEncryptionControl",
))

_ROUTE_TABLE_APIS = frozenset((
    "CreateRouteTable", "DeleteRouteTable", "AssociateRouteTable", "DisassociateRouteTable",
    "ReplaceRouteTableAssociation", "CreateRoute", "DeleteRoute", "ReplaceRoute",
    "EnableVgwRoutePropagation", "DisableVgwRoutePropagation",
))

# Only APIs with an explicit instance target/lifecycle belong here. EBS, AMIs,
# ENIs, fleets, Spot requests, shared event windows, account defaults and generic
# CreateTags/DeleteTags cannot establish an instance operation from API name alone.
_INSTANCE_APIS = frozenset((
    "RunInstances", "RunScheduledInstances", "StartInstances", "StopInstances", "RebootInstances",
    "TerminateInstances", "ModifyInstanceAttribute", "ResetInstanceAttribute",
    "ModifyInstanceCapacityReservationAttributes", "ModifyInstanceCpuOptions",
    "ModifyInstanceCreditSpecification", "ModifyInstanceEventStartTime",
    "ModifyInstanceMaintenanceOptions", "ModifyInstanceMetadataOptions",
    "ModifyInstanceNetworkPerformanceOptions", "ModifyInstancePlacement", "ModifyPrivateDnsNameOptions",
    "MonitorInstances", "UnmonitorInstances", "AssociateIamInstanceProfile",
    "DisassociateIamInstanceProfile", "ReplaceIamInstanceProfileAssociation", "ReportInstanceStatus",
    "SendDiagnosticInterrupt", "CreateDelegateMacVolumeOwnershipTask",
    "CreateMacSystemIntegrityProtectionModificationTask", "EnableInstanceSqlHaStandbyDetections",
    "DisableInstanceSqlHaStandbyDetections",
))

_EC2_GROUPS = (("安全组", _SECURITY_GROUP_APIS),
               ("弹性IP申请/绑定", frozenset(("AllocateAddress", "AssociateAddress"))),
               ("VPC", _VPC_APIS), ("路由表", _ROUTE_TABLE_APIS), ("EC2", _INSTANCE_APIS))


def _zero_counts():
    return dict.fromkeys(RESOURCE_COLUMNS, 0)


def _count(value):
    if type(value) is not int or value < 0:
        raise ValueError("资源操作汇总计数必须为非负整数。")
    return value


def _label(value, maximum):
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("资源操作汇总的身份或 API 名称无效。")
    return value


def _identity(row):
    if not isinstance(row, dict):
        raise ValueError("资源操作汇总需要身份/API 对象数组。")
    actor = _label(row.get("actor"), 1024)
    kind = row.get("identity_type")
    if not isinstance(kind, str) or kind not in _IDENTITY_TYPES:
        raise ValueError("资源操作汇总的身份类型无效。")
    return kind, actor


def _totals():
    return {"total": 0, "failed": 0, "counts": dict.fromkeys(_CATEGORIES, 0)}


def _add_totals(target, total, failed, counts):
    target["total"] += total
    target["failed"] += failed
    for category in _CATEGORIES:
        target["counts"][category] += counts[category]


def _resource_column(source, name):
    # Exact CloudTrail service endpoints, including the China partition. A
    # same-named API from another AWS service never inherits EC2 classification.
    if source in ("elasticloadbalancing.amazonaws.com", "elasticloadbalancing.amazonaws.com.cn"):
        return "负载均衡"
    if source in ("rds.amazonaws.com", "rds.amazonaws.com.cn"):
        return "RDS"
    if source in ("ec2.amazonaws.com", "ec2.amazonaws.com.cn"):
        for column, names in _EC2_GROUPS:
            if name in names:
                return column
    return None


def _metadata_total(meta):
    counts = meta.get("counts")
    if counts is not None and not isinstance(counts, dict):
        raise ValueError("资源操作汇总需要有效的分类总计。")
    category_total = sum(_count(value) for value in counts.values()) if counts is not None else None
    total = _count(meta["total"]) if "total" in meta else category_total
    if total is None or (category_total is not None and total != category_total):
        raise ValueError("资源操作汇总的账号调用总计不一致或缺失。")
    if "failed_or_partial" in meta and _count(meta["failed_or_partial"]) > total:
        raise ValueError("资源操作汇总的账号失败次数超过调用总计。")
    return total


def summarize_resource_operations(report):
    """Return seven exclusive resource-operation columns for one account.

    All identities in ``actors`` receive a row, including those whose operations
    do not match these columns. Names remain unchanged, and identical user/role
    names stay separate. Missing legacy summaries with nonzero metadata totals
    return ``available=False`` so callers can show an explicit unavailable state.
    Invalid or inconsistent supplied summaries raise ``ValueError``.
    """
    if not isinstance(report, dict) or not isinstance(report.get("metadata"), dict):
        raise ValueError("资源操作汇总需要有效的 metadata。")
    meta = report["metadata"]
    total = _metadata_total(meta)
    actors, actor_events = report.get("actors"), report.get("actor_events")
    for values in (actors, actor_events):
        if values is not None and not isinstance(values, list):
            raise ValueError("资源操作汇总需要身份和 API 数组。")
    if total > 0 and (not actors or not actor_events):
        return {"available": False, "rows": [], "counts": _zero_counts()}
    actors = [] if actors is None else actors
    actor_events = [] if actor_events is None else actor_events

    identities, expected = {}, {}
    for actor in actors:
        key = _identity(actor)
        raw_counts = actor.get("counts")
        if not isinstance(raw_counts, dict):
            raise ValueError("资源操作汇总的身份分类计数无效。")
        counts = {category: _count(raw_counts.get(category, 0)) for category in _CATEGORIES}
        row_total, failed = _count(actor.get("total")), _count(actor.get("failed"))
        if row_total != sum(counts.values()) or failed > row_total:
            raise ValueError("资源操作汇总的身份调用或失败总计不一致。")
        identities.setdefault(key, {"actor": key[1], "identity_type": key[0], "counts": _zero_counts()})
        _add_totals(expected.setdefault(key, _totals()), row_total, failed, counts)

    observed, counts = {}, _zero_counts()
    for event in actor_events:
        key = _identity(event)
        source = _label(event.get("source"), 256)
        name = _label(event.get("event_name"), 256)
        category = event.get("category")
        if not isinstance(category, str) or category not in _CATEGORIES:
            raise ValueError("资源操作汇总的 API 分类无效。")
        row_total, failed = _count(event.get("total")), _count(event.get("failed"))
        if failed > row_total:
            raise ValueError("资源操作汇总的 API 失败次数超过调用次数。")
        if key not in identities:
            raise ValueError("资源操作汇总的 API 身份不存在于身份汇总。")
        event_counts = dict.fromkeys(_CATEGORIES, 0)
        event_counts[category] = row_total
        _add_totals(observed.setdefault(key, _totals()), row_total, failed, event_counts)
        column = _resource_column(source, name)
        if column is not None:
            identities[key]["counts"][column] += row_total
            counts[column] += row_total

    # Zero-operation identities legitimately have no corresponding API rows.
    for key in expected:
        observed.setdefault(key, _totals())
    if expected != observed or sum(row["total"] for row in expected.values()) != total:
        raise ValueError("资源操作汇总的 API、身份或账号调用总计不一致。")
    if ("failed_or_partial" in meta
            and sum(row["failed"] for row in expected.values()) != meta["failed_or_partial"]):
        raise ValueError("资源操作汇总的身份与账号失败总计不一致。")
    rows = [identities[key] for key in sorted(identities, key=lambda key: (key[0], key[1].casefold(), key[1]))]
    return {"available": True, "rows": rows, "counts": counts}
