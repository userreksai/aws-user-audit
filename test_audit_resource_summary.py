"""Summary-only resource counts; no request details may enter mail counts."""
from __future__ import annotations

from copy import deepcopy
import unittest

from audit_identity_summary import summarize_identities, summarize_identity_events
from audit_resource_summary import RESOURCE_COLUMNS, summarize_resource_operations


CATEGORIES = ("新增", "修改", "删除", "Secrets Manager 查看", "登录信息", "其他操作")


def event(actor="alice", name="RunInstances", source="ec2.amazonaws.com", total=1,
          failed=0, kind="IAMUser", category="修改"):
    return {"actor": actor, "identity_type": kind, "source": source, "event_name": name,
            "category": category, "total": total, "failed": failed}


def report_fixture(events=(), zero_identities=()):
    actors = {}
    events = list(events)
    for item in events:
        key = (item["identity_type"], item["actor"])
        row = actors.setdefault(key, {"actor": item["actor"], "identity_type": item["identity_type"],
                                      "counts": dict.fromkeys(CATEGORIES, 0), "total": 0, "failed": 0})
        row["counts"][item["category"]] += item["total"]
        row["total"] += item["total"]
        row["failed"] += item["failed"]
    for kind, actor in zero_identities:
        actors[(kind, actor)] = {"actor": actor, "identity_type": kind, "counts": dict.fromkeys(CATEGORIES, 0),
                                "total": 0, "failed": 0}
    rows = list(actors.values())
    return {"metadata": {"total": sum(row["total"] for row in rows),
                         "counts": {category: sum(row["counts"][category] for row in rows) for category in CATEGORIES},
                         "failed_or_partial": sum(row["failed"] for row in rows)},
            "actors": rows, "actor_events": events}


def by_identity(summary):
    return {(row["identity_type"], row["actor"]): row["counts"] for row in summary["rows"]}


class Poison:
    def __iter__(self):
        raise AssertionError("Detailed event data must never be inspected")

    def __len__(self):
        raise AssertionError("Detailed event data must never be inspected")

    def __str__(self):
        raise AssertionError("Detailed event data must never be serialized")


class WhitelistDict(dict):
    def get(self, key, default=None):
        if key in {"events", "parameters", "resources", "source_ip", "identity", "account_id", "account_tag"}:
            raise AssertionError("Private or unrelated fields must never be read: " + key)
        return super().get(key, default)

    def __getitem__(self, key):
        if key in {"events", "parameters", "resources", "source_ip", "identity", "account_id", "account_tag"}:
            raise AssertionError("Private or unrelated fields must never be read: " + key)
        return super().__getitem__(key)


class ResourceSummaryTests(unittest.TestCase):
    def test_exact_columns_and_all_identities_including_zero(self):
        self.assertEqual(RESOURCE_COLUMNS, ("安全组", "负载均衡", "弹性IP申请/绑定", "VPC", "路由表", "EC2", "RDS"))
        report = report_fixture([event(name="ConsoleLogin", source="signin.amazonaws.com")],
                                zero_identities=[("IAMUser", "zero-user"), ("Role", "zero-role")])
        summary = summarize_resource_operations(report)
        self.assertTrue(summary["available"])
        self.assertEqual(len(summary["rows"]), 3)
        for row in summary["rows"]:
            self.assertEqual(tuple(row["counts"]), RESOURCE_COLUMNS)
            self.assertEqual(set(row), {"actor", "identity_type", "counts"})
            self.assertTrue(all(count == 0 for count in row["counts"].values()))

    def test_failed_calls_are_part_of_deduplicated_api_request_total(self):
        report = report_fixture([event(total=5, failed=3), event(name="StopInstances", total=2, failed=2)])
        summary = summarize_resource_operations(report)
        self.assertEqual(summary["counts"]["EC2"], 7)
        self.assertEqual(summary["rows"][0]["counts"]["EC2"], 7)

    def test_seven_resource_columns_are_mutually_exclusive(self):
        values = [event(name="AuthorizeSecurityGroupIngress", total=2),
                  event(name="AssociateSecurityGroupVpc", total=3),
                  event(name="CreateVpc", total=4), event(name="CreateRoute", total=5),
                  event(name="AllocateAddress", total=6), event(name="AssociateAddress", total=7),
                  event(name="ModifyInstanceAttribute", total=8),
                  event(name="CreateListener", source="elasticloadbalancing.amazonaws.com", total=9),
                  event(name="FailoverDBCluster", source="rds.amazonaws.com", total=10)]
        summary = summarize_resource_operations(report_fixture(values))
        self.assertEqual(summary["counts"], dict(zip(RESOURCE_COLUMNS, (5, 9, 13, 4, 5, 8, 10))))
        self.assertEqual(sum(summary["counts"].values()), sum(item["total"] for item in values))

    def test_elastic_ip_only_allocation_and_association(self):
        values = [event(name=name) for name in ("AllocateAddress", "AssociateAddress", "DisassociateAddress",
                                                "ReleaseAddress", "ModifyAddressAttribute", "AcceptAddressTransfer",
                                                "EnableAddressTransfer", "MoveAddressToVpc")]
        summary = summarize_resource_operations(report_fixture(values))
        self.assertEqual(summary["counts"]["弹性IP申请/绑定"], 2)
        self.assertEqual(sum(summary["counts"].values()), 2)

    def test_exact_service_source_prevents_same_named_api_misclassification(self):
        values = [event(name="CreateSecurityGroup", source="example.amazonaws.com"),
                  event(name="RunInstances", source="ec2.amazonaws.com.evil.test"),
                  event(name="CreateDBInstance", source="rds-data.amazonaws.com"),
                  event(name="CreateRoute", source="route53.amazonaws.com"),
                  event(name="CreateSecurityGroup", source="ec2.amazonaws.com.cn"),
                  event(name="CreateLoadBalancer", source="elasticloadbalancing.amazonaws.com.cn"),
                  event(name="CreateDBInstance", source="rds.amazonaws.com.cn")]
        summary = summarize_resource_operations(report_fixture(values))
        self.assertEqual(sum(summary["counts"].values()), 3)
        self.assertEqual(summary["counts"]["安全组"], 1)
        self.assertEqual(summary["counts"]["负载均衡"], 1)
        self.assertEqual(summary["counts"]["RDS"], 1)

    def test_generic_or_other_ec2_resource_apis_are_not_guessed(self):
        values = [event(name=name) for name in (
            "CreateTags", "DeleteTags", "CreateSubnet", "ModifySubnetAttribute", "CreateNatGateway",
            "CreateNetworkInterface", "ModifyNetworkInterfaceAttribute", "AttachNetworkInterface",
            "CreateVolume", "AttachVolume", "CreateImage", "CreateLaunchTemplate", "CreateFleet",
            "CreateTransitGatewayVpcAttachment", "CreateFlowLogs", "CreateInstanceEventWindow",
            "ModifyInstanceMetadataDefaults", "ModifyDefaultCreditSpecification", "RequestSpotInstances",
            "CancelSpotInstanceRequests", "CreateFutureInstanceThing", "DescribeInstances",
        )]
        summary = summarize_resource_operations(report_fixture(values))
        self.assertEqual(sum(summary["counts"].values()), 0)

    def test_vpc_endpoints_peering_configuration_and_instance_configuration(self):
        values = [event(name="ModifyVpcAttribute"), event(name="AcceptVpcPeeringConnection"),
                  event(name="CreateVpcEndpoint"), event(name="ModifyVpcEndpointServicePermissions"),
                  event(name="AssociateDhcpOptions"), event(name="EnableVgwRoutePropagation"),
                  event(name="ReplaceRouteTableAssociation"), event(name="ModifyInstanceMetadataOptions"),
                  event(name="ReplaceIamInstanceProfileAssociation"), event(name="MonitorInstances")]
        summary = summarize_resource_operations(report_fixture(values))
        self.assertEqual((summary["counts"]["VPC"], summary["counts"]["路由表"], summary["counts"]["EC2"]), (5, 2, 3))

    def test_rds_aurora_and_load_balancer_all_filtered_management_actions(self):
        values = [event(name=name, source="rds.amazonaws.com") for name in (
            "CreateDBInstance", "RestoreDBClusterFromSnapshot", "FailoverGlobalCluster", "SwitchoverBlueGreenDeployment")]
        values += [event(name=name, source="elasticloadbalancing.amazonaws.com") for name in (
            "RegisterTargets", "ModifyRule", "SetSecurityGroups", "DeleteTargetGroup")]
        summary = summarize_resource_operations(report_fixture(values))
        self.assertEqual(summary["counts"]["RDS"], 4)
        self.assertEqual(summary["counts"]["负载均衡"], 4)

    def test_users_and_same_named_roles_are_separate_and_stable_names_combine(self):
        report = report_fixture([event(actor="shared", total=2),
                                event(actor="shared", kind="Role", total=3), event(actor="other", total=4)])
        # Different identity keys can have the same public stable name upstream.
        duplicate = deepcopy(report["actors"][1])
        report["actors"].append(duplicate)
        report["actor_events"].append(event(actor="shared", kind="Role", total=3))
        report["metadata"]["total"] += 3
        report["metadata"]["counts"]["修改"] += 3
        rows = by_identity(summarize_resource_operations(report))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[("IAMUser", "shared")]["EC2"], 2)
        self.assertEqual(rows[("Role", "shared")]["EC2"], 6)
        self.assertEqual(rows[("IAMUser", "other")]["EC2"], 4)

    def test_upstream_role_sessions_remain_one_role(self):
        raw = [{"actor": "session-" + session, "identity": {"type": "AssumedRole",
                "arn": "arn:aws:sts::123456789012:assumed-role/team/DeployRole/" + session},
                "category": "修改", "source": "ec2.amazonaws.com", "event_name": "StartInstances"}
               for session in ("a", "b")]
        report = {"metadata": {"total": 2}, "actors": summarize_identities(raw),
                  "actor_events": summarize_identity_events(raw)}
        summary = summarize_resource_operations(report)
        self.assertEqual([(row["actor"], row["identity_type"]) for row in summary["rows"]], [("team/DeployRole", "Role")])
        self.assertEqual(summary["rows"][0]["counts"]["EC2"], 2)

    def test_legacy_nonzero_summaries_are_unavailable_with_counts_fallback(self):
        for fields in ({}, {"actors": []}, {"actor_events": []}, {"actors": [], "actor_events": []}):
            report = {"metadata": {"counts": {"新增": 2, "修改": 1}}, **fields}
            summary = summarize_resource_operations(report)
            self.assertIs(summary["available"], False)
            self.assertEqual(summary["rows"], [])
        report = report_fixture([event()])
        del report["metadata"]["total"]
        self.assertTrue(summarize_resource_operations(report)["available"])

    def test_genuinely_empty_account_and_only_zero_identity_are_available(self):
        self.assertEqual(summarize_resource_operations({"metadata": {"total": 0}}),
                         {"available": True, "rows": [], "counts": dict.fromkeys(RESOURCE_COLUMNS, 0)})
        self.assertEqual(len(summarize_resource_operations(report_fixture(zero_identities=[("IAMUser", "zero")]))["rows"]), 1)

    def test_no_mutation_and_no_details_account_labels_or_private_identity_keys_read(self):
        ordinary = report_fixture([event()])
        before = deepcopy(ordinary)
        summarize_resource_operations(ordinary)
        self.assertEqual(ordinary, before)
        report = WhitelistDict(ordinary)
        report["events"] = Poison()
        report["actors"] = [WhitelistDict({**row, "parameters": Poison(), "identity": Poison()}) for row in report["actors"]]
        report["actor_events"] = [WhitelistDict({**row, "parameters": Poison(), "source_ip": Poison(), "resources": Poison()})
                                   for row in report["actor_events"]]
        summary = summarize_resource_operations(report)
        self.assertEqual(summary["counts"]["EC2"], 1)
        self.assertEqual(set(summary), {"available", "rows", "counts"})

    def test_many_accounts_are_independent_without_fixed_account_count(self):
        for index in range(1, 10):
            report = report_fixture([event(actor="shared", total=index)])
            report["metadata"].update(account_id=f"{index:012d}", account_tag="tag-" + str(index))
            summary = summarize_resource_operations(report)
            self.assertEqual(summary["counts"]["EC2"], index)
            self.assertEqual(len(summary["rows"]), 1)

    def test_invalid_fields_and_inconsistent_supplied_summaries_fail(self):
        mutations = (
            lambda r: r["metadata"].update(total=True),
            lambda r: r["metadata"].update(failed_or_partial=2),
            lambda r: r["actors"][0].update(actor=""),
            lambda r: r["actors"][0].update(identity_type="AssumedRole"),
            lambda r: r["actors"][0].update(total=2),
            lambda r: r["actors"][0]["counts"].update({"修改": True}),
            lambda r: r["actors"][0].update(failed=-1),
            lambda r: r["actor_events"][0].update(actor="other"),
            lambda r: r["actor_events"][0].update(identity_type="Role"),
            lambda r: r["actor_events"][0].update(total=2),
            lambda r: r["actor_events"][0].update(total=1.0),
            lambda r: r["actor_events"][0].update(failed=True),
            lambda r: r["actor_events"][0].update(failed=2),
            lambda r: r["actor_events"][0].update(category="新增"),
            lambda r: r["actor_events"][0].update(category="不合法"),
            lambda r: r["actor_events"][0].update(source=[]),
            lambda r: r["actor_events"][0].update(event_name="\nRunInstances"),
            lambda r: r.update(actor_events={}),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                report = report_fixture([event()])
                mutation(report)
                with self.assertRaises(ValueError):
                    summarize_resource_operations(report)


if __name__ == "__main__":
    unittest.main()
