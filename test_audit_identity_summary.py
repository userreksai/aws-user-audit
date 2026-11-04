"""Identity grouping tests use normalized fictional rows and no transports."""
from copy import deepcopy
import json
import unittest

from audit_identity_summary import CATEGORIES, summarize_identities, summarize_identity_events


def row(actor="hhjgx", *, kind="IAMUser", arn="arn:aws:iam::123456789012:user/hhjgx",
        principal="AIDAFAKE", role="", category="修改", failed=False, **fields):
    return {"actor": actor, "identity": {"type": kind, "arn": arn, "principal_id": principal,
                                          "role_arn": role, "on_behalf_of": {}},
            "category": category, "failed": failed, **fields}


class IdentitySummaryTests(unittest.TestCase):
    def test_iam_user_has_category_counts_and_failures_are_a_subset(self):
        rows = [row(category=category, failed=index == 0) for index, category in enumerate(CATEGORIES)]
        original = deepcopy(rows)
        value = summarize_identities(rows)
        self.assertEqual(len(value), 1)
        self.assertEqual(value[0], {"actor": "hhjgx", "identity_type": "IAMUser",
                                    "counts": {category: 1 for category in CATEGORIES}, "failed": 1, "total": 6})
        self.assertEqual(rows, original)

    def test_role_sessions_merge_under_same_issuer(self):
        role = "arn:aws:iam::123456789012:role/team/DeployRole"
        rows = [row("角色 DeployRole / 会话 "+session, kind="AssumedRole",
                    arn=f"arn:aws:sts::123456789012:assumed-role/team/DeployRole/{session}",
                    principal="AROAROLE:"+session, role=role) for session in ("alice", "bob")]
        result = summarize_identities(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["actor"], "team/DeployRole")
        self.assertEqual(result[0]["identity_type"], "Role")
        self.assertEqual(result[0]["total"], 2)
        self.assertNotIn("alice", json.dumps(result))
        self.assertNotIn("bob", json.dumps(result))

    def test_same_session_name_from_different_roles_stays_separate(self):
        rows = [row("角色 "+name+" / 会话 repeated", kind="AssumedRole",
                    arn=f"arn:aws:sts::123456789012:assumed-role/{name}/repeated", principal="",
                    role=f"arn:aws:iam::123456789012:role/{name}") for name in ("RoleA", "RoleB")]
        result = summarize_identities(rows)
        self.assertEqual([r["actor"] for r in result], ["RoleA", "RoleB"])
        self.assertEqual([r["total"] for r in result], [1, 1])

    def test_role_arn_fallback_canonicalizes_and_joins_issuer_form(self):
        rows = [row(kind="AssumedRole", arn="arn:aws:sts::123456789012:assumed-role/team/DeployRole/one", principal=""),
                row(kind="AssumedRole", arn="arn:aws:sts::123456789012:assumed-role/team/DeployRole/two", principal="",
                    role="arn:aws:iam::123456789012:role/team/DeployRole")]
        result = summarize_identities(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["actor"], "team/DeployRole")
        self.assertEqual(result[0]["total"], 2)

    def test_same_iam_arn_with_display_aliases_merges(self):
        result = summarize_identities([row("renamed-display"), row("other-display")])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["actor"], "hhjgx")
        self.assertEqual(result[0]["total"], 2)

    def test_same_named_iam_user_and_role_never_merge(self):
        result = summarize_identities([row("Shared", arn="arn:aws:iam::123456789012:user/Shared"),
                                       row("角色 Shared / 会话 one", kind="AssumedRole", principal="",
                                           arn="arn:aws:sts::123456789012:assumed-role/Shared/one")])
        self.assertEqual(len(result), 2)
        self.assertEqual({r["identity_type"] for r in result}, {"IAMUser", "Role"})

    def test_same_named_users_in_different_arns_do_not_merge(self):
        result = summarize_identities([row("Shared", arn=f"arn:aws:iam::{account}:user/Shared")
                                       for account in ("123456789012", "210987654321")])
        self.assertEqual(len(result), 2)

    def test_principal_identifier_is_a_stable_fallback_for_iam(self):
        result = summarize_identities([row("z-display", arn="", principal="AIDAONE"),
                                       row("a-display", arn="", principal="AIDAONE")])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["actor"], "a-display")
        self.assertEqual(result[0]["total"], 2)

    def test_root_service_federated_and_unknown_are_explicit_and_separate(self):
        rows = [row("Root", kind="Root", arn="arn:aws:iam::123456789012:root", principal=""),
                row("AWS 服务 ec2.amazonaws.com", kind="AWSService", arn="", principal="ec2.amazonaws.com"),
                row("federated", kind="FederatedUser", arn="arn:aws:sts::123456789012:federated-user/Federated", principal=""),
                row("未知身份", kind="Unknown", arn="", principal=""),
                {"actor": "未知身份", "category": "新增", "failed": True}]
        result = summarize_identities(rows)
        self.assertEqual({r["identity_type"] for r in result}, {"Root", "AWSService", "FederatedUser", "Unknown"})
        unknown = next(r for r in result if r["identity_type"] == "Unknown")
        # Different explicit unknown types may remain separate conservative buckets.
        self.assertEqual(sum(r["total"] for r in result), 5)
        self.assertIn(unknown["actor"], {"未知身份"})
        self.assertEqual(next(r for r in result if r["identity_type"] == "AWSService")["actor"], "ec2.amazonaws.com")

    def test_identity_center_key_contains_store_and_user(self):
        rows = []
        for store in ("d-first", "d-first", "d-second"):
            value = row("center user", kind="IdentityCenterUser", arn="", principal="")
            value["identity"]["on_behalf_of"] = {"userId": "u-fictional", "identityStoreArn": "arn:aws:identitystore::123456789012:identitystore/"+store}
            rows.append(value)
        result = summarize_identities(rows)
        self.assertEqual(len(result), 2)
        self.assertEqual(sorted(r["total"] for r in result), [1, 2])
        self.assertTrue(all(r["identity_type"] == "IdentityCenterUser" for r in result))
        self.assertNotEqual(result[0]["actor"], result[1]["actor"])

    def test_only_valid_report_categories_are_counted_and_order_is_stable(self):
        rows = [row("Zed", arn="arn:aws:iam::123456789012:user/Zed"), row("Alice", arn="arn:aws:iam::123456789012:user/Alice"),
                row(category=None), row(category="ignored"), None, "invalid"]
        result = summarize_identities(rows)
        self.assertEqual([r["actor"] for r in result], ["Alice", "Zed"])
        self.assertEqual(result, summarize_identities(list(reversed(rows))))
        self.assertEqual(sum(r["total"] for r in result), 2)

    def test_output_whitelist_never_contains_request_or_transport_details(self):
        value = row(requestParameters={"password": "PRIVATE_PASSWORD"}, response={"token": "PRIVATE_TOKEN"},
                    source_ip="203.0.113.50", event_name="VERY_PRIVATE_API_NAME", time_local="PRIVATE_TIME",
                    user_agent="PRIVATE_USER_AGENT", resources=["PRIVATE_RESOURCE"])
        result = summarize_identities([value])
        self.assertEqual(set(result[0]), {"actor", "identity_type", "counts", "failed", "total"})
        serialized = json.dumps(result)
        for text in ("PRIVATE_PASSWORD", "PRIVATE_TOKEN", "203.0.113.50", "VERY_PRIVATE_API_NAME", "PRIVATE_TIME", "PRIVATE_USER_AGENT", "PRIVATE_RESOURCE"):
            self.assertNotIn(text, serialized)
        self.assertEqual(sum(result[0]["counts"].values()), result[0]["total"])

    def test_invalid_input_is_rejected_safely(self):
        with self.assertRaises(ValueError):
            summarize_identities({"events": "private"})


def event_row(actor="hhjgx", **fields):
    defaults = {"source": "monitoring.amazonaws.com", "event_name": "PutDashboard",
                "event_label": "创建或覆盖 CloudWatch 控制面板", "translation_status": "reviewed",
                "operation_reference": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutDashboard.html"}
    defaults.update(fields)
    return row(actor, **defaults)


class IdentityEventSummaryTests(unittest.TestCase):
    def test_success_and_failed_calls_share_one_row_with_failure_subset(self):
        rows = [event_row(), event_row(failed=True, event_label="尝试：创建或覆盖 CloudWatch 控制面板"),
                event_row(failed="true")]
        original = deepcopy(rows)
        result = summarize_identity_events(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["total"], 3)
        self.assertEqual(result[0]["failed"], 1)
        self.assertEqual(result[0]["event_label"], "创建或覆盖 CloudWatch 控制面板")
        self.assertEqual(rows, original)

    def test_same_api_for_two_iam_users_has_distinct_rows(self):
        rows = [event_row(), event_row("beiou", arn="arn:aws:iam::123456789012:user/beiou")]
        result = summarize_identity_events(rows)
        self.assertEqual([item["actor"] for item in result], ["beiou", "hhjgx"])
        self.assertTrue(all(item["event_label"] == "创建或覆盖 CloudWatch 控制面板" for item in result))
        self.assertEqual([item["total"] for item in result], [1, 1])

    def test_same_identity_and_service_different_apis_remain_separate(self):
        rows = [event_row(), event_row(event_name="DeleteDashboards", event_label="删除 CloudWatch 控制面板", category="删除")]
        result = summarize_identity_events(rows)
        self.assertEqual([item["event_name"] for item in result], ["DeleteDashboards", "PutDashboard"])
        self.assertEqual([item["category"] for item in result], ["删除", "修改"])

    def test_same_api_from_different_services_never_merges(self):
        rows = [event_row(source=source, event_name="DeletePolicy", category="删除")
                for source in ("iam.amazonaws.com", "organizations.amazonaws.com")]
        result = summarize_identity_events(rows)
        self.assertEqual(len(result), 2)
        self.assertEqual([item["source"] for item in result], ["iam.amazonaws.com", "organizations.amazonaws.com"])
        self.assertEqual(sum(item["total"] for item in result), 2)

    def test_role_sessions_merge_by_stable_issuing_role(self):
        role = "arn:aws:iam::123456789012:role/team/DeployRole"
        rows = [event_row("角色 DeployRole / 会话 "+session, kind="AssumedRole",
                          arn=f"arn:aws:sts::123456789012:assumed-role/team/DeployRole/{session}",
                          principal="AROAROLE:"+session, role=role, failed=index == 0)
                for index, session in enumerate(("alice", "bob"))]
        result = summarize_identity_events(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual((result[0]["actor"], result[0]["identity_type"]), ("team/DeployRole", "Role"))
        self.assertEqual((result[0]["total"], result[0]["failed"]), (2, 1))
        self.assertNotIn("alice", json.dumps(result))
        self.assertNotIn("bob", json.dumps(result))

    def test_same_name_user_and_role_and_distinct_roles_do_not_merge(self):
        rows = [event_row("Shared", arn="arn:aws:iam::123456789012:user/Shared")]
        rows += [event_row("角色 "+name+" / 会话 repeated", kind="AssumedRole", principal="",
                           arn=f"arn:aws:sts::123456789012:assumed-role/{name}/repeated")
                 for name in ("Shared", "AnotherRole")]
        result = summarize_identity_events(rows)
        self.assertEqual([(item["identity_type"], item["actor"]) for item in result],
                         [("IAMUser", "Shared"), ("Role", "AnotherRole"), ("Role", "Shared")])
        self.assertEqual(sum(item["total"] for item in result), 3)

    def test_event_category_and_failure_totals_match_existing_identity_summary(self):
        rows = [event_row(category=category, failed=index % 2 == 0) for index, category in enumerate(CATEGORIES)]
        rows += [event_row("beiou", arn="arn:aws:iam::123456789012:user/beiou", category="新增"),
                 event_row(category="忽略查看"), None]
        identities = summarize_identities(rows)
        result = summarize_identity_events(rows)
        self.assertEqual(sum(item["total"] for item in result), sum(item["total"] for item in identities))
        self.assertEqual(sum(item["failed"] for item in result), sum(item["failed"] for item in identities))
        for identity in identities:
            events = [item for item in result if (item["actor"], item["identity_type"]) ==
                      (identity["actor"], identity["identity_type"])]
            for category in CATEGORIES:
                self.assertEqual(sum(item["total"] for item in events if item["category"] == category),
                                 identity["counts"][category])
            self.assertEqual(sum(item["total"] for item in events), identity["total"])
            self.assertEqual(sum(item["failed"] for item in events), identity["failed"])

    def test_identity_display_alias_is_canonical_across_different_events(self):
        rows = [event_row("z-display", arn="", principal="AIDAONE"),
                event_row("a-display", arn="", principal="AIDAONE", event_name="DeleteDashboards")]
        result = summarize_identity_events(rows)
        self.assertEqual({item["actor"] for item in result}, {summarize_identities(rows)[0]["actor"]})
        self.assertEqual({item["actor"] for item in result}, {"a-display"})

    def test_missing_label_or_unknown_status_keeps_source_and_api_marked_untranslated(self):
        for fields in ({"event_label": ""}, {"translation_status": "made-up"},
                       {"translation_status": []}, {"translation_status": "untranslated"}):
            with self.subTest(fields=fields):
                result = summarize_identity_events([event_row(**fields)])[0]
                self.assertEqual(result["translation_status"], "untranslated")
                self.assertEqual(result["event_label"], "待补中文：monitoring.amazonaws.com / PutDashboard")
                self.assertEqual((result["source"], result["event_name"]), ("monitoring.amazonaws.com", "PutDashboard"))

    def test_missing_service_or_api_still_counts_without_guessing(self):
        result = summarize_identity_events([event_row(source="", event_name="", event_label="")])[0]
        self.assertEqual(result["total"], 1)
        self.assertEqual((result["source"], result["event_name"]), ("未提供服务", "未知事件"))
        self.assertEqual(result["event_label"], "待补中文：未提供服务 / 未知事件")

    def test_mixed_translation_metadata_uses_best_available_label_deterministically(self):
        rows = [event_row(event_label="", translation_status="untranslated", operation_reference=""),
                event_row(event_label="官方中文标签", translation_status="official_zh"),
                event_row(operation_reference=""), event_row()]
        result = summarize_identity_events(rows)
        self.assertEqual(result, summarize_identity_events(list(reversed(rows))))
        self.assertEqual(result[0]["translation_status"], "reviewed")
        self.assertEqual(result[0]["event_label"], "创建或覆盖 CloudWatch 控制面板")
        self.assertTrue(result[0]["operation_reference"].startswith("https://docs.aws.amazon.com/"))
        self.assertEqual(result[0]["total"], 4)

    def test_output_has_only_aggregate_whitelist_and_no_sensitive_details(self):
        value = event_row(requestParameters={"password": "PRIVATE_PASSWORD"}, response={"token": "PRIVATE_TOKEN"},
                          source_ip="203.0.113.50", time_local="PRIVATE_TIME", user_agent="PRIVATE_USER_AGENT",
                          resources=["PRIVATE_RESOURCE"], description="PRIVATE_DESCRIPTION", failed=True)
        result = summarize_identity_events([value])
        self.assertEqual(set(result[0]), {"actor", "identity_type", "source", "event_name", "event_label",
                                         "translation_status", "operation_reference", "category", "total", "failed"})
        serialized = json.dumps(result)
        for private in ("PRIVATE_PASSWORD", "PRIVATE_TOKEN", "203.0.113.50", "PRIVATE_TIME", "PRIVATE_USER_AGENT",
                        "PRIVATE_RESOURCE", "PRIVATE_DESCRIPTION", "requestParameters", "response", "identity", "arn"):
            self.assertNotIn('"'+private+'"', serialized)

    def test_unofficial_or_credential_bearing_reference_is_discarded(self):
        for reference in ("http://docs.aws.amazon.com/A.html", "https://example.com/A.html",
                          "https://docs.aws.amazon.com.evil.example/A.html", "https://user:password@docs.aws.amazon.com/A.html",
                          "https://docs.aws.amazon.com:444/A.html", "https://docs.aws.amazon.com/A.html?token=PRIVATE",
                          "https://docs.aws.amazon.com:bad/A.html"):
            with self.subTest(reference=reference):
                value = summarize_identity_events([event_row(operation_reference=reference)])[0]
                self.assertEqual(value["operation_reference"], "")

    def test_only_valid_report_categories_are_counted_and_order_is_stable(self):
        rows = [event_row("Zed", arn="arn:aws:iam::123456789012:user/Zed"),
                event_row("Alice", arn="arn:aws:iam::123456789012:user/Alice"),
                event_row(category=None), event_row(category="ignored"), None, "invalid"]
        result = summarize_identity_events(rows)
        self.assertEqual([item["actor"] for item in result], ["Alice", "Zed"])
        self.assertEqual(result, summarize_identity_events(list(reversed(rows))))
        self.assertEqual(sum(item["total"] for item in result), 2)

    def test_invalid_input_is_rejected_safely(self):
        with self.assertRaises(ValueError):
            summarize_identity_events({"events": "private"})


if __name__ == "__main__":
    unittest.main()
