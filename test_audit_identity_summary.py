"""Identity grouping tests use normalized fictional rows and no transports."""
from copy import deepcopy
import json
import unittest

from audit_identity_summary import CATEGORIES, summarize_identities


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


if __name__ == "__main__":
    unittest.main()
