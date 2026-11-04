"""Reviewed API rules and local model documentation; no network or credentials."""
from unittest import TestCase, main
from unittest.mock import patch

import audit_actions as actions


def event(service="ec2", name="MonitorInstances", **kwargs):
    return {"eventSource": service + ".amazonaws.com", "eventName": name, **kwargs}


class ReviewedActionTests(TestCase):
    def test_verified_missing_crud_apis_have_precise_service_rules(self):
        samples = (("ec2", "MonitorInstances", "修改"), ("ec2", "UnmonitorInstances", "修改"),
                   ("ec2", "RequestSpotInstances", "新增"), ("ec2", "ProvisionByoipCidr", "新增"),
                   ("ec2", "DeprovisionByoipCidr", "删除"), ("rds", "FailoverDBCluster", "修改"),
                   ("rds", "BacktrackDBCluster", "修改"), ("iam", "DeactivateMFADevice", "修改"),
                   ("cloudformation", "ContinueUpdateRollback", "修改"), ("kms", "ScheduleKeyDeletion", "删除"),
                   ("kms", "RetireGrant", "删除"), ("kms", "ReplicateKey", "新增"),
                   ("secretsmanager", "ReplicateSecretToRegions", "新增"), ("organizations", "MoveAccount", "修改"),
                   ("ecr", "BatchDeleteImage", "删除"), ("autoscaling", "BatchDeleteScheduledAction", "删除"))
        for service, name, category in samples:
            with self.subTest(service=service, name=name):
                row = actions.lookup_action(event(service, name))
                self.assertEqual(row["category"], category)
                self.assertEqual(row["kind"], "resource_change")
                self.assertTrue(row["reference"].startswith("https://docs.aws.amazon.com/"))
                self.assertTrue(row["description"])

    def test_scheduled_deletion_and_async_creation_are_not_claimed_complete(self):
        self.assertIn("计划删除", actions.lookup_action(event("kms", "ScheduleKeyDeletion"))["description"])
        self.assertIn("请求", actions.lookup_action(event("ec2", "RequestSpotInstances"))["description"])
        self.assertIn("异步", actions.lookup_action(event("organizations", "CloseAccount"))["description"])

    def test_temporary_credentials_are_explicit_identity_sessions(self):
        for name in ("GetSessionToken", "GetFederationToken", "AssumeRoot"):
            row = actions.lookup_action(event("sts", name))
            self.assertEqual(row["category"], "登录信息")
            self.assertEqual(row["kind"], "credential_session")
            self.assertIn("不等于控制台登录", row["description"])

    def test_actual_organizations_feature_query_is_explicit_ordinary_read(self):
        for readonly in (True, False, None):
            row = actions.lookup_action(event("iam", "ListOrganizationsFeatures", readOnly=readonly))
            self.assertIsNone(row["category"])
            self.assertEqual(row["kind"], "ordinary_read")
            self.assertEqual(row["reference"], "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOrganizationsFeatures.html")
        self.assertIsNone(actions.lookup_action(event("custom-service", "ListOrganizationsFeatures")))

    def test_crypto_usage_never_becomes_a_resource_mutation(self):
        for name in ("Decrypt", "Encrypt", "GenerateDataKey", "GenerateDataKeyPair", "Sign", "Verify"):
            row = actions.lookup_action(event("kms", name))
            self.assertEqual(row["category"], "其他操作")
            self.assertEqual(row["kind"], "resource_use")

    def test_rules_do_not_change_when_readonly_flag_changes(self):
        # The core classifier, not the documentation catalog, owns read filtering.
        self.assertEqual(actions.lookup_action(event(readOnly=True)), actions.lookup_action(event(readOnly=False)))

    def test_event_source_collision_or_untrusted_suffix_never_matches(self):
        for source in ("rds.amazonaws.com", "ec2.amazonaws.com.evil.invalid", "ec2.amazonaws.com/", "ec2.amazonaws.com:443", "custom.amazonaws.com", None):
            with self.subTest(source=source):
                self.assertIsNone(actions.lookup_action({"eventSource": source, "eventName": "MonitorInstances"}))

    def test_china_event_sources_are_supported_without_broad_suffix_matching(self):
        row = actions.lookup_action({"eventSource": "ec2.amazonaws.com.cn", "eventName": "MonitorInstances"})
        self.assertEqual(row["category"], "修改")
        self.assertIsNone(actions.lookup_action({"eventSource": "ec2.amazonaws.com.cn.evil", "eventName": "MonitorInstances"}))

    def test_records_are_defensive_copies_and_unknown_api_stays_unknown(self):
        row = actions.lookup_action(event())
        row["description"] = "mutated"
        self.assertNotEqual(actions.lookup_action(event())["description"], "mutated")
        self.assertIsNone(actions.lookup_action(event(name="FrobnicateEverything")))


class LocalDocumentationTests(TestCase):
    def tearDown(self):
        actions._local_model.cache_clear()
        actions._operation_metadata.cache_clear()

    def test_local_sdk_documents_real_known_api_without_clients_or_credentials(self):
        import botocore.session
        import urllib.request
        with patch.object(botocore.session.Session, "create_client") as client, \
             patch.object(botocore.session.Session, "get_credentials") as credentials, \
             patch.object(urllib.request, "urlopen") as network:
            row = actions.describe_operation(event("rds", "FailoverDBCluster"))
        self.assertEqual(row["service_name"], "Amazon RDS")
        self.assertIn("failover", row["api_description"].lower())
        self.assertEqual(row["operation_reference"], "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_FailoverDBCluster.html")
        client.assert_not_called()
        credentials.assert_not_called()
        network.assert_not_called()

    def test_unknown_api_has_no_fabricated_description_or_reference(self):
        row = actions.describe_operation(event(name="FrobnicateEverything"))
        self.assertEqual(row["service_name"], "Amazon EC2")
        self.assertEqual(row["api_description"], "")
        self.assertEqual(row["operation_reference"], "")

    def test_optional_sdk_failure_falls_back_without_blocking_reports(self):
        with patch.object(actions, "_local_model", return_value=None):
            row = actions.describe_operation(event())
        self.assertEqual(row, {"service_name": "Amazon EC2", "api_description": "", "operation_reference": ""})

    def test_documentation_tags_are_plain_text_and_first_paragraph_is_bounded(self):
        text = actions._plain_documentation('<p>Changes <code>monitoring</code> &amp; alarms.</p><p>Do not repeat this paragraph.</p>')
        self.assertEqual(text, 'Changes monitoring & alarms.')
        self.assertNotIn('<', text)
        self.assertLessEqual(len(actions._plain_documentation('<p>'+'a'*2000+'</p>')), 600)
        self.assertEqual(actions._plain_documentation('<script>private</script><p>Safe</p>'), 'Safe')

    def test_bad_names_cannot_inject_an_api_documentation_url(self):
        for name in ('../../secrets', '<script>', None, 'GoodName?secret=1'):
            row = actions.describe_operation(event(name=name))
            self.assertEqual(row["operation_reference"], "")
            self.assertEqual(row["api_description"], "")


if __name__ == "__main__":
    main()
