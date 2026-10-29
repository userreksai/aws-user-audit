"""每日单密码和会话状态；虚构口令、本地文件，不访问 AWS 或 Lark。"""
import json
import os
import tempfile
import unittest
from pathlib import Path

import audit_access as access


class AccessRotationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-access-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state_dir = self.root / "private"
        self.publish_dir = self.root / "web"
        self.publish_dir.mkdir()

    def rotate(self, day="2026-10-28"):
        return access.AccessRotation(self.state_dir, self.publish_dir, day)

    def test_first_rotation_publishes_hash_only_and_keeps_notification_password_private(self):
        with self.rotate() as rotation:
            password = rotation.password
            self.assertRegex(password, r"^[A-Za-z0-9_-]{24}$")
            self.assertNotIn(password, json.dumps(rotation.state))
            self.assertFalse((self.state_dir / "access.json").exists())
            rotation.activate()
        state = access.load_access(self.state_dir / "access.json")
        self.assertTrue(access.verify_password(password, state))
        self.assertFalse(access.verify_password("WRONG_PASSWORD_FOR_TEST_ONLY", state))
        self.assertNotIn(password, (self.state_dir / "access.json").read_text(encoding="utf-8"))
        self.assertIn(password, (self.state_dir / "delivery.json").read_text(encoding="utf-8"))
        self.assertFalse(list(self.publish_dir.iterdir()))
        self.assertEqual(state["audit_date"], "2026-10-28")

    def test_same_day_after_uncertain_delivery_reuses_working_password_and_session(self):
        with self.rotate() as rotation:
            password = rotation.password
            rotation.activate()
            token = access.make_session(rotation.state, now=1000)
        # 超时可能发生在消息到群之后；同日再次运行不能让已发密码失效。
        with self.rotate() as retry:
            self.assertEqual(retry.password, password)
            self.assertTrue(access.verify_session(token, retry.state, now=1100))
            retry.activate()
        self.assertTrue(access.verify_password(password, access.load_access(self.state_dir / "access.json")))

    def test_unactivated_new_day_keeps_old_access_and_reuses_pending_password(self):
        with self.rotate() as first:
            first.activate()
            old_state = dict(first.state)
        with self.rotate("2026-10-29") as candidate:
            pending_password = candidate.password
            self.assertNotEqual(candidate.state["rotation_id"], old_state["rotation_id"])
            # 模拟网页发布失败，认证状态还没有切换。
        self.assertEqual(access.load_access(self.state_dir / "access.json"), old_state)
        with self.rotate("2026-10-29") as retry:
            self.assertEqual(retry.password, pending_password)

    def test_next_day_rotates_password_and_invalidates_previous_sessions(self):
        with self.rotate() as old:
            old.activate()
            old_password, old_state = old.password, dict(old.state)
            token = access.make_session(old.state, now=1000)
        with self.rotate("2026-10-29") as new:
            self.assertNotEqual(new.password, old_password)
            new.activate()
            self.assertFalse(access.verify_password(old_password, new.state))
            self.assertFalse(access.verify_session(token, new.state, now=1100))
            self.assertTrue(access.verify_session(access.make_session(new.state, now=1100), new.state, now=1200))
        self.assertNotEqual(access.load_access(self.state_dir / "access.json"), old_state)

    def test_older_report_cannot_roll_back_current_password(self):
        with self.rotate("2026-10-29") as current:
            current.activate()
            expected = dict(current.state)
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            with self.rotate("2026-10-28"):
                self.fail("旧报告不应更换当前认证")
        self.assertEqual(access.load_access(self.state_dir / "access.json"), expected)

    def test_private_state_must_be_outside_webroot_and_archives(self):
        cases = ((self.publish_dir / "private", None), (self.root / "reports" / "auth", self.root / "reports"))
        for folder, archives in cases:
            with self.subTest(folder=folder), self.assertRaises((ValueError, RuntimeError, OSError)):
                with access.AccessRotation(folder, self.publish_dir, "2026-10-28", archive_dir=archives):
                    self.fail("口令不能放入可发布或归档目录")

    def test_competing_publisher_is_rejected_without_changing_active_state(self):
        with self.rotate() as first:
            first.activate()
            expected = dict(first.state)
            with self.assertRaises((ValueError, RuntimeError, OSError)):
                with self.rotate("2026-10-29"):
                    self.fail("另一发布进程不应同时换码")
            self.assertEqual(access.load_access(self.state_dir / "access.json"), expected)

    @unittest.skipUnless(os.name == "posix", "POSIX 文件权限")
    def test_active_state_group_readable_but_delivery_state_owner_only(self):
        with self.rotate() as rotation:
            rotation.activate()
        self.assertEqual((self.state_dir / "access.json").stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.state_dir / "delivery.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state_dir.stat().st_mode & 0o007, 0)


class SessionAndValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="audit-session-test-")
        root = Path(cls.temporary.name)
        with access.AccessRotation(root / "private", root / "web", "2026-10-28") as rotation:
            rotation.activate()
            cls.state = dict(rotation.state)
            cls.password = rotation.password

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_signed_cookie_expires_after_eight_hours_and_rejects_changes(self):
        token = access.make_session(self.state, now=1000)
        self.assertTrue(access.verify_session(token, self.state, now=1000))
        self.assertTrue(access.verify_session(token, self.state, now=1000 + 8 * 3600 - 1))
        self.assertFalse(access.verify_session(token, self.state, now=1000 + 8 * 3600))
        changed = token[:-1] + ("A" if token[-1] != "A" else "B")
        self.assertFalse(access.verify_session(changed, self.state, now=1001))
        for bad in ("", "not-a-token", token + "extra", "\r\n", "x" * 10000, None):
            with self.subTest(value=str(bad)[:30]):
                self.assertFalse(access.verify_session(bad, self.state, now=1001))
        self.assertNotIn(self.password, token)

    def test_malformed_access_state_fails_closed_without_echoing_secret(self):
        with tempfile.TemporaryDirectory(prefix="audit-malformed-test-") as folder:
            target = Path(folder) / "access.json"
            for malformed in ({}, [], {**self.state, "iterations": -1}, {**self.state, "password_hash": "PRIVATE-BAD-HASH"}):
                target.write_text(json.dumps(malformed), encoding="utf-8")
                with self.subTest(malformed=type(malformed).__name__), self.assertRaises((ValueError, RuntimeError, OSError)) as caught:
                    access.load_access(target)
                self.assertNotIn("PRIVATE-BAD-HASH", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
