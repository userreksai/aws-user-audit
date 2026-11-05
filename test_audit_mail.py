"""Offline configuration and SMTP protocol tests; every network call is mocked."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import smtplib
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from audit_mail import DEFAULTS, MailDeliveryError, load_mail_config, send_reports, strip_json_comments, validate_mail_config


class MailConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "mail-config.json"
        self.config = {"SMTP_HOST": "smtp.example.com", "SMTP_USERNAME": "audit@example.com",
                       "SMTP_AUTH_CODE": "PRIVATE-AUTH-CODE", "MAIL_RECIPIENTS": ["to@example.com"]}

    def save(self, data):
        self.path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return self.path

    @patch("audit_mail.smtplib.SMTP")
    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_load_default_settings_and_validate_are_local(self, secure, starttls):
        loaded = load_mail_config(self.save(self.config))
        self.assertEqual(loaded["MAIL_SUBJECT"], "AWS账号操作审计日报")
        self.assertEqual(loaded["SMTP_PORT"], 465)
        self.assertEqual(loaded["SMTP_SECURITY"], "ssl")
        self.assertEqual(loaded["AUTO_MAIL_MAX_PER_DAY"], 1)
        self.assertFalse(loaded["LARK_ALERTS_ENABLED"])
        self.assertEqual(validate_mail_config(self.config), loaded)
        secure.assert_not_called()
        starttls.assert_not_called()

    def test_template_allows_empty_credentials_without_shared_mutable_defaults(self):
        config = validate_mail_config({}, require_complete=False)
        self.assertEqual(config, DEFAULTS)
        config["MAIL_RECIPIENTS"].append("to@example.com")
        self.assertEqual(validate_mail_config({}, require_complete=False)["MAIL_RECIPIENTS"], [])
        with self.assertRaisesRegex(ValueError, "SMTP_HOST"):
            validate_mail_config({})

    def test_jsonc_bom_quoted_comment_markers_escapes_and_relative_font(self):
        content = ('\ufeff{ // line comment\n "SMTP_HOST":"smtp.example.com", /* block\ncomment */'
                   '"SMTP_USERNAME":"audit@example.com", "SMTP_AUTH_CODE":"//https://x/\\\"/*secret*/",'
                   '"MAIL_RECIPIENTS":["to@example.com"], "PDF_FONT_PATH":"fonts/chinese.ttf"}')
        self.path.write_text(content, encoding="utf-8")
        result = load_mail_config(self.path)
        self.assertEqual(result["SMTP_AUTH_CODE"], '//https://x/"/*secret*/')
        self.assertEqual(result["PDF_FONT_PATH"], str((self.root / "fonts/chinese.ttf").resolve()))

    def test_comment_stripping_preserves_newlines_and_does_not_join_tokens(self):
        original = '{\r\n"a":1/* hidden */2, "b":"//literal/*text*/"\r\n}'
        stripped = strip_json_comments(original)
        self.assertEqual(len(stripped), len(original))
        self.assertEqual(stripped.count("\r\n"), 2)
        self.assertIn('"//literal/*text*/"', stripped)
        with self.assertRaises(ValueError):
            json.loads(stripped)

    def test_json_errors_hide_text_credentials_and_duplicate_keys(self):
        for raw in ('{"SMTP_AUTH_CODE":"PRIVATE', '{"x":1,"x":2}', 'null', '[]',
                    '{"SMTP_TIMEOUT":NaN}', '{"SMTP_TIMEOUT":Infinity}', '{/*PRIVATE',
                    '{"SMTP_AUTH_CODE":"PRIVATE",}', '{"x":0} PRIVATE'):
            with self.subTest(raw=raw):
                self.path.write_text(raw, encoding="utf-8")
                with self.assertRaises(ValueError) as failure:
                    load_mail_config(self.path, require_complete=False)
                self.assertNotIn("PRIVATE", str(failure.exception))
        with self.assertRaises(ValueError) as failure:
            load_mail_config(self.root / "PRIVATE-MISSING.json")
        self.assertNotIn("PRIVATE", str(failure.exception))

    def test_invalid_nonempty_template_fields_and_flags_rejected(self):
        invalid = ({"SMTP_PORT": True}, {"SMTP_PORT": 0}, {"SMTP_PORT": 65536},
                   {"SMTP_TIMEOUT": float("nan")}, {"SMTP_TIMEOUT": float("inf")},
                   {"SMTP_TIMEOUT": -1}, {"SMTP_TIMEOUT": 601}, {"SMTP_TIMEOUT": 10 ** 500},
                   {"SMTP_TIMEOUT": True},
                   {"SMTP_SECURITY": "none"}, {"SMTP_USERNAME": "PRIVATE-NOT-ADDRESS"},
                   {"SMTP_HOST": "https://PRIVATE"}, {"MAIL_RECIPIENTS": "PRIVATE"},
                   {"MAIL_CC": ["PRIVATE"]}, {"MAIL_SUBJECT": ""},
                   {"AUTO_MAIL_MAX_PER_DAY": True}, {"AUTO_MAIL_MAX_PER_DAY": 2},
                   {"LARK_ALERTS_ENABLED": 1}, {"PDF_FONT_PATH": None},
                   {"SMTP_AUTH_CODE": "PRIVATE\x00"})
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError) as failure:
                validate_mail_config(values, require_complete=False)
            self.assertNotIn("PRIVATE", str(failure.exception))

    def test_to_cc_casefold_deduplication_and_input_not_mutated(self):
        config = {**self.config, "MAIL_RECIPIENTS": ["to@example.com", "TO@example.com"],
                  "MAIL_CC": ["TO@example.com", "copy@example.com", "COPY@example.com"]}
        before = deepcopy(config)
        result = validate_mail_config(config)
        self.assertEqual(result["MAIL_RECIPIENTS"], ["to@example.com"])
        self.assertEqual(result["MAIL_CC"], ["copy@example.com"])
        self.assertEqual(config, before)


class MailDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.files = [self.root / "账号一-2026-11-04.pdf", self.root / "账号二-2026-11-04.pdf"]
        for path in self.files:
            path.write_bytes(b"%PDF-1.4\nfixture")
        self.config = {"SMTP_HOST": "smtp.example.com", "SMTP_USERNAME": "audit@example.com",
                       "SMTP_AUTH_CODE": "PRIVATE-AUTH-CODE", "MAIL_RECIPIENTS": ["to@example.com"],
                       "MAIL_CC": ["copy@example.com"], "MAIL_SENDER_NAME": "审计系统"}
        self.smtp = MagicMock()
        self.smtp.ehlo.return_value = (250, b"hello")
        self.smtp.send_message.return_value = {}

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_one_ssl_message_all_chinese_named_pdf_attachments_and_cc(self, constructor):
        constructor.return_value = self.smtp
        result = send_reports(self.config, self.files, "数量总览见正文，明细见附件。")
        self.assertTrue(result["smtp_accepted"])
        self.assertEqual(result["attachment_count"], 2)
        self.assertEqual(result["recipients"], ["to@example.com", "copy@example.com"])
        context = constructor.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.smtp.login.assert_called_once_with("audit@example.com", "PRIVATE-AUTH-CODE")
        message = self.smtp.send_message.call_args.args[0]
        self.assertEqual(message["Subject"], "AWS账号操作审计日报")
        self.assertEqual(message["Cc"], "copy@example.com")
        self.assertEqual([part.get_filename() for part in message.iter_attachments()], [path.name for path in self.files])
        self.assertTrue(all(part.get_content_type() == "application/pdf" for part in message.iter_attachments()))
        self.assertNotIn("PRIVATE", message.as_string())
        self.smtp.quit.assert_called_once()
        self.smtp.close.assert_called_once()

    @patch("audit_mail.smtplib.SMTP")
    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_starttls_before_login_with_verified_certificate(self, secure, constructor):
        constructor.return_value = self.smtp
        send_reports({**self.config, "SMTP_PORT": 587, "SMTP_SECURITY": "starttls"}, self.files, "body", "自定义标题")
        secure.assert_not_called()
        self.assertEqual(self.smtp.ehlo.call_count, 2)
        names = [call[0] for call in self.smtp.mock_calls]
        self.assertLess(names.index("starttls"), names.index("login"))
        self.assertTrue(self.smtp.starttls.call_args.kwargs["context"].check_hostname)
        self.assertEqual(self.smtp.send_message.call_args.args[0]["Subject"], "自定义标题")

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_html_table_and_text_fallback_keep_original_pdf_attachment_bytes(self, constructor):
        constructor.return_value = self.smtp
        text = "具体用户 | 安全组 | EC2\nbeiou | 2 | 3"
        html = '<table><tr><th>具体用户</th><th>安全组</th><th>EC2</th></tr><tr><td>beiou</td><td>2</td><td>3</td></tr></table>'
        result = send_reports(self.config, self.files, text, html_body=html)
        self.assertTrue(result["smtp_accepted"])
        message = self.smtp.send_message.call_args.args[0]
        self.assertEqual(message.get_content_type(), "multipart/mixed")
        self.assertEqual(message.get_body(preferencelist=("plain",)).get_content().strip(), text)
        self.assertEqual(message.get_body(preferencelist=("html",)).get_content().strip(), html)
        parts = list(message.iter_attachments())
        self.assertEqual([part.get_filename() for part in parts], [path.name for path in self.files])
        self.assertEqual([part.get_payload(decode=True) for part in parts], [path.read_bytes() for path in self.files])
        self.assertTrue(all(part.get_content_type() == "application/pdf" for part in parts))
        self.assertEqual([part.get_content_type() for part in message.walk()].count("text/html"), 1)

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_invalid_html_body_never_contacts_smtp(self, constructor):
        with self.assertRaisesRegex(ValueError, "HTML"):
            send_reports(self.config, self.files, "body", html_body={"not": "text"})
        constructor.assert_not_called()

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_partial_refusal_is_uncertain_and_error_is_sanitized(self, constructor):
        constructor.return_value = self.smtp
        self.smtp.send_message.return_value = {"copy@example.com": (550, b"PRIVATE-PROVIDER-REPLY")}
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertTrue(failure.exception.delivery_uncertain)
        self.assertEqual(failure.exception.refused, ["copy@example.com"])
        self.assertNotIn("PRIVATE", str(failure.exception))

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_submission_disconnect_is_uncertain(self, constructor):
        constructor.return_value = self.smtp
        self.smtp.send_message.side_effect = smtplib.SMTPServerDisconnected("PRIVATE-PROVIDER-REPLY")
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertTrue(failure.exception.delivery_uncertain)
        self.assertNotIn("PRIVATE", str(failure.exception))
        self.smtp.send_message.assert_called_once()

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_authentication_failure_is_definite(self, constructor):
        constructor.return_value = self.smtp
        self.smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b"PRIVATE-AUTH-CODE")
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertFalse(failure.exception.delivery_uncertain)
        self.assertNotIn("PRIVATE", str(failure.exception))
        self.smtp.send_message.assert_not_called()
        self.smtp.close.assert_called_once()

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_all_recipients_refused_is_definite_failure(self, constructor):
        constructor.return_value = self.smtp
        self.smtp.send_message.side_effect = smtplib.SMTPRecipientsRefused({"to@example.com": (550, b"PRIVATE")})
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertFalse(failure.exception.delivery_uncertain)
        self.assertNotIn("PRIVATE", str(failure.exception))

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_connection_and_ehlo_failure_do_not_submit(self, constructor):
        constructor.side_effect = TimeoutError("PRIVATE-PROVIDER-REPLY")
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertFalse(failure.exception.delivery_uncertain)
        self.assertNotIn("PRIVATE", str(failure.exception))
        constructor.side_effect = None
        constructor.return_value = self.smtp
        self.smtp.ehlo.return_value = (500, b"PRIVATE")
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertFalse(failure.exception.delivery_uncertain)
        self.smtp.login.assert_not_called()

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_quit_failure_after_acceptance_stays_success(self, constructor):
        constructor.return_value = self.smtp
        self.smtp.quit.side_effect = smtplib.SMTPServerDisconnected("PRIVATE")
        self.assertTrue(send_reports(self.config, self.files, "body")["smtp_accepted"])
        self.smtp.send_message.assert_called_once()
        self.smtp.close.assert_called_once()

    @patch("audit_mail.smtplib.SMTP")
    def test_starttls_unavailable_or_second_ehlo_failure_never_authenticate(self, constructor):
        constructor.return_value = self.smtp
        self.smtp.starttls.side_effect = smtplib.SMTPNotSupportedError("PRIVATE-PROVIDER-REPLY")
        config = {**self.config, "SMTP_SECURITY": "starttls", "SMTP_PORT": 587}
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(config, self.files, "body")
        self.assertFalse(failure.exception.delivery_uncertain)
        self.assertNotIn("PRIVATE", str(failure.exception))
        self.smtp.login.assert_not_called()
        self.smtp.starttls.side_effect = None
        self.smtp.ehlo.side_effect = [(250, b"first"), (550, b"PRIVATE")]
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(config, self.files, "body")
        self.assertFalse(failure.exception.delivery_uncertain)
        self.smtp.login.assert_not_called()

    @patch("audit_mail.smtplib.SMTP_SSL")
    def test_header_injection_and_invalid_files_are_rejected_before_connect(self, constructor):
        for changes in ({"MAIL_SUBJECT": "ok\nBcc:PRIVATE@example.com"},
                        {"MAIL_SENDER_NAME": "ok\rPRIVATE"},
                        {"MAIL_RECIPIENTS": ["to@example.com\nPRIVATE"]},
                        {"MAIL_CC": ["Name <copy@example.com>"]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                send_reports({**self.config, **changes}, self.files, "body")
        for attachments in ([], [self.files[0], self.files[0]], [self.root / "missing.pdf"]):
            with self.subTest(attachments=attachments), self.assertRaises(ValueError):
                send_reports(self.config, attachments, "body")
        self.files[0].write_bytes(b"not a PDF")
        with self.assertRaises(ValueError):
            send_reports(self.config, self.files, "body")
        constructor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
