"""Local-only Nginx candidate tests; no server, AWS or Lark calls."""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from deploy import nginx_config as nginx


DOMAIN = "zybocedata-pass.v668live.com"
PUBLISH = "/usr/local/shenji/index"
FRONTEND = '''location / {
        proxy_pass http://127.0.0.1:8890;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }'''
REDIRECT = "location = /audit { return 302 /audit/; }"
OLD_AUDIT = "location ^~ /audit/ { proxy_pass http://127.0.0.1:9998; }"


def fixture(*, audit=OLD_AUDIT, redirect=REDIRECT, frontend=FRONTEND, extra="", listen="8889"):
    return ("# 中文配置；保留此注释和所有业务字节\nserver {\n"
            + "    listen " + listen + ";\n"
            + "    server_name " + DOMAIN + ";\n"
            + "    absolute_redirect off;\n"
            + "    " + redirect + "\n"
            + "    " + frontend + "\n"
            + "    # 业务代理和审计路由之间的注释必须保留\n"
            + "    " + audit + "\n" + extra + "}\n")


class NginxCandidateTests(unittest.TestCase):
    def prepare(self, text, publish=PUBLISH):
        return nginx.prepare_text(text, DOMAIN, 8889, publish)

    def test_changes_audit_only_and_preserves_frontend_and_other_server_exactly(self):
        other = 'server { listen 8899; server_name other.example; location / { return 204; } }\n'
        source = fixture() + other
        candidate = self.prepare(source)
        self.assertIn(FRONTEND, candidate)
        self.assertTrue(candidate.startswith(source[:source.index(REDIRECT)]))
        self.assertTrue(candidate.endswith(source[source.index(OLD_AUDIT) + len(OLD_AUDIT):]))
        self.assertIn("    # 业务代理和审计路由之间的注释必须保留\n", candidate)
        self.assertEqual(candidate.count("location = /audit {"), 1)
        self.assertEqual(candidate.count("location ^~ /audit/ {"), 1)
        self.assertIn('alias "/usr/local/shenji/index/";', candidate)
        self.assertNotIn("proxy_pass http://127.0.0.1:9998", candidate)
        self.assertIn("text/css css;", candidate)
        self.assertIn("application/javascript js;", candidate)
        self.assertNotIn("add_header", candidate)

    def test_repeated_plan_is_byte_identical(self):
        first = self.prepare(fixture())
        for _ in range(4):
            self.assertEqual(self.prepare(first), first)

    def test_duplicate_audit_locations_are_removed_but_named_fallback_is_untouched(self):
        fallback = '''    location @audit_password_unavailable {
        return 503 "Audit authentication unavailable.\\n";
    }
'''
        source = fixture(extra="    " + REDIRECT + "\n    " + OLD_AUDIT + "\n" + fallback)
        candidate = self.prepare(source)
        self.assertEqual(candidate.count("location = /audit {"), 1)
        self.assertEqual(candidate.count("location ^~ /audit/ {"), 1)
        self.assertIn(FRONTEND, candidate)
        self.assertIn(fallback, candidate)
        self.assertEqual(self.prepare(candidate), candidate)

    def test_quoted_and_commented_braces_do_not_change_block_boundaries(self):
        unusual = FRONTEND.replace("        proxy_http_version", (
            '        add_header X-Test "literal } { ; # and \\"quote\\"";\n'
            "        proxy_set_header X-Original-URI ${request_uri};\n"
            "        # } } server { location = /audit { malicious; }\n"
            "        proxy_http_version"))
        source = fixture(frontend=unusual)
        candidate = self.prepare(source)
        self.assertIn(unusual, candidate)
        self.assertEqual(self.prepare(candidate), candidate)

    def test_crlf_and_absence_of_final_newline_are_preserved(self):
        source = fixture().rstrip("\n").replace("\n", "\r\n")
        candidate = self.prepare(source)
        self.assertIn(FRONTEND.replace("\n", "\r\n"), candidate)
        self.assertNotIn("\n", candidate.replace("\r\n", ""))
        self.assertFalse(candidate.endswith(("\n", "\r")))
        self.assertEqual(self.prepare(candidate), candidate)

    def test_plain_and_combined_audit_location_modifiers_are_supported(self):
        for redirect, audit in (("location =/audit { return 302 /audit/; }", "location /audit/ { alias /old/; }"),
                                (REDIRECT, "location ^~/audit/ { proxy_pass http://127.0.0.1:9999; }")):
            with self.subTest(audit=audit):
                candidate = self.prepare(fixture(redirect=redirect, audit=audit))
                self.assertIn(FRONTEND, candidate)
                self.assertIn('alias "/usr/local/shenji/index/";', candidate)

    def test_new_audit_locations_can_be_added_without_inventing_frontend(self):
        source = fixture(audit="", redirect="")
        candidate = self.prepare(source)
        self.assertIn(FRONTEND, candidate)
        self.assertEqual(candidate.count("location = /audit {"), 1)
        self.assertEqual(self.prepare(candidate), candidate)

    def test_ipv4_ipv6_and_http_wrapper_select_only_expected_server(self):
        for listen in ("127.0.0.1:8889 default_server", "[::]:8889", "8889"):
            with self.subTest(listen=listen):
                source = "events {}\nhttp {\n" + fixture(listen=listen) + "}\n"
                self.assertIn(FRONTEND, self.prepare(source))

    def test_missing_ambiguous_and_included_targets_are_rejected(self):
        cases = [fixture().replace(DOMAIN, "other.example"),
                 fixture().replace("listen 8889", "listen 8899"),
                 fixture() + fixture(),
                 fixture(extra="    include /etc/nginx/snippets/routes.conf;\n"),
                 fixture(frontend=""),
                 fixture(frontend="location / { return 404; }"),
                 fixture(frontend=FRONTEND + "\n" + FRONTEND),
                 fixture(frontend=FRONTEND.replace("proxy_pass http://127.0.0.1:8890;", "proxy_pass;")),
                 fixture(extra="    location = /audit/index.html { alias /old/index.html; }\n"),
                 fixture(extra="    location ~ ^/audit/.*$ { proxy_pass http://127.0.0.1:9999; }\n")]
        for source in cases:
            with self.subTest(source=source[-80:]), self.assertRaises(nginx.NginxConfigError):
                self.prepare(source)

    def test_malformed_config_diagnostics_do_not_echo_submitted_values(self):
        for suffix in ('"FICTIONAL_PRIVATE_VALUE', "{", "}", "\\"):
            with self.subTest(suffix=suffix), self.assertRaises(nginx.NginxConfigError) as caught:
                self.prepare(fixture() + suffix)
            self.assertNotIn("FICTIONAL_PRIVATE_VALUE", str(caught.exception))

    def test_publish_paths_are_validated_and_quoted(self):
        for value in ("", "/", "relative/path", "/tmp/../private", "/tmp/$variable", "/tmp/\nroute", None):
            with self.subTest(value=value), self.assertRaises(nginx.NginxConfigError):
                self.prepare(fixture(), value)
        candidate = self.prepare(fixture(), '/srv/audit "quoted"; # files')
        self.assertIn('alias "/srv/audit \\"quoted\\"; # files/";', candidate)
        self.assertIn(FRONTEND, candidate)


class NginxDiscoveryAndCliTests(unittest.TestCase):
    def test_discovery_identifies_actual_source_without_following_http_include(self):
        dump = ("# configuration file /etc/nginx/nginx.conf:\n"
                "events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n"
                "# configuration file /etc/nginx/conf.d/audit.conf:\n" + fixture())
        self.assertEqual(nginx.discover_config(dump, DOMAIN, 8889), Path("/etc/nginx/conf.d/audit.conf"))
        for bad in ("", dump + "# configuration file /etc/nginx/conf.d/other.conf:\n" + fixture(),
                    dump + "# configuration file /etc/nginx/conf.d/audit.conf:\n" + fixture()):
            with self.subTest(length=len(bad)), self.assertRaises(nginx.NginxConfigError):
                nginx.discover_config(bad, DOMAIN, 8889)

    def test_plan_writes_only_new_candidate_and_preserves_original_raw_bytes(self):
        with tempfile.TemporaryDirectory(prefix="nginx-plan-test-") as folder:
            source = Path(folder) / "original.conf"
            output = Path(folder) / "candidate.conf"
            raw = fixture().replace("\n", "\r\n").encode("utf-8")
            source.write_bytes(raw)
            arguments = ["plan", "--nginx-config", str(source), "--publish-dir", PUBLISH,
                         "--server-name", DOMAIN, "--listen-port", "8889", "--output", str(output)]
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(nginx.main(arguments), 0)
                self.assertEqual(nginx.main(arguments), 1)
                same_source = arguments[:-1] + [str(source)]
                self.assertEqual(nginx.main(same_source), 1)
            self.assertEqual(source.read_bytes(), raw)
            planned = output.read_bytes()
            self.assertIn(FRONTEND.replace("\n", "\r\n").encode("utf-8"), planned)
            self.assertNotIn(b"\n", planned.replace(b"\r\n", b""))


if __name__ == "__main__":
    unittest.main()
