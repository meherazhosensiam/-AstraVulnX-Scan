"""End-to-end tests of every scan module against the local fixture application."""

from __future__ import annotations

from astravulnx.models import Severity
from tests.support import FixtureTestCase


class SqlInjectionTests(FixtureTestCase):
    def test_detects_error_based_sqli_in_query_parameter(self) -> None:
        result = self.scan("/item?id=1", "sql_injection")
        [finding] = result.findings
        self.assertEqual(finding.parameter, "id")
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.cwe, "CWE-89")

    def test_detects_sqli_in_post_form_field(self) -> None:
        result = self.scan("/", "sql_injection")
        self.assertIn(("username", "POST"), [(f.parameter, f.method) for f in result.findings])

    def test_ignores_pages_that_always_show_sql_errors(self) -> None:
        self.assertEqual(self.scan("/docs?id=1", "sql_injection").findings, [])

    def test_clean_parameter_is_not_flagged(self) -> None:
        self.assertEqual(self.scan("/safe?q=hello", "sql_injection").findings, [])


class XssTests(FixtureTestCase):
    def test_detects_unencoded_reflection(self) -> None:
        [finding] = self.scan("/search?q=a", "xss").findings
        self.assertEqual((finding.parameter, finding.cwe), ("q", "CWE-79"))

    def test_encoded_reflection_is_not_flagged(self) -> None:
        self.assertEqual(self.scan("/safe?q=a", "xss").findings, [])


class OpenRedirectTests(FixtureTestCase):
    def test_detects_redirect_to_attacker_controlled_host(self) -> None:
        [finding] = self.scan("/go", "open_redirect").findings
        self.assertEqual(finding.parameter, "next")

    def test_no_redirect_no_finding(self) -> None:
        self.assertEqual(self.scan("/secure", "open_redirect").findings, [])


class TraversalTests(FixtureTestCase):
    def test_detects_traversal(self) -> None:
        [finding] = self.scan("/file?name=a.txt", "directory_traversal").findings
        self.assertEqual(finding.parameter, "name")

    def test_clean_page_is_not_flagged(self) -> None:
        self.assertEqual(self.scan("/safe?q=a", "directory_traversal").findings, [])

    def test_quick_profile_limits_payloads(self) -> None:
        # Only the first payload family fits in the quick profile, which still finds this one.
        result = self.scan("/file?name=a.txt", "directory_traversal", profile="quick")
        self.assertEqual(len(result.findings), 1)


class SsrfTests(FixtureTestCase):
    def test_detects_reflected_internal_response(self) -> None:
        [finding] = self.scan("/fetch", "ssrf").findings
        self.assertEqual(finding.parameter, "url")
        self.assertEqual(finding.payload, "http://127.0.0.1:22")

    def test_generic_server_names_in_pages_are_not_flagged(self) -> None:
        self.assertEqual(self.scan("/secure", "ssrf").findings, [])


class CorsTests(FixtureTestCase):
    def test_reflected_origin_with_credentials_is_high(self) -> None:
        [finding] = self.scan("/api", "cors").findings
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_wildcard_is_low(self) -> None:
        [finding] = self.scan("/wildcard", "cors").findings
        self.assertEqual(finding.severity, Severity.LOW)

    def test_no_cors_headers_no_finding(self) -> None:
        self.assertEqual(self.scan("/secure", "cors").findings, [])


class SensitiveDataTests(FixtureTestCase):
    def test_detects_secrets_and_redacts_them(self) -> None:
        result = self.scan("/config", "sensitive_data")
        titles = {f.title for f in result.findings}
        self.assertIn("Sensitive data: AWS access key ID", titles)
        self.assertIn("Sensitive data: Private key block", titles)
        for finding in result.findings:
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", finding.evidence)

    def test_clean_page_has_no_findings(self) -> None:
        self.assertEqual(self.scan("/secure", "sensitive_data").findings, [])


class SecurityHeaderTests(FixtureTestCase):
    def test_reports_missing_headers_on_plain_page(self) -> None:
        result = self.scan("/", "security_headers")
        titles = {f.title for f in result.findings}
        self.assertIn("Missing Content-Security-Policy header", titles)
        self.assertIn("Missing X-Frame-Options header", titles)
        self.assertNotIn("Missing Strict-Transport-Security header", titles)  # target is plain HTTP

    def test_hardened_page_is_clean(self) -> None:
        self.assertEqual(self.scan("/secure", "security_headers").findings, [])
