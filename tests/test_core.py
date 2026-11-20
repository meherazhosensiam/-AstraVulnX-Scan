"""Unit and integration tests for config, HTTP client, discovery, risk and reports."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from astravulnx.config import ConfigError, ScanConfig
from astravulnx.discovery import InjectionPoint, discover_injection_points
from astravulnx.engine import ScanError, Scanner, select_modules
from astravulnx.http import HttpClient, HttpError
from astravulnx.models import Confidence, Finding, ScanResult, Severity
from astravulnx.modules.sensitive_data import luhn_valid, redact
from astravulnx.reporting import infer_format, render_html, render_json, render_text, write_report
from astravulnx.risk import sort_findings, summarize
from tests.support import FixtureTestCase


def make_finding(
    severity: Severity = Severity.HIGH,
    *,
    module: str = "xss",
    title: str = "Example",
    parameter: str = "",
    payload: str = "",
    evidence: str = "",
) -> Finding:
    return Finding(
        module=module, title=title, severity=severity, confidence=Confidence.HIGH,
        url="http://t/", description="d", remediation="r", owasp="A03:2021 Injection",
        cwe="CWE-79", parameter=parameter, payload=payload, evidence=evidence,
    )


def make_result(*findings: Finding) -> ScanResult:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return ScanResult(
        target="http://t/", profile="quick", modules=["xss"], started_at=start,
        finished_at=start + timedelta(seconds=2), findings=list(findings),
    )


class ConfigTests(unittest.TestCase):
    def test_defaults_are_valid(self) -> None:
        config = ScanConfig()
        self.assertEqual(config.payload_limit, 3)
        self.assertIsNone(ScanConfig(profile="deep").payload_limit)

    def test_rejects_invalid_values(self) -> None:
        invalid = (
            lambda: ScanConfig(profile="x"),
            lambda: ScanConfig(timeout=0),
            lambda: ScanConfig(delay=-1),
            lambda: ScanConfig(max_injection_points=0),
            lambda: ScanConfig(max_body_bytes=10),
        )
        for build in invalid:
            with self.assertRaises(ConfigError):
                build()

    def test_from_file_and_unknown_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp, "good.json")
            good.write_text(json.dumps({"profile": "standard", "modules": ["xss"]}))
            config = ScanConfig.from_file(good)
            self.assertEqual((config.profile, config.modules), ("standard", ("xss",)))

            bad = Path(tmp, "bad.json")
            bad.write_text(json.dumps({"unknown": 1}))
            with self.assertRaises(ConfigError):
                ScanConfig.from_file(bad)
            with self.assertRaises(ConfigError):
                ScanConfig.from_file(Path(tmp, "missing.json"))

    def test_select_modules_validates_names(self) -> None:
        config = ScanConfig(modules=("xss", "cors"), exclude_modules=("cors",))
        self.assertEqual(select_modules(config), ["xss"])
        with self.assertRaises(ConfigError):
            select_modules(ScanConfig(modules=("nope",)))


class DiscoveryTests(unittest.TestCase):
    HTML = """
    <a href="/a?x=1">a</a><a href="http://other.example/b?y=2">external</a>
    <form action="/post" method="POST">
      <input name="user"><input name="token" type="hidden" value="t1">
      <input type="submit" name="go"><textarea name="msg"></textarea>
    </form>
    <form method="get"><input name="q"></form>
    <form action="/none"><input type="submit"></form>
    """

    def test_collects_query_form_and_same_host_link_points(self) -> None:
        points = discover_injection_points("http://h/page?id=5", self.HTML, limit=50)
        keys = {(p.method, p.url, p.parameter) for p in points}
        self.assertIn(("GET", "http://h/page", "id"), keys)
        self.assertIn(("POST", "http://h/post", "user"), keys)
        self.assertIn(("POST", "http://h/post", "msg"), keys)
        self.assertIn(("GET", "http://h/page", "q"), keys)  # form without action uses the page URL
        self.assertIn(("GET", "http://h/a", "x"), keys)
        self.assertNotIn("go", {p.parameter for p in points})  # submit buttons skipped
        self.assertFalse(any("other.example" in p.url for p in points))

    def test_limit_is_applied(self) -> None:
        self.assertEqual(len(discover_injection_points("http://h/?a=1&b=2&c=3", "", limit=2)), 2)

    def test_build_request_preserves_other_parameters_and_encoding(self) -> None:
        point = InjectionPoint("http://h/p", "GET", "a", (("a", "1"), ("b", "x y")), "query")
        method, url, data = point.build_request("' OR 1=1--")
        self.assertEqual((method, data), ("GET", None))
        self.assertEqual(url, "http://h/p?a=%27%20OR%201%3D1--&b=x%20y")
        _, encoded_url, _ = point.build_request("..%252f")
        self.assertIn("a=..%252f", encoded_url)  # pre-encoded payloads are not double-encoded

        post = InjectionPoint("http://h/p", "POST", "a", (("a", "1"), ("b", "2")), "form")
        self.assertEqual(post.build_request("v"), ("POST", "http://h/p", {"a": "v", "b": "2"}))


class HttpClientTests(FixtureTestCase):
    def client(self, max_body_bytes: int = 2_000_000) -> HttpClient:
        return HttpClient(ScanConfig(delay=0.0, timeout=3.0, max_body_bytes=max_body_bytes))

    def test_returns_error_statuses_as_responses(self) -> None:
        self.assertEqual(self.client().get(self.base_url + "/missing").status, 404)

    def test_redirects_can_be_disabled(self) -> None:
        url = self.base_url + "/go?next=/secure"
        followed = self.client().get(url)
        self.assertEqual((followed.status, followed.url), (200, self.base_url + "/secure"))
        raw = self.client().request("GET", url, follow_redirects=False)
        self.assertEqual((raw.status, raw.headers["location"]), (302, "/secure"))

    def test_custom_headers_and_post_data(self) -> None:
        response = self.client().request("POST", self.base_url + "/login", data={"username": "x'"},
                                         headers={"X-Test": "1"})
        self.assertIn("SQL syntax", response.body)

    def test_connection_failure_raises_http_error(self) -> None:
        with self.assertRaises(HttpError):
            self.client().get("http://127.0.0.1:1/")
        with self.assertRaises(HttpError):
            self.client().get("ftp://example.org/")

    def test_body_is_capped(self) -> None:
        response = self.client(max_body_bytes=1024).get(self.base_url + "/")
        self.assertLessEqual(len(response.body.encode()), 1024)

    def test_request_counter(self) -> None:
        client = self.client()
        client.get(self.base_url + "/")
        client.get(self.base_url + "/")
        self.assertEqual(client.requests_sent, 2)


class ScannerTests(FixtureTestCase):
    def test_rejects_invalid_target(self) -> None:
        for target in ("example.org", "ftp://example.org", "http://"):
            with self.subTest(target=target), self.assertRaises(ScanError):
                Scanner(ScanConfig(delay=0.0)).scan(target)

    def test_unreachable_target_raises_scan_error(self) -> None:
        with self.assertRaises(ScanError):
            Scanner(ScanConfig(delay=0.0, timeout=2.0)).scan("http://127.0.0.1:1/")

    def test_findings_are_sorted_by_severity_and_unique(self) -> None:
        result = Scanner(ScanConfig(delay=0.0, timeout=5.0)).scan(self.base_url + "/")
        severities = [f.severity for f in result.findings]
        self.assertEqual(severities, sorted(severities, reverse=True))
        keys = [(f.module, f.title, f.url, f.method, f.parameter) for f in result.findings]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(result.errors, [])

    def test_failing_module_is_recorded_not_fatal(self) -> None:
        from astravulnx import modules

        class Broken(modules.ScanModule):
            name = "broken"
            title = "Broken"

            def run(self, ctx: modules.ScanContext) -> Iterator[Finding]:
                raise RuntimeError("boom")
                yield  # pragma: no cover

        modules.REGISTRY["broken"] = Broken
        try:
            with self.assertLogs("astravulnx.engine", level="ERROR"):
                result = Scanner(ScanConfig(delay=0.0, modules=("broken",))).scan(self.base_url + "/")
        finally:
            del modules.REGISTRY["broken"]
        self.assertEqual(len(result.errors), 1)
        self.assertIn("boom", result.errors[0])


class RiskAndModelTests(unittest.TestCase):
    def test_severity_parse_and_order(self) -> None:
        self.assertEqual(Severity.parse(" High "), Severity.HIGH)
        self.assertGreater(Severity.CRITICAL, Severity.LOW)
        with self.assertRaises(ValueError):
            Severity.parse("urgent")

    def test_sort_and_summary(self) -> None:
        low = make_finding(Severity.LOW, title="b")
        crit = make_finding(Severity.CRITICAL, module="sql_injection", title="a")
        self.assertEqual(sort_findings([low, crit])[0], crit)
        summary = summarize([low, crit])
        self.assertEqual((summary.total, summary.highest), (2, Severity.CRITICAL))
        self.assertEqual(summary.by_severity["Low"], 1)
        self.assertIsNone(summarize([]).highest)

    def test_evidence_is_truncated_in_output(self) -> None:
        self.assertLessEqual(len(make_finding(evidence="x" * 5000).to_dict()["evidence"]), 300)

    def test_luhn_and_redaction(self) -> None:
        self.assertTrue(luhn_valid("4111 1111 1111 1111"))
        self.assertFalse(luhn_valid("4111 1111 1111 1112"))
        self.assertFalse(luhn_valid("12345"))
        self.assertEqual(redact("AKIAIOSFODNN7EXAMPLE"), "AKIA********")


class ReportTests(unittest.TestCase):
    def test_json_report_structure(self) -> None:
        data = json.loads(render_json(make_result(make_finding())))
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["tool"]["version"], "4.0.0")
        self.assertEqual(data["summary"]["total"], 1)
        self.assertEqual(data["findings"][0]["severity"], "High")

    def test_html_report_escapes_untrusted_values(self) -> None:
        hostile = "<script>alert(1)</script>"
        page = render_html(make_result(make_finding(payload=hostile, evidence=hostile, parameter=hostile)))
        self.assertNotIn(hostile, page)
        self.assertIn("&lt;script&gt;", page)

    def test_text_report_has_no_ansi_codes_by_default(self) -> None:
        self.assertNotIn("\033[", render_text(make_result(make_finding())))
        self.assertIn("\033[", render_text(make_result(make_finding()), color=True))
        self.assertIn("No potential issues", render_text(make_result()))

    def test_write_report_infers_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_report(make_result(make_finding()), Path(tmp, "out", "r.html"))
            self.assertTrue(path.read_text().startswith("<!DOCTYPE html>"))
        self.assertEqual(infer_format("a.JSON"), "json")
        with self.assertRaises(ValueError):
            infer_format("a.pdf")


if __name__ == "__main__":
    unittest.main()
