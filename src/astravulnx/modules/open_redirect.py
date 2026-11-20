"""Open redirect detection by inspecting the Location header of an un-followed response."""

from __future__ import annotations

from collections.abc import Iterator
from urllib.parse import urlsplit

from astravulnx.models import Confidence, Finding, Severity
from astravulnx.modules.base import ScanContext, ScanModule

PARAMETER_NAMES = ("url", "redirect", "next", "return", "goto", "target", "rurl", "redirect_uri")

# ".invalid" is reserved (RFC 2606); the scanner never connects to this host.
TEST_HOST = "astravulnx-redirect-test.invalid"
PAYLOADS = (
    f"//{TEST_HOST}",
    f"https://{TEST_HOST}",
    f"https://trusted.example@{TEST_HOST}",
)


def redirects_to_test_host(location: str) -> bool:
    return (urlsplit(location).hostname or "").lower() == TEST_HOST


class OpenRedirectModule(ScanModule):
    name = "open_redirect"
    title = "Open redirect"

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        for point in ctx.probe_points(PARAMETER_NAMES):
            for payload in ctx.payloads(PAYLOADS):
                response = ctx.send(point, payload, follow_redirects=False)
                if response is None or not 300 <= response.status < 400:
                    continue
                location = response.headers.get("location", "")
                if redirects_to_test_host(location):
                    yield Finding(
                        module=self.name,
                        title="Open redirect",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        payload=payload,
                        evidence=f"HTTP {response.status} with Location: {location}",
                        description="The application redirects to an attacker-controlled URL, "
                        "which can be used in phishing links.",
                        remediation="Redirect only to relative paths or to an allowlist of hosts.",
                        owasp="A01:2021 Broken Access Control",
                        cwe="CWE-601",
                    )
                    break
