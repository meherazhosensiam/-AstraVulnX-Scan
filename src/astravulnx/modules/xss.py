"""Reflected cross-site scripting detection by exact, unencoded payload reflection."""

from __future__ import annotations

from collections.abc import Iterator

from astravulnx.models import Confidence, Finding, Severity
from astravulnx.modules.base import ScanContext, ScanModule

PAYLOADS = (
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
)


class ReflectedXssModule(ScanModule):
    name = "xss"
    title = "Reflected cross-site scripting"

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        for point in ctx.injection_points:
            for payload in ctx.payloads(PAYLOADS):
                response = ctx.send(point, payload)
                if response is None or not response.is_html or payload not in response.body:
                    continue
                yield Finding(
                    module=self.name,
                    title="Reflected cross-site scripting",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    url=point.url,
                    method=point.method,
                    parameter=point.parameter,
                    payload=payload,
                    evidence="Payload returned in an HTML response without output encoding",
                    description=(
                        "Input is reflected without HTML encoding. Whether it is exploitable "
                        "depends on where it lands in the page; verify manually."
                    ),
                    remediation="Apply context-aware output encoding and add a Content-Security-Policy.",
                    owasp="A03:2021 Injection",
                    cwe="CWE-79",
                )
                break
