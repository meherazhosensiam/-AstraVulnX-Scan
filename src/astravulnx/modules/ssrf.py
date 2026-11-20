"""Heuristic server-side request forgery detection.

Only detects cases where the content fetched from an internal address is
reflected in the response. Blind SSRF (no reflected content) is out of scope.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from astravulnx.models import Confidence, Finding, Severity
from astravulnx.modules.base import ScanContext, ScanModule

PARAMETER_NAMES = ("url", "uri", "path", "dest", "redirect", "link", "src", "domain")

PAYLOADS = (
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://169.254.169.254",
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
)

INDICATORS = {
    "SSH service banner": re.compile(r"^SSH-\d\.\d", re.MULTILINE),
    "/etc/passwd content": re.compile(r"root:[x*]?:0:0:"),
    "cloud metadata keys": re.compile(r"\b(?:ami-id|instance-id|iam/security-credentials)\b"),
}


def match_indicator(body: str) -> str | None:
    for name, pattern in INDICATORS.items():
        if pattern.search(body):
            return name
    return None


class SsrfModule(ScanModule):
    name = "ssrf"
    title = "Server-side request forgery (reflected content only)"

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        for point in ctx.probe_points(PARAMETER_NAMES):
            control = ctx.send(point, point.original_value)
            if control is None or match_indicator(control.body):
                continue
            for payload in ctx.payloads(PAYLOADS):
                response = ctx.send(point, payload)
                indicator = match_indicator(response.body) if response else None
                if indicator:
                    yield Finding(
                        module=self.name,
                        title="Possible server-side request forgery",
                        severity=Severity.HIGH,
                        confidence=Confidence.LOW,
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        payload=payload,
                        evidence=f"{indicator} in response (absent from control request)",
                        description="The application may fetch attacker-supplied URLs and return the result.",
                        remediation="Validate destinations against an allowlist and block "
                        "requests to loopback, link-local and private address ranges.",
                        owasp="A10:2021 Server-Side Request Forgery",
                        cwe="CWE-918",
                    )
                    break
