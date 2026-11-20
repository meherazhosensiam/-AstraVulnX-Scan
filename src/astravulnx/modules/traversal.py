"""Directory (path) traversal detection by file-content signatures."""

from __future__ import annotations

import re
from collections.abc import Iterator

from astravulnx.models import Confidence, Finding, Severity
from astravulnx.modules.base import ScanContext, ScanModule

PAYLOADS = (
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "..\\..\\..\\windows\\win.ini",
)

SIGNATURES = {
    "/etc/passwd": re.compile(r"root:[x*]?:0:0:"),
    "win.ini": re.compile(r"\[(?:fonts|extensions)\]", re.IGNORECASE),
    "boot.ini": re.compile(r"\[boot loader\]", re.IGNORECASE),
}


def match_signature(body: str) -> str | None:
    for name, pattern in SIGNATURES.items():
        if pattern.search(body):
            return name
    return None


class DirectoryTraversalModule(ScanModule):
    name = "directory_traversal"
    title = "Directory traversal"

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        for point in ctx.injection_points:
            control = ctx.send(point, point.original_value)
            if control is None or match_signature(control.body):
                continue
            for payload in ctx.payloads(PAYLOADS):
                response = ctx.send(point, payload)
                signature = match_signature(response.body) if response else None
                if signature:
                    yield Finding(
                        module=self.name,
                        title="Directory traversal",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        payload=payload,
                        evidence=f"{signature} content signature in response "
                        "(absent from control request)",
                        description="A file path parameter allows reading files outside "
                        "the intended directory.",
                        remediation="Resolve paths against a fixed base directory and reject "
                        "inputs that escape it; prefer indirect identifiers over file names.",
                        owasp="A01:2021 Broken Access Control",
                        cwe="CWE-22",
                    )
                    break
