"""Missing HTTP security response headers (uses the initial response; no extra requests)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit

from astravulnx.models import Confidence, Finding, Severity
from astravulnx.modules.base import ScanContext, ScanModule

_OWASP_MISCONFIG = "A05:2021 Security Misconfiguration"


@dataclass(frozen=True)
class _HeaderRule:
    header: str
    severity: Severity
    cwe: str
    owasp: str
    description: str
    remediation: str
    https_only: bool = False


_RULES = (
    _HeaderRule(
        "content-security-policy", Severity.MEDIUM, "CWE-693", _OWASP_MISCONFIG,
        "No Content-Security-Policy header. A CSP limits the impact of injected script.",
        "Define a Content-Security-Policy that restricts script and frame sources.",
    ),
    _HeaderRule(
        "strict-transport-security", Severity.MEDIUM, "CWE-319", "A02:2021 Cryptographic Failures",
        "No Strict-Transport-Security header on an HTTPS response. Browsers may be downgraded to HTTP.",
        "Send Strict-Transport-Security with a long max-age once HTTPS is fully deployed.",
        https_only=True,
    ),
    _HeaderRule(
        "x-content-type-options", Severity.LOW, "CWE-693", _OWASP_MISCONFIG,
        "No X-Content-Type-Options header. Browsers may MIME-sniff responses.",
        "Send 'X-Content-Type-Options: nosniff'.",
    ),
    _HeaderRule(
        "referrer-policy", Severity.LOW, "CWE-200", _OWASP_MISCONFIG,
        "No Referrer-Policy header. Full URLs may be disclosed to other sites in the Referer header.",
        "Send a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
    ),
    _HeaderRule(
        "permissions-policy", Severity.LOW, "CWE-693", _OWASP_MISCONFIG,
        "No Permissions-Policy header. Powerful browser features are not explicitly restricted.",
        "Send a Permissions-Policy that disables features the application does not use.",
    ),
)


class SecurityHeadersModule(ScanModule):
    name = "security_headers"
    title = "Missing security headers (including clickjacking protection)"

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        headers = ctx.baseline.headers
        is_https = urlsplit(ctx.target).scheme == "https"

        for rule in _RULES:
            if rule.https_only and not is_https:
                continue
            if rule.header not in headers:
                yield self._finding(ctx, rule.header, rule.severity, rule.description,
                                    rule.remediation, rule.owasp, rule.cwe)

        csp = headers.get("content-security-policy", "")
        if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
            yield self._finding(
                ctx, "x-frame-options", Severity.MEDIUM,
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is set. "
                "The page can be embedded in a frame, which enables clickjacking.",
                "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
                _OWASP_MISCONFIG, "CWE-1021",
            )

    def _finding(
        self, ctx: ScanContext, header: str, severity: Severity, description: str,
        remediation: str, owasp: str, cwe: str,
    ) -> Finding:
        return Finding(
            module=self.name,
            title=f"Missing {_display_name(header)} header",
            severity=severity,
            confidence=Confidence.HIGH,
            url=ctx.target,
            description=description,
            remediation=remediation,
            owasp=owasp,
            cwe=cwe,
            evidence=f"Header not present in HTTP {ctx.baseline.status} response",
        )


def _display_name(header: str) -> str:
    return "-".join(part.upper() if part in {"x", "csp"} else part.capitalize()
                    for part in header.split("-"))
