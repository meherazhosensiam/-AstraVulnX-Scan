"""Secrets and personal data patterns in the target page's response body.

Matches are redacted in evidence; the full value is never copied into reports.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from astravulnx.models import Confidence, Finding, Severity
from astravulnx.modules.base import ScanContext, ScanModule

_OWASP = "A02:2021 Cryptographic Failures"


@dataclass(frozen=True)
class _Pattern:
    label: str
    regex: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    cwe: str


PATTERNS = (
    _Pattern("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
             Severity.HIGH, Confidence.HIGH, "CWE-798"),
    _Pattern("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
             Severity.MEDIUM, Confidence.HIGH, "CWE-200"),
    _Pattern("Stripe live secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
             Severity.HIGH, Confidence.HIGH, "CWE-798"),
    _Pattern("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
             Severity.HIGH, Confidence.HIGH, "CWE-798"),
    _Pattern("Private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
             Severity.HIGH, Confidence.HIGH, "CWE-321"),
    _Pattern("Hard-coded credential assignment",
             re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key)\b\s*[=:]\s*[\"']?[^\s\"'<>&]{8,}"),
             Severity.MEDIUM, Confidence.LOW, "CWE-798"),
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_MAX_EMAILS_REPORTED = 50  # pages listing many addresses are usually directories, not leaks


def luhn_valid(number: str) -> bool:
    digits = [int(ch) for ch in number if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def redact(value: str) -> str:
    return value[:4] + "*" * min(max(len(value) - 4, 0), 8)


class SensitiveDataModule(ScanModule):
    name = "sensitive_data"
    title = "Sensitive data exposure in page source"

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        body = ctx.baseline.body
        for pattern in PATTERNS:
            matches = [m.group(0) for m in pattern.regex.finditer(body)]
            if matches:
                yield self._finding(ctx, pattern.label, matches, pattern.severity,
                                    pattern.confidence, pattern.cwe)

        cards = [m.group(0) for m in _CARD_CANDIDATE.finditer(body) if luhn_valid(m.group(0))]
        if cards:
            yield self._finding(ctx, "Payment card number (passes Luhn check)", cards,
                                Severity.MEDIUM, Confidence.MEDIUM, "CWE-359")

        emails = sorted(set(_EMAIL.findall(body)))
        if 0 < len(emails) <= _MAX_EMAILS_REPORTED:
            yield self._finding(ctx, "Email address", emails, Severity.INFO, Confidence.HIGH, "CWE-200")

    def _finding(
        self, ctx: ScanContext, label: str, matches: list[str], severity: Severity,
        confidence: Confidence, cwe: str,
    ) -> Finding:
        return Finding(
            module=self.name,
            title=f"Sensitive data: {label}",
            severity=severity,
            confidence=confidence,
            url=ctx.target,
            evidence=f"{len(matches)} match(es); first redacted: {redact(matches[0])}",
            description=f"The response body contains a pattern that looks like: {label.lower()}.",
            remediation="Remove secrets and personal data from client-visible responses and rotate "
            "any credential that was exposed.",
            owasp=_OWASP,
            cwe=cwe,
        )
