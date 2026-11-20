"""Severity ordering and summary statistics for a set of findings."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from astravulnx.models import Finding, Severity


@dataclass(frozen=True)
class Summary:
    total: int
    by_severity: dict[str, int] = field(default_factory=dict)
    by_module: dict[str, int] = field(default_factory=dict)
    by_owasp: dict[str, int] = field(default_factory=dict)
    highest: Severity | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "by_severity": self.by_severity,
            "by_module": self.by_module,
            "by_owasp": self.by_owasp,
            "highest_severity": self.highest.label if self.highest is not None else None,
        }


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Most severe first; ties broken deterministically."""
    return sorted(findings, key=lambda f: (-f.severity, f.module, f.url, f.parameter, f.title))


def summarize(findings: Iterable[Finding]) -> Summary:
    items = list(findings)
    severity_counts = Counter(f.severity for f in items)
    return Summary(
        total=len(items),
        by_severity={
            sev.label: severity_counts[sev] for sev in sorted(Severity, reverse=True)
        },
        by_module=dict(sorted(Counter(f.module for f in items).items())),
        by_owasp=dict(sorted(Counter(f.owasp for f in items).items())),
        highest=max((f.severity for f in items), default=None),
    )
