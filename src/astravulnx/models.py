"""Data models shared by the scanner, modules and report writers."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

MAX_EVIDENCE_CHARS = 300


class Severity(enum.IntEnum):
    """Ordered severity levels. Higher value means more severe."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(member.name.lower() for member in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from None


class Confidence(enum.Enum):
    """How strongly the evidence supports the finding.

    These are coarse, rule-derived labels, not statistical probabilities.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def truncate(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    """Shorten evidence so reports stay readable and do not embed whole pages."""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass(frozen=True)
class Finding:
    """One potential issue reported by a scan module.

    Findings are produced by signature and heuristic checks and should be
    verified manually before being reported as confirmed vulnerabilities.
    """

    module: str
    title: str
    severity: Severity
    confidence: Confidence
    url: str
    description: str
    remediation: str
    owasp: str
    cwe: str
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": self.confidence.value,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": truncate(self.evidence),
            "description": self.description,
            "remediation": self.remediation,
            "owasp": self.owasp,
            "cwe": self.cwe,
        }


@dataclass
class ScanResult:
    """Everything produced by a single scan run."""

    target: str
    profile: str
    modules: list[str]
    started_at: datetime
    finished_at: datetime
    requests_sent: int = 0
    injection_points: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()
