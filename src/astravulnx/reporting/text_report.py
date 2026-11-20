"""Plain-text summary for terminals and CI logs."""

from __future__ import annotations

from astravulnx.__about__ import __version__
from astravulnx.models import Finding, ScanResult, Severity
from astravulnx.risk import summarize

_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def _tag(severity: Severity, color: bool) -> str:
    label = f"[{severity.label.upper()}]"
    return f"{_COLORS[severity]}{label}{_RESET}" if color else label


def _format_finding(index: int, finding: Finding, color: bool) -> list[str]:
    location = finding.url
    if finding.parameter:
        location += f"  (parameter: {finding.parameter}, {finding.method})"
    lines = [f"{index:>2}. {_tag(finding.severity, color)} {finding.title}", f"    {location}"]
    if finding.payload:
        lines.append(f"    Payload:  {finding.payload}")
    lines.append(f"    Evidence: {finding.evidence}")
    lines.append(f"    {finding.cwe} | {finding.owasp} | confidence: {finding.confidence.value}")
    return lines


def render_text(result: ScanResult, *, color: bool = False) -> str:
    summary = summarize(result.findings)
    counts = "  ".join(f"{label} {count}" for label, count in summary.by_severity.items())
    lines = [
        f"AstraVulnX {__version__}",
        "",
        f"Target    {result.target}",
        f"Profile   {result.profile}",
        f"Modules   {', '.join(result.modules)}",
        f"Requests  {result.requests_sent} in {result.duration_seconds:.1f}s",
        "",
        f"Findings: {summary.total}",
        f"  {counts}",
        "",
    ]
    for index, finding in enumerate(result.findings, start=1):
        lines.extend(_format_finding(index, finding, color))
        lines.append("")
    if not result.findings:
        lines.extend(["No potential issues detected by the enabled modules.", ""])
    if result.errors:
        lines.append("Module errors:")
        lines.extend(f"  - {error}" for error in result.errors)
        lines.append("")
    lines.append("Findings are heuristic. Verify each one manually before reporting it.")
    return "\n".join(lines) + "\n"
