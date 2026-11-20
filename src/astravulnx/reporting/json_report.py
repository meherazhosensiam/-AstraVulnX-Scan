"""JSON report: a stable, machine-readable document for CI and tooling."""

from __future__ import annotations

import json
from typing import Any

from astravulnx.__about__ import __version__
from astravulnx.models import ScanResult
from astravulnx.risk import summarize

SCHEMA_VERSION = 1


def to_dict(result: ScanResult) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "AstraVulnX", "version": __version__},
        "target": result.target,
        "profile": result.profile,
        "modules": result.modules,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
        "duration_seconds": round(result.duration_seconds, 2),
        "requests_sent": result.requests_sent,
        "injection_points": result.injection_points,
        "summary": summarize(result.findings).to_dict(),
        "findings": [finding.to_dict() for finding in result.findings],
        "errors": result.errors,
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"
