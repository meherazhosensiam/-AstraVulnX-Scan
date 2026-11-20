"""Scan orchestration: fetch the target, discover inputs, run modules, collect findings."""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from astravulnx.config import ConfigError, ScanConfig
from astravulnx.discovery import discover_injection_points
from astravulnx.http import HttpClient, HttpError
from astravulnx.models import Finding, ScanResult, utc_now
from astravulnx.modules import REGISTRY, ScanContext
from astravulnx.risk import sort_findings

logger = logging.getLogger(__name__)


class ScanError(Exception):
    """Raised when a scan cannot start (invalid target, target unreachable)."""


def validate_target(target: str) -> str:
    parts = urlsplit(target)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ScanError("target must be an absolute http:// or https:// URL")
    return target


def select_modules(config: ScanConfig) -> list[str]:
    requested = list(config.modules) if config.modules is not None else list(REGISTRY)
    unknown = sorted((set(requested) | set(config.exclude_modules)) - set(REGISTRY))
    if unknown:
        raise ConfigError(
            f"unknown module(s): {', '.join(unknown)} (available: {', '.join(REGISTRY)})"
        )
    return [name for name in requested if name not in config.exclude_modules]


class Scanner:
    """Runs the selected modules against one target URL."""

    def __init__(self, config: ScanConfig | None = None, client: HttpClient | None = None) -> None:
        self.config = config or ScanConfig()
        self._module_names = select_modules(self.config)
        self._client = client or HttpClient(self.config)

    def scan(self, target: str) -> ScanResult:
        validate_target(target)
        started_at = utc_now()

        logger.info("Fetching target %s", target)
        try:
            baseline = self._client.get(target)
        except HttpError as exc:
            raise ScanError(f"target is not reachable: {exc}") from exc
        if baseline.status >= 400:
            logger.warning("Target returned HTTP %d; results may be incomplete", baseline.status)

        points = (
            discover_injection_points(target, baseline.body, self.config.max_injection_points)
            if baseline.is_html
            else []
        )
        logger.info("Discovered %d injection point(s)", len(points))

        context = ScanContext(
            target=target,
            config=self.config,
            client=self._client,
            baseline=baseline,
            injection_points=points,
        )
        findings: list[Finding] = []
        errors: list[str] = []
        for name in self._module_names:
            logger.info("Running module: %s", name)
            try:
                findings.extend(REGISTRY[name]().run(context))
            except Exception as exc:  # one failing module must not abort the scan
                logger.exception("Module %s failed", name)
                errors.append(f"{name}: {type(exc).__name__}: {exc}")

        unique = {(f.module, f.title, f.url, f.method, f.parameter): f for f in findings}
        return ScanResult(
            target=target,
            profile=self.config.profile,
            modules=self._module_names,
            started_at=started_at,
            finished_at=utc_now(),
            requests_sent=self._client.requests_sent,
            injection_points=len(points),
            findings=sort_findings(unique.values()),
            errors=errors,
        )
