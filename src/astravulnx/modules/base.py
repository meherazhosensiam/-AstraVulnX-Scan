"""Base class and shared context for scan modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import ClassVar

from astravulnx.config import ScanConfig
from astravulnx.discovery import InjectionPoint, split_query_url
from astravulnx.http import HttpClient, HttpError, Response
from astravulnx.models import Finding


@dataclass
class ScanContext:
    """State shared by all modules during one scan."""

    target: str
    config: ScanConfig
    client: HttpClient
    baseline: Response
    injection_points: list[InjectionPoint] = field(default_factory=list)

    def payloads(self, available: tuple[str, ...]) -> tuple[str, ...]:
        """Apply the active profile's payload limit."""
        limit = self.config.payload_limit
        return available if limit is None else available[:limit]

    def probe_points(self, names: tuple[str, ...]) -> list[InjectionPoint]:
        """Injection points for parameters called ``names``.

        Existing parameters with those names are used as found. Names the target
        does not use yet are added to the target URL as extra GET parameters.
        """
        points = [p for p in self.injection_points if p.parameter in names]
        base, params = split_query_url(self.target)
        known = {p.parameter for p in points if p.method == "GET" and p.url == base}
        for name in names:
            if name not in known:
                points.append(InjectionPoint(base, "GET", name, (*params, (name, "")), "query"))
        return points

    def send(
        self, point: InjectionPoint, value: str, *, follow_redirects: bool = True
    ) -> Response | None:
        """Send ``point`` with ``value`` substituted. Returns ``None`` on network failure."""
        method, url, data = point.build_request(value)
        try:
            return self.client.request(method, url, data=data, follow_redirects=follow_redirects)
        except HttpError:
            return None


class ScanModule(ABC):
    """A single, self-contained check.

    Subclasses set ``name`` and ``title`` and implement :meth:`run`, then are
    registered in ``astravulnx.modules.REGISTRY``.
    """

    name: ClassVar[str]
    title: ClassVar[str]

    @abstractmethod
    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        """Yield findings. Must not raise for ordinary network failures."""
