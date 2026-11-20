"""Scan module registry.

To add a module: create a ``ScanModule`` subclass in this package and add it
to ``_MODULES`` below. See docs/development.md.
"""

from __future__ import annotations

from astravulnx.modules.base import ScanContext, ScanModule
from astravulnx.modules.cors import CorsModule
from astravulnx.modules.headers import SecurityHeadersModule
from astravulnx.modules.open_redirect import OpenRedirectModule
from astravulnx.modules.sensitive_data import SensitiveDataModule
from astravulnx.modules.sqli import SqlInjectionModule
from astravulnx.modules.ssrf import SsrfModule
from astravulnx.modules.traversal import DirectoryTraversalModule
from astravulnx.modules.xss import ReflectedXssModule

_MODULES: tuple[type[ScanModule], ...] = (
    SecurityHeadersModule,
    SqlInjectionModule,
    ReflectedXssModule,
    SsrfModule,
    OpenRedirectModule,
    DirectoryTraversalModule,
    CorsModule,
    SensitiveDataModule,
)

REGISTRY: dict[str, type[ScanModule]] = {module.name: module for module in _MODULES}


def module_names() -> list[str]:
    return list(REGISTRY)


__all__ = ["REGISTRY", "ScanContext", "ScanModule", "module_names"]
