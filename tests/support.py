"""Shared helpers for tests."""

from __future__ import annotations

import unittest

from astravulnx.config import ScanConfig
from astravulnx.engine import Scanner
from astravulnx.models import Finding, ScanResult
from tests.fixture_app import start_server


class FixtureTestCase(unittest.TestCase):
    """Starts the fixture application once per test class."""

    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls._server, cls.base_url = start_server()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._server.shutdown()
        cls._server.server_close()

    def scan(self, path: str, *modules: str, profile: str = "deep") -> ScanResult:
        config = ScanConfig(profile=profile, delay=0.0, timeout=5.0, modules=modules or None)
        return Scanner(config).scan(self.base_url + path)


def titles(findings: list[Finding]) -> list[str]:
    return [finding.title for finding in findings]
