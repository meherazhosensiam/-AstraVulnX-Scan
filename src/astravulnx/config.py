"""Scan configuration: one validated, immutable object passed through the scanner."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from astravulnx.__about__ import __version__

# Number of payloads each module tries per injection point, by profile.
# ``None`` means "all payloads the module defines".
PROFILES: dict[str, int | None] = {"quick": 3, "standard": 6, "deep": None}

DEFAULT_USER_AGENT = f"AstraVulnX/{__version__}"


class ConfigError(ValueError):
    """Raised when configuration values are invalid."""


@dataclass(frozen=True)
class ScanConfig:
    """Settings for one scan."""

    profile: str = "quick"
    timeout: float = 30.0
    delay: float = 0.1
    proxy: str | None = None
    verify_tls: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    headers: dict[str, str] = field(default_factory=dict)
    max_injection_points: int = 25
    max_body_bytes: int = 2_000_000
    modules: tuple[str, ...] | None = None  # None selects every available module
    exclude_modules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.profile not in PROFILES:
            raise ConfigError(f"profile must be one of: {', '.join(PROFILES)}")
        if self.timeout <= 0:
            raise ConfigError("timeout must be greater than zero")
        if self.delay < 0:
            raise ConfigError("delay must not be negative")
        if self.max_injection_points < 1:
            raise ConfigError("max_injection_points must be at least 1")
        if self.max_body_bytes < 1024:
            raise ConfigError("max_body_bytes must be at least 1024")

    @property
    def payload_limit(self) -> int | None:
        """Maximum payloads per injection point for the active profile."""
        return PROFILES[self.profile]

    def with_overrides(self, **changes: Any) -> ScanConfig:
        return replace(self, **changes)

    @classmethod
    def from_file(cls, path: str | Path) -> ScanConfig:
        """Load settings from a JSON object. Unknown keys are rejected."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config file {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError("config file must contain a JSON object")
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ConfigError(f"unknown config keys: {', '.join(unknown)}")
        for key in ("modules", "exclude_modules"):
            if key in data and data[key] is not None:
                data[key] = tuple(data[key])
        return cls(**data)
