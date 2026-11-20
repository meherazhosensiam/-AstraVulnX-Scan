"""Logging setup for the command-line interface."""

from __future__ import annotations

import logging
import sys


def configure_logging(*, quiet: bool = False, verbose: bool = False) -> None:
    """Send progress messages to stderr so stdout stays clean for results."""
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    package_logger = logging.getLogger("astravulnx")
    package_logger.handlers[:] = [handler]
    package_logger.setLevel(level)
    package_logger.propagate = False
