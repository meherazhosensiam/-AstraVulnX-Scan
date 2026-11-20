"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from astravulnx.__about__ import __version__
from astravulnx.config import PROFILES, ConfigError, ScanConfig
from astravulnx.engine import ScanError, Scanner, select_modules
from astravulnx.logging_config import configure_logging
from astravulnx.models import Severity
from astravulnx.modules import REGISTRY
from astravulnx.reporting import infer_format, render_json, render_text, write_report

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_EPILOG = (
    "Only scan systems you own or have explicit written permission to test.\n"
    "Exit codes: 0 success, 1 findings at or above --fail-on, 2 error."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="astravulnx",
        description="Web application security assessment scanner.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"AstraVulnX {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    scan = commands.add_parser(
        "scan", help="scan a target URL", epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument("target", help="target URL (http:// or https://)")
    scan.add_argument("-p", "--profile", choices=list(PROFILES),
                      help="payload depth (default: quick)")
    scan.add_argument("-m", "--modules", metavar="NAMES",
                      help="comma-separated modules to run (default: all)")
    scan.add_argument("-x", "--exclude", metavar="NAMES", help="comma-separated modules to skip")
    scan.add_argument("-t", "--timeout", type=float, metavar="SECONDS",
                      help="request timeout (default: 30)")
    scan.add_argument("--delay", type=float, metavar="SECONDS",
                      help="pause between requests (default: 0.1)")
    scan.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                      help="extra request header; repeatable")
    scan.add_argument("--proxy", metavar="URL", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    scan.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    scan.add_argument("--config", metavar="FILE", help="JSON configuration file; flags override it")
    scan.add_argument("-o", "--output", metavar="FILE",
                      help="also write a report; format is taken from the .json or .html extension")
    scan.add_argument("--format", choices=["text", "json"], default="text",
                      help="stdout format (default: text)")
    scan.add_argument("--fail-on", metavar="SEVERITY", type=Severity.parse,
                      help="exit with status 1 if a finding is at or above this severity "
                      "(info, low, medium, high, critical)")
    scan.add_argument("--no-color", action="store_true", help="disable colored output")
    scan.add_argument("-q", "--quiet", action="store_true", help="suppress progress messages")
    scan.add_argument("-v", "--verbose", action="store_true", help="show debug messages")

    commands.add_parser("modules", help="list available scan modules")
    return parser


def _split_names(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    return tuple(name.strip() for name in value.split(",") if name.strip())


def _parse_headers(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in raw_headers:
        name, separator, value = raw.partition(":")
        if not separator or not name.strip():
            raise ConfigError(f"invalid header {raw!r}; expected 'Name: value'")
        headers[name.strip()] = value.strip()
    return headers


def _build_config(args: argparse.Namespace) -> ScanConfig:
    config = ScanConfig.from_file(args.config) if args.config else ScanConfig()
    overrides: dict[str, object] = {}
    if args.profile:
        overrides["profile"] = args.profile
    if args.timeout is not None:
        overrides["timeout"] = args.timeout
    if args.delay is not None:
        overrides["delay"] = args.delay
    if args.proxy:
        overrides["proxy"] = args.proxy
    if args.insecure:
        overrides["verify_tls"] = False
    if args.header:
        overrides["headers"] = {**config.headers, **_parse_headers(args.header)}
    if args.modules is not None:
        overrides["modules"] = _split_names(args.modules)
    if args.exclude is not None:
        overrides["exclude_modules"] = _split_names(args.exclude)
    return config.with_overrides(**overrides)


def _use_color(args: argparse.Namespace) -> bool:
    return not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()


def _run_scan(args: argparse.Namespace) -> int:
    configure_logging(quiet=args.quiet, verbose=args.verbose)
    try:
        config = _build_config(args)
        select_modules(config)  # fail early on unknown module names
        if args.output:
            infer_format(args.output)  # fail before scanning if the extension is unsupported
        result = Scanner(config).scan(args.target)
        if args.output:
            written = write_report(result, args.output)
            if not args.quiet:
                print(f"Report written to {written}", file=sys.stderr)
    except (ConfigError, ScanError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "json":
        sys.stdout.write(render_json(result))
    else:
        sys.stdout.write(render_text(result, color=_use_color(args)))

    if args.fail_on is not None and any(f.severity >= args.fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def _list_modules() -> int:
    width = max(len(name) for name in REGISTRY)
    for name, module in REGISTRY.items():
        print(f"{name:<{width}}  {module.title}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "modules":
        return _list_modules()
    parser.print_help()
    return EXIT_ERROR


__all__ = ["build_parser", "main"]
