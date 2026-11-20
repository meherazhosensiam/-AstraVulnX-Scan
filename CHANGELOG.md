# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [4.0.0] - 2026-11-20

A restructuring release. Detection logic was kept for every check that worked in 3.0.0 and
tightened where it produced avoidable false positives. The command line, Python API and JSON
report format are **not** backward compatible.

### Changed
- Package moved to a `src/` layout with `pyproject.toml`; one module per check under
  `astravulnx/modules/`.
- HTTP layer rewritten on the standard library. The scanner now has no runtime dependencies
  (`aiohttp`, `requests`, `beautifulsoup4`, `lxml`, `reportlab`, `colorama`, `cryptography`
  and `jsonschema` were declared or installed but not needed). Requests are sequential.
- CLI is now `astravulnx scan <url>` / `astravulnx modules` (also `python -m astravulnx`).
  The banner and decorative output were removed; progress goes to stderr; color is used
  only on a terminal and honours `NO_COLOR`.
- Forms are parsed with `html.parser` and submitted to their real `action` and `method`
  (3.0.0 posted every form to the page URL).
- Scan profiles (`quick`, `standard`, `deep`) now control payloads per parameter, and
  `--proxy` is applied. In 3.0.0 both were accepted but ignored.
- JSON report is versioned (`schema_version: 1`). Findings carry a coarse `confidence`
  label instead of the hard-coded `cvss_score`, which was not computed from anything.
- Reflected XSS severity is Medium (was High with a 6.1 score).
- OWASP labels use the 2021 category names. "OWASP Top 10 2024" in 3.0.0 documentation
  does not correspond to a published edition.
- CORS findings are graded: reflected origin with credentials is High, reflected origin
  without credentials is Medium, wildcard is Low.

### Added
- Control request per parameter: SQL error, traversal and SSRF signatures are reported only
  when absent from the unmodified response.
- HTML report (`-o report.html`), `--fail-on` exit codes for CI, `--format json`,
  `--module/--exclude`, `--header`, `--insecure`, `--config`.
- Test suite with a local, deliberately vulnerable fixture application.
- GitHub Actions workflows, `SECURITY.md`, `CONTRIBUTING.md`.

### Fixed
- Directory traversal: the Windows payload targeted `system32\config\sam` but the detection
  markers belong to `win.ini`, so it could never match.
- Open redirect: `Location` is parsed and its host compared; a substring match flagged any
  URL that merely contained the test domain.
- SSRF: generic markers such as `nginx`, `Apache` and `index of` were removed; they matched
  ordinary pages. Markers must be absent from the control response.
- Reflected XSS: the loose `alert(1)` match was removed; the full payload must be reflected
  unencoded in an HTML response.
- Payloads are percent-encoded; previously they were concatenated into URLs raw.
- Sensitive data: duplicate AWS/API-key patterns merged, card numbers require a Luhn check,
  the noisy 10-digit phone pattern was removed, and evidence is redacted.
- HSTS is only expected on HTTPS targets; `X-XSS-Protection` is no longer required because
  the header is deprecated.
- Header checks reuse the initial GET response (3.0.0 used HEAD, which some servers reject).
- `requirements.txt` listed the obsolete `argparse` and `asyncio` backports, and the
  console-script entry point referenced a module outside the package.

### Removed
- `ai/`, `intelligence/`, `crawler/`, `reporting/` placeholder dictionaries and the
  fabricated "accuracy" figures in them. No machine-learning, self-learning, online-update
  or crawler functionality existed.
- `data/knowledge_base.json` and its loader (not used by the scanner).
- Detection-module metadata for IDOR, file upload and a separate clickjacking module,
  none of which were implemented. Clickjacking protection is checked under `security_headers`.
- `main.py`, `setup.py`, `requirements.txt`, and unused `Config` fields.

## [3.0.0] - 2024

Single-file asynchronous scanner (`aiohttp`) covering security headers, error-based SQL
injection, reflected XSS, heuristic SSRF, open redirect, directory traversal, CORS and
sensitive data patterns, with JSON export. The original changelog for this version also
described AI/ML, PDF reporting and several other modules that were not implemented; those
entries have been removed.

## [2.0.0], [1.0.0]

Earlier prototypes. Not documented here.
