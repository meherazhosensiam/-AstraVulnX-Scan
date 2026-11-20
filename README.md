# AstraVulnX

Web application security assessment scanner written in Python.

Version 4.0.0 · Author: Meheraz Hossen Siam · MIT License

AstraVulnX scans a single target URL, discovers its query parameters and form fields, and
runs a set of signature-based checks for common web vulnerabilities and misconfigurations.
Each finding includes evidence, a CWE identifier, an OWASP Top 10 (2021) category and a
remediation note.

Detection is rule-based. Findings are **potential issues that must be verified manually**.
AstraVulnX is not a replacement for Burp Suite, OWASP ZAP or a manual assessment.

## Purpose and audience

- Security practitioners who want a small, readable scanner for authorized, first-pass checks.
- Students and reviewers who want to see how a DAST tool is structured: discovery, checks,
  evidence, severity and reporting are separate and each is covered by tests.
- Teams that want a dependency-free tool that can run in CI and fail a build on severity.

## Core capabilities

| Module | What it checks | How |
|---|---|---|
| `security_headers` | Missing CSP, HSTS (HTTPS only), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and clickjacking protection (X-Frame-Options or CSP `frame-ancestors`) | Inspects the initial response |
| `sql_injection` | Error-based SQL injection (MySQL/MariaDB, PostgreSQL, Oracle, SQL Server, SQLite signatures) | Injects payloads; reports only if the error is absent from a control request |
| `xss` | Reflected XSS | Reports exact, unencoded payload reflection in an HTML response |
| `ssrf` | Server-side request forgery where fetched internal content is reflected | Internal-address payloads in common URL-like parameters; signatures must be absent from a control request |
| `open_redirect` | Open redirects | Parses the `Location` header of an un-followed response |
| `directory_traversal` | Path traversal | `../` payloads (plain, nested and double-encoded; Windows variant); file-content signatures |
| `cors` | Reflected or wildcard `Access-Control-Allow-Origin` | GET and OPTIONS with forged `Origin`; severity depends on credentials |
| `sensitive_data` | Cloud keys, tokens, private-key blocks, hard-coded credential assignments, Luhn-valid card numbers, email addresses | Regular expressions on the target page; matches are redacted in output |

Other features:

- Discovery of query parameters, form fields (using each form's real action and method) and
  same-host link parameters, capped by `max_injection_points`.
- Scan profiles (`quick`, `standard`, `deep`) that set how many payloads are tried per parameter.
- Text, JSON and HTML output; `--fail-on` for CI gating.
- Proxy support, custom headers, optional TLS verification bypass for lab targets.
- No runtime dependencies (standard library only).

## Architecture overview

```
src/astravulnx/
  cli.py            argument parsing, exit codes, output selection
  engine.py         Scanner: fetch target, discover inputs, run modules, collect findings
  config.py         ScanConfig (validated, immutable) and scan profiles
  http.py           HttpClient: pacing, proxy, TLS, redirect control, body cap
  discovery.py      InjectionPoint and HTML parsing for forms and links
  models.py         Finding, ScanResult, Severity, Confidence
  risk.py           Sorting and summary statistics
  modules/          One file per check; registry in __init__.py
  reporting/        text_report.py, json_report.py, html_report.py
  logging_config.py Logging setup (progress goes to stderr)
tests/              Unit tests, end-to-end tests, and a local vulnerable fixture app
docs/development.md How to add a module or report format; design decisions
```

Scan workflow:

1. `Scanner.scan` validates the URL and fetches it once (the baseline response).
2. `discovery` extracts injection points from the URL, forms and same-host links.
3. Each selected module receives a `ScanContext` (config, HTTP client, baseline, injection
   points) and yields `Finding` objects. A failing module is logged and recorded in the
   result; it does not abort the scan.
4. Findings are de-duplicated, sorted by severity and returned as a `ScanResult`.
5. The CLI renders the result as text or JSON and optionally writes a JSON or HTML report.

How a finding is produced (SQL injection as an example): for each injection point the module
sends an unmodified control request; if the control response already contains a database error
signature the point is skipped. Otherwise payloads are sent in turn, and the first response
that matches a signature produces a finding whose evidence names the engine that matched.

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/meherazhosensiam/-AstraVulnX-Scan.git
cd -- -AstraVulnX-Scan
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install .                    # add -e ".[dev]" for development tools
```

(The repository name begins with a hyphen, hence `cd --`.)

## Quick start

AstraVulnX ships with a deliberately vulnerable local application used by its tests. It binds
to 127.0.0.1 only, so you can try the scanner without touching anyone else's system:

```bash
python -m tests.fixture_app 8099 &        # run from the repository root
astravulnx scan http://127.0.0.1:8099/
```

For real targets, use a lab you control (for example DVWA or OWASP Juice Shop running locally)
or a system you are authorized in writing to test.

## CLI usage

```bash
astravulnx scan https://lab.example.test/products?id=1            # default: quick profile
astravulnx scan https://lab.example.test/ -p deep                  # more payloads per parameter
astravulnx scan https://lab.example.test/ -m sql_injection,xss     # only these modules
astravulnx scan https://lab.example.test/ -x sensitive_data        # skip a module
astravulnx scan https://lab.example.test/ -o report.html           # also write an HTML report
astravulnx scan https://lab.example.test/ --format json > scan.json
astravulnx scan https://lab.example.test/ -H "Cookie: session=..." --proxy http://127.0.0.1:8080
astravulnx scan https://lab.example.test/ --fail-on high           # CI gate
astravulnx modules                                                 # list modules
python -m astravulnx --help
```

Parameter-based modules (SQL injection, XSS, traversal) need parameters to test. Give a URL
that already has a query string, or a page that contains forms or links with parameters.

Exit codes: `0` success, `1` a finding at or above `--fail-on`, `2` usage or scan error.
Progress messages go to stderr; results go to stdout. Color is used only when stdout is a
terminal and `NO_COLOR` is not set, so output is plain in CI logs.

## Configuration

Defaults can be set in a JSON file passed with `--config`; command-line flags override it.
Unknown keys are rejected.

```json
{
  "profile": "standard",
  "timeout": 20,
  "delay": 0.2,
  "headers": {"Authorization": "Bearer <token>"},
  "max_injection_points": 40,
  "exclude_modules": ["sensitive_data"]
}
```

| Key | Default | Meaning |
|---|---|---|
| `profile` | `quick` | Payloads per parameter: `quick` 3, `standard` 6, `deep` all |
| `timeout` | `30` | Per-request timeout in seconds |
| `delay` | `0.1` | Minimum seconds between requests |
| `proxy` | none | HTTP(S) proxy URL |
| `verify_tls` | `true` | Set `false` (or use `--insecure`) for self-signed lab certificates |
| `headers` | `{}` | Extra headers sent with every request |
| `max_injection_points` | `25` | Cap on discovered parameters to test |
| `max_body_bytes` | `2000000` | Response bytes read per request |
| `modules` / `exclude_modules` | all / none | Module selection |

Environment proxy variables are ignored; use `--proxy` explicitly.

## Example assessment output

Abridged output of `astravulnx scan http://127.0.0.1:8099/ -m sql_injection,xss,security_headers`
against the bundled fixture application (not a real system):

```
AstraVulnX 4.0.0

Target    http://127.0.0.1:8099/
Profile   quick
Modules   sql_injection, xss, security_headers

Findings: 8
  Critical 2  High 0  Medium 3  Low 3  Info 0

 1. [CRITICAL] SQL injection (error-based)
    http://127.0.0.1:8099/item  (parameter: id, GET)
    Payload:  '
    Evidence: MySQL/MariaDB error signature in response (absent from control request)
    CWE-89 | A03:2021 Injection | confidence: high

 5. [MEDIUM] Reflected cross-site scripting
    http://127.0.0.1:8099/search  (parameter: q, GET)
    Payload:  <script>alert('XSS')</script>
    Evidence: Payload returned in an HTML response without output encoding
    CWE-79 | A03:2021 Injection | confidence: medium
...
Findings are heuristic. Verify each one manually before reporting it.
```

## Report formats

| Format | How | Use |
|---|---|---|
| Text | default stdout | Terminals and CI logs |
| JSON | `--format json` or `-o file.json` | Tooling and CI. Versioned (`schema_version`), with `summary`, `findings` and `errors` |
| HTML | `-o file.html` | Self-contained, offline-readable document. All values are HTML-escaped |

## Testing

```bash
pip install -e ".[dev]"
pytest                                   # or: python -m unittest discover -s tests -t .
ruff check . && ruff format --check .
mypy
bandit -q -r src
pip-audit
```

Tests run every module end to end against `tests/fixture_app.py`, a local server with
intentionally vulnerable and intentionally safe endpoints. Detection tests include negative
cases (encoded reflection, pages that always show SQL errors, hardened pages).
The suite uses only the standard library `unittest` API, so it also runs without pytest.

## Limitations

- Heuristic, signature-based detection: expect false positives and false negatives.
- Scans one page. It does not crawl; it only follows parameters found in forms and same-host
  links on that page.
- Requests are sent sequentially, so large parameter sets are slow.
- SQL injection is error-based only (no blind, time-based or out-of-band techniques).
- XSS is reflected only (no stored or DOM-based XSS) and does not analyze the reflection context.
- SSRF is detected only when internal content is reflected; blind SSRF is not detected.
- No IDOR or file-upload testing, no authentication flows, no JavaScript execution.
- The sensitive-data module reads only the target page, not linked scripts.
- OWASP and CWE mappings are indicative and should be reviewed for formal reports.
- Not tested against WAF-protected or heavily dynamic applications.

## Responsible use

Only scan systems you own or have **explicit written permission** to test. Scans send
injection and traversal payloads and can trigger alerts, create log noise or, on fragile
applications, cause errors. Agree on scope and timing first, start with the `quick` profile,
and use `--delay` on shared or production-like systems. The authors accept no responsibility
for misuse. To report a security issue in AstraVulnX itself, see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/development.md](docs/development.md).
Bug reports with a reproducible case against a local or public lab target are the most useful.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

OWASP and the CWE project for the reference taxonomies. Parts of the original 3.0.0 code were
written with AI assistance (z.ai), as noted by the author in earlier documentation; testing,
debugging and maintenance are by the author.
