# Development guide

## Adding a scan module

1. Create `src/astravulnx/modules/<name>.py` with a `ScanModule` subclass:

   ```python
   class ExampleModule(ScanModule):
       name = "example"                 # used with --modules / --exclude
       title = "Short human description"

       def run(self, ctx: ScanContext) -> Iterator[Finding]:
           for point in ctx.injection_points:
               response = ctx.send(point, "value")   # None on network failure
               if response is not None and "marker" in response.body:
                   yield Finding(...)
   ```

2. Register the class in `_MODULES` in `src/astravulnx/modules/__init__.py`.
3. Add a route to `tests/fixture_app.py` that is vulnerable and one that is not, then add
   positive and negative tests in `tests/test_modules.py`.
4. Add a row to the module table in `README.md` and an entry to `CHANGELOG.md`.

Useful context members: `ctx.baseline` (initial response), `ctx.injection_points`,
`ctx.probe_points(names)` (adds common parameter names to the target URL),
`ctx.payloads(all_payloads)` (applies the profile limit) and `ctx.client` (for requests that
are not parameter injections, such as the CORS module).

Rules of thumb:

- Compare against a control request whenever a signature could appear on its own.
- Never raise for ordinary network errors; `ctx.send` already returns `None`.
- Put a redacted or truncated sample in `evidence`, never a full secret.

## Adding a report format

Add `reporting/<fmt>_report.py` with a `render_<fmt>(result: ScanResult) -> str` function,
register it in `_RENDERERS` in `reporting/__init__.py` (the file extension selects it), and
test that untrusted values are escaped if the format interprets markup.

## Design decisions

- **Standard-library HTTP.** The scanner is I/O-bound but sequential by design (predictable
  load on the target, simple reasoning about evidence). `urllib` removes all runtime
  dependencies and makes redirect and proxy behavior explicit.
- **Control requests.** Signature matches count only when absent from an unmodified request.
  This removes a whole class of false positives at the cost of one extra request per parameter.
- **Coarse confidence labels** (low/medium/high) instead of numeric scores, because the
  checks are rule-based and a number would imply precision that does not exist.
- **Fixture application for tests.** Tests exercise the real HTTP stack rather than mocks, so
  redirect handling, encoding and form submission are covered end to end.
- **Immutable config and findings** (frozen dataclasses) so modules cannot alter shared state.
