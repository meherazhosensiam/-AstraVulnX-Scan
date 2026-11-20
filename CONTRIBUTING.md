# Contributing

Contributions that fix bugs, reduce false positives, add tests or improve documentation are
welcome. Please open an issue before starting a large change.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

Run these before opening a pull request; CI runs the same commands.

```bash
pytest                      # or: python -m unittest discover -s tests -t .
ruff check . && ruff format --check .
mypy
bandit -q -r src
pip-audit
```

## Guidelines

- Keep detection rules evidence-based. A new check needs a test against the fixture
  application (`tests/fixture_app.py`) for both the positive case and a negative case.
- Prefer a control request over a bare signature match to reduce false positives.
- Do not add runtime dependencies without a clear reason.
- Do not add fabricated results, accuracy claims, or marketing language to code or docs.
- See `docs/development.md` for how to add a module or a report format.

By contributing you agree that your contribution is licensed under the MIT License.
