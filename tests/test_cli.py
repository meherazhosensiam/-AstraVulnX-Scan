"""Command-line interface tests."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
from pathlib import Path

from astravulnx.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from tests.support import FixtureTestCase


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:  # argparse exits on usage errors and --version
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class CliTests(FixtureTestCase):
    FAST = ("--delay", "0", "-t", "5", "-q")

    def test_version_and_modules(self) -> None:
        code, out, _ = run_cli("--version")
        self.assertEqual((code, out.strip()), (EXIT_OK, "AstraVulnX 4.0.0"))
        code, out, _ = run_cli("modules")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("sql_injection", out)

    def test_no_command_prints_help_and_fails(self) -> None:
        code, out, _ = run_cli()
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("usage:", out)

    def test_text_scan_and_fail_on(self) -> None:
        url = self.base_url + "/item?id=1"
        code, out, _ = run_cli("scan", url, "-m", "sql_injection", *self.FAST)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("[CRITICAL] SQL injection", out)
        self.assertNotIn("\033[", out)

        code, _, _ = run_cli("scan", url, "-m", "sql_injection", "--fail-on", "high", *self.FAST)
        self.assertEqual(code, EXIT_FINDINGS)
        code, _, _ = run_cli("scan", self.base_url + "/secure", "--fail-on", "low", *self.FAST)
        self.assertEqual(code, EXIT_OK)

    def test_json_to_stdout_and_report_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            html_path, json_path = Path(tmp, "r.html"), Path(tmp, "r.json")
            code, out, _ = run_cli("scan", self.base_url + "/config", "-m", "sensitive_data",
                                   "--format", "json", "-o", str(html_path), *self.FAST)
            self.assertEqual(code, EXIT_OK)
            self.assertGreater(json.loads(out)["summary"]["total"], 0)
            self.assertIn("<html", html_path.read_text())

            run_cli("scan", self.base_url + "/config", "-m", "sensitive_data",
                    "-o", str(json_path), *self.FAST)
            self.assertEqual(json.loads(json_path.read_text())["tool"]["name"], "AstraVulnX")

    def test_exclude_option_removes_modules(self) -> None:
        code, out, _ = run_cli("scan", self.base_url + "/secure", "-x", "sql_injection,xss",
                               "-H", "X-Test: 1", *self.FAST)
        self.assertEqual(code, EXIT_OK)
        modules_line = next(line for line in out.splitlines() if line.startswith("Modules"))
        self.assertNotIn("sql_injection", modules_line)
        self.assertNotIn("xss", modules_line)
        self.assertIn("cors", modules_line)

    def test_errors_return_exit_code_2(self) -> None:
        bad_inputs = [
            ("scan", "not-a-url"),
            ("scan", self.base_url + "/", "-m", "nope"),
            ("scan", self.base_url + "/", "-H", "bad header"),
            ("scan", self.base_url + "/", "-p", "huge"),
            ("scan", self.base_url + "/", "--fail-on", "urgent"),
            ("scan", self.base_url + "/", "-o", "report.pdf"),
            ("scan", "http://127.0.0.1:1/", "-t", "2", "--delay", "0"),
        ]
        for argv in bad_inputs:
            with self.subTest(argv=argv):
                code, _, err = run_cli(*argv, "-q")
                self.assertEqual(code, EXIT_ERROR)
                self.assertTrue(err)
