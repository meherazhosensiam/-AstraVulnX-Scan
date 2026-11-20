"""Error-based SQL injection detection.

A finding is reported only when a database error signature appears in the
response to an injected value and did not appear in a control response.
Blind and time-based techniques are not implemented.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from astravulnx.models import Confidence, Finding, Severity
from astravulnx.modules.base import ScanContext, ScanModule

PAYLOADS = (
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "' UNION SELECT NULL--",
)

SIGNATURES = {
    "MySQL/MariaDB": re.compile(
        r"SQL syntax.*MySQL|Warning.*mysql_|mysql_fetch"
        r"|check the manual that corresponds to your (?:MySQL|MariaDB)",
        re.IGNORECASE,
    ),
    "PostgreSQL": re.compile(r"PostgreSQL.*ERROR|pg_query\(|unterminated quoted string", re.IGNORECASE),
    "Oracle": re.compile(r"ORA-\d{4,5}|quoted string not properly terminated", re.IGNORECASE),
    "SQL Server": re.compile(
        r"Microsoft OLE DB|Unclosed quotation mark|Incorrect syntax near|odbc_exec", re.IGNORECASE
    ),
    "SQLite": re.compile(r"sqlite3\.OperationalError|SQLite error", re.IGNORECASE),
}


def match_signature(body: str) -> str | None:
    for engine, pattern in SIGNATURES.items():
        if pattern.search(body):
            return engine
    return None


class SqlInjectionModule(ScanModule):
    name = "sql_injection"
    title = "SQL injection (error-based)"

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        for point in ctx.injection_points:
            control = ctx.send(point, point.original_value)
            if control is None or match_signature(control.body):
                continue  # unreachable, or the page already shows SQL errors on its own

            for payload in ctx.payloads(PAYLOADS):
                response = ctx.send(point, payload)
                engine = match_signature(response.body) if response else None
                if response is not None and engine:
                    method, url, _ = point.build_request(payload)
                    yield Finding(
                        module=self.name,
                        title="SQL injection (error-based)",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        url=point.url,
                        method=method,
                        parameter=point.parameter,
                        payload=payload,
                        evidence=f"{engine} error signature in response (absent from control request)",
                        description=(
                            "Injected input changed how the database query was parsed, "
                            "producing a database error message in the response."
                        ),
                        remediation="Use parameterized queries or prepared statements and "
                        "suppress detailed database errors in responses.",
                        owasp="A03:2021 Injection",
                        cwe="CWE-89",
                    )
                    break
