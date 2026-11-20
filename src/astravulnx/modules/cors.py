"""CORS misconfiguration: reflected or wildcard Access-Control-Allow-Origin."""

from __future__ import annotations

from collections.abc import Iterator

from astravulnx.http import HttpError
from astravulnx.models import Confidence, Finding, Severity
from astravulnx.modules.base import ScanContext, ScanModule

# ".invalid" is reserved (RFC 2606); the scanner never connects to this host.
TEST_ORIGINS = ("https://astravulnx-cors-test.invalid", "null")


class CorsModule(ScanModule):
    name = "cors"
    title = "CORS misconfiguration"

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        worst: Finding | None = None
        for origin in TEST_ORIGINS:
            for method in ("GET", "OPTIONS"):
                finding = self._probe(ctx, method, origin)
                if finding is not None and (worst is None or finding.severity > worst.severity):
                    worst = finding
        if worst is not None:
            yield worst

    def _probe(self, ctx: ScanContext, method: str, origin: str) -> Finding | None:
        headers = {"Origin": origin}
        if method == "OPTIONS":
            headers["Access-Control-Request-Method"] = "GET"
        try:
            response = ctx.client.request(method, ctx.target, headers=headers)
        except HttpError:
            return None

        allow_origin = response.headers.get("access-control-allow-origin", "")
        credentials = response.headers.get("access-control-allow-credentials", "").lower() == "true"
        evidence = (
            f"{method} with Origin: {origin} returned "
            f"Access-Control-Allow-Origin: {allow_origin}"
            + ("; Access-Control-Allow-Credentials: true" if credentials else "")
        )

        if allow_origin == origin:
            severity = Severity.HIGH if credentials else Severity.MEDIUM
            title = "CORS trusts the null origin" if origin == "null" else "CORS reflects arbitrary origins"
            description = (
                "Any origin can read responses"
                + (" including credentialed requests." if credentials else " to unauthenticated requests.")
            )
        elif allow_origin == "*":
            severity = Severity.LOW
            title = "CORS allows any origin"
            description = "Any origin can read unauthenticated responses. Credentialed access is not granted."
        else:
            return None

        return Finding(
            module=self.name,
            title=title,
            severity=severity,
            confidence=Confidence.HIGH,
            url=ctx.target,
            method=method,
            evidence=evidence,
            description=description,
            remediation="Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins.",
            owasp="A05:2021 Security Misconfiguration",
            cwe="CWE-942",
        )
