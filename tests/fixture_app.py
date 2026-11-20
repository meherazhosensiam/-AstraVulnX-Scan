"""A deliberately vulnerable local web application used as a test fixture.

It exists so scan modules can be tested end to end without touching third-party
systems. It binds to 127.0.0.1 only and must never be exposed to a network.

Run it manually:  python -m tests.fixture_app [port]
"""

from __future__ import annotations

import html
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}

MYSQL_ERROR = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"

INDEX = """<!DOCTYPE html><html><body><h1>Fixture</h1>
<a href="/item?id=1">item</a>
<form action="/search" method="get"><input name="q" type="text"><input type="submit" value="go"></form>
<form action="/login" method="post"><input name="username"><input name="password" type="password">
<input type="hidden" name="csrf" value="abc"></form>
</body></html>"""

CONFIG_PAGE = """<html><body>
<!-- AKIAIOSFODNN7EXAMPLE -->
<pre>-----BEGIN RSA PRIVATE KEY-----</pre>
<p>contact: admin@example.org</p>
</body></html>"""


def _decode_fully(value: str) -> str:
    previous = None
    while previous != value:
        previous, value = value, unquote(value)
    return value


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # silence request logging
        pass

    def _send(self, body: str, status: int = 200, headers: dict[str, str] | None = None,
              content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _route(self, params: dict[str, str]) -> None:
        path = urlsplit(self.path).path
        origin = self.headers.get("Origin")

        if path == "/":
            self._send(INDEX)
        elif path == "/item":
            value = params.get("id", "")
            self._send(f"<p>{MYSQL_ERROR}</p>" if "'" in value else f"<p>Item {html.escape(value)}</p>")
        elif path == "/login":
            value = params.get("username", "")
            self._send(f"<p>{MYSQL_ERROR}</p>" if "'" in value else "<p>Invalid login</p>")
        elif path == "/docs":  # always shows an SQL error, injected or not
            self._send(f"<p>Troubleshooting: {MYSQL_ERROR}</p>")
        elif path == "/search":  # reflected without encoding
            self._send(f"<p>Results for {params.get('q', '')}</p>")
        elif path == "/safe":  # reflected with encoding
            self._send(f"<p>Results for {html.escape(params.get('q', ''))}</p>")
        elif path == "/go":
            target = params.get("next")
            if target:
                self._send("", 302, {"Location": target})
            else:
                self._send("<p>no redirect</p>")
        elif path == "/file":
            name = _decode_fully(params.get("name", ""))
            leaked = "../" in name or "..\\" in name
            if "win.ini" in name:
                self._send("[fonts]\n[extensions]" if leaked else "<p>not found</p>")
            else:
                self._send("root:x:0:0:root:/root:/bin/bash" if leaked else "<p>not found</p>")
        elif path == "/fetch":
            self._send("SSH-2.0-OpenSSH_8.9" if "127.0.0.1:22" in params.get("url", "") else "<p>fetched</p>")
        elif path == "/api":
            headers = dict(SECURE_HEADERS)
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            self._send("{}", headers=headers, content_type="application/json")
        elif path == "/wildcard":
            self._send("{}", headers={**SECURE_HEADERS, "Access-Control-Allow-Origin": "*"})
        elif path == "/config":
            self._send(CONFIG_PAGE)
        elif path == "/secure":
            self._send("<p>hardened</p>", headers=SECURE_HEADERS)
        else:
            self._send("<p>not found</p>", 404)

    def do_GET(self) -> None:
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        self._route({key: values[0] for key, values in query.items()})

    def do_OPTIONS(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        self._route({key: values[0] for key, values in form.items()})


def start_server(port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """Start the fixture on 127.0.0.1 in a background thread; returns ``(server, base_url)``."""
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


if __name__ == "__main__":
    chosen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    httpd = ThreadingHTTPServer(("127.0.0.1", chosen_port), Handler)
    print(f"Fixture application listening on http://127.0.0.1:{chosen_port} (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
