"""Minimal synchronous HTTP client built on the standard library.

Design notes:
  * Error status codes (404, 500, ...) are returned as normal responses because
    scan modules often need to inspect error pages.
  * Redirects can be disabled per request, which the open-redirect check needs.
  * Only an explicitly configured proxy is used; environment proxies are ignored
    so scans behave the same on every machine.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from http.client import HTTPMessage
from typing import IO

from astravulnx.config import ScanConfig


class HttpError(Exception):
    """Raised when a request cannot be completed (DNS, connection, timeout, ...)."""


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: Mapping[str, str]  # lower-cased header names
    body: str

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type.lower() or not self.content_type


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> None:
        return None


class HttpClient:
    """Sends requests with shared headers, proxy, TLS and pacing settings."""

    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        self.requests_sent = 0
        self._last_request_at = 0.0
        self._follow = self._build_opener(follow_redirects=True)
        self._no_follow = self._build_opener(follow_redirects=False)

    def _build_opener(self, *, follow_redirects: bool) -> urllib.request.OpenerDirector:
        proxies = {"http": self._config.proxy, "https": self._config.proxy}
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.ProxyHandler(proxies if self._config.proxy else {}),
            urllib.request.HTTPHandler(),
            urllib.request.HTTPSHandler(context=self._ssl_context()),
            urllib.request.HTTPErrorProcessor(),
            urllib.request.HTTPDefaultErrorHandler(),
        ]
        handlers.append(
            urllib.request.HTTPRedirectHandler() if follow_redirects else _NoRedirect()
        )
        opener = urllib.request.OpenerDirector()
        for handler in handlers:
            opener.add_handler(handler)
        return opener

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if not self._config.verify_tls:
            # Explicit opt-in (--insecure) for lab targets with self-signed certificates.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # nosec B501
        return context

    def _pace(self) -> None:
        wait = self._config.delay - (time.monotonic() - self._last_request_at)
        if self._last_request_at and wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()

    def request(
        self,
        method: str,
        url: str,
        *,
        data: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> Response:
        if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
            raise HttpError(f"unsupported URL scheme: {url}")
        merged = {"User-Agent": self._config.user_agent, **self._config.headers, **(headers or {})}
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        if body is not None:
            merged.setdefault("Content-Type", "application/x-www-form-urlencoded")
        request = urllib.request.Request(url, data=body, headers=merged, method=method)  # noqa: S310
        opener = self._follow if follow_redirects else self._no_follow

        self._pace()
        self.requests_sent += 1
        try:
            with opener.open(request, timeout=self._config.timeout) as raw:
                return self._to_response(raw.geturl(), raw.status, raw.headers, raw)
        except urllib.error.HTTPError as exc:
            # 3xx without following, 4xx and 5xx all arrive here; they are valid responses.
            return self._to_response(exc.url or url, exc.code, exc.headers, exc)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ssl.SSLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise HttpError(f"{method} {url} failed: {reason}") from exc
        except ValueError as exc:
            raise HttpError(f"invalid request for {url}: {exc}") from exc

    def get(self, url: str, *, headers: Mapping[str, str] | None = None) -> Response:
        return self.request("GET", url, headers=headers)

    def _to_response(
        self, url: str, status: int, headers: HTTPMessage, stream: IO[bytes]
    ) -> Response:
        raw_body = stream.read(self._config.max_body_bytes)
        lowered = {name.lower(): value for name, value in headers.items()}
        charset = headers.get_content_charset() or "utf-8"
        try:
            text = raw_body.decode(charset, errors="replace")
        except LookupError:
            text = raw_body.decode("utf-8", errors="replace")
        return Response(url=url, status=status, headers=lowered, body=text)
