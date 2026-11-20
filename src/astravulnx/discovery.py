"""Find injection points (query parameters and form fields) in a fetched page."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit

# Form controls that are never useful to mutate.
_SKIPPED_INPUT_TYPES = {"submit", "button", "image", "reset", "file"}
_DEFAULT_FIELD_VALUE = "test"


@dataclass(frozen=True)
class InjectionPoint:
    """A single named parameter of a request that modules may mutate.

    ``params`` holds every parameter of the request so that mutating one value
    leaves the others intact.
    """

    url: str  # request URL without query string
    method: str  # "GET" or "POST"
    parameter: str
    params: tuple[tuple[str, str], ...]
    source: str  # "query" or "form"

    @property
    def original_value(self) -> str:
        return next((value for name, value in self.params if name == self.parameter), "")

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.method, self.url, self.parameter)

    def build_request(
        self, value: str
    ) -> tuple[str, str, dict[str, str] | None]:
        """Return ``(method, url, form_data)`` with ``parameter`` set to ``value``.

        ``value`` is percent-encoded except for ``/`` and ``%`` so that
        payloads which intentionally contain encoded sequences are sent as written.
        """
        if self.method == "POST":
            data = {name: (value if name == self.parameter else current)
                    for name, current in self.params}
            return "POST", self.url, data
        pairs = [
            f"{quote(name, safe='')}="
            f"{quote(value, safe='/%') if name == self.parameter else quote(current, safe='')}"
            for name, current in self.params
        ]
        return "GET", f"{self.url}?{'&'.join(pairs)}", None

    def with_extra_parameter(self, name: str) -> InjectionPoint:
        """Return a GET point that also carries ``name`` (used to probe common parameter names)."""
        if any(existing == name for existing, _ in self.params):
            return self
        return InjectionPoint(self.url, "GET", name, (*self.params, (name, "")), "query")


def split_query_url(url: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    parts = urlsplit(url)
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return base, tuple(parse_qsl(parts.query, keep_blank_values=True))


def points_from_url(url: str, source: str = "query") -> list[InjectionPoint]:
    base, params = split_query_url(url)
    return [InjectionPoint(base, "GET", name, params, source) for name, _ in params]


@dataclass
class _Form:
    action: str
    method: str
    fields: list[tuple[str, str]]


class _PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base_url = base_url
        self.forms: list[_Form] = []
        self.links: list[str] = []
        self._current: _Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if tag == "form":
            method = values.get("method", "get").upper()
            self._current = _Form(
                action=urljoin(self._base_url, values.get("action", "") or self._base_url),
                method="POST" if method == "POST" else "GET",
                fields=[],
            )
        elif tag in {"input", "textarea", "select"} and self._current is not None:
            name = values.get("name")
            input_type = values.get("type", "text").lower()
            if name and input_type not in _SKIPPED_INPUT_TYPES:
                self._current.fields.append((name, values.get("value") or _DEFAULT_FIELD_VALUE))
        elif tag == "a" and "href" in values:
            self.links.append(urljoin(self._base_url, values["href"]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            if self._current.fields:
                self.forms.append(self._current)
            self._current = None


def discover_injection_points(
    target_url: str, html: str, limit: int
) -> list[InjectionPoint]:
    """Collect injection points from the target URL, its forms and same-host links."""
    parser = _PageParser(target_url)
    parser.feed(html)
    parser.close()

    candidates: list[InjectionPoint] = points_from_url(target_url)

    for form in parser.forms:
        base, query = split_query_url(form.action)
        params = (*query, *form.fields) if form.method == "GET" else tuple(form.fields)
        url = base
        candidates.extend(
            InjectionPoint(url, form.method, name, params, "form") for name, _ in form.fields
        )

    target_host = urlsplit(target_url).netloc
    for link in parser.links:
        if urlsplit(link).netloc == target_host and "?" in link:
            candidates.extend(points_from_url(link))

    unique: dict[tuple[str, str, str], InjectionPoint] = {}
    for point in candidates:
        unique.setdefault(point.key, point)
    return list(unique.values())[:limit]
