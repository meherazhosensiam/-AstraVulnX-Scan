"""Report writers."""

from __future__ import annotations

from pathlib import Path

from astravulnx.models import ScanResult
from astravulnx.reporting.html_report import render_html
from astravulnx.reporting.json_report import render_json
from astravulnx.reporting.text_report import render_text

_RENDERERS = {"json": render_json, "html": render_html}
REPORT_FORMATS = tuple(_RENDERERS)


def infer_format(path: str | Path) -> str:
    suffix = Path(path).suffix.lower().lstrip(".")
    if suffix not in _RENDERERS:
        raise ValueError(
            f"cannot infer report format from {str(path)!r}; use a .json or .html extension"
        )
    return suffix


def write_report(result: ScanResult, path: str | Path, fmt: str | None = None) -> Path:
    fmt = fmt or infer_format(path)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_RENDERERS[fmt](result), encoding="utf-8")
    return target


__all__ = ["REPORT_FORMATS", "infer_format", "render_html", "render_json", "render_text", "write_report"]
