"""
HTML reporting for SecureBench.

The HTML reporter produces a human-readable operational report without
coupling the reporting layer to a web framework.
"""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Iterable

from securebench.core import (
    AuditResult,
    ExecutionResult,
    VerificationResult,
)


def _as_sequence(value: Any) -> list[Any]:
    """Normalize a single domain object or an iterable into a list."""
    if isinstance(value, (AuditResult, ExecutionResult, VerificationResult)):
        return [value]
    if isinstance(value, (str, bytes)):
        raise TypeError(
            f"expected result object or iterable, got {type(value).__name__}"
        )
    return list(value)


def _format_evidence(evidence: Any) -> str:
    """Return escaped HTML describing evidence items."""
    items = list(evidence or ())
    if not items:
        return ""

    parts: list[str] = []
    for item in items:
        source = escape(str(getattr(item, "source", "") or ""))
        observed = escape(str(getattr(item, "observed", "") or ""))
        expected = escape(str(getattr(item, "expected", "") or ""))
        parts.append(
            f"<div class=\"evidence\">"
            f"<strong>source:</strong> {source}<br>"
            f"<strong>observed:</strong> {observed}<br>"
            f"<strong>expected:</strong> {expected}"
            f"</div>"
        )
    return "".join(parts)


class HtmlReporter:
    """
    Generate standalone HTML reports.
    """

    def render_audit(
        self,
        results: AuditResult | Iterable[AuditResult],
        *,
        title: str = "SecureBench Audit Report",
    ) -> str:
        rows = []
        for result in _as_sequence(results):
            status = escape(result.status.value)
            evidence_html = _format_evidence(
                getattr(result, "evidence", ())
            )
            rows.append(
                "<tr>"
                f"<td>{escape(result.control_id)}</td>"
                f"<td>{escape(result.host)}</td>"
                f"<td>{status}</td>"
                f"<td>{escape(getattr(result, 'message', '') or '')}</td>"
                f"<td>{evidence_html}</td>"
                "</tr>"
            )
        return self._document(
            title=title,
            headers=("Control", "Host", "Status", "Message", "Evidence"),
            rows=rows,
        )

    def render_execution(
        self,
        results: ExecutionResult | Iterable[ExecutionResult],
        *,
        title: str = "SecureBench Execution Report",
    ) -> str:
        rows = []
        for result in _as_sequence(results):
            rows.append(
                "<tr>"
                f"<td>{escape(result.control_id)}</td>"
                f"<td>{escape(result.host)}</td>"
                f"<td>{escape(result.status.value)}</td>"
                f"<td>{escape(str(getattr(result, 'changed', False)))}</td>"
                f"<td>{escape(getattr(result, 'message', '') or '')}</td>"
                "</tr>"
            )
        return self._document(
            title=title,
            headers=("Control", "Host", "Status", "Changed", "Message"),
            rows=rows,
        )

    def render_verification(
        self,
        results: VerificationResult | Iterable[VerificationResult],
        *,
        title: str = "SecureBench Verification Report",
    ) -> str:
        rows = []
        for result in _as_sequence(results):
            evidence_html = _format_evidence(
                getattr(result, "evidence", ())
            )
            rows.append(
                "<tr>"
                f"<td>{escape(result.control_id)}</td>"
                f"<td>{escape(result.host)}</td>"
                f"<td>{escape(result.status.value)}</td>"
                f"<td>{escape(getattr(result, 'message', '') or '')}</td>"
                f"<td>{evidence_html}</td>"
                "</tr>"
            )
        return self._document(
            title=title,
            headers=("Control", "Host", "Status", "Message", "Evidence"),
            rows=rows,
        )

    def write_audit(
        self,
        results: AuditResult | Iterable[AuditResult],
        path: str | Path,
        *,
        title: str = "SecureBench Audit Report",
    ) -> Path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self.render_audit(results, title=title),
            encoding="utf-8",
        )
        return output_path

    @staticmethod
    def _document(
        *,
        title: str,
        headers: tuple[str, ...],
        rows: list[str],
    ) -> str:
        header_html = "".join(f"<th>{escape(h)}</th>" for h in headers)
        body = "\n".join(rows) if rows else (
            f'<tr><td colspan="{len(headers)}">No results</td></tr>'
        )
        return (
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            f"<meta charset=\"utf-8\">\n"
            f"<title>{escape(title)}</title>\n"
            "</head>\n"
            "<body>\n"
            f"<h1>{escape(title)}</h1>\n"
            "<table>\n"
            f"<thead><tr>{header_html}</tr></thead>\n"
            f"<tbody>\n{body}\n</tbody>\n"
            "</table>\n"
            "</body>\n"
            "</html>\n"
        )