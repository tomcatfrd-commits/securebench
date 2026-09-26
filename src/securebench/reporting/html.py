"""
HTML reporting for SecureBench.

The HTML reporter produces a human-readable operational report without
coupling the reporting layer to a web framework.

The initial implementation intentionally uses standard-library HTML
escaping and templating so the reporting layer remains lightweight.
"""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Iterable

from securebench.core import (
    AuditResult,
    ComplianceStatus,
    ExecutionResult,
    VerificationResult,
)


class HtmlReporter:
    """
    Generate standalone HTML reports.
    """

    def audit_report(
        self,
        results: Iterable[AuditResult],
        *,
        title: str = "SecureBench Audit Report",
    ) -> str:
        """Generate an HTML audit report."""

        rows = [
            self._audit_row(result)
            for result in results
        ]

        return self._document(
            title=title,
            heading=title,
            table_headers=(
                "Control",
                "Host",
                "Status",
                "Compliant",
                "Evidence",
                "Message",
            ),
            rows=rows,
        )

    def execution_report(
        self,
        results: Iterable[ExecutionResult],
        *,
        title: str = "SecureBench Execution Report",
    ) -> str:
        """Generate an HTML execution report."""

        rows = [
            self._execution_row(result)
            for result in results
        ]

        return self._document(
            title=title,
            heading=title,
            table_headers=(
                "Control",
                "Host",
                "Status",
                "Changed",
                "Succeeded",
                "Message",
            ),
            rows=rows,
        )

    def verification_report(
        self,
        results: Iterable[VerificationResult],
        *,
        title: str = "SecureBench Verification Report",
    ) -> str:
        """Generate an HTML verification report."""

        rows = [
            self._verification_row(result)
            for result in results
        ]

        return self._document(
            title=title,
            heading=title,
            table_headers=(
                "Control",
                "Host",
                "Status",
                "Verified",
                "Evidence",
                "Message",
            ),
            rows=rows,
        )

    def write(
        self,
        html: str,
        path: str | Path,
    ) -> Path:
        """Write an HTML report to disk."""

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            html,
            encoding="utf-8",
        )

        return output_path

    @staticmethod
    def _audit_row(result: AuditResult) -> tuple[str, ...]:
        return (
            escape(result.control_id),
            escape(result.host),
            escape(result.status.value),
            escape(str(result.compliant)),
            escape(str(len(result.evidence))),
            escape(result.message),
        )

    @staticmethod
    def _execution_row(result: ExecutionResult) -> tuple[str, ...]:
        return (
            escape(result.control_id),
            escape(result.host),
            escape(result.status.value),
            escape(str(result.changed)),
            escape(str(result.succeeded)),
            escape(result.message),
        )

    @staticmethod
    def _verification_row(
        result: VerificationResult,
    ) -> tuple[str, ...]:
        return (
            escape(result.control_id),
            escape(result.host),
            escape(result.status.value),
            escape(str(result.verified)),
            escape(str(len(result.evidence))),
            escape(result.message),
        )

    @staticmethod
    def _document(
        *,
        title: str,
        heading: str,
        table_headers: tuple[str, ...],
        rows: list[tuple[str, ...]],
    ) -> str:
        """Build a standalone HTML document."""

        header_html = "".join(
            f"<th>{escape(header)}</th>"
            for header in table_headers
        )

        row_html = "".join(
            "<tr>"
            + "".join(f"<td>{cell}</td>" for cell in row)
            + "</tr>"
            for row in rows
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<style>
body {{
    font-family: system-ui, sans-serif;
    margin: 2rem;
}}

table {{
    border-collapse: collapse;
    width: 100%;
}}

th,
td {{
    border: 1px solid #ccc;
    padding: 0.6rem;
    text-align: left;
    vertical-align: top;
}}

th {{
    font-weight: 600;
}}

.status-pass {{
    font-weight: 600;
}}
</style>
</head>
<body>
<h1>{escape(heading)}</h1>
<table>
<thead>
<tr>
{header_html}
</tr>
</thead>
<tbody>
{row_html}
</tbody>
</table>
</body>
</html>
"""