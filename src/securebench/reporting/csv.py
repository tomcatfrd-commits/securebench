"""
CSV reporting for SecureBench.

CSV output is intended for operational reporting and spreadsheet-oriented
analysis.
"""

from __future__ import annotations

import csv
from io import StringIO
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


class CsvReporter:
    """
    Produce flat CSV reports from SecureBench results.
    """

    AUDIT_FIELDS = (
        "control_id",
        "host",
        "status",
        "compliant",
        "message",
        "evidence_count",
    )

    EXECUTION_FIELDS = (
        "control_id",
        "host",
        "status",
        "changed",
        "message",
    )

    VERIFICATION_FIELDS = (
        "control_id",
        "host",
        "status",
        "verified",
        "message",
        "evidence_count",
    )

    def render_audit(
        self,
        results: AuditResult | Iterable[AuditResult],
    ) -> str:
        buffer = StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self.AUDIT_FIELDS)
        writer.writeheader()
        for result in _as_sequence(results):
            writer.writerow(
                {
                    "control_id": result.control_id,
                    "host": result.host,
                    "status": result.status.value,
                    "compliant": str(
                        getattr(
                            result,
                            "compliant",
                            result.status.value == "pass",
                        )
                    ).lower(),
                    "message": getattr(result, "message", "") or "",
                    "evidence_count": len(
                        getattr(result, "evidence", ()) or ()
                    ),
                }
            )
        return buffer.getvalue()

    def render_execution(
        self,
        results: ExecutionResult | Iterable[ExecutionResult],
    ) -> str:
        buffer = StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self.EXECUTION_FIELDS)
        writer.writeheader()
        for result in _as_sequence(results):
            writer.writerow(
                {
                    "control_id": result.control_id,
                    "host": result.host,
                    "status": result.status.value,
                    "changed": str(
                        getattr(result, "changed", False)
                    ).lower(),
                    "message": getattr(result, "message", "") or "",
                }
            )
        return buffer.getvalue()

    def render_verification(
        self,
        results: VerificationResult | Iterable[VerificationResult],
    ) -> str:
        buffer = StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=self.VERIFICATION_FIELDS,
        )
        writer.writeheader()
        for result in _as_sequence(results):
            writer.writerow(
                {
                    "control_id": result.control_id,
                    "host": result.host,
                    "status": result.status.value,
                    "verified": str(
                        getattr(
                            result,
                            "verified",
                            result.status.value == "pass",
                        )
                    ).lower(),
                    "message": getattr(result, "message", "") or "",
                    "evidence_count": len(
                        getattr(result, "evidence", ()) or ()
                    ),
                }
            )
        return buffer.getvalue()

    def write_audit(
        self,
        results: AuditResult | Iterable[AuditResult],
        path: str | Path,
    ) -> Path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self.render_audit(results),
            encoding="utf-8",
        )
        return output_path