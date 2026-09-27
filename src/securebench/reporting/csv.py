"""
CSV reporting for SecureBench.

CSV output is intended for operational reporting and spreadsheet-oriented
analysis.
"""

from __future__ import annotations

import csv
from io import StringIO
from pathlib import Path
from typing import Iterable

from securebench.core import (
    AuditResult,
    ExecutionResult,
    VerificationResult,
)


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

    def render_audit(self, results: Iterable[AuditResult]) -> str:
        buffer = StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self.AUDIT_FIELDS)
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "control_id": result.control_id,
                    "host": result.host,
                    "status": result.status.value,
                    "compliant": str(
                        getattr(result, "compliant", result.status.value == "pass")
                    ).lower(),
                    "message": getattr(result, "message", "") or "",
                    "evidence_count": len(getattr(result, "evidence", ()) or ()),
                }
            )
        return buffer.getvalue()

    def render_execution(self, results: Iterable[ExecutionResult]) -> str:
        buffer = StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self.EXECUTION_FIELDS)
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "control_id": result.control_id,
                    "host": result.host,
                    "status": result.status.value,
                    "changed": str(getattr(result, "changed", False)).lower(),
                    "message": getattr(result, "message", "") or "",
                }
            )
        return buffer.getvalue()

    def render_verification(self, results: Iterable[VerificationResult]) -> str:
        buffer = StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self.VERIFICATION_FIELDS)
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "control_id": result.control_id,
                    "host": result.host,
                    "status": result.status.value,
                    "verified": str(
                        getattr(result, "verified", result.status.value == "pass")
                    ).lower(),
                    "message": getattr(result, "message", "") or "",
                    "evidence_count": len(getattr(result, "evidence", ()) or ()),
                }
            )
        return buffer.getvalue()

    def write_audit(
        self,
        results: Iterable[AuditResult],
        path: str | Path,
    ) -> Path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.render_audit(results), encoding="utf-8")
        return output_path