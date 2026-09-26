"""
CSV reporting for SecureBench.

CSV output is intended for operational reporting and spreadsheet-oriented
analysis.

Unlike JSON, CSV requires a deliberately flattened representation because
SecureBench domain objects contain nested evidence and transaction data.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, TextIO

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
        "succeeded",
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

    def audit_results(
        self,
        results: Iterable[AuditResult],
        output: TextIO,
    ) -> None:
        """Write audit results to an open text stream."""

        writer = csv.DictWriter(
            output,
            fieldnames=self.AUDIT_FIELDS,
        )
        writer.writeheader()

        for result in results:
            writer.writerow(
                {
                    "control_id": result.control_id,
                    "host": result.host,
                    "status": result.status.value,
                    "compliant": result.compliant,
                    "message": result.message,
                    "evidence_count": len(result.evidence),
                }
            )

    def execution_results(
        self,
        results: Iterable[ExecutionResult],
        output: TextIO,
    ) -> None:
        """Write execution results to an open text stream."""

        writer = csv.DictWriter(
            output,
            fieldnames=self.EXECUTION_FIELDS,
        )
        writer.writeheader()

        for result in results:
            writer.writerow(
                {
                    "control_id": result.control_id,
                    "host": result.host,
                    "status": result.status.value,
                    "changed": result.changed,
                    "succeeded": result.succeeded,
                    "message": result.message,
                }
            )

    def verification_results(
        self,
        results: Iterable[VerificationResult],
        output: TextIO,
    ) -> None:
        """Write verification results to an open text stream."""

        writer = csv.DictWriter(
            output,
            fieldnames=self.VERIFICATION_FIELDS,
        )
        writer.writeheader()

        for result in results:
            writer.writerow(
                {
                    "control_id": result.control_id,
                    "host": result.host,
                    "status": result.status.value,
                    "verified": result.verified,
                    "message": result.message,
                    "evidence_count": len(result.evidence),
                }
            )

    def write_audit_results(
        self,
        results: Iterable[AuditResult],
        path: str | Path,
    ) -> Path:
        """Write audit results directly to a CSV file."""

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as output:
            self.audit_results(results, output)

        return output_path

    def write_execution_results(
        self,
        results: Iterable[ExecutionResult],
        path: str | Path,
    ) -> Path:
        """Write execution results directly to a CSV file."""

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as output:
            self.execution_results(results, output)

        return output_path

    def write_verification_results(
        self,
        results: Iterable[VerificationResult],
        path: str | Path,
    ) -> Path:
        """Write verification results directly to a CSV file."""

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as output:
            self.verification_results(results, output)

        return output_path