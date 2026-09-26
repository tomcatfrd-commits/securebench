"""
JSON reporting for SecureBench.

Reporting is intentionally read-only. It converts SecureBench domain
objects into serializable structures without changing their state.

JSON is the first reporting format because it can later serve as the
machine-readable interchange format for CLI output, APIs, dashboards,
archival evidence, and CI/CD pipelines.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from securebench.core import (
    AuditResult,
    ExecutionResult,
    Transaction,
    VerificationResult,
)


class JsonReporter:
    """
    Serialize SecureBench results and transactions as JSON.
    """

    def audit_result(
        self,
        result: AuditResult,
        *,
        indent: int = 2,
    ) -> str:
        """Return one audit result as JSON."""

        return self._dump(result, indent=indent)

    def execution_result(
        self,
        result: ExecutionResult,
        *,
        indent: int = 2,
    ) -> str:
        """Return one execution result as JSON."""

        return self._dump(result, indent=indent)

    def verification_result(
        self,
        result: VerificationResult,
        *,
        indent: int = 2,
    ) -> str:
        """Return one verification result as JSON."""

        return self._dump(result, indent=indent)

    def transaction(
        self,
        transaction: Transaction,
        *,
        indent: int = 2,
    ) -> str:
        """Return a transaction and its change records as JSON."""

        return self._dump(transaction, indent=indent)

    def write(
        self,
        data: Any,
        path: str | Path,
        *,
        indent: int = 2,
    ) -> Path:
        """
        Serialize data and write it to a JSON file.

        Parent directories are created when necessary.
        """

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            self._dump(data, indent=indent) + "\n",
            encoding="utf-8",
        )

        return output_path

    @staticmethod
    def _dump(
        data: Any,
        *,
        indent: int,
    ) -> str:
        """Serialize arbitrary supported SecureBench data."""

        return json.dumps(
            JsonReporter._to_serializable(data),
            indent=indent,
            ensure_ascii=False,
            sort_keys=True,
        )

    @staticmethod
    def _to_serializable(value: Any) -> Any:
        """
        Recursively convert SecureBench domain objects into JSON-compatible
        Python values.
        """

        if isinstance(value, StrEnum):
            return value.value

        if is_dataclass(value):
            return JsonReporter._to_serializable(asdict(value))

        if isinstance(value, dict):
            return {
                str(key): JsonReporter._to_serializable(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set, frozenset)):
            return [
                JsonReporter._to_serializable(item)
                for item in value
            ]

        if hasattr(value, "isoformat"):
            return value.isoformat()

        if value is None or isinstance(
            value,
            (str, int, float, bool),
        ):
            return value

        raise TypeError(
            f"unsupported value for JSON serialization: "
            f"{type(value).__name__}"
        )