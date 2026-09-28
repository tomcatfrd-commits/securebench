"""
JSON reporting for SecureBench.

Reporting is intentionally read-only. It converts SecureBench domain
objects into serializable structures without changing their state.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from securebench.core import (
    AuditResult,
    ExecutionResult,
    Transaction,
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


class JsonReporter:
    """
    Serialize SecureBench results and transactions as JSON.
    """

    def render_audit(
        self,
        results: AuditResult | Iterable[AuditResult],
        *,
        indent: int = 2,
    ) -> str:
        """Return audit result(s) as JSON.

        A single ``AuditResult`` is serialized as one object. An iterable of
        results is serialized as a JSON array.
        """
        items = _as_sequence(results)
        if isinstance(results, AuditResult):
            return self._dump(items[0], indent=indent)
        return self._dump(items, indent=indent)

    def render_execution(
        self,
        results: ExecutionResult | Iterable[ExecutionResult],
        *,
        indent: int = 2,
    ) -> str:
        """Return execution result(s) as JSON."""
        items = _as_sequence(results)
        if isinstance(results, ExecutionResult):
            return self._dump(items[0], indent=indent)
        return self._dump(items, indent=indent)

    def render_verification(
        self,
        results: VerificationResult | Iterable[VerificationResult],
        *,
        indent: int = 2,
    ) -> str:
        """Return verification result(s) as JSON."""
        items = _as_sequence(results)
        if isinstance(results, VerificationResult):
            return self._dump(items[0], indent=indent)
        return self._dump(items, indent=indent)

    def render(
        self,
        *,
        audits: Iterable[AuditResult] | None = None,
        executions: Iterable[ExecutionResult] | None = None,
        verifications: Iterable[VerificationResult] | None = None,
        transaction: Transaction | None = None,
        indent: int = 2,
    ) -> str:
        """Return a combined report as JSON."""

        payload: dict[str, Any] = {}
        if audits is not None:
            payload["audits"] = list(audits)
        if executions is not None:
            payload["executions"] = list(executions)
        if verifications is not None:
            payload["verifications"] = list(verifications)
        if transaction is not None:
            payload["transaction"] = transaction
        return self._dump(payload, indent=indent)

    def write_audit(
        self,
        results: AuditResult | Iterable[AuditResult],
        path: str | Path,
        *,
        indent: int = 2,
    ) -> Path:
        """Write an audit report to a JSON file."""

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self.render_audit(results, indent=indent) + "\n",
            encoding="utf-8",
        )
        return output_path

    def write(
        self,
        data: Any,
        path: str | Path,
        *,
        indent: int = 2,
    ) -> Path:
        """Serialize data and write it to a JSON file."""

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self._dump(data, indent=indent) + "\n",
            encoding="utf-8",
        )
        return output_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dump(self, data: Any, *, indent: int) -> str:
        return json.dumps(
            self._to_serializable(data),
            indent=indent,
            ensure_ascii=False,
            sort_keys=True,
        )

    def _to_serializable(self, value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value

        if isinstance(value, Transaction):
            return {
                "transaction_id": value.transaction_id,
                "profile_id": value.profile_id,
                "benchmark_id": value.benchmark_id,
                "status": value.status.value,
                "changes": [
                    self._to_serializable(change) for change in value.changes
                ],
            }

        if is_dataclass(value) and not isinstance(value, type):
            return self._to_serializable(asdict(value))

        if isinstance(value, dict):
            return {
                str(key): self._to_serializable(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set, frozenset)):
            return [self._to_serializable(item) for item in value]

        if hasattr(value, "isoformat"):
            try:
                return value.isoformat()
            except Exception:
                pass

        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        # Fallback for plain objects with a public __dict__
        if hasattr(value, "__dict__"):
            return {
                key: self._to_serializable(item)
                for key, item in vars(value).items()
                if not key.startswith("_")
            }

        raise