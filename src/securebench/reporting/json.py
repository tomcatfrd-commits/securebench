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


class JsonReporter:
    """
    Serialize SecureBench results and transactions as JSON.
    """

    def render_audit(
        self,
        results: Iterable[AuditResult],
        *,
        indent: int = 2,
    ) -> str:
        """Return a list of audit results as JSON."""

        return self._dump(list(results), indent=indent)

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
        results: Iterable[AuditResult],
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

        raise TypeError(
            f"unsupported value for JSON serialization: "
            f"{type(value).__name__}"
        )