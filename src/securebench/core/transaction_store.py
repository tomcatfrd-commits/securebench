"""Durable, atomic JSON storage for remediation transactions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .exceptions import TransactionError
from .transaction import ChangeRecord, ChangeStatus, Transaction, TransactionStatus

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class TransactionStore:
    """Persist transaction state before and after every system change."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def save(self, transaction: Transaction) -> Path:
        if not isinstance(transaction, Transaction):
            raise TypeError("transaction must be a Transaction")
        path = self._path_for(transaction.transaction_id)
        temporary = path.with_suffix(".json.tmp")
        try:
            payload = json.dumps(
                self._serialize(transaction),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            temporary.write_text(payload + "\n", encoding="utf-8")
            temporary.replace(path)
        except (OSError, TypeError, ValueError) as exc:
            raise TransactionError(
                f"unable to persist transaction '{transaction.transaction_id}': {exc}"
            ) from exc
        return path

    def load(self, transaction_id: str) -> Transaction:
        path = self._path_for(transaction_id)
        if not path.is_file():
            raise TransactionError(f"transaction does not exist: {transaction_id}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            transaction = Transaction(
                transaction_id=data["transaction_id"],
                profile_id=data.get("profile_id") or None,
                benchmark_id=data.get("benchmark_id") or None,
                benchmark_version=data.get("benchmark_version") or None,
                host=data.get("host"),
            )
            for raw in data.get("changes", []):
                transaction.add_change(
                    ChangeRecord(
                        change_id=raw["change_id"],
                        control_id=raw["control_id"],
                        host=raw["host"],
                        benchmark_id=raw.get("benchmark_id", ""),
                        benchmark_version=raw.get("benchmark_version", ""),
                        control_digest=raw.get("control_digest", ""),
                        status=ChangeStatus(raw["status"]),
                        before=raw.get("before"),
                        after=raw.get("after"),
                        details=raw.get("details") or {},
                        rollback_data=raw.get("rollback_data"),
                        message=raw.get("message", ""),
                    )
                )
            status = TransactionStatus(data["status"])
            if status is TransactionStatus.COMMITTED:
                transaction.mark_committed()
            elif status is TransactionStatus.ROLLBACK_REQUIRED:
                transaction.mark_rollback_required()
            elif status is TransactionStatus.ROLLED_BACK:
                transaction.mark_rolled_back()
            return transaction
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise TransactionError(
                f"invalid transaction record '{transaction_id}': {exc}"
            ) from exc

    def list_ids(self) -> tuple[str, ...]:
        return tuple(sorted(path.stem for path in self._root.glob("*.json")))

    def _path_for(self, transaction_id: str) -> Path:
        if not isinstance(transaction_id, str) or not _SAFE_ID.fullmatch(transaction_id):
            raise TransactionError("transaction_id contains unsafe path characters")
        return self._root / f"{transaction_id}.json"

    @staticmethod
    def _serialize(transaction: Transaction) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "transaction_id": transaction.transaction_id,
            "profile_id": transaction.profile_id,
            "benchmark_id": transaction.benchmark_id,
            "benchmark_version": transaction.benchmark_version,
            "host": transaction.host,
            "status": transaction.status.value,
            "changes": [
                {
                    "change_id": change.change_id,
                    "control_id": change.control_id,
                    "host": change.host,
                    "benchmark_id": change.benchmark_id,
                    "benchmark_version": change.benchmark_version,
                    "control_digest": change.control_digest,
                    "status": change.status.value,
                    "before": change.before,
                    "after": change.after,
                    "details": change.details,
                    "rollback_data": change.rollback_data,
                    "message": change.message,
                }
                for change in transaction.changes
            ],
        }
