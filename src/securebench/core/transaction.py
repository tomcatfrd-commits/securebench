from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping


class TransactionStatus(StrEnum):
    PENDING = "pending"
    COMMITTED = "committed"
    ROLLBACK_REQUIRED = "rollback_required"
    ROLLED_BACK = "rolled_back"


class ChangeStatus(StrEnum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True, slots=True)
class ChangeRecord:
    change_id: str
    control_id: str
    host: str
    status: ChangeStatus = ChangeStatus.PENDING
    before: Mapping[str, object] = field(default_factory=dict)
    after: Mapping[str, object] = field(default_factory=dict)
    details: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.change_id, str) or not self.change_id.strip():
            raise ValueError("change_id must be a non-empty string")

        if not isinstance(self.control_id, str) or not self.control_id.strip():
            raise ValueError("control_id must be a non-empty string")

        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("host must be a non-empty string")

        if not isinstance(self.status, ChangeStatus):
            raise TypeError("status must be a ChangeStatus")

        if not isinstance(self.before, Mapping):
            raise TypeError("before must be a mapping")

        if not isinstance(self.after, Mapping):
            raise TypeError("after must be a mapping")

        if not isinstance(self.details, Mapping):
            raise TypeError("details must be a mapping")


class Transaction:
    def __init__(self, transaction_id: str) -> None:
        if not isinstance(transaction_id, str) or not transaction_id.strip():
            raise ValueError("transaction_id must be a non-empty string")

        self._transaction_id = transaction_id
        self._status = TransactionStatus.PENDING
        self._changes: list[ChangeRecord] = []

    @property
    def transaction_id(self) -> str:
        return self._transaction_id

    @property
    def status(self) -> TransactionStatus:
        return self._status

    @property
    def changes(self) -> tuple[ChangeRecord, ...]:
        return tuple(self._changes)

    def add_change(self, change: ChangeRecord) -> None:
        if not isinstance(change, ChangeRecord):
            raise TypeError("change must be a ChangeRecord")

        if any(existing.change_id == change.change_id for existing in self._changes):
            raise ValueError(
                f"Duplicate change_id: {change.change_id!r}"
            )

        self._changes.append(change)

    def get_change(self, change_id: str) -> ChangeRecord:
        for change in self._changes:
            if change.change_id == change_id:
                return change

        raise KeyError(f"Unknown change_id: {change_id!r}")

    @property
    def change_count(self) -> int:
        return len(self._changes)

    @property
    def failed_changes(self) -> tuple[ChangeRecord, ...]:
        return tuple(
            change
            for change in self._changes
            if change.status is ChangeStatus.FAILED
        )

    @property
    def successful_changes(self) -> tuple[ChangeRecord, ...]:
        return tuple(
            change
            for change in self._changes
            if change.status is ChangeStatus.SUCCESS
        )

    def mark_rollback_required(self) -> None:
        if self._status is TransactionStatus.ROLLED_BACK:
            raise ValueError("Cannot require rollback for a rolled-back transaction")

        self._status = TransactionStatus.ROLLBACK_REQUIRED

    def mark_committed(self) -> None:
        if self._status is TransactionStatus.ROLLED_BACK:
            raise ValueError("Cannot commit a rolled-back transaction")

        if self.failed_changes:
            raise ValueError(
                "Cannot commit a transaction containing failed changes"
            )

        self._status = TransactionStatus.COMMITTED

    def mark_rolled_back(self) -> None:
        self._status = TransactionStatus.ROLLED_BACK