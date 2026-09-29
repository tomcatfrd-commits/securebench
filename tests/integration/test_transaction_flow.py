from __future__ import annotations

from pathlib import Path

from securebench.core.loader import ConfigurationLoader
from securebench.core.result import ExecutionResult, ExecutionStatus
from securebench.core.transaction import (
    ChangeRecord,
    ChangeStatus,
    Transaction,
    TransactionStatus,
)
from securebench.rollback.engine import RollbackEngine


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_PATH = (
    PROJECT_ROOT
    / "benchmarks"
    / "cis"
    / "ubuntu"
    / "24.04"
    / "benchmark.yml"
)


class FakeRollbackProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def rollback(self, control, host: str, change: ChangeRecord) -> ExecutionResult:
        self.calls.append((control.control_id, host))

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=True,
            message="Rollback completed.",
        )


def _load_control():
    loader = ConfigurationLoader()
    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    return benchmark.get_control("CIS-1.1.1.1")


def _successful_change(
    *,
    control_id: str,
    host: str,
    change_id: str,
) -> ChangeRecord:
    return ChangeRecord(
        change_id=change_id,
        control_id=control_id,
        host=host,
        status=ChangeStatus.SUCCESS,
        message="Remediation completed.",
    )


def test_transaction_can_record_successful_remediation_and_rollback() -> None:
    control = _load_control()
    host = "ubuntu-production-01"

    transaction = Transaction(
        transaction_id="txn-integration-001",
        host=host,
    )

    change = _successful_change(
        control_id=control.control_id,
        host=host,
        change_id="change-001",
    )

    transaction.add_change(change)

    assert transaction.status is TransactionStatus.PENDING
    assert transaction.change_count == 1
    assert transaction.successful_changes == (change,)

    transaction.mark_rollback_required()

    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
    )

    assert result.success is True
    assert transaction.status is TransactionStatus.ROLLED_BACK
    assert provider.calls == [
        (control.control_id, host)
    ]
    assert change.status is ChangeStatus.ROLLED_BACK


def test_failed_change_is_not_rolled_back() -> None:
    control = _load_control()
    host = "ubuntu-production-01"

    transaction = Transaction(
        transaction_id="txn-integration-002",
        host=host,
    )

    successful = _successful_change(
        control_id=control.control_id,
        host=host,
        change_id="change-success",
    )

    failed = ChangeRecord(
        change_id="change-failed",
        control_id=control.control_id,
        host=host,
        status=ChangeStatus.FAILED,
        message="Remediation failed.",
    )

    transaction.add_change(successful)
    transaction.add_change(failed)
    transaction.mark_rollback_required()

    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
    )

    assert result.success is True
    assert transaction.status is TransactionStatus.ROLLED_BACK

    assert provider.calls == [
        (control.control_id, host)
    ]

    assert successful.status is ChangeStatus.ROLLED_BACK
    assert failed.status is ChangeStatus.FAILED


def test_rollback_uses_reverse_change_order() -> None:
    control = _load_control()
    host = "ubuntu-production-01"

    transaction = Transaction(
        transaction_id="txn-integration-003",
        host=host,
    )

    first = _successful_change(
        control_id=control.control_id,
        host=host,
        change_id="change-001",
    )
    second = _successful_change(
        control_id=control.control_id,
        host=host,
        change_id="change-002",
    )

    transaction.add_change(first)
    transaction.add_change(second)
    transaction.mark_rollback_required()

    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
    )

    assert result.success is True
    assert transaction.status is TransactionStatus.ROLLED_BACK

    assert provider.calls == [
        (control.control_id, host),
        (control.control_id, host),
    ]

    assert [change.change_id for change in transaction.changes] == [
        "change-001",
        "change-002",
    ]


def test_missing_control_fails_closed() -> None:
    control = _load_control()
    host = "ubuntu-production-01"

    transaction = Transaction(
        transaction_id="txn-integration-004",
        host=host,
    )

    change = _successful_change(
        control_id=control.control_id,
        host=host,
        change_id="change-001",
    )

    transaction.add_change(change)
    transaction.mark_rollback_required()

    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={},
    )

    assert result.success is False
    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED
    assert provider.calls == []
    assert change.status is ChangeStatus.ROLLBACK_REQUIRED


def test_empty_transaction_can_be_rolled_back() -> None:
    transaction = Transaction(
        transaction_id="txn-integration-005",
        host="ubuntu-production-01",
    )

    transaction.mark_rollback_required()

    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={},
    )

    assert result.success is True
    assert transaction.status is TransactionStatus.ROLLED_BACK
    assert provider.calls == []
