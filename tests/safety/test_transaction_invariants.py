from __future__ import annotations

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
)
from securebench.core.result import ExecutionResult, ExecutionStatus
from securebench.core.transaction import (
    ChangeRecord,
    ChangeStatus,
    Transaction,
    TransactionStatus,
)
from securebench.rollback.engine import RollbackEngine


def make_control(
    *,
    control_id: str = "TEST-1",
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control description.",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="audit.test",
        remediation="remediation.test",
        rollback="rollback.test",
        verification="verification.test",
        rollback_capability=rollback_capability,
    )


def make_change(
    *,
    control_id: str = "TEST-1",
    host: str = "test-host",
    change_id: str = "change-001",
    status: ChangeStatus = ChangeStatus.SUCCESS,
) -> ChangeRecord:
    return ChangeRecord(
        change_id=change_id,
        control_id=control_id,
        host=host,
        status=status,
        message="Test change.",
    )


class RecordingRollbackProvider:
    def __init__(
        self,
        *,
        success: bool = True,
    ) -> None:
        self.success = success
        self.calls: list[tuple[str, str, str]] = []

    def rollback(
        self,
        control,
        host: str,
        change: ChangeRecord,
    ) -> ExecutionResult:
        self.calls.append(
            (
                control.control_id,
                host,
                change.change_id,
            )
        )

        if self.success:
            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.SUCCESS,
                changed=True,
                message="Rollback completed.",
            )

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.FAILED,
            changed=False,
            message="Rollback failed.",
        )


def test_rollback_only_targets_successful_changes() -> None:
    control = make_control()

    transaction = Transaction(
        transaction_id="txn-001",
        host="test-host",
    )

    successful = make_change(
        change_id="change-success",
        status=ChangeStatus.SUCCESS,
    )
    failed = make_change(
        change_id="change-failed",
        status=ChangeStatus.FAILED,
    )
    pending = make_change(
        change_id="change-pending",
        status=ChangeStatus.PENDING,
    )

    transaction.add_change(successful)
    transaction.add_change(failed)
    transaction.add_change(pending)
    transaction.mark_rollback_required()

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
    )

    assert result.success is True
    assert provider.calls == [
        ("TEST-1", "test-host", "change-success"),
    ]

    assert successful.status is ChangeStatus.ROLLED_BACK
    assert failed.status is ChangeStatus.FAILED
    assert pending.status is ChangeStatus.PENDING


def test_rollback_uses_reverse_order() -> None:
    control = make_control()

    transaction = Transaction(
        transaction_id="txn-002",
        host="test-host",
    )

    first = make_change(change_id="change-001")
    second = make_change(change_id="change-002")
    third = make_change(change_id="change-003")

    transaction.add_change(first)
    transaction.add_change(second)
    transaction.add_change(third)
    transaction.mark_rollback_required()

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
    )

    assert result.success is True

    assert provider.calls == [
        ("TEST-1", "test-host", "change-003"),
        ("TEST-1", "test-host", "change-002"),
        ("TEST-1", "test-host", "change-001"),
    ]


def test_failed_rollback_stops_further_rollback() -> None:
    control = make_control()

    transaction = Transaction(
        transaction_id="txn-003",
        host="test-host",
    )

    first = make_change(change_id="change-001")
    second = make_change(change_id="change-002")
    third = make_change(change_id="change-003")

    transaction.add_change(first)
    transaction.add_change(second)
    transaction.add_change(third)
    transaction.mark_rollback_required()

    class FailSecondRollbackProvider(RecordingRollbackProvider):
        def rollback(
            self,
            control,
            host: str,
            change: ChangeRecord,
        ) -> ExecutionResult:
            self.calls.append(
                (
                    control.control_id,
                    host,
                    change.change_id,
                )
            )

            if change.change_id == "change-002":
                return ExecutionResult(
                    control_id=control.control_id,
                    host=host,
                    status=ExecutionStatus.FAILED,
                    changed=False,
                    message="Rollback failed.",
                )

            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.SUCCESS,
                changed=True,
                message="Rollback completed.",
            )

    provider = FailSecondRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
    )

    assert result.success is False

    assert provider.calls == [
        ("TEST-1", "test-host", "change-003"),
        ("TEST-1", "test-host", "change-002"),
    ]

    assert third.status is ChangeStatus.ROLLED_BACK
    assert second.status is ChangeStatus.ROLLBACK_REQUIRED
    assert first.status is ChangeStatus.SUCCESS
    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED


def test_unsupported_rollback_is_denied() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.UNSUPPORTED,
    )

    transaction = Transaction(
        transaction_id="txn-004",
        host="test-host",
    )

    change = make_change()
    transaction.add_change(change)
    transaction.mark_rollback_required()

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
    )

    assert result.success is False
    assert provider.calls == []
    assert change.status is ChangeStatus.ROLLBACK_REQUIRED
    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED


def test_missing_control_fails_closed() -> None:
    transaction = Transaction(
        transaction_id="txn-005",
        host="test-host",
    )

    change = make_change()
    transaction.add_change(change)
    transaction.mark_rollback_required()

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={},
    )

    assert result.success is False
    assert provider.calls == []
    assert change.status is ChangeStatus.SUCCESS
    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED


def test_empty_transaction_does_not_invoke_provider() -> None:
    transaction = Transaction(
        transaction_id="txn-006",
        host="test-host",
    )

    transaction.mark_rollback_required()

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={},
    )

    assert result.success is True
    assert provider.calls == []
    assert transaction.status is TransactionStatus.ROLLED_BACK


def test_rollback_does_not_modify_control_definition() -> None:
    control = make_control()

    transaction = Transaction(
        transaction_id="txn-007",
        host="test-host",
    )

    change = make_change()
    transaction.add_change(change)
    transaction.mark_rollback_required()

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    original_title = control.title
    original_dependencies = control.dependencies
    original_rollback = control.rollback

    engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
    )

    assert control.title == original_title
    assert control.dependencies == original_dependencies
    assert control.rollback == original_rollback