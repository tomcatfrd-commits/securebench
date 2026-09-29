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
from securebench.rollback.engine import (
    RollbackEngine,
    RollbackExecution,
)


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


def make_transaction(
    transaction_id: str = "txn-001",
) -> Transaction:
    return Transaction(
        transaction_id=transaction_id,
        profile_id="test-profile",
        benchmark_id="test-benchmark",
        host="test-host",
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
    def __init__(self, *, success: bool = True) -> None:
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

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=(
                ExecutionStatus.SUCCESS
                if self.success
                else ExecutionStatus.FAILED
            ),
            changed=self.success,
            message=(
                "Rollback completed."
                if self.success
                else "Rollback failed."
            ),
        )


def test_rollback_only_targets_successful_changes() -> None:
    control = make_control()
    transaction = make_transaction()

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
    assert transaction.status is TransactionStatus.ROLLED_BACK


def test_rollback_uses_reverse_change_order() -> None:
    control = make_control()
    transaction = make_transaction()

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

    assert all(
        change.status is ChangeStatus.ROLLED_BACK
        for change in transaction.changes
    )


def test_failed_rollback_stops_further_rollback() -> None:
    control = make_control()
    transaction = make_transaction()

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


def test_unsupported_rollback_fails_closed_without_provider_call() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.UNSUPPORTED,
    )
    transaction = make_transaction()

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


def test_best_effort_rollback_requires_profile_permission() -> None:
    from securebench.core.profile import Profile

    control = make_control(
        rollback_capability=RollbackCapability.BEST_EFFORT,
    )
    transaction = make_transaction()

    change = make_change()
    transaction.add_change(change)
    transaction.mark_rollback_required()

    profile = Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        allow_best_effort_rollback=False,
    )

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
        profile=profile,
    )

    assert result.success is False
    assert provider.calls == []
    assert change.status is ChangeStatus.SUCCESS
    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED


def test_best_effort_rollback_can_execute_when_profile_allows_it() -> None:
    from securebench.core.profile import Profile

    control = make_control(
        rollback_capability=RollbackCapability.BEST_EFFORT,
    )
    transaction = make_transaction()

    change = make_change()
    transaction.add_change(change)
    transaction.mark_rollback_required()

    profile = Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        allow_best_effort_rollback=True,
    )

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={control.control_id: control},
        profile=profile,
    )

    assert result.success is True
    assert provider.calls == [
        ("TEST-1", "test-host", "change-001"),
    ]
    assert change.status is ChangeStatus.ROLLED_BACK
    assert transaction.status is TransactionStatus.ROLLED_BACK


def test_missing_control_fails_closed() -> None:
    transaction = make_transaction()

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
    assert change.status is ChangeStatus.ROLLBACK_REQUIRED
    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED


def test_empty_transaction_is_successfully_rolled_back() -> None:
    transaction = make_transaction()
    transaction.mark_rollback_required()

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_transaction(
        transaction=transaction,
        controls={},
    )

    assert result.success is True
    assert result.executions == ()
    assert provider.calls == []
    assert transaction.status is TransactionStatus.ROLLED_BACK


def test_missing_change_fails_closed() -> None:
    control = make_control()
    transaction = make_transaction()

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_control(
        control=control,
        host="test-host",
        transaction=transaction,
    )

    assert result.success is False
    assert result.control_id == control.control_id
    assert result.host == "test-host"
    assert provider.calls == []


def test_non_successful_change_cannot_be_rolled_back() -> None:
    control = make_control()
    transaction = make_transaction()

    change = make_change(status=ChangeStatus.FAILED)
    transaction.add_change(change)
    transaction.mark_rollback_required()

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_control(
        control=control,
        host="test-host",
        transaction=transaction,
    )

    assert result.success is False
    assert provider.calls == []
    assert change.status is ChangeStatus.FAILED


def test_provider_failure_marks_change_as_rollback_required() -> None:
    control = make_control()
    transaction = make_transaction()

    change = make_change()
    transaction.add_change(change)
    transaction.mark_rollback_required()

    provider = RecordingRollbackProvider(success=False)
    engine = RollbackEngine(provider)

    result = engine.rollback_control(
        control=control,
        host="test-host",
        transaction=transaction,
    )

    assert result.success is False
    assert change.status is ChangeStatus.ROLLBACK_REQUIRED
    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED


def test_provider_exception_marks_change_as_rollback_required() -> None:
    control = make_control()
    transaction = make_transaction()

    change = make_change()
    transaction.add_change(change)
    transaction.mark_rollback_required()

    class RaisingProvider:
        def rollback(
            self,
            control,
            host: str,
            change: ChangeRecord,
        ) -> ExecutionResult:
            raise RuntimeError("rollback backend failure")

    engine = RollbackEngine(RaisingProvider())

    result = engine.rollback_control(
        control=control,
        host="test-host",
        transaction=transaction,
    )

    assert result.success is False
    assert "rollback backend failure" in result.message
    assert change.status is ChangeStatus.ROLLBACK_REQUIRED


def test_rollback_result_normalizes_boolean_success() -> None:
    control = make_control()
    transaction = make_transaction()

    change = make_change()
    transaction.add_change(change)

    class BooleanProvider:
        def rollback(self, control, host: str, change: ChangeRecord) -> bool:
            return True

    engine = RollbackEngine(BooleanProvider())

    result = engine.rollback_control(
        control=control,
        host="test-host",
        transaction=transaction,
    )

    assert isinstance(result, RollbackExecution)
    assert result.success is True
    assert result.succeeded is True
    assert change.status is ChangeStatus.ROLLED_BACK


def test_rollback_result_normalizes_boolean_failure() -> None:
    control = make_control()
    transaction = make_transaction()

    change = make_change()
    transaction.add_change(change)

    class BooleanProvider:
        def rollback(self, control, host: str, change: ChangeRecord) -> bool:
            return False

    engine = RollbackEngine(BooleanProvider())

    result = engine.rollback_control(
        control=control,
        host="test-host",
        transaction=transaction,
    )

    assert result.success is False
    assert result.succeeded is False
    assert change.status is ChangeStatus.ROLLBACK_REQUIRED


def test_explicit_change_is_rolled_back() -> None:
    control = make_control()
    transaction = make_transaction()

    first = make_change(change_id="change-001")
    second = make_change(change_id="change-002")

    transaction.add_change(first)
    transaction.add_change(second)

    provider = RecordingRollbackProvider()
    engine = RollbackEngine(provider)

    result = engine.rollback_control(
        control=control,
        host="test-host",
        transaction=transaction,
        change=second,
    )

    assert result.success is True
    assert provider.calls == [
        ("TEST-1", "test-host", "change-002"),
    ]
    assert second.status is ChangeStatus.ROLLED_BACK
    assert first.status is ChangeStatus.SUCCESS


def test_rollback_execution_validates_identity() -> None:
    try:
        RollbackExecution(
            control_id="",
            host="test-host",
            success=True,
            message="Completed.",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Empty control_id must be rejected")

    try:
        RollbackExecution(
            control_id="TEST-1",
            host="",
            success=True,
            message="Completed.",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Empty host must be rejected")

    try:
        RollbackExecution(
            control_id="TEST-1",
            host="test-host",
            success=True,
            message="",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Empty message must be rejected")