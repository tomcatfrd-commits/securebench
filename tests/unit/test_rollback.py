from __future__ import annotations

import pytest

from securebench.core import (
    ChangeRecord,
    ChangeStatus,
    Control,
    ControlSeverity,
    Profile,
    RollbackCapability,
    Transaction,
)
from securebench.rollback import (
    RollbackEngine,
    RollbackExecution,
)


def make_control(
    *,
    control_id: str = "TEST-001",
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test description",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="test.audit",
        remediation="test.remediate",
        rollback="test.rollback",
        verification="test.verify",
        rollback_capability=rollback_capability,
    )


def make_profile(
    *,
    allow_best_effort_rollback: bool = False,
) -> Profile:
    return Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile",
        allow_best_effort_rollback=allow_best_effort_rollback,
    )


def make_transaction() -> Transaction:
    return Transaction(
        transaction_id="txn-001",
        profile_id="test-profile",
        benchmark_id="test-benchmark",
    )


def make_change(
    *,
    change_id: str = "change-001",
    control_id: str = "TEST-001",
    host: str = "server01",
    status: ChangeStatus = ChangeStatus.SUCCESS,
) -> ChangeRecord:
    return ChangeRecord(
        change_id=change_id,
        control_id=control_id,
        host=host,
        status=status,
    )


class FakeRollbackProvider:
    def __init__(
        self,
        *,
        success: bool = True,
    ) -> None:
        self.success = success
        self.calls: list[tuple[str, str]] = []

    def rollback(
        self,
        control: Control,
        host: str,
    ) -> RollbackExecution:
        self.calls.append((control.control_id, host))

        return RollbackExecution(
            control_id=control.control_id,
            host=host,
            success=self.success,
            message=(
                "Rollback completed"
                if self.success
                else "Rollback failed"
            ),
        )


class TestRollbackEngine:
    def test_successful_control_rollback_marks_change_rolled_back(
        self,
    ) -> None:
        provider = FakeRollbackProvider()
        engine = RollbackEngine(provider=provider)

        control = make_control()
        transaction = make_transaction()
        change = make_change()

        transaction.add_change(change)

        result = engine.rollback_control(
            transaction=transaction,
            control=control,
            host="server01",
        )

        assert result.success is True
        assert result.control_id == "TEST-001"
        assert result.host == "server01"
        assert result.message == "Rollback completed"

        assert transaction.get_change("change-001").status is ChangeStatus.ROLLED_BACK
        assert provider.calls == [("TEST-001", "server01")]

    def test_failed_control_rollback_marks_change_rollback_required(
        self,
    ) -> None:
        provider = FakeRollbackProvider(success=False)
        engine = RollbackEngine(provider=provider)

        control = make_control()
        transaction = make_transaction()
        change = make_change()

        transaction.add_change(change)

        result = engine.rollback_control(
            transaction=transaction,
            control=control,
            host="server01",
        )

        assert result.success is False
        assert transaction.get_change("change-001").status is ChangeStatus.ROLLBACK_REQUIRED

    def test_unsupported_rollback_fails_closed(self) -> None:
        provider = FakeRollbackProvider()
        engine = RollbackEngine(provider=provider)

        control = make_control(
            rollback_capability=RollbackCapability.UNSUPPORTED,
        )
        transaction = make_transaction()
        change = make_change()

        transaction.add_change(change)

        result = engine.rollback_control(
            transaction=transaction,
            control=control,
            host="server01",
        )

        assert result.success is False
        assert "unsupported" in result.message.lower()
        assert provider.calls == []
        assert (
            transaction.get_change("change-001").status
            is ChangeStatus.ROLLBACK_REQUIRED
        )

    def test_best_effort_rollback_is_denied_by_default(self) -> None:
        provider = FakeRollbackProvider()
        engine = RollbackEngine(provider=provider)

        control = make_control(
            rollback_capability=RollbackCapability.BEST_EFFORT,
        )
        transaction = make_transaction()
        change = make_change()

        transaction.add_change(change)

        result = engine.rollback_control(
            transaction=transaction,
            control=control,
            host="server01",
            profile=make_profile(
                allow_best_effort_rollback=False,
            ),
        )

        assert result.success is False
        assert "best-effort" in result.message.lower()
        assert provider.calls == []

    def test_best_effort_rollback_can_be_allowed(self) -> None:
        provider = FakeRollbackProvider()
        engine = RollbackEngine(provider=provider)

        control = make_control(
            rollback_capability=RollbackCapability.BEST_EFFORT,
        )
        transaction = make_transaction()
        change = make_change()

        transaction.add_change(change)

        result = engine.rollback_control(
            transaction=transaction,
            control=control,
            host="server01",
            profile=make_profile(
                allow_best_effort_rollback=True,
            ),
        )

        assert result.success is True
        assert provider.calls == [("TEST-001", "server01")]
        assert transaction.get_change("change-001").status is ChangeStatus.ROLLED_BACK

    def test_only_successful_change_can_be_rolled_back(self) -> None:
        provider = FakeRollbackProvider()
        engine = RollbackEngine(provider=provider)

        control = make_control()
        transaction = make_transaction()

        change = make_change(status=ChangeStatus.FAILED)
        transaction.add_change(change)

        result = engine.rollback_control(
            transaction=transaction,
            control=control,
            host="server01",
        )

        assert result.success is False
        assert "status" in result.message.lower()
        assert provider.calls == []

    def test_unknown_change_fails_closed(self) -> None:
        provider = FakeRollbackProvider()
        engine = RollbackEngine(provider=provider)

        control = make_control()
        transaction = make_transaction()

        result = engine.rollback_control(
            transaction=transaction,
            control=control,
            host="server01",
        )

        assert result.success is False
        assert provider.calls == []

    def test_provider_failure_does_not_mark_change_rolled_back(self) -> None:
        provider = FakeRollbackProvider(success=False)
        engine = RollbackEngine(provider=provider)

        control = make_control()
        transaction = make_transaction()
        change = make_change()

        transaction.add_change(change)

        result = engine.rollback_control(
            transaction=transaction,
            control=control,
            host="server01",
        )

        assert result.success is False
        assert transaction.get_change("change-001").status is not ChangeStatus.ROLLED_BACK

    def test_transaction_rollback_processes_changes_in_reverse_order(
        self,
    ) -> None:
        provider = FakeRollbackProvider()
        engine = RollbackEngine(provider=provider)

        control_a = make_control(control_id="A")
        control_b = make_control(control_id="B")
        control_c = make_control(control_id="C")

        transaction = make_transaction()

        transaction.add_change(
            make_change(
                change_id="change-a",
                control_id="A",
            )
        )
        transaction.add_change(
            make_change(
                change_id="change-b",
                control_id="B",
            )
        )
        transaction.add_change(
            make_change(
                change_id="change-c",
                control_id="C",
            )
        )

        result = engine.rollback_transaction(
            transaction=transaction,
            controls={
                "A": control_a,
                "B": control_b,
                "C": control_c,
            },
        )

        assert result.success is True
        assert provider.calls == [
            ("C", "server01"),
            ("B", "server01"),
            ("A", "server01"),
        ]

        assert transaction.get_change("change-a").status is ChangeStatus.ROLLED_BACK
        assert transaction.get_change("change-b").status is ChangeStatus.ROLLED_BACK
        assert transaction.get_change("change-c").status is ChangeStatus.ROLLED_BACK

    def test_transaction_rollback_stops_after_failure(self) -> None:
        class SelectiveProvider(FakeRollbackProvider):
            def rollback(
                self,
                control: Control,
                host: str,
            ) -> RollbackExecution:
                self.calls.append((control.control_id, host))

                if control.control_id == "B":
                    return RollbackExecution(
                        control_id=control.control_id,
                        host=host,
                        success=False,
                        message="Rollback failed",
                    )

                return RollbackExecution(
                    control_id=control.control_id,
                    host=host,
                    success=True,
                    message="Rollback completed",
                )

        provider = SelectiveProvider()
        engine = RollbackEngine(provider=provider)

        controls = {
            "A": make_control(control_id="A"),
            "B": make_control(control_id="B"),
            "C": make_control(control_id="C"),
        }

        transaction = make_transaction()

        transaction.add_change(
            make_change(
                change_id="change-a",
                control_id="A",
            )
        )
        transaction.add_change(
            make_change(
                change_id="change-b",
                control_id="B",
            )
        )
        transaction.add_change(
            make_change(
                change_id="change-c",
                control_id="C",
            )
        )

        result = engine.rollback_transaction(
            transaction=transaction,
            controls=controls,
        )

        assert result.success is False

        assert provider.calls == [
            ("C", "server01"),
            ("B", "server01"),
        ]

        assert transaction.get_change("change-c").status is ChangeStatus.ROLLED_BACK
        assert transaction.get_change("change-b").status is ChangeStatus.ROLLBACK_REQUIRED
        assert transaction.get_change("change-a").status is ChangeStatus.SUCCESS

    def test_missing_control_definition_fails_closed(self) -> None:
        provider = FakeRollbackProvider()
        engine = RollbackEngine(provider=provider)

        transaction = make_transaction()
        transaction.add_change(
            make_change(
                control_id="MISSING",
            )
        )

        result = engine.rollback_transaction(
            transaction=transaction,
            controls={},
        )

        assert result.success is False
        assert provider.calls == []
        assert transaction.get_change("change-001").status is ChangeStatus.ROLLBACK_REQUIRED


class TestRollbackExecution:
    def test_successful_execution(self) -> None:
        execution = RollbackExecution(
            control_id="TEST-001",
            host="server01",
            success=True,
            message="Rollback completed",
        )

        assert execution.success is True
        assert execution.control_id == "TEST-001"
        assert execution.host == "server01"

    def test_failed_execution(self) -> None:
        execution = RollbackExecution(
            control_id="TEST-001",
            host="server01",
            success=False,
            message="Rollback failed",
        )

        assert execution.success is False

    def test_execution_requires_message(self) -> None:
        with pytest.raises(ValueError):
            RollbackExecution(
                control_id="TEST-001",
                host="server01",
                success=True,
                message="",
            )


def test_rollback_rejects_different_control_definition() -> None:
    control = Control(
        control_id="TEST-001",
        benchmark_id="test-benchmark",
        benchmark_version="2.0.0",
        definition_digest="a" * 64,
        title="Test control",
        description="Test description",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="test.audit",
        remediation="test.remediate",
        rollback="test.rollback",
        verification="test.verify",
        rollback_capability=RollbackCapability.GUARANTEED,
    )
    transaction = make_transaction()
    change = ChangeRecord(
        change_id="change-001",
        control_id=control.control_id,
        host="server01",
        benchmark_id=control.benchmark_id,
        benchmark_version=control.benchmark_version,
        control_digest="b" * 64,
        status=ChangeStatus.SUCCESS,
    )
    transaction.add_change(change)
    provider = FakeRollbackProvider()

    result = RollbackEngine(provider).rollback_control(
        control=control,
        host="server01",
        transaction=transaction,
    )

    assert result.success is False
    assert "definition" in result.message.lower()
    assert provider.calls == []
    assert change.status is ChangeStatus.ROLLBACK_REQUIRED
