from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.transaction import (
    ChangeRecord,
    ChangeStatus,
    Transaction,
    TransactionStatus,
)
from securebench.rollback.engine import RollbackEngine
from securebench.rollback.snapshot import (
    Snapshot,
    SnapshotCapability,
)
from securebench.rollback.transaction import (
    TransactionRollbackCoordinator,
)


def make_control(
    control_id: str = "TEST-1",
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control description",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="test.audit",
        remediation="test.remediate",
        rollback="test.rollback",
        verification="test.verify",
        rollback_capability=rollback_capability,
        metadata={
            "safety": {
                "default": SafetyClassification.SAFE.value,
                "prechecks": (),
            },
            "requirements": {
                "setting": "expected",
            },
        },
    )


def make_change(
    change_id: str,
    control_id: str,
    host: str = "server01",
    status: ChangeStatus = ChangeStatus.SUCCESS,
) -> ChangeRecord:
    return ChangeRecord(
        change_id=change_id,
        control_id=control_id,
        host=host,
        status=status,
        before={"value": "old"},
        after={"value": "new"},
        rollback_data={"value": "old"},
    )


@dataclass
class FakeRollbackProvider:
    succeed: bool = True
    calls: list[tuple[str, str]] = field(default_factory=list)

    def rollback(
        self,
        control: Control,
        host: str,
        change: ChangeRecord,
    ):
        self.calls.append((control.control_id, host))

        return self.succeed


@dataclass
class FakeSnapshotProvider:
    capability: SnapshotCapability = SnapshotCapability.SUPPORTED
    snapshots: list[Snapshot] = field(default_factory=list)
    create_calls: list[str] = field(default_factory=list)
    restore_calls: list[str] = field(default_factory=list)

    def create(self, host: str, transaction_id: str) -> Snapshot:
        self.create_calls.append(host)

        snapshot = Snapshot(
            snapshot_id=f"snapshot-{len(self.snapshots) + 1}",
            host=host,
            transaction_id=transaction_id,
            capability=self.capability,
        )

        self.snapshots.append(snapshot)
        return snapshot

    def restore(self, snapshot: Snapshot) -> bool:
        self.restore_calls.append(snapshot.snapshot_id)
        return True


def test_coordinator_rolls_back_transaction_in_reverse_order() -> None:
    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider=provider)
    coordinator = TransactionRollbackCoordinator(
        rollback_engine=engine,
    )

    transaction = Transaction(transaction_id="tx-001")

    transaction.add_change(
        make_change("change-001", "TEST-1")
    )
    transaction.add_change(
        make_change("change-002", "TEST-2")
    )
    transaction.add_change(
        make_change("change-003", "TEST-3")
    )

    controls = {
        "TEST-1": make_control("TEST-1"),
        "TEST-2": make_control("TEST-2"),
        "TEST-3": make_control("TEST-3"),
    }

    result = coordinator.rollback(
        transaction=transaction,
        controls=controls,
    )

    assert result.success is True

    assert provider.calls == [
        ("TEST-3", "server01"),
        ("TEST-2", "server01"),
        ("TEST-1", "server01"),
    ]

    assert transaction.status is TransactionStatus.ROLLED_BACK


def test_coordinator_rolls_back_only_successful_changes() -> None:
    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider=provider)
    coordinator = TransactionRollbackCoordinator(
        rollback_engine=engine,
    )

    transaction = Transaction(transaction_id="tx-002")

    transaction.add_change(
        make_change(
            "change-001",
            "TEST-1",
            status=ChangeStatus.SUCCESS,
        )
    )
    transaction.add_change(
        make_change(
            "change-002",
            "TEST-2",
            status=ChangeStatus.FAILED,
        )
    )

    controls = {
        "TEST-1": make_control("TEST-1"),
        "TEST-2": make_control("TEST-2"),
    }

    result = coordinator.rollback(
        transaction=transaction,
        controls=controls,
    )

    assert result.success is True
    assert provider.calls == [
        ("TEST-1", "server01"),
    ]


def test_coordinator_stops_when_rollback_fails() -> None:
    provider = FakeRollbackProvider(succeed=False)
    engine = RollbackEngine(provider=provider)
    coordinator = TransactionRollbackCoordinator(
        rollback_engine=engine,
    )

    transaction = Transaction(transaction_id="tx-003")

    transaction.add_change(
        make_change("change-001", "TEST-1")
    )
    transaction.add_change(
        make_change("change-002", "TEST-2")
    )

    controls = {
        "TEST-1": make_control("TEST-1"),
        "TEST-2": make_control("TEST-2"),
    }

    result = coordinator.rollback(
        transaction=transaction,
        controls=controls,
    )

    assert result.success is False
    assert provider.calls == [
        ("TEST-2", "server01"),
    ]

    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED


def test_coordinator_fails_closed_for_missing_control() -> None:
    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider=provider)
    coordinator = TransactionRollbackCoordinator(
        rollback_engine=engine,
    )

    transaction = Transaction(transaction_id="tx-004")

    transaction.add_change(
        make_change("change-001", "UNKNOWN-CONTROL")
    )

    with pytest.raises(KeyError):
        coordinator.rollback(
            transaction=transaction,
            controls={},
        )

    assert provider.calls == []


def test_coordinator_handles_empty_transaction() -> None:
    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider=provider)
    coordinator = TransactionRollbackCoordinator(
        rollback_engine=engine,
    )

    transaction = Transaction(transaction_id="tx-005")

    result = coordinator.rollback(
        transaction=transaction,
        controls={},
    )

    assert result.success is True
    assert provider.calls == []


def test_coordinator_does_not_rollback_unsupported_control() -> None:
    provider = FakeRollbackProvider()
    engine = RollbackEngine(provider=provider)
    coordinator = TransactionRollbackCoordinator(
        rollback_engine=engine,
    )

    transaction = Transaction(transaction_id="tx-006")

    transaction.add_change(
        make_change("change-001", "TEST-1")
    )

    controls = {
        "TEST-1": make_control(
            "TEST-1",
            rollback_capability=RollbackCapability.UNSUPPORTED,
        ),
    }

    result = coordinator.rollback(
        transaction=transaction,
        controls=controls,
    )

    assert result.success is False
    assert provider.calls == []


def test_snapshot_provider_creates_snapshot() -> None:
    provider = FakeSnapshotProvider()

    snapshot = provider.create(
        host="server01",
        transaction_id="tx-007",
    )

    assert snapshot.snapshot_id == "snapshot-1"
    assert snapshot.host == "server01"
    assert snapshot.transaction_id == "tx-007"
    assert snapshot.capability is SnapshotCapability.SUPPORTED

    assert provider.create_calls == ["server01"]


def test_snapshot_provider_restores_snapshot() -> None:
    provider = FakeSnapshotProvider()

    snapshot = provider.create(
        host="server01",
        transaction_id="tx-008",
    )

    restored = provider.restore(snapshot)

    assert restored is True
    assert provider.restore_calls == [
        snapshot.snapshot_id,
    ]


def test_snapshot_is_immutable() -> None:
    provider = FakeSnapshotProvider()

    snapshot = provider.create(
        host="server01",
        transaction_id="tx-009",
    )

    with pytest.raises(AttributeError):
        snapshot.host = "server02"  # type: ignore[misc]


def test_unsupported_snapshot_capability_is_preserved() -> None:
    provider = FakeSnapshotProvider(
        capability=SnapshotCapability.UNSUPPORTED,
    )

    snapshot = provider.create(
        host="server01",
        transaction_id="tx-010",
    )

    assert snapshot.capability is SnapshotCapability.UNSUPPORTED