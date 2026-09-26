from __future__ import annotations

import pytest

from securebench.rollback.snapshot import (
    Snapshot,
    SnapshotCapability,
    UnsupportedSnapshotProvider,
)


def make_snapshot(
    snapshot_id: str = "snapshot-001",
    host: str = "server01",
    transaction_id: str = "tx-001",
    capability: SnapshotCapability = SnapshotCapability.SUPPORTED,
) -> Snapshot:
    return Snapshot(
        snapshot_id=snapshot_id,
        host=host,
        transaction_id=transaction_id,
        capability=capability,
    )


def test_snapshot_supported_capability() -> None:
    snapshot = make_snapshot()

    assert snapshot.snapshot_id == "snapshot-001"
    assert snapshot.host == "server01"
    assert snapshot.transaction_id == "tx-001"
    assert snapshot.capability is SnapshotCapability.SUPPORTED


def test_snapshot_unsupported_capability() -> None:
    snapshot = make_snapshot(
        capability=SnapshotCapability.UNSUPPORTED,
    )

    assert snapshot.capability is SnapshotCapability.UNSUPPORTED


def test_snapshot_is_immutable() -> None:
    snapshot = make_snapshot()

    with pytest.raises(AttributeError):
        snapshot.host = "server02"  # type: ignore[misc]


def test_snapshot_is_immutable_for_all_fields() -> None:
    snapshot = make_snapshot()

    with pytest.raises(AttributeError):
        snapshot.snapshot_id = "snapshot-002"  # type: ignore[misc]

    with pytest.raises(AttributeError):
        snapshot.transaction_id = "tx-002"  # type: ignore[misc]

    with pytest.raises(AttributeError):
        snapshot.capability = SnapshotCapability.UNSUPPORTED  # type: ignore[misc]


def test_snapshot_requires_non_empty_snapshot_id() -> None:
    with pytest.raises(ValueError):
        make_snapshot(snapshot_id="")


def test_snapshot_requires_non_empty_host() -> None:
    with pytest.raises(ValueError):
        make_snapshot(host="")


def test_snapshot_requires_non_empty_transaction_id() -> None:
    with pytest.raises(ValueError):
        make_snapshot(transaction_id="")


def test_snapshot_rejects_invalid_capability() -> None:
    with pytest.raises(TypeError):
        Snapshot(
            snapshot_id="snapshot-001",
            host="server01",
            transaction_id="tx-001",
            capability="supported",  # type: ignore[arg-type]
        )


def test_snapshot_capability_values_are_stable() -> None:
    assert SnapshotCapability.SUPPORTED.value == "supported"
    assert SnapshotCapability.UNSUPPORTED.value == "unsupported"


def test_unsupported_snapshot_provider_is_explicitly_unsupported() -> None:
    provider = UnsupportedSnapshotProvider()

    assert provider.capability is SnapshotCapability.UNSUPPORTED


def test_unsupported_snapshot_provider_create_fails_closed() -> None:
    provider = UnsupportedSnapshotProvider()

    with pytest.raises(NotImplementedError):
        provider.create(
            host="server01",
            transaction_id="tx-001",
        )


def test_unsupported_snapshot_provider_restore_fails_closed() -> None:
    provider = UnsupportedSnapshotProvider()
    snapshot = make_snapshot(
        capability=SnapshotCapability.UNSUPPORTED,
    )

    with pytest.raises(NotImplementedError):
        provider.restore(snapshot)