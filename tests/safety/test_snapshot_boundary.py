from __future__ import annotations

import pytest

from securebench.core.exceptions import RollbackError
from securebench.rollback.snapshot import (
    Snapshot,
    SnapshotCapability,
    UnsupportedSnapshotProvider,
)


def make_snapshot() -> Snapshot:
    return Snapshot(
        snapshot_id="snapshot-001",
        host="test-host",
        provider="test-provider",
        location="/snapshots/test",
    )


def test_snapshot_capability_values_are_distinct() -> None:
    assert SnapshotCapability.SUPPORTED.value == "supported"
    assert SnapshotCapability.UNSUPPORTED.value == "unsupported"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("snapshot_id", ""),
        ("host", ""),
        ("provider", ""),
        ("location", ""),
    ),
)
def test_snapshot_requires_non_empty_identity_fields(field: str, value: str) -> None:
    values = {
        "snapshot_id": "snapshot-001",
        "host": "test-host",
        "provider": "test-provider",
        "location": "/snapshots/test",
    }
    values[field] = value

    with pytest.raises(ValueError):
        Snapshot(**values)


def test_snapshot_is_immutable() -> None:
    snapshot = make_snapshot()

    with pytest.raises(AttributeError):
        snapshot.snapshot_id = "changed"  # type: ignore[misc]


def test_snapshot_metadata_is_preserved_and_immutable() -> None:
    metadata = {"filesystem": "root", "size": "20G"}
    snapshot = Snapshot(
        snapshot_id="snapshot-001",
        host="test-host",
        provider="test-provider",
        location="/snapshots/test",
        metadata=metadata,
    )
    metadata["size"] = "40G"

    assert dict(snapshot.metadata) == {"filesystem": "root", "size": "20G"}
    with pytest.raises(TypeError):
        snapshot.metadata["size"] = "40G"  # type: ignore[index]


def test_unsupported_snapshot_provider_reports_unsupported_capability() -> None:
    provider = UnsupportedSnapshotProvider()

    assert provider.capability is SnapshotCapability.UNSUPPORTED


def test_unsupported_snapshot_provider_operations_fail_closed() -> None:
    provider = UnsupportedSnapshotProvider()
    snapshot = make_snapshot()

    operations = (
        lambda: provider.create_snapshot("test-host"),
        lambda: provider.restore_snapshot(snapshot),
        lambda: provider.delete_snapshot(snapshot),
    )

    for operation in operations:
        with pytest.raises(RollbackError):
            operation()
