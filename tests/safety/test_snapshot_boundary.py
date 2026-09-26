from __future__ import annotations

import pytest

from securebench.core.exceptions import RollbackError
from securebench.rollback.snapshot import (
    Snapshot,
    SnapshotCapability,
    UnsupportedSnapshotProvider,
)


def test_snapshot_capability_values_are_distinct() -> None:
    assert SnapshotCapability.SUPPORTED.value == "supported"
    assert SnapshotCapability.UNSUPPORTED.value == "unsupported"


def test_snapshot_requires_identity() -> None:
    with pytest.raises(ValueError):
        Snapshot(
            snapshot_id="",
            host="test-host",
            provider="test-provider",
            location="/snapshots/test",
        )


def test_snapshot_requires_host() -> None:
    with pytest.raises(ValueError):
        Snapshot(
            snapshot_id="snapshot-001",
            host="",
            provider="test-provider",
            location="/snapshots/test",
        )


def test_snapshot_requires_provider() -> None:
    with pytest.raises(ValueError):
        Snapshot(
            snapshot_id="snapshot-001",
            host="test-host",
            provider="",
            location="/snapshots/test",
        )


def test_snapshot_requires_location() -> None:
    with pytest.raises(ValueError):
        Snapshot(
            snapshot_id="snapshot-001",
            host="test-host",
            provider="test-provider",
            location="",
        )


def test_snapshot_is_immutable() -> None:
    snapshot = Snapshot(
        snapshot_id="snapshot-001",
        host="test-host",
        provider="test-provider",
        location="/snapshots/test",
    )

    with pytest.raises(AttributeError):
        snapshot.snapshot_id = "changed"  # type: ignore[misc]

    with pytest.raises(AttributeError):
        snapshot.location = "/different/location"  # type: ignore[misc]


def test_snapshot_metadata_is_optional() -> None:
    snapshot = Snapshot(
        snapshot_id="snapshot-001",
        host="test-host",
        provider="test-provider",
        location="/snapshots/test",
    )

    assert snapshot.metadata == {}


def test_snapshot_metadata_is_preserved() -> None:
    snapshot = Snapshot(
        snapshot_id="snapshot-001",
        host="test-host",
        provider="test-provider",
        location="/snapshots/test",
        metadata={
            "filesystem": "root",
            "size": "20G",
        },
    )

    assert snapshot.metadata["filesystem"] == "root"
    assert snapshot.metadata["size"] == "20G"


def test_unsupported_snapshot_provider_reports_unsupported_capability() -> None:
    provider = UnsupportedSnapshotProvider()

    assert provider.capability() is SnapshotCapability.UNSUPPORTED


def test_unsupported_snapshot_provider_fails_closed() -> None:
    provider = UnsupportedSnapshotProvider()

    with pytest.raises(RollbackError):
        provider.create_snapshot("test-host")


def test_unsupported_snapshot_provider_cannot_restore_snapshot() -> None:
    provider = UnsupportedSnapshotProvider()

    snapshot = Snapshot(
        snapshot_id="snapshot-001",
        host="test-host",
        provider="unsupported",
        location="/snapshots/test",
    )

    with pytest.raises(RollbackError):
        provider.restore_snapshot(snapshot)


def test_unsupported_snapshot_provider_cannot_delete_snapshot() -> None:
    provider = UnsupportedSnapshotProvider()

    snapshot = Snapshot(
        snapshot_id="snapshot-001",
        host="test-host",
        provider="unsupported",
        location="/snapshots/test",
    )

    with pytest.raises(RollbackError):
        provider.delete_snapshot(snapshot)


def test_snapshot_provider_does_not_claim_support_without_implementation() -> None:
    provider = UnsupportedSnapshotProvider()

    assert provider.capability() is SnapshotCapability.UNSUPPORTED