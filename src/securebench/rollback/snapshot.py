from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from securebench.core.exceptions import RollbackError


class SnapshotCapability(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class Snapshot:
    """
    Immutable record of a pre-change system snapshot.

    ``transaction_id`` is used by the transaction coordinator.
    ``provider`` / ``location`` / ``metadata`` support operational
    snapshot backends and safety-boundary tests.
    """

    snapshot_id: str
    host: str
    transaction_id: str = "unknown"
    provider: str = "unknown"
    location: str = "/snapshots"
    capability: SnapshotCapability = SnapshotCapability.SUPPORTED
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot_id, str) or not self.snapshot_id.strip():
            raise ValueError("snapshot_id must be a non-empty string")

        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("host must be a non-empty string")

        if not isinstance(self.transaction_id, str) or not self.transaction_id.strip():
            raise ValueError("transaction_id must be a non-empty string")

        if not isinstance(self.provider, str) or not self.provider.strip():
            raise ValueError("provider must be a non-empty string")

        if not isinstance(self.location, str) or not self.location.strip():
            raise ValueError("location must be a non-empty string")

        if not isinstance(self.capability, SnapshotCapability):
            raise TypeError("capability must be a SnapshotCapability")

        if not isinstance(self.metadata, Mapping):
            raise TypeError("metadata must be a mapping")

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata)),
        )


class SnapshotProvider(Protocol):
    @property
    def capability(self) -> SnapshotCapability:
        ...

    def create(
        self,
        host: str,
        transaction_id: str,
    ) -> Snapshot:
        ...

    def restore(
        self,
        snapshot: Snapshot,
    ) -> None:
        ...


class UnsupportedSnapshotProvider:
    """
    Explicitly unsupported snapshot backend.

    Callers must treat the absence of snapshot support as a hard failure
    for any workflow that requires pre-change snapshots.
    """

    @property
    def capability(self) -> SnapshotCapability:
        """Report that this provider does not support snapshots."""
        return SnapshotCapability.UNSUPPORTED

    def create(
        self,
        host: str,
        transaction_id: str = "",
    ) -> Snapshot:
        raise RollbackError(
            "Snapshot creation is unsupported by the configured provider."
        )

    def restore(
        self,
        snapshot: Snapshot,
    ) -> None:
        raise RollbackError(
            "Snapshot restoration is unsupported by the configured provider."
        )

    def delete(
        self,
        snapshot: Snapshot,
    ) -> None:
        raise RollbackError(
            "Snapshot deletion is unsupported by the configured provider."
        )

    # ------------------------------------------------------------------
    # Aliases expected by safety-boundary tests
    # ------------------------------------------------------------------

    def create_snapshot(self, host: str, transaction_id: str = "") -> Snapshot:
        return self.create(host=host, transaction_id=transaction_id)

    def restore_snapshot(self, snapshot: Snapshot) -> None:
        self.restore(snapshot)

    def delete_snapshot(self, snapshot: Snapshot) -> None:
        self.delete(snapshot)