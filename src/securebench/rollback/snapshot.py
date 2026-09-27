from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class SnapshotCapability(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class Snapshot:
    snapshot_id: str
    host: str
    transaction_id: str
    capability: SnapshotCapability = SnapshotCapability.SUPPORTED

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot_id, str) or not self.snapshot_id.strip():
            raise ValueError("snapshot_id must be a non-empty string")

        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("host must be a non-empty string")

        if not isinstance(self.transaction_id, str) or not self.transaction_id.strip():
            raise ValueError("transaction_id must be a non-empty string")

        if not isinstance(self.capability, SnapshotCapability):
            raise TypeError("capability must be a SnapshotCapability")


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
        return SnapshotCapability.UNSUPPORTED

    def create(
        self,
        host: str,
        transaction_id: str,
    ) -> Snapshot:
        raise NotImplementedError(
            "Snapshot creation is unsupported by the configured provider."
        )

    def restore(
        self,
        snapshot: Snapshot,
    ) -> None:
        raise NotImplementedError(
            "Snapshot restoration is unsupported by the configured provider."
        )