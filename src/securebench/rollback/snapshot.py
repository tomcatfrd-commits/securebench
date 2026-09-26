from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping, Protocol


class SnapshotCapability(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class Snapshot:
    snapshot_id: str
    host: str
    provider: str
    capability: SnapshotCapability
    details: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot_id, str) or not self.snapshot_id.strip():
            raise ValueError("snapshot_id must be a non-empty string")

        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("host must be a non-empty string")

        if not isinstance(self.provider, str) or not self.provider.strip():
            raise ValueError("provider must be a non-empty string")

        if not isinstance(self.capability, SnapshotCapability):
            raise TypeError("capability must be a SnapshotCapability")

        if not isinstance(self.details, Mapping):
            raise TypeError("details must be a mapping")


class SnapshotProvider(Protocol):
    @property
    def capability(self) -> SnapshotCapability:
        ...

    def create(
        self,
        host: str,
        context: Mapping[str, object],
    ) -> Snapshot:
        ...

    def restore(
        self,
        snapshot: Snapshot,
        host: str,
        context: Mapping[str, object],
    ) -> None:
        ...


class UnsupportedSnapshotProvider:
    @property
    def capability(self) -> SnapshotCapability:
        return SnapshotCapability.UNSUPPORTED

    def create(
        self,
        host: str,
        context: Mapping[str, object],
    ) -> Snapshot:
        raise RuntimeError(
            "Snapshot creation is unsupported by the configured provider."
        )

    def restore(
        self,
        snapshot: Snapshot,
        host: str,
        context: Mapping[str, object],
    ) -> None:
        raise RuntimeError(
            "Snapshot restoration is unsupported by the configured provider."
        )