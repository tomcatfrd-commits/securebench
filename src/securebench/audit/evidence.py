"""
Audit evidence handling.

This module provides the storage model used by the audit layer to preserve
what was observed on a target system.

Evidence is intentionally separate from AuditResult:

    Evidence    = what was observed
    AuditResult = how that observation was evaluated
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from securebench.core import Evidence


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """
    A stored piece of audit evidence.

    ``evidence_id`` provides a stable reference that can later be attached
    to transaction records, reports, and rollback records.

    The Evidence fields are exposed through read-only properties so callers
    that only need audit evidence do not have to know about the storage
    wrapper.
    """

    evidence_id: str
    evidence: Evidence
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        if not isinstance(self.evidence, Evidence):
            raise TypeError("evidence must be an Evidence instance")

    @property
    def control_id(self) -> str:
        """Return the control ID associated with this evidence."""

        return self.evidence.control_id

    @property
    def host(self) -> str:
        """Return the host associated with this evidence."""

        return self.evidence.host

    @property
    def source(self) -> str:
        """Return the evidence collection source."""

        return self.evidence.source

    @property
    def observed(self) -> Any:
        """Return the observed value."""

        return self.evidence.observed

    @property
    def expected(self) -> Any:
        """Return the expected value."""

        return self.evidence.expected

    @property
    def collected_at(self) -> datetime:
        """Return the evidence collection timestamp."""

        return self.evidence.collected_at

    @property
    def details(self) -> Mapping[str, Any]:
        """Return additional evidence details."""

        return self.evidence.details


class EvidenceStore:
    """
    In-memory evidence store.

    The public storage API accepts an Evidence object and generates the
    storage identifier internally. This keeps evidence collection independent
    from persistence details.

    A persistent backend can later replace this implementation without
    changing the AuditEngine contract.
    """

    def __init__(self) -> None:
        self._records: dict[str, EvidenceRecord] = {}

    def add(
        self,
        evidence: Evidence,
        *,
        evidence_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> EvidenceRecord:
        """
        Store evidence and return its storage record.

        ``evidence_id`` is optional. When omitted, SecureBench generates a
        unique identifier. Supplying an explicit ID is supported for callers
        that need deterministic identifiers.

        Duplicate IDs are rejected rather than silently overwritten.
        """

        if not isinstance(evidence, Evidence):
            raise TypeError("evidence must be an Evidence instance")

        record_id = evidence_id or str(uuid4())

        if not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("evidence_id must not be empty")

        if record_id in self._records:
            raise ValueError(
                f"evidence ID '{record_id}' already exists"
            )

        record = EvidenceRecord(
            evidence_id=record_id,
            evidence=evidence,
            metadata=dict(metadata or {}),
        )

        self._records[record_id] = record
        return record

    def get(self, evidence_id: str) -> EvidenceRecord:
        """Return evidence by its storage ID."""

        try:
            return self._records[evidence_id]
        except KeyError as exc:
            raise KeyError(
                f"evidence ID '{evidence_id}' does not exist"
            ) from exc

    def contains(self, evidence_id: str) -> bool:
        """Return whether an evidence ID exists."""

        return evidence_id in self._records

    def all(self) -> tuple[EvidenceRecord, ...]:
        """Return all stored evidence in insertion order."""

        return tuple(self._records.values())

    def for_control(
        self,
        control_id: str,
        host: str | None = None,
    ) -> tuple[Evidence, ...]:
        """
        Return the original evidence objects belonging to a control.

        If ``host`` is supplied, results are restricted to that host.

        The storage wrapper remains an internal persistence detail.
        Callers retrieving evidence receive the exact immutable Evidence
        objects that were originally stored.
        """

        return tuple(
            record.evidence
            for record in self._records.values()
            if record.control_id == control_id
            and (host is None or record.host == host)
        )

    def clear(self) -> None:
        """Remove all in-memory evidence."""

        self._records.clear()


def create_evidence(
    *,
    control_id: str,
    host: str,
    source: str,
    observed: Any,
    expected: Any,
    details: Mapping[str, Any] | None = None,
) -> Evidence:
    """
    Construct an Evidence object with a UTC collection timestamp.

    Keeping construction here gives future persistent audit implementations
    one place to standardize evidence creation.
    """

    return Evidence(
        control_id=control_id,
        host=host,
        source=source,
        observed=observed,
        expected=expected,
        collected_at=datetime.now(timezone.utc),
        details=dict(details or {}),
    )