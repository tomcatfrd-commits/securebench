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

from securebench.core import Evidence


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """
    A stored piece of audit evidence.

    ``evidence_id`` provides a stable reference that can later be attached
    to transaction records, reports, and rollback records.
    """

    evidence_id: str
    evidence: Evidence
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence_id must not be empty")


class EvidenceStore:
    """
    In-memory evidence store.

    This is intentionally a small abstraction.

    The first implementation can use memory while the architecture is being
    developed. A persistent backend can later store evidence in JSON, SQLite,
    PostgreSQL, or another database without changing the audit engine API.
    """

    def __init__(self) -> None:
        self._records: dict[str, EvidenceRecord] = {}

    def add(
        self,
        evidence_id: str,
        evidence: Evidence,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> EvidenceRecord:
        """
        Store evidence under a unique ID.

        Duplicate IDs are rejected rather than silently overwritten.
        """

        if evidence_id in self._records:
            raise ValueError(
                f"evidence ID '{evidence_id}' already exists"
            )

        record = EvidenceRecord(
            evidence_id=evidence_id,
            evidence=evidence,
            metadata=dict(metadata or {}),
        )

        self._records[evidence_id] = record
        return record

    def get(self, evidence_id: str) -> EvidenceRecord:
        """Return evidence by ID."""

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
    ) -> tuple[EvidenceRecord, ...]:
        """
        Return evidence belonging to a control.

        If ``host`` is supplied, results are restricted to that host.
        """

        return tuple(
            record
            for record in self._records.values()
            if record.evidence.control_id == control_id
            and (host is None or record.evidence.host == host)
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