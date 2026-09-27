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
    """

    evidence_id: str
    evidence: Evidence
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        if not isinstance(self.evidence, Evidence):
            raise TypeError("evidence must be an Evidence instance")


class EvidenceStore:
    """
    In-memory evidence store.

    The store keeps EvidenceRecord objects internally while exposing the
    underlying Evidence objects for control/host-oriented queries.

    A persistent backend can later replace this implementation without
    changing the audit engine API.
    """

    def __init__(self) -> None:
        self._records: dict[str, EvidenceRecord] = {}

    def add(
        self,
        evidence: Evidence | str,
        evidence_value: Evidence | None = None,
        *,
        evidence_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> EvidenceRecord:
        """
        Store evidence and return its EvidenceRecord.

        Preferred form:

            store.add(evidence)

        An explicit ID may also be supplied:

            store.add(evidence, evidence_id="evidence-001")

        For backward compatibility with the previous API, this form is also
        accepted:

            store.add("evidence-001", evidence)

        If no ID is supplied, a unique ID is generated automatically.
        """

        if isinstance(evidence, str):
            if evidence_value is None:
                raise TypeError(
                    "evidence must be supplied when the first argument "
                    "is an evidence ID"
                )

            if evidence_id is not None:
                raise TypeError(
                    "evidence_id must not be supplied when the first "
                    "argument is already an evidence ID"
                )

            resolved_evidence_id = evidence
            resolved_evidence = evidence_value

        else:
            if evidence_value is not None:
                raise TypeError(
                    "evidence_value must not be supplied when the first "
                    "argument is an Evidence object"
                )

            resolved_evidence = evidence

            if not isinstance(resolved_evidence, Evidence):
                raise TypeError("evidence must be an Evidence instance")

            resolved_evidence_id = (
                evidence_id
                if evidence_id is not None
                else self._generate_evidence_id()
            )

        if not isinstance(resolved_evidence, Evidence):
            raise TypeError("evidence must be an Evidence instance")

        if not isinstance(resolved_evidence_id, str):
            raise TypeError("evidence_id must be a string")

        if not resolved_evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        if resolved_evidence_id in self._records:
            raise ValueError(
                f"evidence ID '{resolved_evidence_id}' already exists"
            )

        record = EvidenceRecord(
            evidence_id=resolved_evidence_id,
            evidence=resolved_evidence,
            metadata=dict(metadata or {}),
        )

        self._records[resolved_evidence_id] = record
        return record

    def get(self, evidence_id: str) -> EvidenceRecord:
        """Return an evidence record by ID."""

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
        """Return all stored evidence records in insertion order."""

        return tuple(self._records.values())

    def for_control(
        self,
        control_id: str,
        host: str | None = None,
    ) -> tuple[Evidence, ...]:
        """
        Return Evidence objects belonging to a control.

        If ``host`` is supplied, results are restricted to that host.

        This method deliberately returns Evidence rather than EvidenceRecord
        because callers of the audit layer care about the observed evidence,
        while the internal record ID is an implementation/storage concern.
        """

        return tuple(
            record.evidence
            for record in self._records.values()
            if record.evidence.control_id == control_id
            and (host is None or record.evidence.host == host)
        )

    def records_for_control(
        self,
        control_id: str,
        host: str | None = None,
    ) -> tuple[EvidenceRecord, ...]:
        """
        Return complete EvidenceRecord objects for a control.

        This provides access to storage metadata and evidence IDs when those
        are required by transaction/reporting/rollback layers.
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

    @staticmethod
    def _generate_evidence_id() -> str:
        """Generate a unique identifier for automatically stored evidence."""

        return f"evidence-{uuid4().hex}"


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