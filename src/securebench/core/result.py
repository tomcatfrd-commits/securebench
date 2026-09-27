"""
Result and evidence domain models.

These objects represent what SecureBench learned or what happened during
audit, remediation, and verification.

They intentionally contain data rather than execution logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping


class ComplianceStatus(StrEnum):
    """Result of evaluating a control against its required state."""

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    UNKNOWN = "unknown"


class ExecutionStatus(StrEnum):
    """Result of an attempted remediation or rollback operation."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_RUN = "not_run"


@dataclass(frozen=True, slots=True)
class Evidence:
    """
    Immutable evidence collected from a target system.

    Evidence should be sufficient for a human or another component to
    understand why a control received its result.

    Parameters
    ----------
    control_id:
        Control that produced this evidence.

    host:
        Target host from which the evidence was collected.

    source:
        Name of the audit mechanism that produced the evidence.

    observed:
        Raw or normalized observed value.

    expected:
        Value/state required by the control.

    collected_at:
        UTC timestamp when the evidence was collected.

    details:
        Optional structured information supporting the result.
    """

    control_id: str
    host: str
    source: str
    observed: Any
    expected: Any
    collected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.control_id.strip():
            raise ValueError("control_id must not be empty")

        if not self.host.strip():
            raise ValueError("host must not be empty")

        if not self.source.strip():
            raise ValueError("source must not be empty")


@dataclass(frozen=True, slots=True)
class AuditResult:
    """
    Immutable result of auditing one control on one host.

    ``collected_at`` identifies when the audit result itself was produced.
    Individual evidence objects retain their own collection timestamps.
    """

    control_id: str
    host: str
    status: ComplianceStatus
    evidence: tuple[Evidence, ...] = ()
    message: str = ""
    collected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def compliant(self) -> bool:
        """Return True only when the control explicitly passed."""

        return self.status is ComplianceStatus.PASS


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """
    Result of independently verifying the state after remediation.
    """

    control_id: str
    host: str
    status: ComplianceStatus
    evidence: tuple[Evidence, ...] = ()
    message: str = ""
    collected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def verified(self) -> bool:
        """Return True only when verification explicitly passed."""

        return self.status is ComplianceStatus.PASS


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """
    Result of an execution operation.

    ``changed`` indicates that the execution backend reports an actual
    system change. It does not mean that the security control is compliant;
    verification remains authoritative for that decision.
    """

    control_id: str
    host: str
    status: ExecutionStatus
    changed: bool = False
    message: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        """Return whether the execution operation completed successfully."""

        return self.status is ExecutionStatus.SUCCESS