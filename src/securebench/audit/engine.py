from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from securebench.core.control import Control
from securebench.core.result import AuditResult, ComplianceStatus, Evidence

from .evidence import EvidenceStore


class AuditProvider(Protocol):
    """Backend capable of auditing one control on one host."""

    def audit(self, control: Control, host: str) -> AuditResult:
        ...


@dataclass(frozen=True, slots=True)
class AuditRequest:
    """A single audit request."""

    control: Control
    host: str

    def __post_init__(self) -> None:
        if not isinstance(self.control, Control):
            raise TypeError("control must be a Control")

        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("host must be a non-empty string")


class AuditEngine:
    """
    Benchmark-independent audit orchestration.

    The engine delegates the actual system inspection to an AuditProvider.
    It does not modify the target system.

    Two calling forms are supported:

        audit(control, host)
        audit(AuditRequest(control=control, host=host))

    The first form is the simple public API. The request-object form is
    retained for workflows that already construct AuditRequest objects.
    """

    def __init__(
        self,
        provider: AuditProvider,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        if provider is None:
            raise ValueError("provider is required")

        self._provider = provider
        self._evidence_store = evidence_store

    def audit(
        self,
        control_or_request: Control | AuditRequest,
        host: str | None = None,
    ) -> AuditResult:
        """
        Audit one control on one host.

        The provider result is returned unchanged with respect to its
        compliance status and evidence. The engine only handles orchestration
        and optional evidence persistence.
        """
        control, target_host = self._normalize_request(
            control_or_request,
            host,
        )

        result = self._provider.audit(control, target_host)

        if not isinstance(result, AuditResult):
            raise TypeError("audit provider must return an AuditResult")

        if result.control_id != control.control_id:
            raise ValueError(
                f"audit provider returned control_id '{result.control_id}' "
                f"for requested control '{control.control_id}'"
            )

        if result.host != target_host:
            raise ValueError(
                f"audit provider returned host '{result.host}' "
                f"for requested host '{target_host}'"
            )

        if self._evidence_store is not None:
            for sequence, evidence in enumerate(result.evidence):
                self._store_evidence(
                    evidence=evidence,
                    sequence=sequence,
                )

        return result

    def audit_many(
        self,
        requests: list[AuditRequest] | tuple[AuditRequest, ...],
    ) -> tuple[AuditResult, ...]:
        """Audit requests sequentially while preserving input order."""

        if not isinstance(requests, (list, tuple)):
            raise TypeError("requests must be a list or tuple")

        return tuple(self.audit(request) for request in requests)

    def _normalize_request(
        self,
        control_or_request: Control | AuditRequest,
        host: str | None,
    ) -> tuple[Control, str]:
        if isinstance(control_or_request, AuditRequest):
            if host is not None:
                raise TypeError(
                    "host must not be supplied when using AuditRequest"
                )

            return control_or_request.control, control_or_request.host

        if not isinstance(control_or_request, Control):
            raise TypeError("control must be a Control")

        if not isinstance(host, str) or not host.strip():
            raise ValueError("host must be a non-empty string")

        return control_or_request, host

    def _store_evidence(
        self,
        *,
        evidence: Evidence,
        sequence: int,
    ) -> None:
        """
        Persist one evidence object in the configured EvidenceStore.

        EvidenceStore requires an explicit stable identifier. The identifier
        is derived from the audit target, control, collection timestamp, and
        evidence sequence within the AuditResult.

        The evidence itself is never modified.
        """
        store = self._evidence_store

        if store is None:
            return

        add = getattr(store, "add", None)

        if add is None:
            raise TypeError(
                "evidence_store must provide an add("
                "evidence_id, evidence) method"
            )

        evidence_id = (
            f"{evidence.host}:"
            f"{evidence.control_id}:"
            f"{evidence.collected_at.isoformat()}:"
            f"{sequence}"
        )

        add(evidence_id, evidence)


class UnsupportedAuditProvider:
    """
    Explicit fail-closed provider for controls without an implementation.

    An unsupported audit must never claim compliance.
    """

    def audit(self, control: Control, host: str) -> AuditResult:
        evidence = Evidence(
            control_id=control.control_id,
            host=host,
            source="unsupported-audit-provider",
            observed={"supported": False},
            expected={"supported": True},
            details={
                "message": (
                    f"No audit implementation is available for "
                    f"control '{control.control_id}'."
                )
            },
        )

        return AuditResult(
            control_id=control.control_id,
            host=host,
            status=ComplianceStatus.UNKNOWN,
            evidence=(evidence,),
            message="Audit implementation is not available.",
        )