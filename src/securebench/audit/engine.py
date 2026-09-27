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

    The engine delegates system inspection to an AuditProvider and never
    modifies the target system itself.

    Evidence returned by the provider is persisted exactly as supplied.
    The engine does not manufacture evidence when the provider returns none.
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

        The provider remains responsible for producing the actual observation.
        The engine validates the provider result and optionally persists every
        evidence item returned by that provider.
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
            for evidence in result.evidence:
                self._store_evidence(evidence)

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

    def _store_evidence(self, evidence: Evidence) -> None:
        """
        Persist one provider-produced evidence item.

        EvidenceStore requires an explicit stable ID. The ID is derived from
        the immutable identity of the evidence rather than from an arbitrary
        counter, so the same control/host/source combination is deterministic.
        """
        store = self._evidence_store

        if store is None:
            return

        evidence_id = self._evidence_id(evidence)

        store.add(
            evidence_id=evidence_id,
            evidence=evidence,
        )

    @staticmethod
    def _evidence_id(evidence: Evidence) -> str:
        """
        Build the EvidenceStore key for one evidence object.

        The ID is intentionally derived from evidence identity and contains
        only stable fields needed to distinguish evidence records.
        """
        return ":".join(
            (
                evidence.control_id,
                evidence.host,
                evidence.source,
            )
        )


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