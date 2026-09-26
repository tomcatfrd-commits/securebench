from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol

from securebench.core.control import Control
from securebench.core.result import Evidence, VerificationResult


@dataclass(frozen=True, slots=True)
class VerificationRequest:
    control: Control
    host: str
    context: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.control, Control):
            raise TypeError("control must be a Control")

        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("host must be a non-empty string")

        if not isinstance(self.context, Mapping):
            raise TypeError("context must be a mapping")


class VerificationProvider(Protocol):
    def verify(
        self,
        control: Control,
        host: str,
        context: Mapping[str, object],
    ) -> VerificationResult:
        ...


class VerificationEngine:
    """
    Execute independent, read-only verification.

    Verification is deliberately separate from remediation execution.
    A successful remediation operation is not itself evidence of compliance.
    """

    def __init__(self, provider: VerificationProvider) -> None:
        self._provider = provider

    def verify(self, request: VerificationRequest) -> VerificationResult:
        if not isinstance(request, VerificationRequest):
            raise TypeError("request must be a VerificationRequest")

        return self._provider.verify(
            control=request.control,
            host=request.host,
            context=request.context,
        )

    def verify_many(
        self,
        requests: tuple[VerificationRequest, ...],
    ) -> tuple[VerificationResult, ...]:
        return tuple(self.verify(request) for request in requests)


class UnsupportedVerificationProvider:
    """
    Fail closed when no verification implementation exists.

    The absence of a verification mechanism must never be interpreted as
    successful verification.
    """

    def verify(
        self,
        control: Control,
        host: str,
        context: Mapping[str, object],
    ) -> VerificationResult:
        return VerificationResult(
            control_id=control.control_id,
            host=host,
            status="UNKNOWN",
            evidence=Evidence(
                control_id=control.control_id,
                host=host,
                source="unsupported-verification-provider",
                observed=None,
                expected=None,
                details={
                    "reason": "No verification provider is configured.",
                },
            ),
        )