from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from securebench.core.control import Control
from securebench.core.result import ComplianceStatus, Evidence, VerificationResult


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
        context: Mapping[str, object] = {},
    ) -> VerificationResult:
        ...


class VerificationEngine:
    """
    Execute independent, read-only verification.

    Verification is deliberately separate from remediation execution.
    A successful remediation operation is not itself evidence of compliance.

    The engine accepts either a VerificationRequest or the legacy
    (control, host) calling convention used by unit tests.
    """

    def __init__(self, provider: VerificationProvider) -> None:
        self._provider = provider

    def verify(
        self,
        request_or_control: VerificationRequest | Control,
        host: str | None = None,
    ) -> VerificationResult:
        if isinstance(request_or_control, VerificationRequest):
            request = request_or_control
        elif isinstance(request_or_control, Control):
            if host is None or not isinstance(host, str) or not host.strip():
                raise ValueError(
                    "host must be a non-empty string when calling "
                    "verify(control, host)"
                )
            request = VerificationRequest(
                control=request_or_control,
                host=host,
            )
        else:
            raise TypeError(
                "verify() expects a VerificationRequest or "
                "(control, host)"
            )

        return self._call_provider(request)

    def verify_many(
        self,
        requests: tuple[VerificationRequest, ...] | list[VerificationRequest],
    ) -> tuple[VerificationResult, ...]:
        return tuple(self.verify(request) for request in requests)

    def _call_provider(self, request: VerificationRequest) -> VerificationResult:
        """
        Invoke the provider, tolerating implementations that do not yet
        accept the context argument.
        """
        method = self._provider.verify
        try:
            signature = inspect.signature(method)
            accepts_context = "context" in signature.parameters
        except (TypeError, ValueError):
            # Builtins / C extensions etc. – fall back to trying with context.
            accepts_context = True

        if accepts_context:
            return method(
                control=request.control,
                host=request.host,
                context=request.context,
            )

        return method(
            control=request.control,
            host=request.host,
        )


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
        context: Mapping[str, object] | None = None,
    ) -> VerificationResult:
        return VerificationResult(
            control_id=control.control_id,
            host=host,
            status=ComplianceStatus.UNKNOWN,
            evidence=(
                Evidence(
                    control_id=control.control_id,
                    host=host,
                    source="unsupported-verification-provider",
                    observed=None,
                    expected=None,
                    details={
                        "reason": "No verification provider is configured.",
                    },
                ),
            ),
            message="No verification provider is configured.",
        )