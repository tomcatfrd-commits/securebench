from __future__ import annotations

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
)
from securebench.core.result import (
    ComplianceStatus,
    Evidence,
    VerificationResult,
)
from securebench.verification.engine import (
    VerificationEngine,
    VerificationRequest,
)


def make_control(
    control_id: str = "TEST-1",
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control.",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="audit.test",
        remediation="remediation.test",
        rollback="rollback.test",
        verification="verification.test",
        rollback_capability=RollbackCapability.GUARANTEED,
    )


class RecordingVerificationProvider:
    def __init__(
        self,
        *,
        status: ComplianceStatus = ComplianceStatus.PASS,
    ) -> None:
        self.status = status
        self.calls: list[tuple[str, str]] = []

    def verify(
        self,
        control: Control,
        host: str,
    ) -> VerificationResult:
        self.calls.append(
            (control.control_id, host)
        )

        evidence = Evidence(
            control_id=control.control_id,
            host=host,
            source="recording-verification-provider",
            observed={"compliant": self.status is ComplianceStatus.PASS},
            expected={"compliant": True},
        )

        return VerificationResult(
            control_id=control.control_id,
            host=host,
            status=self.status,
            evidence=(evidence,),
        )


def test_verification_delegates_to_provider() -> None:
    control = make_control()
    provider = RecordingVerificationProvider()
    engine = VerificationEngine(provider=provider)

    result = engine.verify(
        VerificationRequest(
            control=control,
            host="production-01",
        )
    )

    assert provider.calls == [
        ("TEST-1", "production-01"),
    ]
    assert result.status is ComplianceStatus.PASS
    assert result.verified is True


def test_verification_is_read_only_at_engine_boundary() -> None:
    control = make_control()
    provider = RecordingVerificationProvider()
    engine = VerificationEngine(provider=provider)

    original = (
        control.control_id,
        control.title,
        control.dependencies,
        control.conflicts,
    )

    engine.verify(
        VerificationRequest(
            control=control,
            host="production-01",
        )
    )

    assert (
        control.control_id,
        control.title,
        control.dependencies,
        control.conflicts,
    ) == original


def test_verification_does_not_execute_remediation() -> None:
    control = make_control()

    class ProviderWithOperationTracking(
        RecordingVerificationProvider
    ):
        def __init__(self) -> None:
            super().__init__()
            self.remediation_calls = 0

        def remediate(self) -> None:
            self.remediation_calls += 1

    provider = ProviderWithOperationTracking()
    engine = VerificationEngine(provider=provider)

    engine.verify(
        VerificationRequest(
            control=control,
            host="production-01",
        )
    )

    assert provider.remediation_calls == 0


def test_verification_does_not_execute_rollback() -> None:
    control = make_control()

    class ProviderWithOperationTracking(
        RecordingVerificationProvider
    ):
        def __init__(self) -> None:
            super().__init__()
            self.rollback_calls = 0

        def rollback(self) -> None:
            self.rollback_calls += 1

    provider = ProviderWithOperationTracking()
    engine = VerificationEngine(provider=provider)

    engine.verify(
        VerificationRequest(
            control=control,
            host="production-01",
        )
    )

    assert provider.rollback_calls == 0


def test_failed_verification_is_preserved() -> None:
    control = make_control()
    provider = RecordingVerificationProvider(
        status=ComplianceStatus.FAIL,
    )
    engine = VerificationEngine(provider=provider)

    result = engine.verify(
        VerificationRequest(
            control=control,
            host="production-01",
        )
    )

    assert result.status is ComplianceStatus.FAIL
    assert result.verified is False


def test_unknown_verification_is_preserved() -> None:
    control = make_control()
    provider = RecordingVerificationProvider(
        status=ComplianceStatus.UNKNOWN,
    )
    engine = VerificationEngine(provider=provider)

    result = engine.verify(
        VerificationRequest(
            control=control,
            host="production-01",
        )
    )

    assert result.status is ComplianceStatus.UNKNOWN
    assert result.verified is False


def test_verification_evidence_is_preserved() -> None:
    control = make_control()
    provider = RecordingVerificationProvider()
    engine = VerificationEngine(provider=provider)

    result = engine.verify(
        VerificationRequest(
            control=control,
            host="production-01",
        )
    )

    assert len(result.evidence) == 1
    assert (
        result.evidence[0].source
        == "recording-verification-provider"
    )


def test_verification_many_preserves_request_order() -> None:
    controls = (
        make_control("TEST-1"),
        make_control("TEST-2"),
        make_control("TEST-3"),
    )

    provider = RecordingVerificationProvider()
    engine = VerificationEngine(provider=provider)

    requests = tuple(
        VerificationRequest(
            control=control,
            host="production-01",
        )
        for control in controls
    )

    results = engine.verify_many(requests)

    assert [result.control_id for result in results] == [
        "TEST-1",
        "TEST-2",
        "TEST-3",
    ]

    assert provider.calls == [
        ("TEST-1", "production-01"),
        ("TEST-2", "production-01"),
        ("TEST-3", "production-01"),
    ]


def test_empty_verification_batch_has_no_side_effects() -> None:
    provider = RecordingVerificationProvider()
    engine = VerificationEngine(provider=provider)

    results = engine.verify_many(())

    assert results == ()
    assert provider.calls == []


def test_verification_request_is_immutable() -> None:
    control = make_control()

    request = VerificationRequest(
        control=control,
        host="production-01",
    )

    try:
        request.host = "production-02"  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "VerificationRequest must be immutable."
        )


def test_verification_provider_failure_is_not_converted_to_pass() -> None:
    control = make_control()

    class FailingProvider:
        def verify(
            self,
            control: Control,
            host: str,
        ) -> VerificationResult:
            raise RuntimeError("verification backend failed")

    engine = VerificationEngine(
        provider=FailingProvider(),
    )

    try:
        engine.verify(
            VerificationRequest(
                control=control,
                host="production-01",
            )
        )
    except RuntimeError as exc:
        assert str(exc) == "verification backend failed"
    else:
        raise AssertionError(
            "Verification failure was silently converted to success."
        )