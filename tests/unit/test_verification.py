from __future__ import annotations

from datetime import UTC, datetime

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.result import ComplianceStatus, VerificationResult
from securebench.verification.engine import (
    UnsupportedVerificationProvider,
    VerificationEngine,
    VerificationRequest,
)


def make_control(control_id: str = "TEST-1") -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control description",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="test.audit",
        remediation="test.remediate",
        rollback="test.rollback",
        verification="test.verify",
        rollback_capability=RollbackCapability.GUARANTEED,
        metadata={
            "safety": {
                "default": SafetyClassification.SAFE.value,
                "prechecks": (),
            },
            "requirements": {
                "setting": "expected",
            },
        },
    )


class FakeVerificationProvider:
    def __init__(self, status: ComplianceStatus = ComplianceStatus.PASS) -> None:
        self.status = status
        self.calls: list[tuple[str, str]] = []

    def verify(self, control: Control, host: str) -> VerificationResult:
        self.calls.append((control.control_id, host))

        return VerificationResult(
            control_id=control.control_id,
            host=host,
            status=self.status,
            evidence=(),
            message=f"Verification returned {self.status.value}.",
        )


class FailingVerificationProvider:
    def verify(self, control: Control, host: str) -> VerificationResult:
        raise RuntimeError(
            f"Verification failed for {control.control_id} on {host}"
        )


def test_verification_engine_delegates_to_provider() -> None:
    provider = FakeVerificationProvider()
    engine = VerificationEngine(provider=provider)

    result = engine.verify(make_control(), "server01")

    assert result.control_id == "TEST-1"
    assert result.host == "server01"
    assert result.status is ComplianceStatus.PASS
    assert provider.calls == [("TEST-1", "server01")]


def test_verification_engine_does_not_modify_control() -> None:
    provider = FakeVerificationProvider()
    engine = VerificationEngine(provider=provider)

    control = make_control()
    result = engine.verify(control, "server01")

    assert result.status is ComplianceStatus.PASS
    assert control.control_id == "TEST-1"
    assert control is control


@pytest.mark.parametrize(
    "status",
    [
        ComplianceStatus.PASS,
        ComplianceStatus.FAIL,
        ComplianceStatus.UNKNOWN,
        ComplianceStatus.ERROR,
    ],
)
def test_verification_engine_preserves_provider_status(
    status: ComplianceStatus,
) -> None:
    provider = FakeVerificationProvider(status=status)
    engine = VerificationEngine(provider=provider)

    result = engine.verify(make_control(), "server01")

    assert result.status is status
    assert result.verified is (status is ComplianceStatus.PASS)


def test_verification_engine_is_read_only_from_workflow_perspective() -> None:
    provider = FakeVerificationProvider()
    engine = VerificationEngine(provider=provider)

    control = make_control()

    before = (
        control.control_id,
        control.title,
        control.remediation,
        control.rollback,
        control.metadata,
    )

    engine.verify(control, "server01")

    after = (
        control.control_id,
        control.title,
        control.remediation,
        control.rollback,
        control.metadata,
    )

    assert after == before


def test_verification_result_verified_is_true_only_for_pass() -> None:
    for status in ComplianceStatus:
        result = VerificationResult(
            control_id="TEST-1",
            host="server01",
            status=status,
            evidence=(),
        )

        assert result.verified is (status is ComplianceStatus.PASS)


def test_verification_many_preserves_input_order() -> None:
    provider = FakeVerificationProvider()
    engine = VerificationEngine(provider=provider)

    controls = [
        make_control("TEST-1"),
        make_control("TEST-2"),
        make_control("TEST-3"),
    ]

    requests = [
        VerificationRequest(control=controls[0], host="server01"),
        VerificationRequest(control=controls[1], host="server02"),
        VerificationRequest(control=controls[2], host="server03"),
    ]

    results = engine.verify_many(requests)

    assert [result.control_id for result in results] == [
        "TEST-1",
        "TEST-2",
        "TEST-3",
    ]

    assert [result.host for result in results] == [
        "server01",
        "server02",
        "server03",
    ]

    assert provider.calls == [
        ("TEST-1", "server01"),
        ("TEST-2", "server02"),
        ("TEST-3", "server03"),
    ]


def test_verification_many_empty_input_returns_empty_tuple() -> None:
    provider = FakeVerificationProvider()
    engine = VerificationEngine(provider=provider)

    assert engine.verify_many([]) == ()


def test_unsupported_provider_returns_unknown() -> None:
    provider = UnsupportedVerificationProvider()
    engine = VerificationEngine(provider=provider)

    result = engine.verify(make_control(), "server01")

    assert result.status is ComplianceStatus.UNKNOWN
    assert result.verified is False
    assert result.evidence
    assert result.evidence[0].source == "unsupported-verification-provider"


def test_unsupported_provider_does_not_claim_verification() -> None:
    provider = UnsupportedVerificationProvider()
    engine = VerificationEngine(provider=provider)

    result = engine.verify(make_control(), "server01")

    assert result.status is ComplianceStatus.UNKNOWN
    assert result.verified is False


def test_verification_engine_propagates_provider_failure() -> None:
    provider = FailingVerificationProvider()
    engine = VerificationEngine(provider=provider)

    with pytest.raises(RuntimeError, match="Verification failed"):
        engine.verify(make_control(), "server01")


def test_verification_request_is_immutable() -> None:
    request = VerificationRequest(
        control=make_control(),
        host="server01",
    )

    with pytest.raises(AttributeError):
        request.host = "server02"  # type: ignore[misc]


def test_verification_result_is_immutable() -> None:
    result = VerificationResult(
        control_id="TEST-1",
        host="server01",
        status=ComplianceStatus.PASS,
        evidence=(),
        collected_at=datetime.now(UTC),
    )

    with pytest.raises(AttributeError):
        result.host = "server02"  # type: ignore[misc]